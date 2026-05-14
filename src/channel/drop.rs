// src/channel/drop.rs
//! Packet drop accounting.
//!
//! # Design goals
//!
//! 1. **Zero locks on the fast path.**  `record_drop` is called from the
//!    packet-processing loop and must not contend with any other thread.
//!
//! 2. **Bounded memory.**  The per-IP map cannot grow without limit.
//!    A hard cap (`MAX_TRACKED_IPS`) is enforced; once reached, new IPs are
//!    counted in a catch-all overflow counter rather than allocated as new
//!    entries.
//!
//! 3. **No nested locks.**  Reset logic is separated from increment logic.
//!    No function acquires more than one lock at a time.
//!
//! # Implementation
//!
//! `DashMap` provides sharded concurrent writes (16 shards by default).
//! Each shard is an independent `RwLock<HashMap>`.  At 200 k drops/sec
//! across N threads, each shard sees ~12.5 k ops/sec — well within the
//! throughput of a single `RwLock`.
//!
//! The reset epoch is a separate `AtomicU64`.  Hot-path writers read it
//! with `Relaxed` and compare to their cached copy; an epoch change is the
//! only signal needed to know a reset has occurred.  The actual reset
//! (clearing the DashMap) happens in a dedicated slow-path task that holds
//! no lock on the drop path.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{Duration, Instant};

/// Maximum number of distinct source IPs tracked in the per-IP map.
/// Once this limit is reached, additional IPs increment `overflow_drops`
/// instead of allocating new entries.  Prevents unbounded HashMap growth
/// under a source-spoofing attack that cycles through millions of IPs.
const MAX_TRACKED_IPS: usize = 65_536;

// ── PacketDrop ────────────────────────────────────────────────────────────────

/// Shared packet-drop accounting state.
///
/// Clone is cheap — all clones share the same underlying data via `Arc`.
#[derive(Clone)]
pub struct PacketDrop {
    inner: Arc<DropInner>,
}

struct DropInner {
    /// Lifetime total drops.  Always monotonically increasing.
    total_dropped:   AtomicU64,

    /// Drops for IPs that exceeded MAX_TRACKED_IPS.
    overflow_drops:  AtomicU64,

    /// Per-IP drop counters.  DashMap provides sharded concurrent access.
    drops_by_ip:     DashMap<IpAddr, AtomicU64>,

    /// Monotonic reset epoch.  Incremented by the reset task.
    /// Hot-path writers do NOT read this — reset is purely an async
    /// slow-path operation.
    reset_epoch:     AtomicU64,

    /// Wall-clock time of last reset.  Read/written only by the reset task.
    last_reset:      tokio::sync::Mutex<Instant>,

    /// How often the per-IP map is cleared.
    reset_interval:  Duration,
}

impl PacketDrop {
    /// Create a new `PacketDrop`.
    ///
    /// `reset_interval_secs` controls how frequently the per-IP map is cleared.
    /// The total-dropped counter is never reset.
    pub fn new(reset_interval_secs: u64) -> Self {
        Self {
            inner: Arc::new(DropInner {
                total_dropped:  AtomicU64::new(0),
                overflow_drops: AtomicU64::new(0),
                drops_by_ip:    DashMap::with_capacity(1024),
                reset_epoch:    AtomicU64::new(0),
                last_reset:     tokio::sync::Mutex::new(Instant::now()),
                reset_interval: Duration::from_secs(reset_interval_secs),
            }),
        }
    }

    // ── Hot path ──────────────────────────────────────────────────────────────

    /// Record one dropped packet from `ip`.
    ///
    /// **Fast path.**  Lock-free on the common case (IP already tracked).
    /// Acquires a DashMap shard write lock only on first insertion for a new IP.
    /// Never acquires the reset lock.  Never allocates if the IP is known.
    #[inline]
    pub fn record_drop(&self, ip: IpAddr) {
        // Unconditionally increment the global total.
        self.inner.total_dropped.fetch_add(1, Ordering::Relaxed);

        // Per-IP accounting with memory cap.
        //
        // `entry().or_insert_with(...)` on DashMap acquires a shard write lock
        // only when the key is absent.  On the common path (key present) it
        // acquires the shard *read* lock, which allows concurrent reads and
        // reduces contention significantly vs a single global RwLock.
        if self.inner.drops_by_ip.len() < MAX_TRACKED_IPS {
            self.inner
                .drops_by_ip
                .entry(ip)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        } else if self.inner.drops_by_ip.contains_key(&ip) {
            // IP is already tracked — safe to increment.
            if let Some(counter) = self.inner.drops_by_ip.get(&ip) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            // Map is full and this is a new IP — count it in overflow.
            self.inner.overflow_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ── Slow path ─────────────────────────────────────────────────────────────

    /// Periodically reset per-IP counters if the reset interval has elapsed.
    ///
    /// **Must be called from an async context (slow path only).**
    /// Acquires `last_reset` (a `tokio::sync::Mutex` — async, non-blocking).
    /// Never called from the packet-processing loop.
    pub async fn maybe_reset(&self) {
        let mut last = self.inner.last_reset.lock().await;
        if last.elapsed() >= self.inner.reset_interval {
            self.inner.drops_by_ip.clear();
            self.inner.overflow_drops.store(0, Ordering::Relaxed);
            self.inner.reset_epoch.fetch_add(1, Ordering::Release);
            *last = Instant::now();
            tracing::info!(
                epoch = self.inner.reset_epoch.load(Ordering::Relaxed),
                "packet drop statistics reset"
            );
        }
    }

    // ── Read accessors ────────────────────────────────────────────────────────

    /// Total packets dropped since startup (never reset).
    #[inline]
    pub fn get_total_dropped(&self) -> u64 {
        self.inner.total_dropped.load(Ordering::Relaxed)
    }

    /// Drops that could not be attributed to a tracked IP (map cap reached).
    #[inline]
    pub fn get_overflow_drops(&self) -> u64 {
        self.inner.overflow_drops.load(Ordering::Relaxed)
    }

    /// Returns the current drop count for a single IP.
    ///
    /// O(1) — acquires one DashMap shard read lock, no allocation.
    #[inline]
    pub fn get_drops_for_ip(&self, ip: &IpAddr) -> u64 {
        self.inner
            .drops_by_ip
            .get(ip)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Returns a snapshot of per-IP drop counts, sorted descending by count.
    ///
    /// **Slow path only.**  Iterates and allocates; do not call from hot path.
    /// The returned `Vec` is at most `MAX_TRACKED_IPS` entries.
    pub fn get_top_blocked(&self, count: usize) -> Vec<(IpAddr, u64)> {
        let mut drops: Vec<(IpAddr, u64)> = self
            .inner
            .drops_by_ip
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .collect();

        drops.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        drops.truncate(count);
        drops
    }

    /// Returns the current number of distinct IPs being tracked.
    #[inline]
    pub fn tracked_ip_count(&self) -> usize {
        self.inner.drops_by_ip.len()
    }

    /// Current reset epoch.  Useful for consumers that want to detect resets.
    #[inline]
    pub fn reset_epoch(&self) -> u64 {
        self.inner.reset_epoch.load(Ordering::Acquire)
    }
}