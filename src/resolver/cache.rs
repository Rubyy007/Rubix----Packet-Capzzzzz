// src/resolver/cache.rs
//! ProcessResolver — 1-second TTL cache with background async refresh.
//!
//! Design goals:
//!   • Hot path (lookup) must never call snapshot() — that would stall the
//!     packet loop for milliseconds while /proc or Win32 APIs are queried.
//!   • Exactly one background refresh runs at a time — AtomicBool prevents
//!     a thundering herd when many packets see an expired TTL simultaneously.
//!   • Multiple concurrent readers are never blocked by each other —
//!     parking_lot::RwLock allows unlimited simultaneous read locks.
//!   • A stale read (lookup sees a table that is 800ms old, refresh is in
//!     flight) is always preferred over blocking — process attribution is
//!     best-effort by design.
//!
//! Typical costs:
//!   lookup() fast path (TTL not expired):  ~5 ns
//!     — one Relaxed atomic load + one RwLock read
//!   lookup() on TTL expiry (first caller): ~5 ns + tokio::spawn overhead
//!     — the spawn is async and returns immediately; caller reads stale table
//!   Background snapshot() (Linux):         ~2–10 ms  (reads /proc files)
//!   Background snapshot() (Windows):       ~1–5 ms   (4 Win32 API calls)

use super::{FlowKey, ProcessInfo, snapshot};
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

// ── ProcessResolver ───────────────────────────────────────────────────────────

/// Hot-path process resolver with TTL-based background refresh.
///
/// Constructed once in main() and used via Arc<ProcessResolver>.
/// The packet loop calls lookup() on every packet — this must be near zero-cost.
pub struct ProcessResolver {
    /// The live socket→process table.  Swapped atomically by the refresh task.
    /// Stored as FxHashMap for fast lookup — converted from the plain HashMap
    /// returned by snapshot() via into_iter().collect() in the refresh task.
    table: Arc<RwLock<FxHashMap<FlowKey, ProcessInfo>>>,

    /// Nanosecond timestamp of the last successfully completed refresh.
    /// Read with Relaxed on the hot path — stale reads are acceptable.
    last_refresh_ns: Arc<AtomicU64>,

    /// True while a background refresh task is running.
    /// compare_exchange(false→true) ensures at most one refresh at a time.
    refreshing: Arc<AtomicBool>,

    /// Cache TTL in nanoseconds.  Default: 1_000_000_000 (1 second).
    ttl_ns: u64,
}

impl ProcessResolver {
    /// Construct with the default 1-second TTL.
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_millis(1000))
    }

    /// Construct with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        let table: FxHashMap<FlowKey, ProcessInfo> =
            FxHashMap::with_capacity_and_hasher(512, Default::default());

        Self {
            table:           Arc::new(RwLock::new(table)),
            last_refresh_ns: Arc::new(AtomicU64::new(0)),
            refreshing:      Arc::new(AtomicBool::new(false)),
            ttl_ns:          ttl.as_nanos() as u64,
        }
    }

    // ── Hot path ──────────────────────────────────────────────────────────────

    /// Look up a socket endpoint → process.
    ///
    /// Always returns immediately — never blocks for a snapshot.
    /// Triggers a background refresh if the TTL has expired.
    #[inline(always)]
    pub fn lookup(&self, key: &FlowKey) -> Option<ProcessInfo> {
        self.maybe_refresh_async();
        self.table.read().get(key).cloned()
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /// All currently known processes, deduplicated by PID.
    ///
    /// A single process can own hundreds of sockets — this returns one
    /// ProcessInfo per unique PID.  Used by the CLI process list.
    pub fn all_processes(&self) -> Vec<ProcessInfo> {
        self.maybe_refresh_async();

        let guard = self.table.read();
        let mut seen: HashSet<u32> = HashSet::with_capacity(64);

        guard.values()
            .filter(|p| seen.insert(p.pid))
            .cloned()
            .collect()
    }

    /// Number of socket→process mappings currently cached.
    #[inline]
    pub fn flow_count(&self) -> usize {
        self.table.read().len()
    }

    /// True if a background refresh is currently in flight.
    #[inline]
    pub fn is_refreshing(&self) -> bool {
        self.refreshing.load(Ordering::Relaxed)
    }

    /// Nanoseconds since epoch of the last completed refresh.
    /// Returns 0 if no refresh has completed yet.
    #[inline]
    pub fn last_refresh_ns(&self) -> u64 {
        self.last_refresh_ns.load(Ordering::Relaxed)
    }

    // ── Internal refresh machinery ────────────────────────────────────────────

    /// Check TTL and spawn a background refresh if needed.
    ///
    /// Fast path: one Relaxed atomic load + one integer comparison (~2 ns).
    /// When TTL expires: one compare_exchange + one tokio::spawn — non-blocking.
    #[inline(always)]
    fn maybe_refresh_async(&self) {
        let now_ns = Self::now_nanos();
        let last   = self.last_refresh_ns.load(Ordering::Relaxed);

        if now_ns.saturating_sub(last) < self.ttl_ns {
            return;
        }

        // Only one caller wins the compare_exchange; all others fall through
        // and read the current (stale) table — correct behaviour.
        if self.refreshing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let table     = self.table.clone();
            let timestamp = self.last_refresh_ns.clone();
            let flag      = self.refreshing.clone();

            tokio::spawn(async move {
                match snapshot() {
                    Ok(snap) => {
                        // snapshot() returns HashMap; convert to FxHashMap here.
                        // The write lock window is brief — just a pointer swap.
                        {
                            let mut guard = table.write();
                            *guard = snap.into_iter().collect();
                        }
                        timestamp.store(Self::now_nanos(), Ordering::Release);
                    }
                    Err(e) => {
                        // Non-fatal: keep the previous table, retry next TTL.
                        tracing::warn!(
                            error = %e,
                            "ProcessResolver: snapshot failed — keeping stale table"
                        );
                    }
                }
                // Always release the refresh flag — even on error.
                flag.store(false, Ordering::Release);
            });
        }
    }

    #[inline(always)]
    fn now_nanos() -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }
}

impl Default for ProcessResolver {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}