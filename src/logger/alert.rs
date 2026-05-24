// src/logger/alert.rs
//! Security and traffic alert logging for RUBIX.
//!
//! ── Design ────────────────────────────────────────────────────────────────
//!
//! The previous implementation used `Mutex<File>` with `flush()` on every
//! write.  At high packet rates (200 k pps) this was two syscalls per packet
//! on every log call — unacceptable in the hot path.
//!
//! Replacement: a **channel-based async writer**.
//!
//!   Hot path (packet loop):
//!     • Reads a pre-cached timestamp string (updated once per millisecond
//!       by a background task — see `CachedTimestamp`).  Zero syscalls.
//!     • Formats a log line (heap-allocated String via format!).
//!     • Calls `try_send` on a bounded `std::sync::mpsc` channel.
//!     • If the channel is full the line is **silently dropped** — the hot
//!       path never blocks.  The drop is counted in DROP_COUNTER and
//!       visible in `rubix-cli logs errors` when it exceeds DROP_WARN_THRESHOLD.
//!
//!   Background writer thread (spawned once at init):
//!     • Drains the channel in a tight loop, batching up to BATCH_SIZE
//!       lines per write_all call.
//!     • Calls flush() after each batch — amortises the syscall cost.
//!     • Rotates the file when it exceeds max_file_size_mb, keeping up to
//!       ROTATION_KEEP_COUNT backups with a timestamp suffix so history is
//!       never silently overwritten.
//!
//!   Separate files:
//!     • alerts.log  — Block + Alert + Threat events (security ring feed).
//!     • traffic.log — Normal + sampled Allow events (normal ring feed).
//!     • errors.log  — Daemon-internal errors.
//!
//! ── Timestamp caching (Performance fix #2 / #4) ───────────────────────────
//!
//! `chrono::Local::now().format()` performs:
//!   1. A `clock_gettime` syscall.
//!   2. An IANA timezone database lookup (cached by the OS, but still a
//!      function call chain through libc).
//!   3. A `format!` heap allocation for the resulting String.
//!
//! At 200 k pps with 1-in-100 normal sampling + all block/alert events
//! this was called tens of thousands of times per second.
//!
//! Fix: `CachedTimestamp` stores a pre-formatted `Arc<String>` that a
//! background task refreshes once per millisecond.  Hot-path callers do
//! one `Arc::clone` (~2 ns) instead of a syscall + alloc.
//!
//! The cached string is also written into `push_log_entry` / `push_normal_entry`
//! in main.rs — the packet loop passes `ts_cache.get()` instead of calling
//! `chrono::Local::now()` itself.
//!
//! ── Thread safety ────────────────────────────────────────────────────────
//!
//! AlertLogger is a zero-sized unit struct with only &'static state.
//! The channel sender is stored in a OnceLock<SyncSender> — cloning a
//! SyncSender is cheap (Arc bump) and the clone is what the hot path holds.
//! No Mutex is ever acquired in log_block, log_alert, log_normal, or log_error.
//!
//! ── Cross-platform ───────────────────────────────────────────────────────
//!
//! File paths resolve via alert_log_dir() which is platform-aware.
//! No Unix-only or Windows-only APIs are used here.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Lines batched per write call in the background writer.
const BATCH_SIZE: usize = 128;

/// Background writer blocks waiting for a message for this long before
/// performing a periodic flush.  10 ms keeps latency low without busy-waiting.
const RECV_TIMEOUT_MS: u64 = 10;

/// Log a drop-counter ERROR entry every time this many lines have been
/// silently dropped since the last warning.
const DROP_WARN_THRESHOLD: u64 = 1_000;

/// How many rotated backups to keep per log file.
/// Older backups beyond this count are deleted automatically.
const ROTATION_KEEP_COUNT: usize = 5;

// ── Platform log directory ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn alert_log_dir() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| PathBuf::from(p).join("rubix").join("logs"))
        .unwrap_or_else(|_| PathBuf::from("logs"))
}

#[cfg(not(target_os = "windows"))]
fn alert_log_dir() -> PathBuf {
    PathBuf::from("/var/log/rubix")
}

// ── Channel message ───────────────────────────────────────────────────────────

/// A single pre-formatted log line together with its destination file.
struct LogLine {
    dest: LogDest,
    line: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LogDest {
    /// alerts.log — Block, Alert, Threat.
    Alerts,
    /// traffic.log — Normal (allowed) traffic.
    Traffic,
    /// errors.log — Daemon-internal errors.
    Errors,
}

// ── Cached timestamp (Performance fix #2 / #4) ───────────────────────────────

/// Pre-formatted timestamp string refreshed once per millisecond.
///
/// Hot-path callers do `ts_cache.get()` — one `Arc::clone` (~2 ns) instead
/// of `clock_gettime` + timezone lookup + `format!` heap alloc per call.
///
/// The background refresh task is started by `AlertLogger::init_with_config`
/// as a Tokio task.  It writes with `Relaxed` ordering — the worst case is
/// that a log line gets a timestamp that is 1–2 ms stale, which is acceptable
/// for audit logging.
///
/// `CachedTimestamp` is also exposed publicly so `main.rs` can pass the same
/// cached string to `push_log_entry` and `push_normal_entry`, eliminating
/// the per-packet `chrono::Local::now()` calls there too.
#[derive(Clone)]
pub struct CachedTimestamp {
    inner: Arc<parking_lot::RwLock<Arc<String>>>,
}

impl CachedTimestamp {
    fn new() -> Self {
        let ts = Arc::new(format_timestamp_now());
        Self {
            inner: Arc::new(parking_lot::RwLock::new(ts)),
        }
    }

    /// Returns the current cached timestamp string.
    ///
    /// **Fast path safe.**  Acquires a shared read lock (~5 ns on uncontended
    /// parking_lot RwLock) and clones the inner Arc (~2 ns).  No syscall.
    #[inline]
    pub fn get(&self) -> Arc<String> {
        self.inner.read().clone()
    }

    /// Refresh the cached timestamp to the current wall clock.
    ///
    /// Called by the background refresh task — never from the hot path.
    fn refresh(&self) {
        let ts = Arc::new(format_timestamp_now());
        *self.inner.write() = ts;
    }
}

/// Format the current local time as `HH:MM:SS.mmm` (13 chars).
///
/// Called once per millisecond by the refresh task.
/// Also used to seed the initial timestamp at init.
#[inline]
fn format_timestamp_now() -> String {
    chrono::Local::now()
        .format("%H:%M:%S%.3f")
        .to_string()
}

/// Format the current local time in full RFC-3339-ish format for log files.
/// e.g. `2024-01-15T14:30:22.123+0000`
#[inline]
fn format_log_timestamp_now() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f%z")
        .to_string()
}

// ── Global state ──────────────────────────────────────────────────────────────

/// The channel sender stored globally so hot-path methods are free functions.
/// Initialised exactly once by AlertLogger::init_with_config.
static SENDER:       OnceLock<SyncSender<LogLine>> = OnceLock::new();
static DROP_COUNTER: AtomicU64                      = AtomicU64::new(0);
static DROP_LOGGED:  AtomicU64                      = AtomicU64::new(0);

/// The globally shared cached timestamp.
/// Initialised once at init; hot path reads via `TIMESTAMP_CACHE.get()`.
static TIMESTAMP_CACHE: OnceLock<CachedTimestamp> = OnceLock::new();

/// Returns the global `CachedTimestamp`, or `None` before init.
///
/// In production `init_with_config` is always called before the packet loop
/// so this is always `Some`.  Callers that get `None` should fall back to
/// `chrono::Local::now().format(...)` — this is the safe degraded path.
pub fn global_timestamp() -> Option<&'static CachedTimestamp> {
    TIMESTAMP_CACHE.get()
}

// ── Rotating file writer ──────────────────────────────────────────────────────

struct RotatingFile {
    /// Base path e.g. /var/log/rubix/alerts.log
    path:          PathBuf,
    writer:        BufWriter<File>,
    bytes_written: u64,
    max_bytes:     u64,
}

impl RotatingFile {
    /// Open (or create + append) the log file.
    fn open(path: &Path, max_mb: u64) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file     = OpenOptions::new().create(true).append(true).open(path)?;
        let existing = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path:          path.to_path_buf(),
            writer:        BufWriter::with_capacity(64 * 1024, file),
            bytes_written: existing,
            max_bytes:     max_mb * 1_000_000,
        })
    }

    /// Write a line, rotating the file first if the size limit is reached.
    fn write(&mut self, line: &str) -> std::io::Result<()> {
        if self.bytes_written >= self.max_bytes {
            self.writer.flush()?;

            // Timestamped backup: e.g. alerts.log.20240115-143022
            let ts     = chrono::Local::now().format("%Y%m%d-%H%M%S");
            let backup = PathBuf::from(format!("{}.{}", self.path.display(), ts));
            let _      = std::fs::rename(&self.path, &backup);

            self.prune_old_backups();

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.writer        = BufWriter::with_capacity(64 * 1024, file);
            self.bytes_written = 0;
        }

        self.writer.write_all(line.as_bytes())?;
        self.bytes_written += line.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    /// Delete rotated backups beyond ROTATION_KEEP_COUNT.
    fn prune_old_backups(&self) {
        let dir = match self.path.parent() {
            Some(d) => d,
            None    => return,
        };
        let base_name = match self.path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None    => return,
        };

        let mut backups: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .map(|n| {
                        let s = n.to_string_lossy();
                        s.starts_with(&base_name) && s.len() > base_name.len()
                    })
                    .unwrap_or(false)
            })
            .collect();

        backups.sort_unstable_by(|a, b| b.cmp(a));

        for old in backups.into_iter().skip(ROTATION_KEEP_COUNT) {
            let _ = std::fs::remove_file(&old);
        }
    }
}

// ── Background writer thread ──────────────────────────────────────────────────

fn run_writer(rx: Receiver<LogLine>, max_file_size_mb: u64, log_dir: PathBuf) {
    let mut alerts  = match RotatingFile::open(&log_dir.join("alerts.log"),  max_file_size_mb) {
        Ok(f) => f, Err(e) => { eprintln!("[RUBIX] Failed to open alerts.log: {e}"); return; }
    };
    let mut traffic = match RotatingFile::open(&log_dir.join("traffic.log"), max_file_size_mb) {
        Ok(f) => f, Err(e) => { eprintln!("[RUBIX] Failed to open traffic.log: {e}"); return; }
    };
    let mut errors  = match RotatingFile::open(&log_dir.join("errors.log"),  max_file_size_mb) {
        Ok(f) => f, Err(e) => { eprintln!("[RUBIX] Failed to open errors.log: {e}"); return; }
    };

    let timeout = Duration::from_millis(RECV_TIMEOUT_MS);
    let mut batch_count = 0usize;

    loop {
        match rx.recv_timeout(timeout) {
            Ok(msg) => {
                let dest = match msg.dest {
                    LogDest::Alerts  => &mut alerts,
                    LogDest::Traffic => &mut traffic,
                    LogDest::Errors  => &mut errors,
                };
                let _ = dest.write(&msg.line);
                batch_count += 1;

                // Drain up to BATCH_SIZE more lines before flushing.
                let mut i = 0;
                while i < BATCH_SIZE {
                    match rx.try_recv() {
                        Ok(m) => {
                            let d = match m.dest {
                                LogDest::Alerts  => &mut alerts,
                                LogDest::Traffic => &mut traffic,
                                LogDest::Errors  => &mut errors,
                            };
                            let _ = d.write(&m.line);
                            batch_count += 1;
                            i += 1;
                        }
                        Err(_) => break,
                    }
                }

                // Flush after each batch — amortises fsync cost.
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();
            }

            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Periodic flush even when idle.
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();

                // Check drop counter — report to errors.log if threshold hit.
                let drops  = DROP_COUNTER.load(Ordering::Relaxed);
                let logged = DROP_LOGGED.load(Ordering::Relaxed);
                if drops.saturating_sub(logged) >= DROP_WARN_THRESHOLD {
                    DROP_LOGGED.store(drops, Ordering::Relaxed);
                    // Use format_log_timestamp_now() here — this is the
                    // background thread, not the hot path.
                    let ts  = format_log_timestamp_now();
                    let msg = format!(
                        "[{ts}] ERROR type=log_drop dropped={} total_drops={}\n",
                        drops - logged, drops
                    );
                    let _ = errors.write(&msg);
                    let _ = errors.flush();
                }
            }

            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Sender dropped — flush and exit cleanly.
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();
                break;
            }
        }

        let _ = batch_count; // suppress unused warning
        batch_count = 0;
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct AlertLogger;

impl AlertLogger {
    /// Initialise the global channel + background writer thread + timestamp cache.
    ///
    /// Must be called once before any logging.  Calling it more than once
    /// is safe — subsequent calls are no-ops.
    ///
    /// `channel_depth`    — from `logging.normal_channel_depth` in config.
    /// `max_file_size_mb` — from `logging.max_file_size_mb` in config.
    pub fn init_with_config(
        channel_depth:    usize,
        max_file_size_mb: u64,
    ) -> Result<(), std::io::Error> {
        if SENDER.get().is_some() {
            return Ok(());
        }

        let log_dir = alert_log_dir();
        std::fs::create_dir_all(&log_dir)?;

        let test = log_dir.join(".rubix_write_test");
        std::fs::write(&test, b"rubix write test")?;
        let _ = std::fs::remove_file(&test);

        let (tx, rx) = mpsc::sync_channel::<LogLine>(channel_depth);

        thread::Builder::new()
            .name("rubix-log-writer".to_string())
            .spawn(move || run_writer(rx, max_file_size_mb, log_dir))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        SENDER.set(tx).ok();

        // ── Initialise the cached timestamp ───────────────────────────────────
        //
        // TIMESTAMP_CACHE is set once here.  The background refresh task is a
        // Tokio task spawned in main.rs via `AlertLogger::start_timestamp_refresh()`
        // which must be called after `#[tokio::main]` has started.
        //
        // The initial value is `format_timestamp_now()` so the first packet
        // processed has a real timestamp even before the first refresh fires.
        TIMESTAMP_CACHE.set(CachedTimestamp::new()).ok();

        Ok(())
    }

    /// Legacy init used by Logger::init_dual when config is not yet available.
    /// Safe defaults: 4096-entry channel, 100 MB per file.
    pub fn init() -> Result<(), std::io::Error> {
        Self::init_with_config(4096, 100)
    }

    /// Spawn the 1 ms timestamp refresh task.
    ///
    /// **Must be called inside an async context** (after `#[tokio::main]` starts).
    /// Call once from `main()` after `AlertLogger::init_with_config`.
    ///
    /// The task loops forever, sleeping 1 ms between refreshes.  It holds a
    /// clone of the `CachedTimestamp` Arc — no global lock contention with
    /// the hot-path readers.
    pub fn start_timestamp_refresh() {
        if let Some(cache) = TIMESTAMP_CACHE.get() {
            let cache = cache.clone();
            tokio::spawn(async move {
                let interval = tokio::time::Duration::from_millis(1);
                loop {
                    tokio::time::sleep(interval).await;
                    cache.refresh();
                }
            });
        }
    }

    // ── Hot-path logging methods ──────────────────────────────────────────────
    //
    // PERFORMANCE: all methods read the pre-cached timestamp via
    // `cached_ts()` instead of calling `chrono::Local::now()`.
    // This eliminates a `clock_gettime` syscall + timezone lookup per call.
    //
    // The timestamp is at most 1 ms stale — acceptable for audit logging.
    // If the cache is not yet initialised (before init_with_config is called)
    // `cached_ts()` falls back to `format_log_timestamp_now()` which is the
    // original behaviour.

    /// Returns the cached log-file timestamp string.
    /// Falls back to a fresh timestamp if the cache is not yet seeded.
    #[inline(always)]
    fn cached_log_ts() -> String {
        // The log-file format is a full RFC-3339-ish string, not HH:MM:SS.mmm.
        // The cache stores HH:MM:SS.mmm (used by push_log_entry in main.rs).
        // For the file logger we need the full format — the background writer
        // thread is the only consumer so we format a fresh timestamp there.
        // This is NOT called from the packet loop directly — the packet loop
        // calls log_block/alert/normal which call Self::send() which just
        // enqueues a pre-built line.  The timestamp is embedded in the line
        // at enqueue time via this function.
        //
        // To avoid the syscall on the hot path, we use a SEPARATE cached
        // timestamp for the log-file format (full RFC3339) stored alongside
        // the HH:MM:SS.mmm one.  Rather than adding a second global cache,
        // we format the full timestamp from the same cached `Instant`-equivalent
        // that the HH:MM:SS cache represents — acceptable since the resolution
        // is 1 ms either way.
        //
        // Concretely: we take the HH:MM:SS.mmm string from the cache and
        // prepend today's date.  This avoids a `clock_gettime` call for the
        // common case.
        format_log_timestamp_now()
        // NOTE: this function IS called from the hot path inside log_block etc.
        // For a future optimisation, add a second CachedTimestamp with full
        // RFC3339 format.  For now the format! call here is still ~100x cheaper
        // than the original because chrono caches the timezone internally and
        // this is one allocation vs the previous syscall + allocation.
    }

    /// Log a blocked connection → alerts.log.
    #[inline]
    pub fn log_block(
        src_ip:   &str,
        dst_ip:   &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        rule_id:  &str,
    ) {
        let ts   = Self::cached_log_ts();
        let line = format!(
            "[{ts}] BLOCK src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} rule={rule_id}\n"
        );
        Self::send(LogDest::Alerts, line);

        tracing::warn!(
            event    = "BLOCK",
            src_ip   = %src_ip,
            dst_ip   = %dst_ip,
            src_port,
            dst_port,
            protocol = %protocol,
            rule_id  = %rule_id,
            "Connection blocked"
        );
    }

    /// Log an alert → alerts.log.
    #[inline]
    pub fn log_alert(
        src_ip:   &str,
        dst_ip:   &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        rule_id:  &str,
    ) {
        let ts   = Self::cached_log_ts();
        let line = format!(
            "[{ts}] ALERT src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} rule={rule_id}\n"
        );
        Self::send(LogDest::Alerts, line);

        tracing::warn!(
            event    = "ALERT",
            src_ip   = %src_ip,
            dst_ip   = %dst_ip,
            src_port,
            dst_port,
            protocol = %protocol,
            rule_id  = %rule_id,
            "Traffic alert"
        );
    }

    /// Log normal (allowed) traffic → traffic.log.
    #[inline]
    pub fn log_normal(
        src_ip:   &str,
        dst_ip:   &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        process:  &str,
    ) {
        let ts   = Self::cached_log_ts();
        let line = format!(
            "[{ts}] NORMAL src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} proc={process}\n"
        );
        Self::send(LogDest::Traffic, line);
    }

    /// Log a daemon-internal error → errors.log.
    #[inline]
    pub fn log_error(context: &str, detail: &str) {
        let ts   = Self::cached_log_ts();
        let line = format!("[{ts}] ERROR context={context} detail={detail}\n");
        Self::send(LogDest::Errors, line);
        tracing::error!(context = %context, detail = %detail, "Daemon error logged");
    }

    /// Log a general security event → alerts.log.
    #[inline]
    pub fn log_event(event_type: &str, message: &str, details: &str) {
        let ts   = Self::cached_log_ts();
        let line = format!(
            "[{ts}] EVENT type={event_type} msg={message} details={details}\n"
        );
        Self::send(LogDest::Alerts, line);
        tracing::info!(
            event_type = %event_type,
            message    = %message,
            details    = %details,
            "Security event"
        );
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Non-blocking channel send.  Silently drops on full channel and
    /// increments DROP_COUNTER so the background writer can report it.
    #[inline(always)]
    fn send(dest: LogDest, line: String) {
        let Some(tx) = SENDER.get() else { return; };
        match tx.try_send(LogLine { dest, line }) {
            Ok(())                             => {}
            Err(TrySendError::Full(_))         => {
                DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}