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
use std::sync::OnceLock;
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

// ── Global state ──────────────────────────────────────────────────────────────

/// The channel sender stored globally so hot-path methods are free functions.
/// Initialised exactly once by AlertLogger::init_with_config.
static SENDER:       OnceLock<SyncSender<LogLine>> = OnceLock::new();
static DROP_COUNTER: AtomicU64                     = AtomicU64::new(0);
static DROP_LOGGED:  AtomicU64                     = AtomicU64::new(0);

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
    ///
    /// Rotation strategy:
    ///   1. Flush the current writer.
    ///   2. Rename the current file to <base>.log.<YYYYMMDD-HHMMSS>.
    ///   3. Delete the oldest backup if more than ROTATION_KEEP_COUNT exist.
    ///   4. Open a fresh file at the original path.
    ///
    /// Using a timestamp suffix means each rotation is uniquely named and
    /// history is never silently overwritten (unlike the previous .log.1
    /// scheme which clobbered the previous backup every rotation).
    fn write(&mut self, line: &str) -> std::io::Result<()> {
        if self.bytes_written >= self.max_bytes {
            self.writer.flush()?;

            // Build a timestamped backup name:
            // e.g. alerts.log.20240115-143022
            let ts        = chrono::Local::now().format("%Y%m%d-%H%M%S");
            let backup    = PathBuf::from(format!("{}.{}", self.path.display(), ts));
            let _ = std::fs::rename(&self.path, &backup);

            // Prune old backups: keep the ROTATION_KEEP_COUNT most recent.
            self.prune_old_backups();

            // Open a fresh file.
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
    ///
    /// Matches files named <base_name>.<timestamp> in the same directory.
    /// Sorts by name descending (newest first, since timestamps sort
    /// lexicographically) and removes the oldest.
    fn prune_old_backups(&self) {
        let dir = match self.path.parent() {
            Some(d) => d,
            None    => return,
        };
        let base_name = match self.path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None    => return,
        };

        // Collect all backup files for this log.
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

        // Sort descending (newest first — timestamp suffix sorts lexicographically).
        backups.sort_unstable_by(|a, b| b.cmp(a));

        // Remove everything beyond the keep count.
        for old in backups.into_iter().skip(ROTATION_KEEP_COUNT) {
            let _ = std::fs::remove_file(&old);
        }
    }
}

// ── Background writer thread ──────────────────────────────────────────────────

/// Entry point for the dedicated log-writer OS thread.
///
/// Never calls std::process::exit — if a file cannot be opened or written,
/// the error is printed to stderr and the thread panics.  A thread panic
/// surfaces the error cleanly without bypassing Drop implementations in the
/// main thread (WorkerGuard, etc.).
fn run_writer(rx: Receiver<LogLine>, max_mb: u64, log_dir: PathBuf) {
    // Open all three log files at startup.  Panic on failure — the caller
    // (AlertLogger::init_with_config) already validated write access, so a
    // failure here indicates a real unrecoverable problem.
    let open = |name: &str| -> RotatingFile {
        let path = log_dir.join(name);
        RotatingFile::open(&path, max_mb).unwrap_or_else(|e| {
            panic!("[RUBIX] cannot open log file {:?}: {}", path, e);
        })
    };

    let mut alerts  = open("alerts.log");
    let mut traffic = open("traffic.log");
    let mut errors  = open("errors.log");

    let mut batch: Vec<LogLine> = Vec::with_capacity(BATCH_SIZE);

    loop {
        // Block until a message arrives or RECV_TIMEOUT_MS elapses.
        // On timeout: flush buffered bytes and loop — this handles the
        // low-traffic / idle case without busy-waiting.
        match rx.recv_timeout(Duration::from_millis(RECV_TIMEOUT_MS)) {
            Err(_timeout) => {
                // Flush unconditionally on idle timeout.
                // BufWriter::flush is a no-op when the buffer is empty, so
                // this is cheap when nothing has been written since the last
                // flush.
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();
                continue;
            }
            Ok(first) => {
                batch.push(first);
                // Non-blocking drain up to BATCH_SIZE.
                while batch.len() < BATCH_SIZE {
                    match rx.try_recv() {
                        Ok(m)  => batch.push(m),
                        Err(_) => break,
                    }
                }
            }
        }

        // Write the batch to the appropriate file.
        for msg in batch.drain(..) {
            let dest = match msg.dest {
                LogDest::Alerts  => &mut alerts,
                LogDest::Traffic => &mut traffic,
                LogDest::Errors  => &mut errors,
            };
            if let Err(e) = dest.write(&msg.line) {
                // File write failed — can't use the normal log path, use stderr.
                eprintln!("[RUBIX] log write error: {}", e);
            }
        }

        // Flush after every batch — amortises the syscall cost over BATCH_SIZE lines.
        let _ = alerts.flush();
        let _ = traffic.flush();
        let _ = errors.flush();

        // Check drop counter and emit a synthetic error line if the threshold
        // has been crossed since the last warning.
        let drops  = DROP_COUNTER.load(Ordering::Relaxed);
        let logged = DROP_LOGGED.load(Ordering::Relaxed);
        if drops.saturating_sub(logged) >= DROP_WARN_THRESHOLD {
            DROP_LOGGED.store(drops, Ordering::Relaxed);
            let ts  = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
            let msg = format!(
                "[{ts}] ERROR type=log_drop dropped={} total_drops={}\n",
                drops - logged, drops
            );
            let _ = errors.write(&msg);
            let _ = errors.flush();
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct AlertLogger;

impl AlertLogger {
    /// Initialise the global channel + background writer thread.
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
        // Guard against double-init (e.g. in tests).
        if SENDER.get().is_some() {
            return Ok(());
        }

        let log_dir = alert_log_dir();
        std::fs::create_dir_all(&log_dir)?;

        // Validate write access before spawning the thread so the error
        // is surfaced immediately with a clear message rather than as a
        // thread panic after startup.
        let test = log_dir.join(".rubix_write_test");
        std::fs::write(&test, b"rubix write test")?;
        let _ = std::fs::remove_file(&test);

        let (tx, rx) = mpsc::sync_channel::<LogLine>(channel_depth);

        // Dedicated OS thread — not a Tokio task — so the writer is never
        // preempted by the async runtime under load.
        thread::Builder::new()
            .name("rubix-log-writer".to_string())
            .spawn(move || run_writer(rx, max_file_size_mb, log_dir))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // ok() — double-init guard already handled above so this only fails
        // if another thread raced us to set it, which is harmless.
        SENDER.set(tx).ok();

        Ok(())
    }

    /// Legacy init used by Logger::init_dual when config is not yet available.
    /// Safe defaults: 4096-entry channel, 100 MB per file.
    pub fn init() -> Result<(), std::io::Error> {
        Self::init_with_config(4096, 100)
    }

    // ── Hot-path logging methods ──────────────────────────────────────────────
    //
    // All methods:
    //   1. Format the log line (one heap allocation per call — unavoidable
    //      because the String must outlive the hot-path stack frame).
    //   2. Call try_send — non-blocking, never parks the calling thread.
    //   3. On channel-full: increment DROP_COUNTER and return immediately.
    //
    // None of these methods acquire a Mutex or call a syscall directly.

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
        let ts   = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
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
        let ts   = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
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
    ///
    /// Called from the hot path only when log_normal_traffic = true and
    /// the packet passes the sampling gate.  The gate is evaluated by the
    /// caller — this method always writes unconditionally.
    ///
    /// No tracing event emitted — this is high-frequency, file-only.
    #[inline]
    pub fn log_normal(
        src_ip:   &str,
        dst_ip:   &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        process:  &str,
    ) {
        let ts   = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
        let line = format!(
            "[{ts}] NORMAL src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} proc={process}\n"
        );
        Self::send(LogDest::Traffic, line);
    }

    /// Log a daemon-internal error → errors.log.
    ///
    /// Also emits a tracing::error! event so the message appears in the
    /// console and structured log.
    #[inline]
    pub fn log_error(context: &str, detail: &str) {
        let ts   = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
        let line = format!("[{ts}] ERROR context={context} detail={detail}\n");
        Self::send(LogDest::Errors, line);
        tracing::error!(context = %context, detail = %detail, "Daemon error logged");
    }

    /// Log a general security event → alerts.log.
    #[inline]
    pub fn log_event(event_type: &str, message: &str, details: &str) {
        let ts   = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
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
        let Some(tx) = SENDER.get() else {
            // Called before init_with_config — silently discard.
            // This should never happen in production because init is called
            // before the packet loop starts.
            return;
        };
        match tx.try_send(LogLine { dest, line }) {
            Ok(())                             => {}
            Err(TrySendError::Full(_))         => {
                DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // Writer thread died — nothing safe to do in the hot path.
                // The drop counter won't help here but stderr is always open.
            }
        }
    }
}
