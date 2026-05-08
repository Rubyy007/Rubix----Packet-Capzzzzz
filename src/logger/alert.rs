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
//!     • Formats a log line (stack-allocated via `format!`).
//!     • Calls `try_send` on a bounded `std::sync::mpsc` channel.
//!     • If the channel is full the line is **silently dropped** — the hot
//!       path never blocks.  The drop is counted in `DROP_COUNTER` and
//!       visible in `rubix-cli logs` as an ERROR entry when it exceeds a
//!       threshold.
//!
//!   Background writer task (spawned once at init):
//!     • Drains the channel in a tight loop, batching up to
//!       `BATCH_SIZE` lines per `write_all` call.
//!     • Calls `flush()` after each batch — amortises the syscall cost.
//!     • Rotates the file when it exceeds `max_file_size_mb`.
//!
//!   Separate files:
//!     • `alerts.log`  — Block + Alert + Threat events (security ring feed).
//!     • `traffic.log` — Normal + sampled Allow events (normal ring feed).
//!     • `errors.log`  — Daemon-internal errors.
//!
//! ── Thread safety ────────────────────────────────────────────────────────
//!
//! `AlertLogger` is a zero-sized unit struct with only `&'static` state.
//! The channel sender is stored in a `OnceLock<Sender>` — cloning a
//! `Sender` is cheap (Arc bump) and the clone is what the hot path holds.
//! No `Mutex` is ever acquired in `log_block`, `log_alert`, `log_normal`,
//! or `log_error`.
//!
//! ── Cross-platform ───────────────────────────────────────────────────────
//!
//! File paths resolve via `alert_log_dir()` which is already
//! platform-aware.  No Unix-only or Windows-only APIs are used here.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Lines batched per `write_all` call in the background writer.
const BATCH_SIZE: usize = 128;

/// Background writer sleep when channel is empty.
const DRAIN_SLEEP_MS: u64 = 10;

/// Log a drop-counter ERROR entry to the normal ring every time this many
/// lines have been silently dropped.
const DROP_WARN_THRESHOLD: u64 = 1_000;

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
    /// `alerts.log` — Block, Alert, Threat.
    Alerts,
    /// `traffic.log` — Normal (allowed) traffic.
    Traffic,
    /// `errors.log` — Daemon-internal errors.
    Errors,
}

// ── Global state ──────────────────────────────────────────────────────────────

/// Channel depth.  Each `LogLine` is ~200 bytes on the heap.
/// 8 192 × 200 bytes ≈ 1.6 MB.  Enough to absorb multi-second bursts
/// without dropping during normal operation.
static CHANNEL_DEPTH: OnceLock<usize>          = OnceLock::new();
static SENDER:        OnceLock<SyncSender<LogLine>> = OnceLock::new();
static DROP_COUNTER:  AtomicU64               = AtomicU64::new(0);
static DROP_LOGGED:   AtomicU64               = AtomicU64::new(0);

// ── Background writer ─────────────────────────────────────────────────────────

struct RotatingFile {
    path:           PathBuf,
    writer:         BufWriter<File>,
    bytes_written:  u64,
    max_bytes:      u64,
}

impl RotatingFile {
    fn open(path: &Path, max_mb: u64) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let existing = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path:          path.to_path_buf(),
            writer:        BufWriter::with_capacity(64 * 1024, file),
            bytes_written: existing,
            max_bytes:     max_mb * 1_000_000,
        })
    }

    /// Write a line.  Rotates if size limit is exceeded.
    fn write(&mut self, line: &str) -> std::io::Result<()> {
        // Rotate: rename current file to .1, open fresh.
        if self.bytes_written >= self.max_bytes {
            self.writer.flush()?;
            let rotated = self.path.with_extension("log.1");
            let _ = std::fs::rename(&self.path, &rotated);
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
}

/// Spawned once.  Drains the channel and writes in batches.
/// Never touches SENDER — completely independent of the hot path.
fn run_writer(rx: Receiver<LogLine>, max_mb: u64, log_dir: PathBuf) {
    let open = |name: &str| -> RotatingFile {
        let path = log_dir.join(name);
        RotatingFile::open(&path, max_mb).unwrap_or_else(|e| {
            eprintln!("[RUBIX] FATAL: cannot open log file {:?}: {}", path, e);
            std::process::exit(1);
        })
    };

    let mut alerts  = open("alerts.log");
    let mut traffic = open("traffic.log");
    let mut errors  = open("errors.log");

    let mut batch: Vec<LogLine> = Vec::with_capacity(BATCH_SIZE);

    loop {
        // Block until at least one message arrives, then drain up to BATCH_SIZE.
        match rx.recv_timeout(Duration::from_millis(DRAIN_SLEEP_MS)) {
            Ok(msg) => {
                batch.push(msg);
                // Non-blocking drain of the rest of the batch.
                while batch.len() < BATCH_SIZE {
                    match rx.try_recv() {
                        Ok(m)  => batch.push(m),
                        Err(_) => break,
                    }
                }
            }
            Err(_) => {
                // Timeout — just flush any buffered bytes and loop.
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();
                continue;
            }
        }

        // Write the batch.
        for msg in batch.drain(..) {
            let dest = match msg.dest {
                LogDest::Alerts  => &mut alerts,
                LogDest::Traffic => &mut traffic,
                LogDest::Errors  => &mut errors,
            };
            if let Err(e) = dest.write(&msg.line) {
                // File write failed — can't log it normally, use stderr.
                eprintln!("[RUBIX] log write error: {}", e);
            }
        }

        // Flush after every batch — amortises the syscall.
        let _ = alerts.flush();
        let _ = traffic.flush();
        let _ = errors.flush();

        // Check drop counter and emit a synthetic error log line if needed.
        let drops = DROP_COUNTER.load(Ordering::Relaxed);
        let logged = DROP_LOGGED.load(Ordering::Relaxed);
        if drops - logged >= DROP_WARN_THRESHOLD {
            DROP_LOGGED.store(drops, Ordering::Relaxed);
            let ts  = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
            let msg = format!(
                "[{}] ERROR type=log_drop dropped={} total_drops={}\n",
                ts, drops - logged, drops
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
    /// Must be called once from `Logger::init_dual()` before any logging.
    /// `channel_depth` is taken from `logging.normal_channel_depth` in config;
    /// `max_file_size_mb` from `logging.max_file_size_mb`.
    pub fn init_with_config(
        channel_depth:    usize,
        max_file_size_mb: u64,
    ) -> Result<(), std::io::Error> {
        // Guard against double-init (e.g. in tests).
        if SENDER.get().is_some() {
            return Ok(());
        }

        CHANNEL_DEPTH.get_or_init(|| channel_depth);

        let log_dir = alert_log_dir();
        std::fs::create_dir_all(&log_dir)?;

        // Validate write access before spawning the thread.
        let test = log_dir.join(".rubix_write_test");
        std::fs::write(&test, b"rubix write test")?;
        let _ = std::fs::remove_file(&test);

        let (tx, rx) = mpsc::sync_channel::<LogLine>(channel_depth);

        // Background writer thread — dedicated OS thread, not a Tokio task,
        // so it is never preempted by the async runtime.
        thread::Builder::new()
            .name("rubix-log-writer".to_string())
            .spawn(move || run_writer(rx, max_file_size_mb, log_dir))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        SENDER.set(tx).ok(); // ok() — double-init guard already handled above.

        Ok(())
    }

    /// Legacy init (used by Logger::init_dual when config is not yet parsed).
    /// Uses safe defaults: 4096-entry channel, 100 MB per file.
    pub fn init() -> Result<(), std::io::Error> {
        Self::init_with_config(4096, 100)
    }

    // ── Hot-path logging methods ──────────────────────────────────────────────
    //
    // All four methods:
    //   1. Format the log line on the stack (no heap allocation for the
    //      format string itself — `format!` allocates, but it is one small
    //      String, not multiple).
    //   2. Call `try_send` — non-blocking, never parks the calling thread.
    //   3. On channel-full: increment DROP_COUNTER, return immediately.
    //
    // None of these methods ever acquire a Mutex or call a syscall directly.

    /// Log a blocked connection → `alerts.log`.
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

    /// Log an alert → `alerts.log`.
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

    /// Log normal (allowed) traffic → `traffic.log`.
    ///
    /// Called from the hot path only when `log_normal_traffic = true`
    /// and the packet passes the sampling gate.  The gate is evaluated
    /// by the caller — this method always writes unconditionally.
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
        // No tracing event — this is high-frequency, file-only.
    }

    /// Log a daemon-internal error → `errors.log`.
    ///
    /// Also emits a `tracing::error!` event so the message appears in
    /// the console/structured log.
    #[inline]
    pub fn log_error(context: &str, detail: &str) {
        let ts   = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z");
        let line = format!("[{ts}] ERROR context={context} detail={detail}\n");
        Self::send(LogDest::Errors, line);
        tracing::error!(context = %context, detail = %detail, "Daemon error logged");
    }

    /// Log a general security event → `alerts.log`.
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

    /// Non-blocking channel send.  Silently drops on full channel.
    #[inline(always)]
    fn send(dest: LogDest, line: String) {
        if let Some(tx) = SENDER.get() {
            match tx.try_send(LogLine { dest, line }) {
                Ok(())                          => {}
                Err(TrySendError::Full(_))      => {
                    DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    // Writer thread died — nothing we can do in the hot path.
                }
            }
        }
        // If SENDER is not yet initialised (called before AlertLogger::init)
        // the line is silently discarded.  This should never happen in
        // production because init() is called before the packet loop starts.
    }
}
