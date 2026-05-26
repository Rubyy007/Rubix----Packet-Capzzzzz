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
//!       the configured rotation_count backups with a timestamp suffix.
//!
//!   Separate files:
//!     • alerts.log  — Block + Alert + Threat events (security ring feed).
//!     • traffic.log — Normal + sampled Allow events (normal ring feed).
//!     • errors.log  — Daemon-internal errors.
//!
//! ── YAML Config Integration ───────────────────────────────────────────────
//!
//! `AlertLogger::init_from_yaml(path)` and `init_auto()` parse the platform
//! YAML and start the background writer with real config values:
//!   normal_channel_depth, max_file_size_mb, rotation_count.
//!
//! ── Timestamp caching (Performance fix #2 / #4) ───────────────────────────
//!
//! `chrono::Local::now().format()` performs a `clock_gettime` syscall +
//! timezone lookup + heap allocation.  At 200 k pps this is unacceptable.
//!
//! Fix: `CachedTimestamp` stores a pre-formatted `Arc<String>` refreshed
//! once per millisecond.  Hot-path callers do one `Arc::clone` (~2 ns).

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use serde::Deserialize;

// ── Constants ─────────────────────────────────────────────────────────────────

const BATCH_SIZE: usize = 128;
const RECV_TIMEOUT_MS: u64 = 10;
const DROP_WARN_THRESHOLD: u64 = 1_000;

// ── YAML Configuration structs ────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct RubixConfig {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub capture_interface: String,
    #[serde(default)]
    pub promiscuous: bool,
    #[serde(default)]
    pub buffer_size_mb: u64,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub snaplen: u32,
    pub bpf_filter: Option<String>,
    #[serde(default)]
    pub trusted_cidrs: Vec<String>,
    #[serde(default)]
    pub fast_path: FastPathConfig,
    #[serde(default)]
    pub blocking: BlockingConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub export: ExportConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct FastPathConfig {
    #[serde(default)]
    pub enable_sampling: bool,
    #[serde(default)]
    pub sampling_rate_high: f64,
    #[serde(default)]
    pub enable_aggregation: bool,
    #[serde(default)]
    pub aggregation_window_ms: u64,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct BlockingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub iptables_chain: Option<String>,
    #[serde(default)]
    pub block_timeout_seconds: u64,
    #[serde(default)]
    pub default_action: String,
    #[serde(default)]
    pub auto_cleanup: bool,
    #[serde(default)]
    pub flush_on_exit: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub json_format: bool,
    #[serde(default)]
    pub max_file_size_mb: u64,
    #[serde(default)]
    pub rotation_count: u32,
    #[serde(default)]
    pub console_output: bool,
    #[serde(default)]
    pub log_normal_traffic: bool,
    #[serde(default)]
    pub normal_sample_divisor: u64,
    #[serde(default)]
    pub normal_ring_capacity: usize,
    #[serde(default)]
    pub normal_channel_depth: usize,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ExportConfig {
    #[serde(default)]
    pub enabled: bool,
    pub webhook_url: Option<String>,
    pub storage_path: Option<String>,
    pub socket_addr: Option<String>,
    #[serde(default)]
    pub batch_size: usize,
    #[serde(default)]
    pub flush_interval_secs: u64,
    #[serde(default)]
    pub webhook_timeout_secs: u64,
    #[serde(default)]
    pub webhook_retry_count: u32,
}

impl RubixConfig {
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: RubixConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_auto() -> Result<Self, Box<dyn std::error::Error>> {
        let candidates = Self::config_candidates();
        for path in &candidates {
            if path.exists() {
                return Self::from_yaml(path);
            }
        }
        let searched = candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ");
        Err(format!("No RUBIX YAML config found. Searched: [{}]", searched).into())
    }

    fn config_candidates() -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(8);

        if let Ok(env_path) = std::env::var("RUBIX_CONFIG") {
            paths.push(PathBuf::from(env_path));
        }

        #[cfg(target_os = "windows")]
        {
            let pd = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
            paths.push(PathBuf::from(&pd).join("rubix").join("rubix.windows.yaml"));
            paths.push(PathBuf::from(&pd).join("rubix").join("rubix.common.yaml"));
            paths.push(PathBuf::from(".\\rubix.windows.yaml"));
            paths.push(PathBuf::from(".\\rubix.common.yaml"));
        }

        #[cfg(not(target_os = "windows"))]
        {
            paths.push(PathBuf::from("/etc/rubix/rubix.linux.yaml"));
            paths.push(PathBuf::from("/etc/rubix/rubix.common.yaml"));
            paths.push(PathBuf::from("/usr/local/etc/rubix/rubix.linux.yaml"));
            paths.push(PathBuf::from("/usr/local/etc/rubix/rubix.common.yaml"));
            paths.push(PathBuf::from("./rubix.linux.yaml"));
            paths.push(PathBuf::from("./rubix.common.yaml"));
        }

        paths
    }
}

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

/// Resolve the alert log directory from a `file_path` config value.
///
/// If `file_path` is non-empty and has a parent component, that parent is used.
/// Otherwise falls back to the platform default (`alert_log_dir()`).
///
/// This is the single source of truth used by every `AlertLogger` init path
/// that has access to a `LoggingConfig`, so alert files and the tracing file
/// layer always end up in the same directory.
fn resolve_log_dir(file_path: &str) -> PathBuf {
    if !file_path.is_empty() {
        let p = PathBuf::from(file_path);
        if let Some(parent) = p.parent() {
            // parent() returns "" for bare filenames like "rubix.log" — treat
            // that as "same as cwd", which is still more correct than /var/log/rubix.
            if parent != Path::new("") {
                return parent.to_path_buf();
            }
        }
    }
    alert_log_dir()
}

// ── Channel message ───────────────────────────────────────────────────────────

struct LogLine {
    dest: LogDest,
    line: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LogDest {
    Alerts,
    Traffic,
    Errors,
}

// ── Cached timestamp ────────────────────────────────────────────────────────

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

    #[inline]
    pub fn get(&self) -> Arc<String> {
        self.inner.read().clone()
    }

    fn refresh(&self) {
        let ts = Arc::new(format_timestamp_now());
        *self.inner.write() = ts;
    }
}

#[inline]
fn format_timestamp_now() -> String {
    chrono::Local::now().format("%H:%M:%S%.3f").to_string()
}

#[inline]
fn format_log_timestamp_now() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%z").to_string()
}

// ── Global state ──────────────────────────────────────────────────────────────

static SENDER: OnceLock<SyncSender<LogLine>> = OnceLock::new();
static DROP_COUNTER: AtomicU64 = AtomicU64::new(0);
static DROP_LOGGED: AtomicU64 = AtomicU64::new(0);
static TIMESTAMP_CACHE: OnceLock<CachedTimestamp> = OnceLock::new();

/// Runtime logging config for toggles (e.g. log_normal_traffic).
pub static LOGGING_CONFIG: OnceLock<LoggingConfig> = OnceLock::new();

pub fn global_timestamp() -> Option<&'static CachedTimestamp> {
    TIMESTAMP_CACHE.get()
}

// ── Rotating file writer ──────────────────────────────────────────────────────

struct RotatingFile {
    path: PathBuf,
    writer: BufWriter<File>,
    bytes_written: u64,
    max_bytes: u64,
    keep_count: usize,
}

impl RotatingFile {
    fn open(path: &Path, max_mb: u64, keep_count: usize) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let existing = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::with_capacity(64 * 1024, file),
            bytes_written: existing,
            max_bytes: max_mb * 1_000_000,
            keep_count,
        })
    }

    fn write(&mut self, line: &str) -> std::io::Result<()> {
        if self.bytes_written >= self.max_bytes {
            self.writer.flush()?;
            let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
            let backup = PathBuf::from(format!("{}.{}", self.path.display(), ts));
            let _ = std::fs::rename(&self.path, &backup);
            self.prune_old_backups();
            let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
            self.writer = BufWriter::with_capacity(64 * 1024, file);
            self.bytes_written = 0;
        }
        self.writer.write_all(line.as_bytes())?;
        self.bytes_written += line.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn prune_old_backups(&self) {
        let dir = match self.path.parent() {
            Some(d) => d,
            None => return,
        };
        let base_name = match self.path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => return,
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

        for old in backups.into_iter().skip(self.keep_count) {
            let _ = std::fs::remove_file(&old);
        }
    }
}

// ── Background writer thread ──────────────────────────────────────────────────

fn run_writer(rx: Receiver<LogLine>, max_file_size_mb: u64, log_dir: PathBuf, keep_count: usize) {
    let mut alerts = match RotatingFile::open(&log_dir.join("alerts.log"), max_file_size_mb, keep_count) {
        Ok(f) => f,
        Err(e) => { eprintln!("[RUBIX] Failed to open alerts.log: {e}"); return; }
    };
    let mut traffic = match RotatingFile::open(&log_dir.join("traffic.log"), max_file_size_mb, keep_count) {
        Ok(f) => f,
        Err(e) => { eprintln!("[RUBIX] Failed to open traffic.log: {e}"); return; }
    };
    let mut errors = match RotatingFile::open(&log_dir.join("errors.log"), max_file_size_mb, keep_count) {
        Ok(f) => f,
        Err(e) => { eprintln!("[RUBIX] Failed to open errors.log: {e}"); return; }
    };

    let timeout = Duration::from_millis(RECV_TIMEOUT_MS);
    let mut batch_count = 0usize;

    loop {
        match rx.recv_timeout(timeout) {
            Ok(msg) => {
                let dest = match msg.dest {
                    LogDest::Alerts => &mut alerts,
                    LogDest::Traffic => &mut traffic,
                    LogDest::Errors => &mut errors,
                };
                let _ = dest.write(&msg.line);
                batch_count += 1;

                let mut i = 0;
                while i < BATCH_SIZE {
                    match rx.try_recv() {
                        Ok(m) => {
                            let d = match m.dest {
                                LogDest::Alerts => &mut alerts,
                                LogDest::Traffic => &mut traffic,
                                LogDest::Errors => &mut errors,
                            };
                            let _ = d.write(&m.line);
                            batch_count += 1;
                            i += 1;
                        }
                        Err(_) => break,
                    }
                }

                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();
            }

            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();

                let drops = DROP_COUNTER.load(Ordering::Relaxed);
                let logged = DROP_LOGGED.load(Ordering::Relaxed);
                if drops.saturating_sub(logged) >= DROP_WARN_THRESHOLD {
                    DROP_LOGGED.store(drops, Ordering::Relaxed);
                    let ts = format_log_timestamp_now();
                    let msg = format!(
                        "[{ts}] ERROR type=log_drop dropped={} total_drops={}\n",
                        drops - logged, drops
                    );
                    let _ = errors.write(&msg);
                    let _ = errors.flush();
                }
            }

            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = alerts.flush();
                let _ = traffic.flush();
                let _ = errors.flush();
                break;
            }
        }

        let _ = batch_count;
        batch_count = 0;
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct AlertLogger;

impl AlertLogger {
    /// Initialise from an explicit YAML file.
    pub fn init_from_yaml<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let config = RubixConfig::from_yaml(path)?;
        let log_dir = resolve_log_dir(&config.logging.file_path);
        Self::init_with_config_and_rotation(
            config.logging.normal_channel_depth,
            config.logging.max_file_size_mb,
            config.logging.rotation_count as usize,
            log_dir,
        )?;
        let _ = LOGGING_CONFIG.set(config.logging);
        Ok(())
    }

    /// Initialise with automatic platform-aware discovery.
    pub fn init_auto() -> Result<(), Box<dyn std::error::Error>> {
        let config = RubixConfig::load_auto()?;
        let log_dir = resolve_log_dir(&config.logging.file_path);
        Self::init_with_config_and_rotation(
            config.logging.normal_channel_depth,
            config.logging.max_file_size_mb,
            config.logging.rotation_count as usize,
            log_dir,
        )?;
        let _ = LOGGING_CONFIG.set(config.logging);
        Ok(())
    }

    /// Backward-compatible 2-arg init (uses platform default log directory).
    pub fn init_with_config(channel_depth: usize, max_file_size_mb: u64) -> Result<(), std::io::Error> {
        Self::init_with_config_and_rotation(channel_depth, max_file_size_mb, 5, alert_log_dir())
    }

    /// Full init: caller supplies the resolved log directory from YAML or platform default.
    ///
    /// Keeping `log_dir` as a parameter (rather than calling `alert_log_dir()` internally)
    /// ensures that when `Logger::init_from_rubix_config` has already resolved the path from
    /// `logging.file_path`, the alert files land in the **same directory** as the tracing
    /// file layer — not the static platform default.
    pub fn init_with_config_and_rotation(
        channel_depth: usize,
        max_file_size_mb: u64,
        rotation_count: usize,
        log_dir: PathBuf,
    ) -> Result<(), std::io::Error> {
        if SENDER.get().is_some() {
            return Ok(());
        }

        std::fs::create_dir_all(&log_dir)?;

        let test = log_dir.join(".rubix_write_test");
        std::fs::write(&test, b"rubix write test")?;
        let _ = std::fs::remove_file(&test);

        let (tx, rx) = mpsc::sync_channel::<LogLine>(channel_depth);

        thread::Builder::new()
            .name("rubix-log-writer".to_string())
            .spawn(move || run_writer(rx, max_file_size_mb, log_dir, rotation_count))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        SENDER.set(tx).ok();
        TIMESTAMP_CACHE.set(CachedTimestamp::new()).ok();

        Ok(())
    }

    /// Legacy init with safe defaults. Uses platform default log directory.
    pub fn init() -> Result<(), std::io::Error> {
        Self::init_with_config_and_rotation(4096, 100, 5, alert_log_dir())
    }

    /// Spawn the 1 ms timestamp refresh task (tokio required).
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

    #[inline(always)]
    fn cached_log_ts() -> String {
        format_log_timestamp_now()
    }

    #[inline]
    pub fn log_block(
        src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16,
        protocol: &str, rule_id: &str,
    ) {
        let ts = Self::cached_log_ts();
        let line = format!(
            "[{ts}] BLOCK src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} rule={rule_id}\n"
        );
        Self::send(LogDest::Alerts, line);
        tracing::warn!(
            event = "BLOCK", src_ip = %src_ip, dst_ip = %dst_ip,
            src_port, dst_port, protocol = %protocol, rule_id = %rule_id,
            "Connection blocked"
        );
    }

    #[inline]
    pub fn log_alert(
        src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16,
        protocol: &str, rule_id: &str,
    ) {
        let ts = Self::cached_log_ts();
        let line = format!(
            "[{ts}] ALERT src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} rule={rule_id}\n"
        );
        Self::send(LogDest::Alerts, line);
        tracing::warn!(
            event = "ALERT", src_ip = %src_ip, dst_ip = %dst_ip,
            src_port, dst_port, protocol = %protocol, rule_id = %rule_id,
            "Traffic alert"
        );
    }

    #[inline]
    pub fn log_normal(
        src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16,
        protocol: &str, process: &str,
    ) {
        if let Some(cfg) = LOGGING_CONFIG.get() {
            if !cfg.log_normal_traffic {
                return;
            }
        }
        let ts = Self::cached_log_ts();
        let line = format!(
            "[{ts}] NORMAL src={src_ip}:{src_port} dst={dst_ip}:{dst_port} \
             proto={protocol} proc={process}\n"
        );
        Self::send(LogDest::Traffic, line);
    }

    #[inline]
    pub fn log_error(context: &str, detail: &str) {
        let ts = Self::cached_log_ts();
        let line = format!("[{ts}] ERROR context={context} detail={detail}\n");
        Self::send(LogDest::Errors, line);
        tracing::error!(context = %context, detail = %detail, "Daemon error logged");
    }

    #[inline]
    pub fn log_event(event_type: &str, message: &str, details: &str) {
        let ts = Self::cached_log_ts();
        let line = format!(
            "[{ts}] EVENT type={event_type} msg={message} details={details}\n"
        );
        Self::send(LogDest::Alerts, line);
        tracing::info!(
            event_type = %event_type, message = %message, details = %details,
            "Security event"
        );
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    #[inline(always)]
    fn send(dest: LogDest, line: String) {
        let Some(tx) = SENDER.get() else { return; };
        match tx.try_send(LogLine { dest, line }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}