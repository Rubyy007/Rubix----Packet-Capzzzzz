// src/logger/mod.rs
//! Production logging system for RUBIX
//!
//! Features:
//! - Dual output: JSON file + pretty stderr console
//! - 30-day automatic log rotation and cleanup
//! - Windows/Linux compatible paths
//! - Non-blocking writers (never stalls packet processing)
//! - Structured JSON for SIEM ingestion
//! - Eager permission validation on startup

pub mod alert;
pub use alert::AlertLogger;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{prelude::*, EnvFilter};
use std::path::{Path, PathBuf};
use std::fs;
use std::time::{Duration, SystemTime};

// ── Platform log directory ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn default_log_dir() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| PathBuf::from(p).join("rubix").join("logs"))
        .unwrap_or_else(|_| PathBuf::from("logs"))
}

#[cfg(not(target_os = "windows"))]
fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/rubix")
}

// ── Log retention ─────────────────────────────────────────────────────────────

const LOG_RETENTION_DAYS: u64 = 30;

/// Delete log files older than LOG_RETENTION_DAYS from the given directory.
/// Only touches files matching *.log patterns.
/// Non-fatal — errors are printed to stderr, never panic.
fn cleanup_old_logs(log_dir: &Path) {
    let cutoff = match SystemTime::now()
        .checked_sub(Duration::from_secs(LOG_RETENTION_DAYS * 24 * 60 * 60))
    {
        Some(t) => t,
        None    => return,
    };

    let entries = match fs::read_dir(log_dir) {
        Ok(e)  => e,
        Err(e) => {
            eprintln!("[RUBIX] Log cleanup: cannot read dir {:?}: {}", log_dir, e);
            return;
        }
    };

    let mut removed = 0u32;
    let mut freed   = 0u64;

    for entry in entries.flatten() {
        let path = entry.path();

        // Only clean up log files — never touch configs or other files
        let is_log = path.extension()
            .map(|e| e == "log")
            .unwrap_or(false)
            || path.to_string_lossy().contains(".log.");

        if !is_log {
            continue;
        }

        // Get file modification time
        let modified = match entry.metadata().and_then(|m| m.modified()) {
            Ok(t)  => t,
            Err(_) => continue,
        };

        if modified < cutoff {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

            match fs::remove_file(&path) {
                Ok(_) => {
                    removed += 1;
                    freed   += size;
                    tracing::debug!(
                        path = %path.display(),
                        "Removed expired log file"
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[RUBIX] Log cleanup: failed to remove {:?}: {}",
                        path, e
                    );
                }
            }
        }
    }

    if removed > 0 {
        tracing::info!(
            files  = removed,
            freed  = format!("{:.1} MB", freed as f64 / 1_000_000.0),
            "Log cleanup complete"
        );
    }
}

/// Spawn a background task that runs cleanup once at startup,
/// then repeats every 24 hours.
fn spawn_cleanup_task(log_dir: PathBuf) {
    tokio::spawn(async move {
        // Run immediately on startup
        let dir = log_dir.clone();
        tokio::task::spawn_blocking(move || cleanup_old_logs(&dir))
            .await
            .ok();

        // Then every 24 hours
        let mut interval = tokio::time::interval(
            Duration::from_secs(24 * 60 * 60),
        );
        // Skip the first immediate tick — already ran above
        interval.tick().await;

        loop {
            interval.tick().await;
            let dir = log_dir.clone();
            tokio::task::spawn_blocking(move || cleanup_old_logs(&dir))
                .await
                .ok();
        }
    });
}

// ── Private helpers (free functions, not methods) ─────────────────────────────

/// Build a non-blocking daily-rolling file writer.
/// Files are named: rubix.YYYY-MM-DD.log
fn build_file_writer(
    log_dir: &Path,
) -> Result<(NonBlocking, WorkerGuard), Box<dyn std::error::Error>> {
    validate_write_access(log_dir)?;

    let file_appender = tracing_appender::rolling::daily(log_dir, "rubix.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    Ok((non_blocking, guard))
}

/// Validate that we can write to the log directory.
/// Creates and removes a test file — surfaces permission errors at startup.
fn validate_write_access(log_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let test_path = log_dir.join(".rubix_write_test");

    fs::write(&test_path, b"rubix write test")
        .map_err(|e| format!(
            "Cannot write to log directory {:?}: {}. \
             Check directory permissions.",
            log_dir, e
        ))?;

    // Best-effort removal — ignore errors
    let _ = fs::remove_file(&test_path);

    Ok(())
}

/// Build the default log filter.
/// Respects RUST_LOG env var if set, otherwise uses sensible defaults.
fn default_filter() -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

// ── Logger ────────────────────────────────────────────────────────────────────

/// Holds the non-blocking writer guard.
///
/// **Must be bound to a named variable in `main()` for the entire program lifetime.**
/// Dropping it flushes and closes the log file.
///
/// ```rust
/// let _logger = Logger::init_dual()?;
/// _logger.start_cleanup_task(); // call inside async context
/// ```
pub struct Logger {
    _guard:  WorkerGuard,
    log_dir: PathBuf,
}

impl Logger {
    // ── Public constructors ───────────────────────────────────────────────────

    /// File-only JSON logging.
    /// Use this when running as a service with no terminal.
    pub fn init() -> Result<Self, Box<dyn std::error::Error>> {
        let log_dir = default_log_dir();
        fs::create_dir_all(&log_dir)?;

        let (non_blocking, guard) = build_file_writer(&log_dir)?;
        let filter                = default_filter();

        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_writer(non_blocking);

        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .init();

        AlertLogger::init()?;

        tracing::info!(
            log_dir        = %log_dir.display(),
            retention_days = LOG_RETENTION_DAYS,
            "Logger initialised (file only)"
        );

        Ok(Self { _guard: guard, log_dir })
    }

    /// Console-only logging (pretty, human-readable).
    /// Use for `--debug` CLI flag or development.
    /// Writes to stderr so the heartbeat line on stdout is never broken.
    pub fn init_console() -> Result<(), Box<dyn std::error::Error>> {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("debug"));

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_writer(std::io::stderr)
            .pretty()
            .init();

        Ok(())
    }

    /// Dual output: JSON file + pretty stderr console.
    ///
    /// Recommended mode for interactive use.
    /// Console goes to **stderr** — never interferes with the
    /// heartbeat line written to **stdout**.
    pub fn init_dual() -> Result<Self, Box<dyn std::error::Error>> {
        let log_dir = default_log_dir();
        fs::create_dir_all(&log_dir)?;

        let (non_blocking, guard) = build_file_writer(&log_dir)?;

        // ── File layer: JSON, full structured detail ───────────────────────────
        let file_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_writer(non_blocking)
            .with_filter(file_filter);

        // ── Console layer: pretty, concise, stderr ONLY ───────────────────────
        // stderr guarantees the heartbeat line on stdout is never
        // broken by a log message appearing mid-line.
        let console_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let console_layer = tracing_subscriber::fmt::layer()
            .pretty()
            .with_target(false)
            .with_thread_ids(false)
            .with_file(true)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .with_filter(console_filter);

        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .init();

        AlertLogger::init()?;

        tracing::info!(
            log_dir        = %log_dir.display(),
            retention_days = LOG_RETENTION_DAYS,
            "Logger initialised (dual: file + console)"
        );

        Ok(Self { _guard: guard, log_dir })
    }

    // ── Cleanup task ──────────────────────────────────────────────────────────

    /// Start the 30-day log cleanup background task.
    ///
    /// **Must be called inside an async context** (after `#[tokio::main]` starts).
    /// Runs once immediately at startup, then every 24 hours.
    ///
    /// Safe to call multiple times — each call spawns one independent task.
    pub fn start_cleanup_task(&self) {
        spawn_cleanup_task(self.log_dir.clone());
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        // WorkerGuard flushes and closes file on drop.
        // This impl documents the intent explicitly.
        tracing::debug!("Logger shutting down — flushing log buffers");
    }
}