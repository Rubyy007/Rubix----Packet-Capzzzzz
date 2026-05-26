// src/logger/mod.rs
//! Production logging system for RUBIX
//!
//! - Dual output: JSON file + pretty stderr console
//! - 30-day automatic log rotation and cleanup
//! - Windows/Linux compatible paths
//! - Non-blocking writers (never stalls packet processing)
//! - Structured JSON for SIEM ingestion
//! - YAML config integration (rubix.{linux,windows,common}.yaml)

pub mod alert;
pub use alert::{AlertLogger, CachedTimestamp, RubixConfig, LoggingConfig};

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

fn cleanup_old_logs(log_dir: &Path) {
    let cutoff = match SystemTime::now()
        .checked_sub(Duration::from_secs(LOG_RETENTION_DAYS * 24 * 60 * 60))
    {
        Some(t) => t,
        None => return,
    };

    let entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[RUBIX] Log cleanup: cannot read dir {:?}: {}", log_dir, e);
            return;
        }
    };

    let mut removed = 0u32;
    let mut freed = 0u64;

    for entry in entries.flatten() {
        let path = entry.path();
        let is_log = path.extension()
            .map(|e| e == "log")
            .unwrap_or(false)
            || path.to_string_lossy().contains(".log.");

        if !is_log {
            continue;
        }

        let modified = match entry.metadata().and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };

        if modified < cutoff {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(&path) {
                Ok(_) => {
                    removed += 1;
                    freed += size;
                    tracing::debug!(path = %path.display(), "Removed expired log file");
                }
                Err(e) => {
                    eprintln!("[RUBIX] Log cleanup: failed to remove {:?}: {}", path, e);
                }
            }
        }
    }

    if removed > 0 {
        tracing::info!(
            files = removed,
            freed = format!("{:.1} MB", freed as f64 / 1_000_000.0),
            "Log cleanup complete"
        );
    }
}

fn spawn_cleanup_task(log_dir: PathBuf) {
    tokio::spawn(async move {
        let dir = log_dir.clone();
        tokio::task::spawn_blocking(move || cleanup_old_logs(&dir))
            .await
            .ok();

        let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
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

// ── Private helpers ───────────────────────────────────────────────────────────

fn build_file_writer_with_prefix(
    log_dir: &Path,
    prefix: &str,
) -> Result<(NonBlocking, WorkerGuard), Box<dyn std::error::Error>> {
    validate_write_access(log_dir)?;
    let file_appender = tracing_appender::rolling::daily(log_dir, prefix);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    Ok((non_blocking, guard))
}

fn validate_write_access(log_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let test_path = log_dir.join(".rubix_write_test");
    fs::write(&test_path, b"rubix write test")
        .map_err(|e| format!(
            "Cannot write to log directory {:?}: {}. Check directory permissions.",
            log_dir, e
        ))?;
    let _ = fs::remove_file(&test_path);
    Ok(())
}

fn default_filter() -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

// ── Logger ────────────────────────────────────────────────────────────────────

pub struct Logger {
    _guard: WorkerGuard,
    log_dir: PathBuf,
}

impl Logger {
    // ── Legacy constructors (backward compatible) ───────────────────────────

    pub fn init() -> Result<Self, Box<dyn std::error::Error>> {
        let log_dir = default_log_dir();
        fs::create_dir_all(&log_dir)?;
        let (non_blocking, guard) = build_file_writer_with_prefix(&log_dir, "rubix")?;
        let filter = default_filter();

        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_writer(non_blocking)
            .with_filter(filter);

        tracing_subscriber::registry().with(file_layer).init();
        AlertLogger::init().map_err(|e| format!("AlertLogger::init failed: {}", e))?;

        tracing::info!(log_dir = %log_dir.display(), "Logger initialised (file only)");
        Ok(Self { _guard: guard, log_dir })
    }

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
        AlertLogger::init().map_err(|e| format!("AlertLogger::init failed: {}", e))?;
        Ok(())
    }

    pub fn init_dual() -> Result<Self, Box<dyn std::error::Error>> {
        let log_dir = default_log_dir();
        fs::create_dir_all(&log_dir)?;
        let (non_blocking, guard) = build_file_writer_with_prefix(&log_dir, "rubix")?;

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

        AlertLogger::init().map_err(|e| format!("AlertLogger::init failed: {}", e))?;

        tracing::info!(log_dir = %log_dir.display(), "Logger initialised (dual: file + console)");
        Ok(Self { _guard: guard, log_dir })
    }

    // ── YAML-aware constructors ─────────────────────────────────────────────

    pub fn init_from_yaml<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let config = alert::RubixConfig::from_yaml(path)?;
        Self::init_from_rubix_config(config)
    }

    pub fn init_auto() -> Result<Self, Box<dyn std::error::Error>> {
        let config = alert::RubixConfig::load_auto()?;
        Self::init_from_rubix_config(config)
    }

    fn init_from_rubix_config(
        config: alert::RubixConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let logging = &config.logging;

        let log_path = PathBuf::from(&logging.file_path);
        let log_dir = log_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(default_log_dir);
        let prefix = log_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rubix");

        fs::create_dir_all(&log_dir)?;
        let (non_blocking, guard) = build_file_writer_with_prefix(&log_dir, prefix)?;

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&logging.level));

        let file_layer = if logging.json_format {
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_writer(non_blocking)
                .with_filter(filter.clone())
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_file(true)
                .with_line_number(true)
                .with_writer(non_blocking)
                .with_filter(filter.clone())
                .boxed()
        };

        let registry = tracing_subscriber::registry().with(file_layer);

        if logging.console_output {
            let console_filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&logging.level));
            let console_layer = tracing_subscriber::fmt::layer()
                .pretty()
                .with_target(false)
                .with_thread_ids(false)
                .with_file(true)
                .with_line_number(true)
                .with_writer(std::io::stderr)
                .with_filter(console_filter);
            registry.with(console_layer).init();
        } else {
            registry.init();
        }

        // Pass the already-resolved `log_dir` so alert files (alerts.log,
        // traffic.log, errors.log) land in the same directory as the tracing
        // file layer — not the static platform default.
        AlertLogger::init_with_config_and_rotation(
            logging.normal_channel_depth,
            logging.max_file_size_mb,
            logging.rotation_count as usize,
            log_dir.clone(),
        ).map_err(|e| format!("AlertLogger init failed: {}", e))?;

        let _ = alert::LOGGING_CONFIG.set(logging.clone());

        tracing::info!(
            log_dir = %log_dir.display(),
            prefix = %prefix,
            level = %logging.level,
            json_format = logging.json_format,
            console_output = logging.console_output,
            channel_depth = logging.normal_channel_depth,
            max_file_size_mb = logging.max_file_size_mb,
            rotation_count = logging.rotation_count,
            "Logger initialised from YAML config"
        );

        Ok(Self { _guard: guard, log_dir })
    }

    // ── Cleanup task ──────────────────────────────────────────────────────────

    pub fn start_cleanup_task(&self) {
        spawn_cleanup_task(self.log_dir.clone());
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        tracing::debug!("Logger shutting down — flushing log buffers");
    }
}