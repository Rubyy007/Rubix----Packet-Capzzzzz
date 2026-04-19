//! Production logging system for RUBIX

pub mod alert;

pub use alert::AlertLogger;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{prelude::*, EnvFilter};
use std::path::PathBuf;
use std::fs;

/// Holds the non-blocking writer guard.
///
/// **Must be held for the entire lifetime of the program.**
/// Drop it (or let it go out of scope) and all buffered log lines are lost.
///
/// ```rust
/// // In main():
/// let _logger = logger::Logger::init()?;
/// // _logger must stay alive until the end of main()
/// ```
pub struct Logger {
    _guard: WorkerGuard,
}

impl Logger {
    /// Initialise file-based JSON logging to `/var/log/rubix/rubix.log`.
    ///
    /// Returns a `Logger` whose `WorkerGuard` **must** be bound to a variable
    /// in `main()` so it is not dropped early.
    pub fn init() -> Result<Self, Box<dyn std::error::Error>> {
        let log_dir = PathBuf::from("/var/log/rubix");
        fs::create_dir_all(&log_dir)?;

        // Rolling daily log: rubix.2025-01-01.log etc.
        let file_appender = tracing_appender::rolling::daily(&log_dir, "rubix.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("rubix=info,blocker=info,capture=warn"));

        // JSON format — structured, SIEM-friendly
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

        // Eagerly init AlertLogger so permission errors surface immediately
        AlertLogger::init()?;

        tracing::info!("Logger initialised — writing to /var/log/rubix/rubix.log");

        Ok(Self { _guard: guard })
    }

    /// Initialise console-only logging (human-readable).
    /// Useful for local dev / `--debug` CLI flag.
    pub fn init_console() -> Result<(), Box<dyn std::error::Error>> {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("rubix=debug"));

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(true)
            .pretty()
            .init();

        Ok(())
    }

    /// Initialise both file (JSON) and console (pretty) output simultaneously.
    /// Useful for running interactively while still writing structured logs.
    pub fn init_dual() -> Result<Self, Box<dyn std::error::Error>> {
        let log_dir = PathBuf::from("/var/log/rubix");
        fs::create_dir_all(&log_dir)?;

        let file_appender = tracing_appender::rolling::daily(&log_dir, "rubix.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let file_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("rubix=info,blocker=info,capture=warn"));

        let console_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("rubix=info"));

        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_writer(non_blocking)
            .with_filter(file_filter);

        let console_layer = tracing_subscriber::fmt::layer()
            .pretty()
            .with_target(false)
            .with_thread_ids(false)
            .with_writer(std::io::stderr)
            .with_filter(console_filter);

        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .init();

        AlertLogger::init()?;

        tracing::info!("Logger initialised (dual: file + console)");

        Ok(Self { _guard: guard })
    }
}