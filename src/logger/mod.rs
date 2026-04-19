//! Production logging system for RUBIX

use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::non_blocking::WorkerGuard;
use std::path::PathBuf;
use std::fs;

pub struct Logger {
    _guard: Option<WorkerGuard>,
}

impl Logger {
    pub fn init() -> Result<Self, Box<dyn std::error::Error>> {
        // Create log directory if it doesn't exist
        let log_dir = PathBuf::from("/var/log/rubix");
        if !log_dir.exists() {
            fs::create_dir_all(&log_dir)?;
        }
        
        // Set log file path
        let log_file = log_dir.join("rubix.log");
        
        // Create file appender with rotation
        let file_appender = tracing_appender::rolling::daily(&log_dir, "rubix.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        
        // Set up environment filter
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("rubix=info,blocker=info,capture=warn"));
        
        // Configure subscriber with both file and console output
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .json()
            .with_writer(non_blocking)
            .finish();
        
        tracing::subscriber::set_global_default(subscriber)?;
        
        Ok(Self { _guard: Some(guard) })
    }
    
    pub fn init_console() -> Result<(), Box<dyn std::error::Error>> {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("rubix=info"));
        
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_thread_ids(true)
            .init();
        
        Ok(())
    }
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        tracing::error!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*)
    };
}
