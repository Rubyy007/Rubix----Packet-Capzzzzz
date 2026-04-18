// src/logger/mod.rs
// Simple logging module

pub fn init_logger() {
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_target(false)
        .with_thread_ids(true)
        .init();
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
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*)
    };
}