// src/logger/alert.rs
//! Security alert logging for RUBIX
//!
//! Features:
//! - Platform-aware log path (Windows: %PROGRAMDATA%, Linux: /var/log/rubix)
//! - Mutex-protected file writer (safe from concurrent packet loop calls)
//! - Never panics in hot path — logs errors to tracing instead
//! - Structured tracing events for SIEM pipeline
//! - Log rotation awareness (respects 30-day cleanup from mod.rs)

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use once_cell::sync::Lazy;

// ── Platform alert log path ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn alert_log_path() -> std::path::PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| std::path::PathBuf::from(p)
            .join("rubix")
            .join("logs")
            .join("alerts.log"))
        .unwrap_or_else(|_| std::path::PathBuf::from("logs").join("alerts.log"))
}

#[cfg(not(target_os = "windows"))]
fn alert_log_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/log/rubix/alerts.log")
}

// ── Global alert logger ───────────────────────────────────────────────────────

static ALERT_LOGGER: Lazy<Mutex<AlertLoggerInner>> = Lazy::new(|| {
    Mutex::new(
        AlertLoggerInner::new().unwrap_or_else(|e| {
            // Can't use tracing here (may not be initialized yet)
            eprintln!("[RUBIX] FATAL: Failed to initialize AlertLogger: {}", e);
            std::process::exit(1);
        })
    )
});

// ── Inner implementation ──────────────────────────────────────────────────────

struct AlertLoggerInner {
    file:     std::fs::File,
    log_path: std::path::PathBuf,
}

impl AlertLoggerInner {
    fn new() -> Result<Self, std::io::Error> {
        let log_path = alert_log_path();

        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        Ok(Self { file, log_path })
    }

    #[inline]
    fn write_line(&mut self, line: &str) -> Result<(), std::io::Error> {
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        Ok(())
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct AlertLogger;

impl AlertLogger {
    /// Eagerly initialize the global logger.
    /// Call from `Logger::init_dual()` so permission errors surface at startup.
    pub fn init() -> Result<(), std::io::Error> {
        // Touch the lazy static to force initialization
        let _guard = ALERT_LOGGER.lock().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "AlertLogger mutex poisoned during init",
            )
        })?;
        Ok(())
    }

    /// Log a blocked connection.
    ///
    /// Thread-safe, non-panicking.
    /// Writes to both the alert file and the tracing pipeline.
    ///
    /// # Arguments
    /// * `src_ip`   - Source IP address string
    /// * `dst_ip`   - Destination IP address string  
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `protocol` - Protocol string: "TCP", "UDP", "ICMP", etc.
    /// * `rule_id`  - Rule ID or process label (e.g. "proc=brave.exe(23516)")
    pub fn log_block(
        src_ip:   &str,
        dst_ip:   &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        rule_id:  &str,
    ) {
        let timestamp = chrono::Local::now()
            .format("%Y-%m-%dT%H:%M:%S%.3f%z");

        let line = format!(
            "[{timestamp}] BLOCK src={src_ip}:{src_port} dst={dst_ip}:{dst_port} proto={protocol} rule={rule_id}\n"
        );

        Self::write_to_file(&line);

        // Structured tracing event — picked up by SIEM/export pipeline
        tracing::warn!(
            event    = "BLOCK",
            src_ip   = %src_ip,
            dst_ip   = %dst_ip,
            src_port = src_port,
            dst_port = dst_port,
            protocol = %protocol,
            rule_id  = %rule_id,
            "Connection blocked"
        );
    }

    /// Log an alert (matched alert rule, traffic not blocked).
    ///
    /// Thread-safe, non-panicking.
    pub fn log_alert(
        src_ip:   &str,
        dst_ip:   &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        rule_id:  &str,
    ) {
        let timestamp = chrono::Local::now()
            .format("%Y-%m-%dT%H:%M:%S%.3f%z");

        let line = format!(
            "[{timestamp}] ALERT src={src_ip}:{src_port} dst={dst_ip}:{dst_port} proto={protocol} rule={rule_id}\n"
        );

        Self::write_to_file(&line);

        tracing::warn!(
            event    = "ALERT",
            src_ip   = %src_ip,
            dst_ip   = %dst_ip,
            src_port = src_port,
            dst_port = dst_port,
            protocol = %protocol,
            rule_id  = %rule_id,
            "Traffic alert"
        );
    }

    /// Log a general security event (e.g. new process detected, anomaly).
    pub fn log_event(
        event_type: &str,
        message:    &str,
        details:    &str,
    ) {
        let timestamp = chrono::Local::now()
            .format("%Y-%m-%dT%H:%M:%S%.3f%z");

        let line = format!(
            "[{timestamp}] EVENT type={event_type} msg={message} details={details}\n"
        );

        Self::write_to_file(&line);

        tracing::info!(
            event_type = %event_type,
            message    = %message,
            details    = %details,
            "Security event"
        );
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Write to the alert log file.
    /// Never panics — on error logs to tracing stderr only.
    #[inline]
    fn write_to_file(line: &str) {
        match ALERT_LOGGER.lock() {
            Ok(mut logger) => {
                if let Err(e) = logger.write_line(line) {
                    // Hot path — don't panic, just log the error
                    tracing::error!(
                        error = %e,
                        path  = %logger.log_path.display(),
                        "Failed to write to alert log"
                    );
                }
            }
            Err(e) => {
                // Mutex poisoned — extremely rare, log and continue
                tracing::error!(
                    error = %e,
                    "AlertLogger mutex poisoned — alert not written to file"
                );
            }
        }
    }
}