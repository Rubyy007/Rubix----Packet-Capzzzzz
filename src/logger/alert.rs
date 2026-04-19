//! Security alert logging for RUBIX

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use once_cell::sync::Lazy;

static ALERT_LOGGER: Lazy<Mutex<AlertLogger>> = Lazy::new(|| {
    Mutex::new(AlertLogger::new_internal().expect(
        "Failed to initialize AlertLogger — check /var/log/rubix permissions"
    ))
});

pub struct AlertLogger {
    file: std::fs::File,
}

impl AlertLogger {
    /// Internal constructor used by the global static.
    fn new_internal() -> Result<Self, std::io::Error> {
        std::fs::create_dir_all("/var/log/rubix")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/rubix/alerts.log")?;
        Ok(Self { file })
    }

    /// Call this early in `main()` to eagerly surface permission errors
    /// rather than panicking on the first log call.
    pub fn init() -> Result<(), std::io::Error> {
        // ✅ _unused instead of _ so the lock guard isn't dropped immediately
        let _unused = ALERT_LOGGER.lock().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "AlertLogger mutex poisoned during init",
            )
        })?;
        Ok(())
    }

    /// Log a blocked connection.
    ///
    /// # Arguments
    /// * `src_ip`   - Source IP address
    /// * `dst_ip`   - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port (the service being contacted)
    /// * `protocol` - Protocol string e.g. "TCP", "UDP"
    /// * `rule_id`  - ID of the matching policy rule
    pub fn log_block(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        rule_id: &str,
    ) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_line = format!(
            "[{timestamp}] BLOCK src={src_ip}:{src_port} dst={dst_ip}:{dst_port} proto={protocol} rule={rule_id}\n"
        );

        match ALERT_LOGGER.lock() {
            Ok(mut logger) => {
                if let Err(e) = logger.file.write_all(log_line.as_bytes()) {
                    tracing::error!(error = %e, "Failed to write alert to alerts.log");
                }
                if let Err(e) = logger.file.flush() {
                    tracing::error!(error = %e, "Failed to flush alerts.log");
                }
            }
            Err(e) => {
                // Mutex poisoned — log to tracing only, don't panic in hot path
                tracing::error!(error = %e, "AlertLogger mutex poisoned");
            }
        }

        // Structured log for SIEM / tracing pipeline
        tracing::warn!(
            src_ip   = %src_ip,
            dst_ip   = %dst_ip,
            src_port = src_port,
            dst_port = dst_port,
            protocol = %protocol,
            rule_id  = %rule_id,
            "SECURITY_ALERT: Connection blocked"
        );
    }

    /// Log an alert (traffic that matched an alert rule but was not blocked).
    pub fn log_alert(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        protocol: &str,
        rule_id: &str,
    ) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_line = format!(
            "[{timestamp}] ALERT src={src_ip}:{src_port} dst={dst_ip}:{dst_port} proto={protocol} rule={rule_id}\n"
        );

        match ALERT_LOGGER.lock() {
            Ok(mut logger) => {
                if let Err(e) = logger.file.write_all(log_line.as_bytes()) {
                    tracing::error!(error = %e, "Failed to write alert to alerts.log");
                }
                if let Err(e) = logger.file.flush() {
                    tracing::error!(error = %e, "Failed to flush alerts.log");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "AlertLogger mutex poisoned");
            }
        }

        tracing::warn!(
            src_ip   = %src_ip,
            dst_ip   = %dst_ip,
            src_port = src_port,
            dst_port = dst_port,
            protocol = %protocol,
            rule_id  = %rule_id,
            "SECURITY_ALERT: Traffic alert"
        );
    }
}