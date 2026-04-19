//! Security alert logging for RUBIX

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use once_cell::sync::Lazy;

static ALERT_LOGGER: Lazy<Mutex<AlertLogger>> = Lazy::new(|| {
    Mutex::new(AlertLogger::new().unwrap())
});

pub struct AlertLogger {
    file: std::fs::File,
}

impl AlertLogger {
    pub fn new() -> Result<Self, std::io::Error> {
        std::fs::create_dir_all("/var/log/rubix")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/rubix/alerts.log")?;
        Ok(Self { file })
    }
    
    pub fn log_block(src_ip: &str, dst_ip: &str, port: u16, protocol: &str, rule_id: &str) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_line = format!(
            "[{}] BLOCK: {}:{} -> {}:{} ({}) rule={}\n",
            timestamp, src_ip, port, dst_ip, port, protocol, rule_id
        );
        
        if let Ok(mut logger) = ALERT_LOGGER.lock() {
            let _ = logger.file.write_all(log_line.as_bytes());
            let _ = logger.file.flush();
        }
        
        // Also log to syslog for SIEM integration
        tracing::warn!(
            src_ip = %src_ip,
            dst_ip = %dst_ip,
            port = port,
            protocol = %protocol,
            rule_id = %rule_id,
            "SECURITY_ALERT: Connection blocked"
        );
    }
}
