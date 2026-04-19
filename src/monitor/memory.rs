//! Memory monitoring

use std::process;
use tracing::{info, warn};

pub struct MemoryMonitor {
    warning_threshold_mb: u64,
    critical_threshold_mb: u64,
}

impl MemoryMonitor {
    pub fn new(warning_threshold_mb: u64, critical_threshold_mb: u64) -> Self {
        Self {
            warning_threshold_mb,
            critical_threshold_mb,
        }
    }
    
    pub fn get_current_usage() -> Result<u64, String> {
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|e| format!("Failed to read memory: {}", e))?;
            
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let kb: u64 = parts[1].parse().map_err(|_| "Invalid memory value")?;
                        return Ok(kb / 1024); // Convert KB to MB
                    }
                }
            }
            Ok(0)
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows implementation would use GlobalMemoryStatusEx
            Ok(0)
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Ok(0)
        }
    }
    
    pub fn check_and_alert(&self) {
        if let Ok(usage) = Self::get_current_usage() {
            if usage >= self.critical_threshold_mb {
                warn!(
                    "CRITICAL: Memory usage {} MB exceeds threshold {} MB",
                    usage, self.critical_threshold_mb
                );
            } else if usage >= self.warning_threshold_mb {
                warn!(
                    "WARNING: Memory usage {} MB exceeds threshold {} MB",
                    usage, self.warning_threshold_mb
                );
            } else {
                info!("Memory usage: {} MB", usage);
            }
        }
    }
    
    pub fn start_monitoring(&self, interval_secs: u64) {
        let warning = self.warning_threshold_mb;
        let critical = self.critical_threshold_mb;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            
            loop {
                interval.tick().await;
                
                if let Ok(usage) = MemoryMonitor::get_current_usage() {
                    if usage >= critical {
                        warn!("CRITICAL: Memory usage {} MB", usage);
                    } else if usage >= warning {
                        warn!("WARNING: Memory usage {} MB", usage);
                    }
                }
            }
        });
    }
}