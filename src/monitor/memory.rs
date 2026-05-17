// src/monitor/memory.rs
//! Memory monitoring — cross-platform RSS tracking with threshold alerting.
//!
//! Linux:   reads VmRSS from /proc/self/status  (kernel-maintained, fast)
//! Windows: uses GlobalMemoryStatusEx via windows-sys to get process working set

use std::time::Duration;
use tracing::{info, warn};

pub struct MemoryMonitor {
    warning_threshold_mb:  u64,
    critical_threshold_mb: u64,
}

impl MemoryMonitor {
    pub fn new(warning_threshold_mb: u64, critical_threshold_mb: u64) -> Self {
        Self {
            warning_threshold_mb,
            critical_threshold_mb,
        }
    }

    /// Returns current process RSS in megabytes.
    pub fn get_current_usage() -> Result<u64, String> {
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|e| format!("Failed to read /proc/self/status: {}", e))?;

            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let kb: u64 = parts[1]
                            .parse()
                            .map_err(|_| "Invalid VmRSS value in /proc/self/status")?;
                        return Ok(kb / 1024);
                    }
                }
            }
            Err("VmRSS not found in /proc/self/status".to_string())
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::ProcessStatus::{
                GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
            };
            use windows_sys::Win32::System::Threading::GetCurrentProcess;

            unsafe {
                let handle = GetCurrentProcess();
                let mut pmc = PROCESS_MEMORY_COUNTERS {
                    cb:                         std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                    PageFaultCount:             0,
                    PeakWorkingSetSize:         0,
                    WorkingSetSize:             0,
                    QuotaPeakPagedPoolUsage:    0,
                    QuotaPagedPoolUsage:        0,
                    QuotaPeakNonPagedPoolUsage: 0,
                    QuotaNonPagedPoolUsage:     0,
                    PagefileUsage:              0,
                    PeakPagefileUsage:          0,
                };

                if GetProcessMemoryInfo(handle, &mut pmc, pmc.cb) != 0 {
                    // WorkingSetSize is in bytes — convert to MB.
                    Ok(pmc.WorkingSetSize as u64 / (1024 * 1024))
                } else {
                    Err("GetProcessMemoryInfo failed".to_string())
                }
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Ok(0)
        }
    }

    /// Check memory once and emit a log line at the appropriate level.
    pub fn check_and_alert(&self) {
        match Self::get_current_usage() {
            Ok(usage) => {
                if usage >= self.critical_threshold_mb {
                    warn!(
                        usage_mb  = usage,
                        threshold = self.critical_threshold_mb,
                        "CRITICAL: memory usage exceeds critical threshold"
                    );
                } else if usage >= self.warning_threshold_mb {
                    warn!(
                        usage_mb  = usage,
                        threshold = self.warning_threshold_mb,
                        "WARNING: memory usage exceeds warning threshold"
                    );
                } else {
                    info!(usage_mb = usage, "Memory usage nominal");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to read memory usage");
            }
        }
    }

    /// Spawn a background Tokio task that polls memory every `interval_secs`.
    ///
    /// Must be called inside an async context (after #[tokio::main] starts).
    pub fn start_monitoring(&self, interval_secs: u64) {
        let warning  = self.warning_threshold_mb;
        let critical = self.critical_threshold_mb;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

            loop {
                ticker.tick().await;

                match MemoryMonitor::get_current_usage() {
                    Ok(usage) => {
                        if usage >= critical {
                            warn!(usage_mb = usage, threshold = critical,
                                "CRITICAL: memory usage exceeds critical threshold");
                        } else if usage >= warning {
                            warn!(usage_mb = usage, threshold = warning,
                                "WARNING: memory usage exceeds warning threshold");
                        } else {
                            info!(usage_mb = usage, "Memory usage nominal");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read memory usage");
                    }
                }
            }
        });
    }
}