//! Monitoring and metrics collection

mod health;
mod memory;
mod metrics;

pub use health::HealthChecker;
pub use memory::MemoryMonitor;
pub use metrics::MetricsCollector;

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub enabled: bool,
    pub health_check_interval_secs: u64,
    pub metrics_port: Option<u16>,
    pub memory_warning_threshold_mb: u64,
    pub memory_critical_threshold_mb: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            health_check_interval_secs: 30,
            metrics_port: Some(9090),
            memory_warning_threshold_mb: 1024,
            memory_critical_threshold_mb: 2048,
        }
    }
}