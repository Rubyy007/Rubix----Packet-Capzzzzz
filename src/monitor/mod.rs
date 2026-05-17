// src/monitor/mod.rs
//! Runtime monitoring subsystem for RUBIX.
//!
//! Three components:
//!   HealthChecker   — periodic daemon health checks (liveness, connectivity)
//!   MemoryMonitor   — RSS tracking with warning/critical thresholds
//!   MetricsCollector — atomic counters + Prometheus-compatible HTTP endpoint

mod health;
mod memory;
mod metrics;

pub use health::HealthChecker;
pub use memory::MemoryMonitor;
pub use metrics::MetricsCollector;

use serde::{Deserialize, Serialize};

// ── MonitorConfig ─────────────────────────────────────────────────────────────

/// Monitoring configuration — loaded from rubix.*.yaml under `monitor:`.
///
/// Example:
/// ```yaml
/// monitor:
///   enabled: true
///   health_check_interval_secs: 30
///   metrics_port: 9090
///   memory_warning_threshold_mb: 1024
///   memory_critical_threshold_mb: 2048
///   memory_check_interval_secs: 60
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Master switch — if false, no background monitoring tasks are started.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How often the health checker runs (seconds).
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,

    /// Port to expose Prometheus metrics on.
    /// Set to null / omit to disable the metrics HTTP server.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: Option<u16>,

    /// RSS threshold for a WARNING log line (megabytes).
    #[serde(default = "default_warn_mb")]
    pub memory_warning_threshold_mb: u64,

    /// RSS threshold for a CRITICAL log line (megabytes).
    #[serde(default = "default_critical_mb")]
    pub memory_critical_threshold_mb: u64,

    /// How often to poll memory usage (seconds).
    #[serde(default = "default_memory_interval")]
    pub memory_check_interval_secs: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled:                      true,
            health_check_interval_secs:   default_health_interval(),
            metrics_port:                 default_metrics_port(),
            memory_warning_threshold_mb:  default_warn_mb(),
            memory_critical_threshold_mb: default_critical_mb(),
            memory_check_interval_secs:   default_memory_interval(),
        }
    }
}

fn default_true()           -> bool        { true        }
fn default_health_interval() -> u64        { 30          }
fn default_metrics_port()   -> Option<u16> { Some(9090)  }
fn default_warn_mb()        -> u64         { 1024        }
fn default_critical_mb()    -> u64         { 2048        }
fn default_memory_interval() -> u64        { 60          }