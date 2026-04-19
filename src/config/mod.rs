//! Configuration management for RUBIX

pub mod loader;
pub mod watcher;

// Remove this line - it causes conflict:
// pub use self::RubixConfig;

// Keep this re-export
pub use loader::ConfigLoader;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RubixConfig {
    pub mode: OperationMode,
    pub capture_interface: String,
    pub promiscuous: bool,
    pub buffer_size_mb: u64,
    pub timeout_ms: u64,
    pub snaplen: u32,
    pub bpf_filter: Option<String>,
    pub fast_path: FastPathConfig,
    pub blocking: BlockingConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationMode {
    Block,
    Monitor,
    Off,
}

impl fmt::Display for OperationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationMode::Block => write!(f, "Block"),
            OperationMode::Monitor => write!(f, "Monitor"),
            OperationMode::Off => write!(f, "Off"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPathConfig {
    pub enable_sampling: bool,
    pub sampling_rate_high: f64,
    pub enable_aggregation: bool,
    pub aggregation_window_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingConfig {
    pub iptables_chain: String,
    pub block_timeout_seconds: u64,
    pub default_action: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_cleanup: bool,
    #[serde(default = "default_false")]
    pub flush_on_exit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: PathBuf,
    pub json_format: bool,
    pub max_file_size_mb: u64,
    pub rotation_count: u32,
    #[serde(default = "default_true")]
    pub console_output: bool,
}

fn default_true() -> bool { true }
fn default_false() -> bool { false }

impl Default for RubixConfig {
    fn default() -> Self {
        Self {
            mode: OperationMode::Block,
            capture_interface: "auto".to_string(),
            promiscuous: true,
            buffer_size_mb: 64,
            timeout_ms: 10,
            snaplen: 65535,
            bpf_filter: Some("ip or ip6".to_string()),
            fast_path: FastPathConfig {
                enable_sampling: false,
                sampling_rate_high: 0.3,
                enable_aggregation: false,
                aggregation_window_ms: 1000,
            },
            blocking: BlockingConfig {
                iptables_chain: "RUBIX".to_string(),
                block_timeout_seconds: 3600,
                default_action: "drop".to_string(),
                enabled: true,
                auto_cleanup: true,
                flush_on_exit: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: PathBuf::from("/var/log/rubix/rubix.log"),
                json_format: true,
                max_file_size_mb: 100,
                rotation_count: 5,
                console_output: true,
            },
        }
    }
}