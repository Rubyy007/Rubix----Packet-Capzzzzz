// src/config/mod.rs
//! Configuration management for RUBIX

pub mod loader;
pub mod watcher;

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
    #[serde(default)]
    pub fast_path: FastPathConfig,
    #[serde(default)]
    pub blocking: BlockingConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

// ── Operation mode ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum OperationMode {
    #[default]
    Block,
    Monitor,
    Off,
}

impl fmt::Display for OperationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationMode::Block   => write!(f, "Block"),
            OperationMode::Monitor => write!(f, "Monitor"),
            OperationMode::Off     => write!(f, "Off"),
        }
    }
}

// ── Fast path ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPathConfig {
    #[serde(default)]
    pub enable_sampling: bool,
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate_high: f64,
    #[serde(default)]
    pub enable_aggregation: bool,
    #[serde(default = "default_aggregation_window")]
    pub aggregation_window_ms: u64,
}

impl Default for FastPathConfig {
    fn default() -> Self {
        Self {
            enable_sampling:       false,
            sampling_rate_high:    0.3,
            enable_aggregation:    false,
            aggregation_window_ms: 1000,
        }
    }
}

// ── Blocking ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingConfig {
    #[serde(default = "default_iptables_chain")]
    pub iptables_chain: String,
    #[serde(default = "default_block_timeout")]
    pub block_timeout_seconds: u64,
    #[serde(default = "default_action")]
    pub default_action: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_cleanup: bool,
    #[serde(default)]
    pub flush_on_exit: bool,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            iptables_chain:        "RUBIX".to_string(),
            block_timeout_seconds: 3600,
            default_action:        "drop".to_string(),
            enabled:               true,
            auto_cleanup:          true,
            flush_on_exit:         false,
        }
    }
}

// ── Logging ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default = "default_log_path")]
    pub file_path: PathBuf,

    #[serde(default = "default_true")]
    pub json_format: bool,

    #[serde(default = "default_log_size")]
    pub max_file_size_mb: u64,

    #[serde(default = "default_rotation_count")]
    pub rotation_count: u32,

    #[serde(default = "default_true")]
    pub console_output: bool,

    // ── Normal-traffic logging ─────────────────────────────────────────────
    //
    // When `log_normal_traffic` is false (default) the Allow arm of the
    // packet loop is a true no-op — zero overhead.
    //
    // When true, every 1-in-`normal_sample_divisor` allowed packet is:
    //   • pushed into the in-memory `normal_logs` ring (capped at
    //     `normal_ring_capacity`), and
    //   • sent to the async file writer via a non-blocking channel.
    //
    // `normal_sample_divisor = 1`  → log every allowed packet (full capture)
    // `normal_sample_divisor = 100`→ log 1% (default — low overhead)
    //
    // The file writer batches writes; it never touches a Mutex from the
    // hot path.
    /// Enable logging of allowed (normal) traffic.
    #[serde(default)]
    pub log_normal_traffic: bool,

    /// Log 1-in-N allowed packets.  1 = every packet, 100 = 1%.
    /// Values below 1 are clamped to 1.
    #[serde(default = "default_normal_sample_divisor")]
    pub normal_sample_divisor: u64,

    /// Maximum entries in the in-memory normal-traffic ring shown by the CLI.
    /// Separate from `LOG_RING_CAPACITY` (security events) so normal traffic
    /// never evicts Block/Alert/Threat entries.
    #[serde(default = "default_normal_ring_capacity")]
    pub normal_ring_capacity: usize,

    /// Channel depth for the async normal-traffic file writer.
    /// If the channel fills (writer can't keep up) sends are silently dropped
    /// — this is intentional: the hot path must never block.
    #[serde(default = "default_normal_channel_depth")]
    pub normal_channel_depth: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level:                 "info".to_string(),
            file_path:             default_log_path(),
            json_format:           true,
            max_file_size_mb:      100,
            rotation_count:        5,
            console_output:        true,
            log_normal_traffic:    false,
            normal_sample_divisor: default_normal_sample_divisor(),
            normal_ring_capacity:  default_normal_ring_capacity(),
            normal_channel_depth:  default_normal_channel_depth(),
        }
    }
}

// ── Serde defaults ────────────────────────────────────────────────────────────

fn default_true()                  -> bool   { true }
fn default_sampling_rate()         -> f64    { 0.3 }
fn default_aggregation_window()    -> u64    { 1000 }
fn default_iptables_chain()        -> String { "RUBIX".to_string() }
fn default_block_timeout()         -> u64    { 3600 }
fn default_action()                -> String { "drop".to_string() }
fn default_log_level()             -> String { "info".to_string() }
fn default_log_size()              -> u64    { 100 }
fn default_rotation_count()        -> u32    { 5 }
fn default_normal_sample_divisor() -> u64    { 100 }
fn default_normal_ring_capacity()  -> usize  { 200 }
fn default_normal_channel_depth()  -> usize  { 4096 }

fn default_log_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    return PathBuf::from(r"C:\ProgramData\rubix\rubix.log");
    #[cfg(not(target_os = "windows"))]
    return PathBuf::from("/var/log/rubix/rubix.log");
}

// ── Top-level default ─────────────────────────────────────────────────────────

impl Default for RubixConfig {
    fn default() -> Self {
        Self {
            mode:              OperationMode::Block,
            capture_interface: "auto".to_string(),
            promiscuous:       true,
            buffer_size_mb:    64,
            timeout_ms:        10,
            snaplen:           65535,
            bpf_filter:        None,
            fast_path:         FastPathConfig::default(),
            blocking:          BlockingConfig::default(),
            logging:           LoggingConfig::default(),
        }
    }
}
