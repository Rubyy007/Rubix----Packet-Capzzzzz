// src/control/commands.rs
use crate::types::stats::LiveStats;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Status,
    Stats,
    Logs,
    BlockIp   { ip: IpAddr, duration_secs: Option<u64>, reason: Option<String> },
    UnblockIp { ip: IpAddr },
    ListBlocked,

    /// Block a specific running PID.
    /// {"cmd":"block_pid","pid":1234,"duration_secs":300,"reason":"suspicious"}
    BlockPid {
        pid:          u32,
        duration_secs: Option<u64>,
        reason:       Option<String>,
    },

    /// Block all processes running from an executable path.
    /// {"cmd":"block_executable","path":"/usr/bin/curl","reason":"banned"}
    BlockExecutable {
        path:   PathBuf,
        reason: Option<String>,
    },

    /// Block any process whose executable SHA-256 matches.
    /// {"cmd":"block_hash","sha256":"aabbcc...","reason":"malware"}
    BlockHash {
        /// Lowercase hex-encoded SHA-256 (64 chars).
        sha256: String,
        reason: Option<String>,
    },

    UnblockPid        { pid:    u32     },
    UnblockExecutable { path:   PathBuf },
    UnblockHash       { sha256: String  },

    ListBlockedProcesses,

    ReloadConfig,
    Shutdown,
    GetRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success:   bool,
    pub message:   String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data:      Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_stats: Option<LiveStats>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CommandResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self { success: true,  message: message.into(), data: None, live_stats: None, timestamp: chrono::Utc::now() }
    }
    pub fn success_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self { success: true,  message: message.into(), data: Some(data), live_stats: None, timestamp: chrono::Utc::now() }
    }
    pub fn success_with_stats(message: impl Into<String>, stats: LiveStats) -> Self {
        Self { success: true,  message: message.into(), data: None, live_stats: Some(stats), timestamp: chrono::Utc::now() }
    }
    pub fn error(message: impl Into<String>) -> Self {
        Self { success: false, message: message.into(), data: None, live_stats: None, timestamp: chrono::Utc::now() }
    }
}