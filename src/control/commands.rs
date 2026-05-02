// src/control/commands.rs
//! Control commands and responses for RUBIX IPC

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Status,
    Stats,
    BlockIp {
        ip: IpAddr,
        /// Block duration in seconds — None means permanent
        duration_secs: Option<u64>,
        reason: Option<String>,
    },
    UnblockIp {
        ip: IpAddr,
    },
    ListBlocked,
    ReloadConfig,
    Shutdown,
    GetRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CommandResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn success_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
            timestamp: chrono::Utc::now(),
        }
    }
}