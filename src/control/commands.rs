//! Control commands for RUBIX

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    Status,
    Stats,
    BlockIp { ip: IpAddr, reason: Option<String> },
    UnblockIp { ip: IpAddr },
    ListBlocked,
    ReloadConfig,
    Shutdown,
    GetRules,
    AddRule { rule: String },
    RemoveRule { rule_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CommandResponse {
    pub fn success(message: String) -> Self {
        Self {
            success: true,
            message,
            data: None,
            timestamp: chrono::Utc::now(),
        }
    }
    
    pub fn error(message: String) -> Self {
        Self {
            success: false,
            message,
            data: None,
            timestamp: chrono::Utc::now(),
        }
    }
    
    pub fn with_data(message: String, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message,
            data: Some(data),
            timestamp: chrono::Utc::now(),
        }
    }
}