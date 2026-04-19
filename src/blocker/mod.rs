mod cache;
mod cleaner;
mod linux;
mod windows;

#[cfg(target_os = "linux")]
pub use linux::LinuxBlocker;

#[cfg(target_os = "windows")]
pub use windows::WindowsBlocker;

use async_trait::async_trait;
use std::net::IpAddr;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct BlockRule {
    pub id: String,
    pub target: IpAddr,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub reason: String,
}

#[derive(Error, Debug)]
pub enum BlockerError {
    #[error("iptables error: {0}")]
    IptablesError(String),
    
    #[error("Rule already exists: {0}")]
    RuleExists(String),
    
    #[error("Permission denied: run with sudo")]
    PermissionDenied,
    
    #[error("Failed to execute command: {0}")]
    CommandFailed(String),
}

#[async_trait]
pub trait Blocker: Send + Sync {
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError>;
    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError>;
    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError>;
    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError>;
    async fn cleanup(&self) -> Result<(), BlockerError>;
}