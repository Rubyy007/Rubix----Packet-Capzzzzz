// src/blocker/mod.rs
//! Blocker module — kernel-level IP enforcement + process blocklist.

#![allow(dead_code)]

pub mod cache;
pub mod cleaner;
pub mod process;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::LinuxBlocker;
#[cfg(target_os = "windows")]
pub use windows::WindowsBlocker;

#[cfg(target_os = "linux")]
pub type PlatformBlocker = linux::LinuxBlocker;
#[cfg(target_os = "windows")]
pub type PlatformBlocker = windows::WindowsBlocker;

pub use process::ProcessBlocklist;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use thiserror::Error;

// ── IP block rule ─────────────────────────────────────────────────────────────

/// Optional origin tag — set when a kernel IP rule was installed
/// as a consequence of a process block.  Enables per-process cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockOrigin {
    /// Installed manually via CLI `block-ip`.
    Manual,
    /// Installed automatically because of a process block.
    ProcessBlock {
        pid:  u32,
        name: String,
        exe:  Option<PathBuf>,
    },
}

impl Default for BlockOrigin {
    fn default() -> Self { BlockOrigin::Manual }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRule {
    pub id:         String,
    pub target:     IpAddr,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub reason:     String,
    #[serde(default)]
    pub origin:     BlockOrigin,
}

impl BlockRule {
    #[inline]
    pub fn is_permanent(&self) -> bool { self.expires_at.is_none() }

    pub fn remaining(&self) -> Option<Duration> {
        let expires = self.expires_at?;
        expires.duration_since(SystemTime::now()).ok()
    }

    pub fn duration_display(&self) -> String {
        match self.remaining() {
            None if self.is_permanent() => "permanent".to_string(),
            None => "expired".to_string(),
            Some(d) => {
                let secs = d.as_secs();
                if secs >= 3600 {
                    format!("{}h {}m remaining", secs / 3600, (secs % 3600) / 60)
                } else if secs >= 60 {
                    format!("{}m {}s remaining", secs / 60, secs % 60)
                } else {
                    format!("{}s remaining", secs)
                }
            }
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum BlockerError {
    #[error("nftables error: {0}")]
    NftablesError(String),

    #[error("iptables error: {0}")]
    IptablesError(String),

    #[error("WFP/Firewall error: {0}")]
    WfpError(String),

    #[error("Rule already exists: {0}")]
    RuleExists(String),

    #[error("Permission denied: run as root/Administrator")]
    PermissionDenied,

    #[error("Failed to execute command: {0}")]
    CommandFailed(String),

    #[error("Process error: {0}")]
    ProcessError(String),
}

// ── Blocker trait ─────────────────────────────────────────────────────────────

#[async_trait]
pub trait Blocker: Send + Sync {
    /// Block an IP permanently.
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError>;

    /// Block an IP permanently with an origin tag.
    async fn block_ip_with_origin(
        &self,
        ip:     IpAddr,
        origin: BlockOrigin,
    ) -> Result<String, BlockerError>;

    /// Block an IP for a specific duration.
    async fn block_ip_timed(
        &self,
        ip:       IpAddr,
        duration: Duration,
    ) -> Result<String, BlockerError>;

    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError>;
    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError>;
    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError>;
    async fn cleanup(&self) -> Result<(), BlockerError>;
}