// src/blocker/mod.rs
//! Blocker module — kernel-level IP enforcement

#![allow(dead_code)]

mod cache;
mod cleaner;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

// ── Public re-exports ─────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub use linux::LinuxBlocker;

#[cfg(target_os = "windows")]
pub use windows::WindowsBlocker;

// ── Platform type alias ───────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub type PlatformBlocker = linux::LinuxBlocker;

#[cfg(target_os = "windows")]
pub type PlatformBlocker = windows::WindowsBlocker;

// ── Shared types ──────────────────────────────────────────────────────────────
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct BlockRule {
    pub id: String,
    pub target: IpAddr,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub reason: String,
}

impl BlockRule {
    /// Returns true if this is a permanent block (no expiry)
    pub fn is_permanent(&self) -> bool {
        self.expires_at.is_none()
    }

    /// Returns remaining duration for timed blocks, None if permanent or expired
    pub fn remaining(&self) -> Option<Duration> {
        let expires = self.expires_at?;
        expires.duration_since(SystemTime::now()).ok()
    }

    /// Returns a human-readable description of the block duration
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

#[derive(Error, Debug)]
pub enum BlockerError {
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
}

// ── Trait ─────────────────────────────────────────────────────────────────────
#[async_trait]
pub trait Blocker: Send + Sync {
    /// Block an IP permanently until manually unblocked.
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError>;

    /// Block an IP for a specific duration, then auto-unblock.
    async fn block_ip_timed(
        &self,
        ip: IpAddr,
        duration: Duration,
    ) -> Result<String, BlockerError>;

    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError>;
    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError>;
    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError>;
    async fn cleanup(&self) -> Result<(), BlockerError>;
}