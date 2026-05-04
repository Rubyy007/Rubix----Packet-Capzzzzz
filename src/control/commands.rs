// src/control/commands.rs
//! Control commands and responses for RUBIX IPC.
//!
//! Transport: JSON over Unix socket (Linux) / TCP loopback (Windows).
//! All commands are tagged with `"cmd"` so the wire format is stable and
//! forwards-compatible.

use crate::types::stats::LiveStats;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ── Commands (CLI → daemon) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Lightweight status check: uptime, block count, rule count.
    Status,

    /// Full live-stats snapshot: pps, top procs, recent threats, heartbeat.
    /// Powers the `rubix-cli monitor` TUI dashboard.
    Stats,

    /// Block an IP address, optionally for a limited duration.
    BlockIp {
        ip:            IpAddr,
        /// None or 0 → permanent.
        duration_secs: Option<u64>,
        reason:        Option<String>,
    },

    /// Remove a block rule.
    UnblockIp {
        ip: IpAddr,
    },

    /// List all currently active block rules.
    ListBlocked,

    /// Hot-reload rules.yaml without restarting.
    ReloadConfig,

    /// Ask the daemon to perform a graceful shutdown.
    Shutdown,

    /// List all loaded policy rules.
    GetRules,
}

// ── Responses (daemon → CLI) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success:   bool,
    pub message:   String,

    /// Present for Status, ListBlocked, GetRules, Stats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data:      Option<serde_json::Value>,

    /// Full live-stats snapshot — only set for the `Stats` command.
    /// Kept as a dedicated field (not folded into `data`) so the CLI can
    /// deserialise it without extra JSON pointer lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_stats: Option<LiveStats>,

    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CommandResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success:    true,
            message:    message.into(),
            data:       None,
            live_stats: None,
            timestamp:  chrono::Utc::now(),
        }
    }

    pub fn success_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success:    true,
            message:    message.into(),
            data:       Some(data),
            live_stats: None,
            timestamp:  chrono::Utc::now(),
        }
    }

    pub fn success_with_stats(message: impl Into<String>, stats: LiveStats) -> Self {
        Self {
            success:    true,
            message:    message.into(),
            data:       None,
            live_stats: Some(stats),
            timestamp:  chrono::Utc::now(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success:    false,
            message:    message.into(),
            data:       None,
            live_stats: None,
            timestamp:  chrono::Utc::now(),
        }
    }
}
