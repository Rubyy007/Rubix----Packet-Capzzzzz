// src/export/mod.rs
//! Export and integration pipeline for RUBIX.
//!
//! Sends security events (blocks, alerts, threats) to external systems
//! after the packet loop makes a decision.  Runs entirely in the slow path.
//!
//! Backends:
//!   webhook  — HTTP POST batches to a configured URL (feature: webhook)
//!   storage  — SQLite audit log on disk            (feature: storage)
//!   socket   — streaming JSON over TCP/Unix socket (always available)
//!
//! All backends are optional.  If none are configured the dispatcher is a
//! no-op with zero overhead.

mod batch;
mod dispatcher;
mod socket;
mod storage;
mod webhook;

pub use batch::BatchProcessor;
pub use dispatcher::ExportDispatcher;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── ExportConfig ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    #[serde(default)]
    pub enabled: bool,

    /// HTTP/HTTPS URL to POST batched events to.
    /// Requires the `webhook` Cargo feature.
    #[serde(default)]
    pub webhook_url: Option<String>,

    /// Path to the SQLite database for persistent event storage.
    /// Requires the `storage` Cargo feature.
    #[serde(default)]
    pub storage_path: Option<PathBuf>,

    /// TCP address to stream events to local consumers.
    /// Connect with: nc 127.0.0.1 9877
    #[serde(default)]
    pub socket_addr: Option<String>,

    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    #[serde(default = "default_webhook_timeout")]
    pub webhook_timeout_secs: u64,

    #[serde(default = "default_retry_count")]
    pub webhook_retry_count: u32,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled:              false,
            webhook_url:          None,
            storage_path:         None,
            socket_addr:          None,
            batch_size:           default_batch_size(),
            flush_interval_secs:  default_flush_interval(),
            webhook_timeout_secs: default_webhook_timeout(),
            webhook_retry_count:  default_retry_count(),
        }
    }
}

fn default_batch_size()      -> usize { 50 }
fn default_flush_interval()  -> u64   { 10 }
fn default_webhook_timeout() -> u64   { 5  }
fn default_retry_count()     -> u32   { 3  }

// ── ExportEvent ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEvent {
    pub timestamp: String,
    pub kind:      ExportKind,
    pub src_ip:    String,
    pub dst_ip:    String,
    pub src_port:  u16,
    pub dst_port:  u16,
    pub protocol:  String,
    pub process:   String,
    pub detail:    String,
    pub severity:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExportKind {
    Threat,
    Block,
    Alert,
}

impl ExportEvent {
    pub fn from_threat(
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
        protocol: &str, process: &str, detail: &str, severity: &str,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind:      ExportKind::Threat,
            src_ip:    src_ip.to_string(),
            dst_ip:    dst_ip.to_string(),
            src_port,  dst_port,
            protocol:  protocol.to_string(),
            process:   process.to_string(),
            detail:    detail.to_string(),
            severity:  severity.to_string(),
        }
    }

    pub fn from_block(
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
        protocol: &str, process: &str, detail: &str,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind:      ExportKind::Block,
            src_ip:    src_ip.to_string(),
            dst_ip:    dst_ip.to_string(),
            src_port,  dst_port,
            protocol:  protocol.to_string(),
            process:   process.to_string(),
            detail:    detail.to_string(),
            severity:  "HIGH".to_string(),
        }
    }

    pub fn from_alert(
        src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
        protocol: &str, process: &str, detail: &str,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind:      ExportKind::Alert,
            src_ip:    src_ip.to_string(),
            dst_ip:    dst_ip.to_string(),
            src_port,  dst_port,
            protocol:  protocol.to_string(),
            process:   process.to_string(),
            detail:    detail.to_string(),
            severity:  "MEDIUM".to_string(),
        }
    }
}