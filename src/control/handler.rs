// src/control/handler.rs
//! Command handler — executes control commands against live daemon state.
//!
//! The `shared_stats` field is an `Arc<parking_lot::RwLock<LiveStats>>`.
//! parking_lot is already a project dependency and provides:
//!   • Writer-preference fairness (no reader starvation of the packet loop).
//!   • ~3× faster than std::sync::RwLock on contested paths.
//!   • Poisoning-free — a panicking reader/writer does not corrupt state.
//!
//! The handler only ever calls `read()` — the write side lives exclusively in
//! the packet loop in main.rs, which uses `try_write()` and skips the update
//! if contended, keeping the hot path latency-free.

use super::commands::{Command, CommandResponse};
use crate::blocker::{Blocker, PlatformBlocker};
use crate::policy::{PolicyEngine, PolicyReloader};
use crate::types::stats::LiveStats;

use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

// ── Handler ───────────────────────────────────────────────────────────────────

pub struct CommandHandler {
    blocker:       Arc<PlatformBlocker>,
    policy_engine: Arc<PolicyEngine>,
    reloader:      Arc<PolicyReloader>,
    start_time:    Instant,
    /// Live stats written by the packet loop every ~500 ms.
    /// The CLI `monitor` command reads this once per second.
    shared_stats:  Arc<RwLock<LiveStats>>,
}

impl CommandHandler {
    pub fn new(
        blocker:       Arc<PlatformBlocker>,
        policy_engine: Arc<PolicyEngine>,
        reloader:      Arc<PolicyReloader>,
        start_time:    Instant,
        shared_stats:  Arc<RwLock<LiveStats>>,
    ) -> Self {
        Self { blocker, policy_engine, reloader, start_time, shared_stats }
    }

    pub async fn handle(&self, command: Command) -> CommandResponse {
        match command {
            Command::Status                               => self.status().await,
            Command::Stats                               => self.stats(),
            Command::BlockIp { ip, duration_secs, reason } =>
                self.block_ip(ip, duration_secs, reason).await,
            Command::UnblockIp { ip }                    => self.unblock_ip(ip).await,
            Command::ListBlocked                         => self.list_blocked().await,
            Command::ReloadConfig                        => self.reload_config().await,
            Command::Shutdown                            => self.shutdown().await,
            Command::GetRules                            => self.get_rules().await,
        }
    }

    // ── Stats — the only non-async handler (pure memory read) ────────────────

    /// Return a full `LiveStats` snapshot to the CLI.
    ///
    /// Takes a read lock — zero allocation on the hot path because the
    /// snapshot is cloned once and then the lock is immediately released
    /// before any serialisation work begins.
    fn stats(&self) -> CommandResponse {
        let snapshot: LiveStats = self.shared_stats.read().clone();
        CommandResponse::success_with_stats("Live stats snapshot", snapshot)
    }

    // ── Status ────────────────────────────────────────────────────────────────

    async fn status(&self) -> CommandResponse {
        let uptime = self.start_time.elapsed().as_secs();
        let h      = uptime / 3600;
        let m      = (uptime % 3600) / 60;
        let s      = uptime % 60;
        let rules  = self.blocker.list_rules().await.unwrap_or_default();

        let data = serde_json::json!({
            "status":        "running",
            "uptime_secs":   uptime,
            "uptime_human":  format!("{:02}h {:02}m {:02}s", h, m, s),
            "active_blocks": rules.len(),
            "policy_rules":  self.policy_engine.rule_count(),
        });

        CommandResponse::success_with_data(
            format!("RUBIX running — up {:02}h {:02}m {:02}s", h, m, s),
            data,
        )
    }

    // ── Block ─────────────────────────────────────────────────────────────────

    async fn block_ip(
        &self,
        ip:            IpAddr,
        duration_secs: Option<u64>,
        reason:        Option<String>,
    ) -> CommandResponse {
        let result = match duration_secs.filter(|&d| d > 0) {
            Some(secs) => {
                info!(ip = %ip, secs, "Timed block via CLI");
                self.blocker.block_ip_timed(ip, Duration::from_secs(secs)).await
            }
            None => {
                info!(ip = %ip, "Permanent block via CLI");
                self.blocker.block_ip(ip).await
            }
        };

        match result {
            Ok(rule_id) => {
                let _ = reason; // stored inside BlockRule in the blocker
                let desc = match duration_secs.filter(|&d| d > 0) {
                    Some(secs) => {
                        let h = secs / 3600;
                        let m = (secs % 3600) / 60;
                        let s = secs % 60;
                        if h > 0 {
                            format!("blocked for {:02}h {:02}m {:02}s", h, m, s)
                        } else if m > 0 {
                            format!("blocked for {:02}m {:02}s", m, s)
                        } else {
                            format!("blocked for {}s", s)
                        }
                    }
                    None => "permanently blocked".to_string(),
                };

                let data = serde_json::json!({
                    "ip":      ip.to_string(),
                    "rule_id": rule_id,
                    "type":    if duration_secs.unwrap_or(0) > 0 { "timed" } else { "permanent" },
                });

                CommandResponse::success_with_data(
                    format!("{} {} (rule: {})", ip, desc, rule_id),
                    data,
                )
            }
            Err(e) => {
                error!(ip = %ip, error = %e, "Block via CLI failed");
                CommandResponse::error(format!("Failed to block {}: {}", ip, e))
            }
        }
    }

    // ── Unblock ───────────────────────────────────────────────────────────────

    async fn unblock_ip(&self, ip: IpAddr) -> CommandResponse {
        match self.blocker.unblock_ip(ip).await {
            Ok(true) => {
                info!(ip = %ip, "Unblocked via CLI");
                CommandResponse::success(format!("{} unblocked successfully", ip))
            }
            Ok(false) => {
                warn!(ip = %ip, "Unblock requested but IP not in block list");
                CommandResponse::error(format!("{} was not in the block list", ip))
            }
            Err(e) => {
                error!(ip = %ip, error = %e, "Unblock via CLI failed");
                CommandResponse::error(format!("Failed to unblock {}: {}", ip, e))
            }
        }
    }

    // ── List blocked ──────────────────────────────────────────────────────────

    async fn list_blocked(&self) -> CommandResponse {
        match self.blocker.list_rules().await {
            Ok(rules) if rules.is_empty() => {
                CommandResponse::success("No active block rules")
            }
            Ok(rules) => {
                let rules_json: Vec<serde_json::Value> = rules
                    .iter()
                    .map(|r| serde_json::json!({
                        "id":        r.id,
                        "ip":        r.target.to_string(),
                        "permanent": r.is_permanent(),
                        "remaining": r.duration_display(),
                        "reason":    r.reason,
                    }))
                    .collect();

                let count = rules_json.len();
                let data  = serde_json::json!({
                    "rules": rules_json,
                    "count": count,
                });

                CommandResponse::success_with_data(
                    format!("{} active block rule(s)", count),
                    data,
                )
            }
            Err(e) => {
                error!(error = %e, "List rules failed");
                CommandResponse::error(format!("Failed to list rules: {}", e))
            }
        }
    }

    // ── Reload ────────────────────────────────────────────────────────────────

    async fn reload_config(&self) -> CommandResponse {
        match self.reloader.load_initial() {
            Ok(()) => {
                info!("Rules reloaded via CLI");
                CommandResponse::success(format!(
                    "Rules reloaded — {} rules active",
                    self.policy_engine.rule_count()
                ))
            }
            Err(e) => {
                error!(error = %e, "Rule reload failed");
                CommandResponse::error(format!("Reload failed: {}", e))
            }
        }
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────

    async fn shutdown(&self) -> CommandResponse {
        info!("Shutdown requested via CLI");
        CommandResponse::success("Shutdown signal sent — RUBIX stopping...")
    }

    // ── Get rules ─────────────────────────────────────────────────────────────

    async fn get_rules(&self) -> CommandResponse {
        let rules = self.policy_engine.get_rules();
        let json: Vec<serde_json::Value> = rules
            .iter()
            .map(|r| serde_json::json!({
                "id":      r.id,
                "name":    r.name,
                "action":  format!("{:?}", r.action),
                "enabled": r.enabled,
            }))
            .collect();

        let count = json.len();
        let data  = serde_json::json!({
            "rules": json,
            "count": count,
        });

        CommandResponse::success_with_data(
            format!("{} policy rules loaded", count),
            data,
        )
    }
}
