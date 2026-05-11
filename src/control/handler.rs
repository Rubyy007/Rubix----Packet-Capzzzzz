// src/control/handler.rs
use super::commands::{Command, CommandResponse};
use crate::blocker::{Blocker, PlatformBlocker, ProcessBlocklist};
use crate::policy::{PolicyEngine, PolicyReloader};
use crate::types::stats::LiveStats;

use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

pub struct CommandHandler {
    blocker:      Arc<PlatformBlocker>,
    proc_bl:      Arc<ProcessBlocklist>,
    policy_engine: Arc<PolicyEngine>,
    reloader:     Arc<PolicyReloader>,
    start_time:   Instant,
    shared_stats: Arc<RwLock<LiveStats>>,
}

impl CommandHandler {
    pub fn new(
        blocker:       Arc<PlatformBlocker>,
        proc_bl:       Arc<ProcessBlocklist>,
        policy_engine: Arc<PolicyEngine>,
        reloader:      Arc<PolicyReloader>,
        start_time:    Instant,
        shared_stats:  Arc<RwLock<LiveStats>>,
    ) -> Self {
        Self { blocker, proc_bl, policy_engine, reloader, start_time, shared_stats }
    }

    pub async fn handle(&self, command: Command) -> CommandResponse {
        match command {
            Command::Status                                        => self.status().await,
            Command::Stats                                         => self.stats(),
            Command::Logs                                          => self.logs(),
            Command::BlockIp { ip, duration_secs, reason }        => self.block_ip(ip, duration_secs, reason).await,
            Command::UnblockIp { ip }                              => self.unblock_ip(ip).await,
            Command::ListBlocked                                   => self.list_blocked().await,
            Command::BlockPid { pid, duration_secs, reason }      => self.block_pid(pid, duration_secs, reason).await,
            Command::BlockExecutable { path, reason }              => self.block_executable(path, reason).await,
            Command::BlockHash { sha256, reason }                  => self.block_hash(sha256, reason).await,
            Command::UnblockPid { pid }                            => self.unblock_pid(pid).await,
            Command::UnblockExecutable { path }                    => self.unblock_executable(path).await,
            Command::UnblockHash { sha256 }                        => self.unblock_hash(sha256).await,
            Command::ListBlockedProcesses                          => self.list_blocked_processes().await,
            Command::ReloadConfig                                  => self.reload_config().await,
            Command::Shutdown                                      => self.shutdown().await,
            Command::GetRules                                      => self.get_rules().await,
        }
    }

    fn stats(&self) -> CommandResponse {
        CommandResponse::success_with_stats("Live stats", self.shared_stats.read().clone())
    }

    fn logs(&self) -> CommandResponse {
        CommandResponse::success_with_stats("Live logs", self.shared_stats.read().clone())
    }

    async fn status(&self) -> CommandResponse {
        let uptime = self.start_time.elapsed().as_secs();
        let rules  = self.blocker.list_rules().await.unwrap_or_default();
        let pids   = self.proc_bl.list_pid_blocks();
        let exes   = self.proc_bl.list_exe_blocks();
        let hashes = self.proc_bl.list_hash_blocks();

        CommandResponse::success_with_data(
            format!("RUBIX running — up {:02}h {:02}m {:02}s",
                uptime/3600, (uptime%3600)/60, uptime%60),
            serde_json::json!({
                "status":              "running",
                "uptime_secs":         uptime,
                "active_ip_blocks":    rules.len(),
                "active_pid_blocks":   pids.len(),
                "active_exe_blocks":   exes.len(),
                "active_hash_blocks":  hashes.len(),
                "policy_rules":        self.policy_engine.rule_count(),
            }),
        )
    }

    async fn block_ip(
        &self, ip: IpAddr, duration_secs: Option<u64>, _reason: Option<String>,
    ) -> CommandResponse {
        let result = match duration_secs.filter(|&d| d > 0) {
            Some(s) => self.blocker.block_ip_timed(ip, Duration::from_secs(s)).await,
            None    => self.blocker.block_ip(ip).await,
        };
        match result {
            Ok(id) => CommandResponse::success_with_data(
                format!("{} blocked (rule: {})", ip, id),
                serde_json::json!({ "ip": ip.to_string(), "rule_id": id }),
            ),
            Err(e) => CommandResponse::error(format!("Failed to block {}: {}", ip, e)),
        }
    }

    async fn unblock_ip(&self, ip: IpAddr) -> CommandResponse {
        match self.blocker.unblock_ip(ip).await {
            Ok(true)  => CommandResponse::success(format!("{} unblocked", ip)),
            Ok(false) => CommandResponse::error(format!("{} not in block list", ip)),
            Err(e)    => CommandResponse::error(format!("Failed: {}", e)),
        }
    }

    async fn list_blocked(&self) -> CommandResponse {
        match self.blocker.list_rules().await {
            Ok(rules) => {
                let json: Vec<_> = rules.iter().map(|r| serde_json::json!({
                    "id":        r.id,
                    "ip":        r.target.to_string(),
                    "permanent": r.is_permanent(),
                    "remaining": r.duration_display(),
                    "reason":    r.reason,
                    "origin":    format!("{:?}", r.origin),
                })).collect();
                CommandResponse::success_with_data(
                    format!("{} active IP block(s)", json.len()),
                    serde_json::json!({ "rules": json, "count": json.len() }),
                )
            }
            Err(e) => CommandResponse::error(format!("Failed: {}", e)),
        }
    }

    // ── PID block ─────────────────────────────────────────────────────────────

    async fn block_pid(
        &self,
        pid:          u32,
        duration_secs: Option<u64>,
        reason:       Option<String>,
    ) -> CommandResponse {
        let reason = reason.as_deref().unwrap_or("manual");
        let dur    = duration_secs.filter(|&d| d > 0).map(Duration::from_secs);

        // Resolve name from live resolver for the display label.
        // If not found, fall back to "pid:N".
        let name = format!("pid:{}", pid);

        let newly = self.proc_bl.block_pid(pid, &name, dur, reason);

        CommandResponse::success_with_data(
            if newly {
                format!("PID {} blocked", pid)
            } else {
                format!("PID {} was already blocked", pid)
            },
            serde_json::json!({
                "pid":           pid,
                "newly_blocked": newly,
                "duration_secs": duration_secs,
                "reason":        reason,
            }),
        )
    }

    // ── Executable block ──────────────────────────────────────────────────────

    async fn block_executable(&self, path: PathBuf, reason: Option<String>) -> CommandResponse {
        let reason = reason.as_deref().unwrap_or("manual");
        match self.proc_bl.block_executable(&path, reason) {
            Ok(canonical) => CommandResponse::success_with_data(
                format!("Executable blocked: {}", canonical.display()),
                serde_json::json!({
                    "path":   canonical.to_string_lossy(),
                    "reason": reason,
                    "note":   "All running instances have been PID-blocked. \
                               New instances will be blocked automatically.",
                }),
            ),
            Err(e) => CommandResponse::error(format!("Failed to block executable: {}", e)),
        }
    }

    // ── Hash block ────────────────────────────────────────────────────────────

    async fn block_hash(&self, sha256_hex: String, reason: Option<String>) -> CommandResponse {
        let reason = reason.as_deref().unwrap_or("manual");

        if sha256_hex.len() != 64 {
            return CommandResponse::error(
                "SHA-256 must be 64 lowercase hex characters"
            );
        }

        let mut bytes = [0u8; 32];
        if hex::decode_to_slice(&sha256_hex, &mut bytes).is_err() {
            return CommandResponse::error("Invalid hex in sha256 field");
        }

        let newly = self.proc_bl.block_hash(bytes, reason);
        CommandResponse::success_with_data(
            if newly {
                format!("Hash {} blocked", &sha256_hex[..16])
            } else {
                format!("Hash {} already blocked", &sha256_hex[..16])
            },
            serde_json::json!({
                "sha256": sha256_hex,
                "reason": reason,
                "note":   "All running processes with this hash have been PID-blocked.",
            }),
        )
    }

    // ── Unblock process entries ───────────────────────────────────────────────

    async fn unblock_pid(&self, pid: u32) -> CommandResponse {
        match self.proc_bl.unblock_pid(pid) {
            Some(kernel_ips) => {
                // Flush kernel IP rules that were installed for this PID.
                for ip in &kernel_ips {
                    if let Err(e) = self.blocker.unblock_ip(*ip).await {
                        warn!(ip = %ip, error = %e, "Failed to flush kernel IP for PID unblock");
                    }
                }
                CommandResponse::success_with_data(
                    format!("PID {} unblocked ({} kernel IP(s) flushed)", pid, kernel_ips.len()),
                    serde_json::json!({
                        "pid":              pid,
                        "kernel_ips_flushed": kernel_ips.len(),
                    }),
                )
            }
            None => CommandResponse::error(format!("PID {} not in block list", pid)),
        }
    }

    async fn unblock_executable(&self, path: PathBuf) -> CommandResponse {
        if self.proc_bl.unblock_executable(&path) {
            CommandResponse::success(format!(
                "Executable block removed: {} \
                 (existing PID blocks remain until process exits)",
                path.display()
            ))
        } else {
            CommandResponse::error(format!("{} was not in the block list", path.display()))
        }
    }

    async fn unblock_hash(&self, sha256_hex: String) -> CommandResponse {
        if sha256_hex.len() != 64 {
            return CommandResponse::error("SHA-256 must be 64 hex characters");
        }
        let mut bytes = [0u8; 32];
        if hex::decode_to_slice(&sha256_hex, &mut bytes).is_err() {
            return CommandResponse::error("Invalid hex");
        }
        if self.proc_bl.unblock_hash(&bytes) {
            CommandResponse::success(format!("Hash {} unblocked", &sha256_hex[..16]))
        } else {
            CommandResponse::error(format!("Hash {} not in block list", &sha256_hex[..16]))
        }
    }

    // ── List ──────────────────────────────────────────────────────────────────

    async fn list_blocked_processes(&self) -> CommandResponse {
        let pids   = self.proc_bl.list_pid_blocks();
        let exes   = self.proc_bl.list_exe_blocks();
        let hashes = self.proc_bl.list_hash_blocks();

        let pid_json: Vec<_> = pids.iter().map(|b| serde_json::json!({
            "pid":         b.pid,
            "name":        b.name,
            "reason":      b.reason,
            "kernel_ips":  b.kernel_ips.len(),
            "expires":     b.expires_at.map(|e| {
                let rem = e.saturating_duration_since(std::time::Instant::now());
                format!("{}s remaining", rem.as_secs())
            }).unwrap_or_else(|| "permanent".to_string()),
        })).collect();

        let exe_json: Vec<_> = exes.iter().map(|b| serde_json::json!({
            "path":   b.path.to_string_lossy(),
            "reason": b.reason,
        })).collect();

        let hash_json: Vec<_> = hashes.iter().map(|b| serde_json::json!({
            "sha256": hex::encode(b.sha256),
            "reason": b.reason,
        })).collect();

        CommandResponse::success_with_data(
            format!(
                "{} PID block(s), {} exe block(s), {} hash block(s)",
                pid_json.len(), exe_json.len(), hash_json.len()
            ),
            serde_json::json!({
                "pid_blocks":  pid_json,
                "exe_blocks":  exe_json,
                "hash_blocks": hash_json,
            }),
        )
    }

    // ── Reload / Shutdown / Rules ─────────────────────────────────────────────

    async fn reload_config(&self) -> CommandResponse {
        match self.reloader.load_initial() {
            Ok(()) => CommandResponse::success(format!(
                "Rules reloaded — {} active", self.policy_engine.rule_count()
            )),
            Err(e) => CommandResponse::error(format!("Reload failed: {}", e)),
        }
    }

    async fn shutdown(&self) -> CommandResponse {
        info!("Shutdown via CLI");
        CommandResponse::success("Shutdown signal sent")
    }

    async fn get_rules(&self) -> CommandResponse {
        let rules = self.policy_engine.get_rules();
        let json: Vec<_> = rules.iter().map(|r| serde_json::json!({
            "id": r.id, "name": r.name,
            "action": format!("{:?}", r.action), "enabled": r.enabled,
        })).collect();
        CommandResponse::success_with_data(
            format!("{} policy rules", json.len()),
            serde_json::json!({ "rules": json, "count": json.len() }),
        )
    }
}