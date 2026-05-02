// src/blocker/windows.rs
//! Windows production blocker using Windows Firewall (netsh/PowerShell)
//! Supports permanent blocking and timed blocking with auto-expiry.
//!
//! Enforcement path:
//!   netsh advfirewall → Windows Filtering Platform (WFP) → kernel drop
//!   All rules named "RUBIX-BLOCK-{IP}" for easy identification and cleanup.

use super::{Blocker, BlockRule, BlockerError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time;
use tracing::{error, info, warn};

// ── Rule store ────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct ActiveRule {
    block_rule: BlockRule,
    permanent: bool,
}

pub struct WindowsBlocker {
    rules: Arc<Mutex<HashMap<IpAddr, ActiveRule>>>,
}

impl WindowsBlocker {
    pub fn new() -> Self {
        info!("Initialising Windows Firewall blocker (netsh → WFP)");
        let blocker = Self {
            rules: Arc::new(Mutex::new(HashMap::new())),
        };
        // Start background expiry checker
        blocker.start_expiry_task();
        blocker
    }

    // ── netsh helpers ─────────────────────────────────────────────────────────

    fn rule_name(ip: &IpAddr) -> String {
        format!("RUBIX-BLOCK-{}", ip)
    }

    /// Install a Windows Firewall outbound + inbound block rule for this IP.
    fn install_fw_rule(ip: &IpAddr) -> Result<(), BlockerError> {
        use std::process::Command;
        let name = Self::rule_name(ip);
        let ip_str = ip.to_string();

        // Block outbound (we initiate connection to malicious IP)
        let out = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}-OUT", name),
                "dir=out",
                "action=block",
                &format!("remoteip={}", ip_str),
                "enable=yes",
                "profile=any",
                "protocol=any",
            ])
            .output()
            .map_err(|e| BlockerError::CommandFailed(format!("netsh spawn failed: {}", e)))?;

        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stdout);
            // "already exists" is fine — idempotent
            if !msg.to_lowercase().contains("already") {
                return Err(BlockerError::CommandFailed(
                    format!("netsh OUT rule failed for {}: {}", ip, msg)
                ));
            }
        }

        // Block inbound (malicious IP connects to us)
        let out = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}-IN", name),
                "dir=in",
                "action=block",
                &format!("remoteip={}", ip_str),
                "enable=yes",
                "profile=any",
                "protocol=any",
            ])
            .output()
            .map_err(|e| BlockerError::CommandFailed(format!("netsh spawn failed: {}", e)))?;

        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stdout);
            if !msg.to_lowercase().contains("already") {
                return Err(BlockerError::CommandFailed(
                    format!("netsh IN rule failed for {}: {}", ip, msg)
                ));
            }
        }

        info!(ip = %ip, "Windows Firewall block rules installed (IN + OUT)");
        Ok(())
    }

    /// Remove Windows Firewall block rules for this IP.
    fn remove_fw_rule(ip: &IpAddr) -> Result<(), BlockerError> {
        use std::process::Command;
        let name = Self::rule_name(ip);

        for suffix in &["-OUT", "-IN"] {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "delete", "rule",
                    &format!("name={}{}", name, suffix),
                ])
                .output();
        }

        info!(ip = %ip, "Windows Firewall block rules removed");
        Ok(())
    }

    /// Remove ALL RUBIX rules from Windows Firewall.
    fn remove_all_fw_rules() -> Result<(), BlockerError> {
        use std::process::Command;

        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetFirewallRule | \
                 Where-Object { $_.DisplayName -like 'RUBIX-BLOCK-*' } | \
                 Remove-NetFirewallRule",
            ])
            .output()
            .map_err(|e| BlockerError::CommandFailed(e.to_string()))?;

        if out.status.success() {
            info!("All RUBIX Windows Firewall rules removed");
        } else {
            warn!("Some RUBIX rules may not have been removed (may already be gone)");
        }

        Ok(())
    }

    /// Check if a Windows Firewall rule exists for this IP.
    fn fw_rule_exists(ip: &IpAddr) -> bool {
        use std::process::Command;
        let name = format!("RUBIX-BLOCK-{}-OUT", Self::rule_name(ip));
        Command::new("netsh")
            .args([
                "advfirewall", "firewall", "show", "rule",
                &format!("name={}", name),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    // ── Core block logic ──────────────────────────────────────────────────────

    /// Internal block — used by both public block_ip and timed block.
    fn do_block(
        &self,
        ip: IpAddr,
        duration: Option<Duration>,
    ) -> Result<String, BlockerError> {
        let rule_id = format!("rubix-{}-{}", ip,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        // Check if already blocked
        {
            let rules = self.rules.lock()
                .map_err(|_| BlockerError::CommandFailed("Lock poisoned".into()))?;
            if rules.contains_key(&ip) {
                info!(ip = %ip, "Already blocked — skipping duplicate");
                return Ok(rule_id);
            }
        }

        // Install Windows Firewall rule
        Self::install_fw_rule(&ip)?;

        let expires_at = duration.map(|d| SystemTime::now() + d);
        let permanent  = duration.is_none();

        let rule = BlockRule {
            id: rule_id.clone(),
            target: ip,
            created_at: SystemTime::now(),
            expires_at,
            reason: if permanent {
                "permanent-block".to_string()
            } else {
                format!("timed-block-{}s", duration.unwrap_or_default().as_secs())
            },
        };

        self.rules.lock()
            .map_err(|_| BlockerError::CommandFailed("Lock poisoned".into()))?
            .insert(ip, ActiveRule { block_rule: rule, permanent });

        if permanent {
            info!(ip = %ip, "Permanently blocked");
        } else {
            info!(
                ip = %ip,
                secs = duration.unwrap_or_default().as_secs(),
                "Timed block installed"
            );
        }

        Ok(rule_id)
    }

    // ── Background expiry task ────────────────────────────────────────────────

    fn start_expiry_task(&self) {
        let rules = self.rules.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let now = SystemTime::now();
                let mut expired: Vec<IpAddr> = Vec::new();

                // Find expired timed rules
                if let Ok(guard) = rules.lock() {
                    for (ip, active) in guard.iter() {
                        if active.permanent {
                            continue;
                        }
                        if let Some(expires_at) = active.block_rule.expires_at {
                            if now >= expires_at {
                                expired.push(*ip);
                            }
                        }
                    }
                }

                // Remove expired rules
                for ip in expired {
                    if let Err(e) = Self::remove_fw_rule(&ip) {
                        error!(ip = %ip, error = %e, "Failed to remove expired block rule");
                    } else {
                        if let Ok(mut guard) = rules.lock() {
                            guard.remove(&ip);
                        }
                        info!(ip = %ip, "Timed block expired — rule removed");
                    }
                }
            }
        });
    }
}

impl Default for WindowsBlocker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Blocker for WindowsBlocker {
    /// Block an IP permanently.
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError> {
        self.do_block(ip, None)
    }

    /// Block an IP for a specific duration, then auto-unblock.
    async fn block_ip_timed(
        &self,
        ip: IpAddr,
        duration: Duration,
    ) -> Result<String, BlockerError> {
        self.do_block(ip, Some(duration))
    }

    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError> {
        let existed = {
            let mut rules = self.rules.lock()
                .map_err(|_| BlockerError::CommandFailed("Lock poisoned".into()))?;
            rules.remove(&ip).is_some()
        };

        if existed {
            Self::remove_fw_rule(&ip)?;
            info!(ip = %ip, "Manually unblocked");
            Ok(true)
        } else {
            warn!(ip = %ip, "Unblock requested but IP was not in block list");
            Ok(false)
        }
    }

    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        let in_memory = self.rules.lock()
            .map_err(|_| BlockerError::CommandFailed("Lock poisoned".into()))?
            .contains_key(ip);

        // Also verify the firewall rule actually exists
        // (guards against rules removed externally)
        Ok(in_memory && Self::fw_rule_exists(ip))
    }

    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        let rules = self.rules.lock()
            .map_err(|_| BlockerError::CommandFailed("Lock poisoned".into()))?;

        let mut list: Vec<BlockRule> = rules
            .values()
            .map(|a| a.block_rule.clone())
            .collect();

        // Sort permanent first, then by creation time
        list.sort_by(|a, b| {
            let a_perm = a.expires_at.is_none();
            let b_perm = b.expires_at.is_none();
            b_perm.cmp(&a_perm)
                .then(a.created_at.cmp(&b.created_at))
        });

        Ok(list)
    }

    async fn cleanup(&self) -> Result<(), BlockerError> {
        Self::remove_all_fw_rules()?;

        self.rules.lock()
            .map_err(|_| BlockerError::CommandFailed("Lock poisoned".into()))?
            .clear();

        info!("Windows Firewall cleanup complete");
        Ok(())
    }
}