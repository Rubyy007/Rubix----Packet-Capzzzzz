// src/blocker/linux.rs
//! Linux iptables implementation — permanent and timed blocking

use super::{Blocker, BlockRule, BlockerError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
struct ActiveRule {
    block_rule: BlockRule,
    permanent: bool,
}

pub struct LinuxBlocker {
    chain_name: String,
    rules: Arc<Mutex<HashMap<IpAddr, ActiveRule>>>,
}

impl LinuxBlocker {
    pub fn new() -> Self {
        let blocker = Self {
            chain_name: "RUBIX".to_string(),
            rules: Arc::new(Mutex::new(HashMap::new())),
        };
        blocker.start_expiry_task();
        blocker
    }

    // ── iptables helpers ──────────────────────────────────────────────────────

    fn ensure_chain(&self) -> Result<(), BlockerError> {
        // Create chain if it doesn't exist
        let check = Command::new("iptables")
            .args(["-L", &self.chain_name, "-n"])
            .output()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;

        if !check.status.success() {
            info!("Creating iptables chain: {}", self.chain_name);
            Command::new("iptables")
                .args(["-N", &self.chain_name])
                .status()
                .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        }

        // Hook into INPUT chain if not already
        let hooked = Command::new("iptables")
            .args(["-C", "INPUT", "-j", &self.chain_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !hooked {
            Command::new("iptables")
                .args(["-I", "INPUT", "1", "-j", &self.chain_name])
                .status()
                .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        }

        // Hook into OUTPUT chain if not already
        let hooked_out = Command::new("iptables")
            .args(["-C", "OUTPUT", "-j", &self.chain_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !hooked_out {
            Command::new("iptables")
                .args(["-I", "OUTPUT", "1", "-j", &self.chain_name])
                .status()
                .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        }

        Ok(())
    }

    fn add_iptables_rule(&self, ip: &IpAddr) -> Result<(), BlockerError> {
        let ip_str = ip.to_string();

        // Block outbound to this IP
        let out_exists = Command::new("iptables")
            .args(["-C", &self.chain_name, "-d", &ip_str, "-j", "DROP"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !out_exists {
            Command::new("iptables")
                .args(["-A", &self.chain_name, "-d", &ip_str, "-j", "DROP"])
                .status()
                .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        }

        // Block inbound from this IP
        let in_exists = Command::new("iptables")
            .args(["-C", &self.chain_name, "-s", &ip_str, "-j", "DROP"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !in_exists {
            Command::new("iptables")
                .args(["-A", &self.chain_name, "-s", &ip_str, "-j", "DROP"])
                .status()
                .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        }

        info!(ip = %ip, "iptables DROP rules installed (IN + OUT)");
        Ok(())
    }

    fn remove_iptables_rule(&self, ip: &IpAddr) -> Result<(), BlockerError> {
        let ip_str = ip.to_string();

        let _ = Command::new("iptables")
            .args(["-D", &self.chain_name, "-d", &ip_str, "-j", "DROP"])
            .status();

        let _ = Command::new("iptables")
            .args(["-D", &self.chain_name, "-s", &ip_str, "-j", "DROP"])
            .status();

        info!(ip = %ip, "iptables DROP rules removed");
        Ok(())
    }

    // ── Core block logic ──────────────────────────────────────────────────────

    fn do_block(&self, ip: IpAddr, duration: Option<Duration>) -> Result<String, BlockerError> {
        self.ensure_chain()?;

        let rule_id = format!(
            "rubix-{}-{}",
            ip,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        // Check already blocked
        {
            let rules = self.rules.lock()
                .map_err(|_| BlockerError::IptablesError("Lock poisoned".into()))?;
            if rules.contains_key(&ip) {
                info!(ip = %ip, "Already blocked — skipping duplicate");
                return Ok(rule_id);
            }
        }

        self.add_iptables_rule(&ip)?;

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
            .map_err(|_| BlockerError::IptablesError("Lock poisoned".into()))?
            .insert(ip, ActiveRule { block_rule: rule, permanent });

        if permanent {
            info!(ip = %ip, "Permanently blocked via iptables");
        } else {
            info!(
                ip = %ip,
                secs = duration.unwrap_or_default().as_secs(),
                "Timed iptables block installed"
            );
        }

        Ok(rule_id)
    }

    // ── Background expiry task ────────────────────────────────────────────────

    fn start_expiry_task(&self) {
        let rules      = self.rules.clone();
        let chain_name = self.chain_name.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let now = SystemTime::now();
                let mut expired: Vec<IpAddr> = Vec::new();

                if let Ok(guard) = rules.lock() {
                    for (ip, active) in guard.iter() {
                        if active.permanent { continue; }
                        if let Some(exp) = active.block_rule.expires_at {
                            if now >= exp {
                                expired.push(*ip);
                            }
                        }
                    }
                }

                for ip in expired {
                    let ip_str = ip.to_string();
                    let _ = Command::new("iptables")
                        .args(["-D", &chain_name, "-d", &ip_str, "-j", "DROP"])
                        .status();
                    let _ = Command::new("iptables")
                        .args(["-D", &chain_name, "-s", &ip_str, "-j", "DROP"])
                        .status();

                    if let Ok(mut guard) = rules.lock() {
                        guard.remove(&ip);
                    }
                    info!(ip = %ip, "Timed block expired — iptables rules removed");
                }
            }
        });
    }
}

impl Default for LinuxBlocker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Blocker for LinuxBlocker {
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError> {
        self.do_block(ip, None)
    }

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
                .map_err(|_| BlockerError::IptablesError("Lock poisoned".into()))?;
            rules.remove(&ip).is_some()
        };

        if existed {
            self.remove_iptables_rule(&ip)?;
            info!(ip = %ip, "Manually unblocked");
            Ok(true)
        } else {
            warn!(ip = %ip, "Unblock requested but IP was not tracked");
            Ok(false)
        }
    }

    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        Ok(self.rules.lock()
            .map_err(|_| BlockerError::IptablesError("Lock poisoned".into()))?
            .contains_key(ip))
    }

    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        let rules = self.rules.lock()
            .map_err(|_| BlockerError::IptablesError("Lock poisoned".into()))?;

        let mut list: Vec<BlockRule> = rules
            .values()
            .map(|a| a.block_rule.clone())
            .collect();

        list.sort_by(|a, b| {
            let a_perm = a.expires_at.is_none();
            let b_perm = b.expires_at.is_none();
            b_perm.cmp(&a_perm).then(a.created_at.cmp(&b.created_at))
        });

        Ok(list)
    }

    async fn cleanup(&self) -> Result<(), BlockerError> {
        info!("Cleaning up iptables chain: RUBIX");

        let _ = Command::new("iptables").args(["-F", "RUBIX"]).status();
        let _ = Command::new("iptables").args(["-D", "INPUT",  "-j", "RUBIX"]).status();
        let _ = Command::new("iptables").args(["-D", "OUTPUT", "-j", "RUBIX"]).status();
        let _ = Command::new("iptables").args(["-X", "RUBIX"]).status();

        self.rules.lock()
            .map_err(|_| BlockerError::IptablesError("Lock poisoned".into()))?
            .clear();

        info!("iptables cleanup complete");
        Ok(())
    }
}