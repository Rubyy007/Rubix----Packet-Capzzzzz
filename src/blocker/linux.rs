//! Linux iptables implementation for kernel-level blocking

use super::{Blocker, BlockRule, BlockerError};
use async_trait::async_trait;
use std::process::Command;
use std::net::IpAddr;
use std::time::SystemTime;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn, debug};  // Removed unused 'error'

pub struct LinuxBlocker {
    chain_name: String,
    rule_counter: AtomicU64,
}

impl LinuxBlocker {
    pub fn new() -> Self {
        Self {
            chain_name: "RUBIX".to_string(),
            rule_counter: AtomicU64::new(0),
        }
    }
    
    fn ensure_chain(&self) -> Result<(), BlockerError> {
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
        
        let input_check = Command::new("iptables")
            .args(["-C", "INPUT", "-j", &self.chain_name])
            .output();
        
        if let Ok(output) = input_check {
            if !output.status.success() {
                Command::new("iptables")
                    .args(["-I", "INPUT", "1", "-j", &self.chain_name])
                    .status()
                    .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
            }
        } else {
            Command::new("iptables")
                .args(["-I", "INPUT", "1", "-j", &self.chain_name])
                .status()
                .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        }
        
        Ok(())
    }
    
    fn generate_rule_id(&self) -> String {
        let count = self.rule_counter.fetch_add(1, Ordering::SeqCst);
        format!("rb-{}", count)
    }
    
    fn rule_exists(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        let ip_str = ip.to_string();
        
        let check_out = Command::new("iptables")
            .args(["-C", &self.chain_name, "-d", &ip_str, "-j", "DROP"])
            .output()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        let check_in = Command::new("iptables")
            .args(["-C", &self.chain_name, "-s", &ip_str, "-j", "DROP"])
            .output()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        Ok(check_out.status.success() || check_in.status.success())
    }
    
    fn add_rule_if_not_exists(&self, direction: &str, ip: &IpAddr) -> Result<bool, BlockerError> {
        let ip_str = ip.to_string();
        
        let check = Command::new("iptables")
            .args(["-C", &self.chain_name, direction, &ip_str, "-j", "DROP"])
            .output()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        if check.status.success() {
            debug!("Rule already exists: {} {} DROP", direction, ip_str);
            return Ok(false);
        }
        
        let status = Command::new("iptables")
            .args(["-A", &self.chain_name, direction, &ip_str, "-j", "DROP"])
            .status()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        Ok(status.success())
    }
}

#[async_trait]
impl Blocker for LinuxBlocker {
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError> {
        self.ensure_chain()?;
        let rule_id = self.generate_rule_id();
        
        if self.rule_exists(&ip)? {
            info!("IP {} already blocked, skipping", ip);
            return Err(BlockerError::RuleExists(format!("IP {} already blocked", ip)));
        }
        
        info!("Adding DROP rules for {}", ip);
        let out_added = self.add_rule_if_not_exists("-d", &ip)?;
        let in_added = self.add_rule_if_not_exists("-s", &ip)?;
        
        if out_added || in_added {
            info!("✅ Blocked {} (both directions)", ip);
            Ok(rule_id)
        } else {
            Err(BlockerError::IptablesError(format!("Failed to block {}", ip)))
        }
    }
    
    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError> {
        let ip_str = ip.to_string();
        info!("Removing DROP rules for {}", ip_str);
        
        let mut any_removed = false;
        
        let status_out = Command::new("iptables")
            .args(["-D", &self.chain_name, "-d", &ip_str, "-j", "DROP"])
            .status()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        if status_out.success() {
            any_removed = true;
        }
        
        let status_in = Command::new("iptables")
            .args(["-D", &self.chain_name, "-s", &ip_str, "-j", "DROP"])
            .status()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        if status_in.success() {
            any_removed = true;
        }
        
        if any_removed {
            info!("✅ Unblocked {}", ip_str);
        } else {
            warn!("IP {} wasn't blocked", ip_str);
        }
        
        Ok(any_removed)
    }
    
    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        self.rule_exists(ip)
    }
    
    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        let output = Command::new("iptables")
            .args(["-L", &self.chain_name, "-n", "--line-numbers"])
            .output()
            .map_err(|e| BlockerError::IptablesError(e.to_string()))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();
        
        for line in output_str.lines() {
            if line.contains("DROP") && (line.contains("-d") || line.contains("-s")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for part in parts {
                    if let Ok(ip) = part.parse::<IpAddr>() {
                        rules.push(BlockRule {
                            id: format!("rule-{}", rules.len()),
                            target: ip,
                            created_at: SystemTime::now(),
                            expires_at: None,
                            reason: "Blocked by RUBIX".to_string(),
                        });
                        break;
                    }
                }
            }
        }
        
        Ok(rules)
    }
    
    async fn cleanup(&self) -> Result<(), BlockerError> {
        info!("Cleaning up iptables rules...");
        
        let _ = Command::new("iptables")
            .args(["-F", &self.chain_name])
            .status();
        
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-j", &self.chain_name])
            .status();
        
        let _ = Command::new("iptables")
            .args(["-X", &self.chain_name])
            .status();
        
        info!("✅ Cleanup complete");
        Ok(())
    }
}

impl Default for LinuxBlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LinuxBlocker {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}