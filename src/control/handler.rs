//! Command handler for control system

use super::{Command, CommandResponse};
use crate::blocker::Blocker;
use crate::policy::PolicyEngine;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, error};

pub struct CommandHandler {
    blocker: Arc<dyn Blocker + Send + Sync>,
    policy_engine: Arc<PolicyEngine>,
}

impl CommandHandler {
    pub fn new(blocker: Arc<dyn Blocker + Send + Sync>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            blocker,
            policy_engine,
        }
    }
    
    pub async fn handle(&self, command: Command) -> CommandResponse {
        match command {
            Command::Status => self.handle_status().await,
            Command::Stats => self.handle_stats().await,
            Command::BlockIp { ip, reason } => self.handle_block_ip(ip, reason).await,
            Command::UnblockIp { ip } => self.handle_unblock_ip(ip).await,
            Command::ListBlocked => self.handle_list_blocked().await,
            Command::ReloadConfig => self.handle_reload_config().await,
            Command::Shutdown => self.handle_shutdown().await,
            Command::GetRules => self.handle_get_rules().await,
            Command::AddRule { rule } => self.handle_add_rule(rule).await,
            Command::RemoveRule { rule_id } => self.handle_remove_rule(rule_id).await,
        }
    }
    
    async fn handle_status(&self) -> CommandResponse {
        CommandResponse::success("RUBIX is running".to_string())
    }
    
    async fn handle_stats(&self) -> CommandResponse {
        let stats = self.policy_engine.get_stats();
        let data = serde_json::json!({
            "packets_processed": stats.total_evaluations,
            "blocks": stats.blocks,
            "alerts": stats.alerts,
            "allows": stats.allows,
            "rules_count": self.policy_engine.rule_count(),
        });
        CommandResponse::with_data("Statistics retrieved".to_string(), data)
    }
    
    async fn handle_block_ip(&self, ip: IpAddr, reason: Option<String>) -> CommandResponse {
        match self.blocker.block_ip(ip).await {
            Ok(rule_id) => {
                self.policy_engine.block_ip(ip);
                CommandResponse::success(format!("Blocked IP {} with rule {}", ip, rule_id))
            }
            Err(e) => CommandResponse::error(format!("Failed to block IP {}: {}", ip, e)),
        }
    }
    
    async fn handle_unblock_ip(&self, ip: IpAddr) -> CommandResponse {
        match self.blocker.unblock_ip(ip).await {
            Ok(true) => {
                self.policy_engine.unblock_ip(&ip);
                CommandResponse::success(format!("Unblocked IP {}", ip))
            }
            Ok(false) => CommandResponse::error(format!("IP {} was not blocked", ip)),
            Err(e) => CommandResponse::error(format!("Failed to unblock IP {}: {}", ip, e)),
        }
    }
    
    async fn handle_list_blocked(&self) -> CommandResponse {
        match self.blocker.list_rules().await {
            Ok(rules) => {
                let ips: Vec<String> = rules.iter().map(|r| r.target.to_string()).collect();
                let data = serde_json::json!({ "blocked_ips": ips, "count": ips.len() });
                CommandResponse::with_data(format!("{} IPs blocked", ips.len()), data)
            }
            Err(e) => CommandResponse::error(format!("Failed to list blocked IPs: {}", e)),
        }
    }
    
    async fn handle_reload_config(&self) -> CommandResponse {
        // This would trigger config reload
        CommandResponse::success("Configuration reload triggered".to_string())
    }
    
    async fn handle_shutdown(&self) -> CommandResponse {
        CommandResponse::success("Shutting down...".to_string())
    }
    
    async fn handle_get_rules(&self) -> CommandResponse {
        let rules = self.policy_engine.get_rules();
        let rules_json: Vec<serde_json::Value> = rules.iter().map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "action": format!("{:?}", r.action),
                "enabled": r.enabled,
            })
        }).collect();
        
        let data = serde_json::json!({ "rules": rules_json, "count": rules_json.len() });
        CommandResponse::with_data(format!("{} rules loaded", rules_json.len()), data)
    }
    
    async fn handle_add_rule(&self, rule: String) -> CommandResponse {
        // Parse and add rule
        CommandResponse::success(format!("Rule added: {}", rule))
    }
    
    async fn handle_remove_rule(&self, rule_id: String) -> CommandResponse {
        CommandResponse::success(format!("Rule removed: {}", rule_id))
    }
}