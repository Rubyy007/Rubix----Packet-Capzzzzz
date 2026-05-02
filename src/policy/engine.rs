//! Rule evaluation engine

use super::Rule;
use crate::types::Packet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;
use tracing::{info, error, debug};

/// Action to take when a rule matches
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
    Alert,
}

#[derive(Debug, Default, Clone)]
pub struct EngineStats {
    pub total_evaluations: u64,
    pub cache_hits: u64,
    pub blocks: u64,
    pub allows: u64,
    pub alerts: u64,
}

pub struct PolicyEngine {
    rules: RwLock<Vec<Rule>>,
    blocked_ips: RwLock<HashSet<IpAddr>>,
    stats: RwLock<EngineStats>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            blocked_ips: RwLock::new(HashSet::new()),
            stats: RwLock::new(EngineStats::default()),
        }
    }
    
    pub fn add_rule(&self, rule: Rule) {
        if rule.enabled {
            match self.rules.write() {
                Ok(mut rules) => {
                    rules.push(rule);
                    debug!("Added rule, total rules: {}", rules.len());
                }
                Err(e) => error!("Rules lock poisoned, cannot add rule: {}", e),
            }
        }
    }
    
    pub fn load_rules(&self, rules: Vec<Rule>) {
        let enabled_rules: Vec<Rule> = rules.into_iter()
            .filter(|r| r.enabled)
            .collect();
        
        match self.rules.write() {
            Ok(mut guard) => {
                *guard = enabled_rules;
                info!("Loaded {} policy rules", guard.len());
            }
            Err(e) => error!("Failed to load rules, lock poisoned: {}", e),
        }
    }
    
    pub fn evaluate(&self, packet: &Packet) -> RuleAction {
        // Update stats
        {
            let mut stats = match self.stats.write() {
                Ok(s) => s,
                Err(e) => {
                    error!("Stats lock poisoned: {}", e);
                    return RuleAction::Allow;
                }
            };
            stats.total_evaluations += 1;
        }
        
        // Check blocked IPs first
        let is_blocked = match self.blocked_ips.read() {
            Ok(guard) => guard.contains(&packet.dst_ip),
            Err(e) => {
                error!("Blocked IPs lock poisoned: {}", e);
                false
            }
        };
        
        if is_blocked {
            debug!("IP {} is in block list", packet.dst_ip);
            let mut stats = match self.stats.write() {
                Ok(s) => s,
                Err(e) => {
                    error!("Stats lock poisoned: {}", e);
                    return RuleAction::Block;
                }
            };
            stats.blocks += 1;
            return RuleAction::Block;
        }
        
        // Evaluate rules
        let rules = match self.rules.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Rules lock poisoned: {}", e);
                return RuleAction::Allow;
            }
        };
        
        for rule in rules.iter() {
            if self.matches_rule(packet, rule) {
                debug!("Packet matched rule: {} ({}) -> {:?}", rule.id, rule.name, rule.action);
                
                let mut stats = match self.stats.write() {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Stats lock poisoned: {}", e);
                        return rule.action.clone();
                    }
                };
                
                match rule.action {
                    RuleAction::Block => stats.blocks += 1,
                    RuleAction::Alert => stats.alerts += 1,
                    RuleAction::Allow => stats.allows += 1,
                }
                
                return rule.action.clone();
            }
        }
        
        // Default action: Allow
        {
            let mut stats = match self.stats.write() {
                Ok(s) => s,
                Err(e) => {
                    error!("Stats lock poisoned: {}", e);
                    return RuleAction::Allow;
                }
            };
            stats.allows += 1;
        }
        
        RuleAction::Allow
    }
    
    fn matches_rule(&self, packet: &Packet, rule: &Rule) -> bool {
        let cond = &rule.conditions;
        
        if let Some(src_ips) = &cond.src_ips {
            if !src_ips.iter().any(|ip| ip.matches(&packet.src_ip)) {
                return false;
            }
        }
        
        if let Some(dst_ips) = &cond.dst_ips {
            if !dst_ips.iter().any(|ip| ip.matches(&packet.dst_ip)) {
                return false;
            }
        }
        
        if let Some(src_ports) = &cond.src_ports {
            if !src_ports.contains(&packet.src_port) {
                return false;
            }
        }
        
        if let Some(dst_ports) = &cond.dst_ports {
            if !dst_ports.contains(&packet.dst_port) {
                return false;
            }
        }
        
        if let Some(protocols) = &cond.protocols {
            let proto_str = packet.protocol.as_str();
            if !protocols.iter().any(|p| p.eq_ignore_ascii_case(proto_str)) {
                return false;
            }
        }
        
        true
    }
    
    pub fn block_ip(&self, ip: IpAddr) {
        match self.blocked_ips.write() {
            Ok(mut guard) => {
                guard.insert(ip);
                info!("Added IP to block list: {}", ip);
            }
            Err(e) => error!("Cannot block IP, lock poisoned: {}", e),
        }
    }
    
    pub fn unblock_ip(&self, ip: &IpAddr) -> bool {
        match self.blocked_ips.write() {
            Ok(mut guard) => {
                let result = guard.remove(ip);
                if result {
                    info!("Removed IP from block list: {}", ip);
                }
                result
            }
            Err(e) => {
                error!("Cannot unblock IP, lock poisoned: {}", e);
                false
            }
        }
    }
    
    pub fn get_rules(&self) -> Vec<Rule> {
        match self.rules.read() {
            Ok(guard) => guard.clone(),
            Err(e) => {
                error!("Cannot get rules, lock poisoned: {}", e);
                Vec::new()
            }
        }
    }
    
    pub fn rule_count(&self) -> usize {
        match self.rules.read() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }
    
    pub fn get_stats(&self) -> EngineStats {
        match self.stats.read() {
            Ok(guard) => guard.clone(),
            Err(_) => EngineStats::default(),
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}