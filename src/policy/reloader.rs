use super::{PolicyEngine, Rule, RuleAction, RuleConditions, IpNetOrAddr};
use std::sync::Arc;
use tracing::{info, warn, debug};
use anyhow::{Result, anyhow};

pub struct PolicyReloader {
    engine: Arc<PolicyEngine>,
    rules_path: String,
}

impl PolicyReloader {
    pub fn new(engine: Arc<PolicyEngine>, rules_path: String) -> Self {
        Self {
            engine,
            rules_path,
        }
    }
    
    pub fn load_initial(&self) -> Result<()> {
        self.load_rules_from_file()
    }
    
    pub fn load_rules_from_file(&self) -> Result<()> {
        let contents = std::fs::read_to_string(&self.rules_path)?;
        let rules_data: Vec<serde_yaml::Value> = serde_yaml::from_str(&contents)?;
        
        let mut rules = Vec::new();
        
        for rule_data in rules_data {
            match self.parse_rule(&rule_data) {
                Ok(Some(rule)) => {
                    debug!("Parsed rule: {} ({})", rule.id, rule.name);
                    rules.push(rule);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to parse rule: {}", e);
                }
            }
        }
        
        info!("Loaded {} rules from {}", rules.len(), self.rules_path);
        self.engine.load_rules(rules);
        
        Ok(())
    }
    
    fn parse_rule(&self, data: &serde_yaml::Value) -> Result<Option<Rule>> {
        let id = match data.get("id") {
            Some(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None => return Err(anyhow!("id must be string")),
            },
            None => return Err(anyhow!("Missing id")),
        };
        
        let name = match data.get("name") {
            Some(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None => return Err(anyhow!("name must be string")),
            },
            None => return Err(anyhow!("Missing name")),
        };
        
        let enabled = data.get("enabled")
            .and_then(|e| e.as_bool())
            .unwrap_or(true);
        
        if !enabled {
            debug!("Rule {} is disabled, skipping", id);
            return Ok(None);
        }
        
        let action_str = match data.get("action") {
            Some(v) => match v.as_str() {
                Some(s) => s,
                None => return Err(anyhow!("action must be string")),
            },
            None => return Err(anyhow!("Missing action")),
        };
        
        let action = match action_str {
            "Allow" => RuleAction::Allow,
            "Block" => RuleAction::Block,
            "Alert" => RuleAction::Alert,
            _ => return Err(anyhow!("Unknown action: {}", action_str)),
        };
        
        let conditions_data = match data.get("conditions") {
            Some(v) => v,
            None => return Err(anyhow!("Missing conditions")),
        };
        
        let mut conditions = RuleConditions::default();
        
        if let Some(src_ips) = conditions_data.get("src_ips").and_then(|v| v.as_sequence()) {
            let mut ips = Vec::new();
            for ip_val in src_ips {
                if let Some(ip_str) = ip_val.as_str() {
                    match IpNetOrAddr::parse(ip_str) {
                        Ok(ip) => ips.push(ip),
                        Err(e) => warn!("Invalid src_ip {} in rule {}: {}", ip_str, id, e),
                    }
                }
            }
            if !ips.is_empty() {
                conditions.src_ips = Some(ips);
            }
        }
        
        if let Some(dst_ips) = conditions_data.get("dst_ips").and_then(|v| v.as_sequence()) {
            let mut ips = Vec::new();
            for ip_val in dst_ips {
                if let Some(ip_str) = ip_val.as_str() {
                    match IpNetOrAddr::parse(ip_str) {
                        Ok(ip) => ips.push(ip),
                        Err(e) => warn!("Invalid dst_ip {} in rule {}: {}", ip_str, id, e),
                    }
                }
            }
            if !ips.is_empty() {
                conditions.dst_ips = Some(ips);
            }
        }
        
        if let Some(src_ports) = conditions_data.get("src_ports").and_then(|v| v.as_sequence()) {
            let mut ports = Vec::new();
            for port_val in src_ports {
                if let Some(port) = port_val.as_u64() {
                    ports.push(port as u16);
                }
            }
            if !ports.is_empty() {
                conditions.src_ports = Some(ports);
            }
        }
        
        if let Some(dst_ports) = conditions_data.get("dst_ports").and_then(|v| v.as_sequence()) {
            let mut ports = Vec::new();
            for port_val in dst_ports {
                if let Some(port) = port_val.as_u64() {
                    ports.push(port as u16);
                }
            }
            if !ports.is_empty() {
                conditions.dst_ports = Some(ports);
            }
        }
        
        if let Some(protocols) = conditions_data.get("protocols").and_then(|v| v.as_sequence()) {
            let mut protos = Vec::new();
            for proto_val in protocols {
                if let Some(proto) = proto_val.as_str() {
                    protos.push(proto.to_string());
                }
            }
            if !protos.is_empty() {
                conditions.protocols = Some(protos);
            }
        }
        
        Ok(Some(Rule {
            id,
            name,
            enabled,
            action,
            conditions,
        }))
    }
    
    pub fn reload(&self) -> Result<()> {
        info!("Reloading policies from {}", self.rules_path);
        self.load_rules_from_file()
    }
}