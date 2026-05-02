//! Policy module - network security policy engine

mod engine;
mod reloader;
mod watcher;

// Re-export from engine - RuleAction is defined in engine.rs
pub use engine::{PolicyEngine, RuleAction};
pub use reloader::PolicyReloader;
// pub use watcher::PolicyWatcher; // Uncomment when implemented

// Shared types used across policy module
use std::net::IpAddr;
use ipnet::IpNet;

/// IP address or network range
#[derive(Debug, Clone)]
pub enum IpNetOrAddr {
    Single(IpAddr),
    Network(IpNet),
}

impl IpNetOrAddr {
    /// Check if given IP matches this address/network
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            IpNetOrAddr::Single(addr) => addr == ip,
            IpNetOrAddr::Network(net) => net.contains(ip),
        }
    }
    
    /// Parse from string (IP or CIDR notation)
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.contains('/') {
            match s.parse::<IpNet>() {
                Ok(net) => Ok(IpNetOrAddr::Network(net)),
                Err(e) => Err(format!("Invalid CIDR {}: {}", s, e)),
            }
        } else {
            match s.parse::<IpAddr>() {
                Ok(addr) => Ok(IpNetOrAddr::Single(addr)),
                Err(e) => Err(format!("Invalid IP {}: {}", s, e)),
            }
        }
    }
}

/// Conditions for matching a rule
#[derive(Debug, Clone)]
pub struct RuleConditions {
    pub src_ips: Option<Vec<IpNetOrAddr>>,
    pub dst_ips: Option<Vec<IpNetOrAddr>>,
    pub src_ports: Option<Vec<u16>>,
    pub dst_ports: Option<Vec<u16>>,
    pub protocols: Option<Vec<String>>,
}

impl Default for RuleConditions {
    fn default() -> Self {
        Self {
            src_ips: None,
            dst_ips: None,
            src_ports: None,
            dst_ports: None,
            protocols: None,
        }
    }
}

/// Security rule definition
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Action to take when rule matches (re-exported from engine)
    pub action: RuleAction,
    pub conditions: RuleConditions,
}