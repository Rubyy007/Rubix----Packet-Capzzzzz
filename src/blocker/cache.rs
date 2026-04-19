//! Cache for blocked IPs to avoid repeated iptables calls

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{SystemTime, Duration};
use tracing::debug;

pub struct BlockCache {
    blocked_ips: RwLock<HashSet<IpAddr>>,
    max_size: usize,
}

impl BlockCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            blocked_ips: RwLock::new(HashSet::with_capacity(max_size)),
            max_size,
        }
    }
    
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self.blocked_ips.read() {
            Ok(guard) => guard.contains(ip),
            Err(_) => false,
        }
    }
    
    pub fn insert(&self, ip: IpAddr) -> bool {
        match self.blocked_ips.write() {
            Ok(mut guard) => {
                if guard.len() >= self.max_size {
                    let to_remove: Vec<IpAddr> = guard.iter().take(self.max_size / 2).cloned().collect();
                    for ip in to_remove {
                        guard.remove(&ip);
                    }
                }
                guard.insert(ip)
            }
            Err(_) => false,
        }
    }
    
    pub fn remove(&self, ip: &IpAddr) -> bool {
        match self.blocked_ips.write() {
            Ok(mut guard) => guard.remove(ip),
            Err(_) => false,
        }
    }
    
    pub fn clear(&self) {
        match self.blocked_ips.write() {
            Ok(mut guard) => guard.clear(),
            Err(_) => {}
        }
        debug!("Block cache cleared");
    }
    
    pub fn len(&self) -> usize {
        match self.blocked_ips.read() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }
}