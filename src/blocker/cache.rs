// src/blocker/cache.rs
//! In-memory cache for blocked IPs — avoids repeated kernel calls

#![allow(dead_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;
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
        self.blocked_ips.read()
            .map(|g| g.contains(ip))
            .unwrap_or(false)
    }

    pub fn insert(&self, ip: IpAddr) -> bool {
        match self.blocked_ips.write() {
            Ok(mut guard) => {
                if guard.len() >= self.max_size {
                    let to_remove: Vec<IpAddr> = guard
                        .iter()
                        .take(self.max_size / 2)
                        .cloned()
                        .collect();
                    for ip in to_remove {
                        guard.remove(&ip);
                    }
                    debug!("Block cache evicted {} entries", self.max_size / 2);
                }
                guard.insert(ip)
            }
            Err(_) => false,
        }
    }

    pub fn remove(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.write()
            .map(|mut g| g.remove(ip))
            .unwrap_or(false)
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.blocked_ips.write() {
            g.clear();
        }
        debug!("Block cache cleared");
    }

    pub fn len(&self) -> usize {
        self.blocked_ips.read()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}