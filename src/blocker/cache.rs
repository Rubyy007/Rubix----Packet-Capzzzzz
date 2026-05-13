// src/blocker/cache.rs
//! In-memory cache for blocked IPs — avoids repeated kernel calls.
//! Uses parking_lot::RwLock for poison-free operation consistent with
//! the rest of the codebase.

#![allow(dead_code)]

use parking_lot::RwLock;
use rustc_hash::FxHashSet;
use std::net::IpAddr;
use tracing::debug;

pub struct BlockCache {
    blocked_ips: RwLock<FxHashSet<IpAddr>>,
    max_size:    usize,
}

impl BlockCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            blocked_ips: RwLock::new(FxHashSet::with_capacity_and_hasher(
                max_size.min(4096),
                Default::default(),
            )),
            max_size,
        }
    }

    #[inline]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.read().contains(ip)
    }

    pub fn insert(&self, ip: IpAddr) -> bool {
        let mut guard = self.blocked_ips.write();
        if guard.len() >= self.max_size {
            // Evict half — deterministic order via collect+drain.
            let to_remove: Vec<IpAddr> = guard
                .iter()
                .take(self.max_size / 2)
                .cloned()
                .collect();
            for evict in &to_remove {
                guard.remove(evict);
            }
            debug!(evicted = to_remove.len(), "Block cache evicted entries");
        }
        guard.insert(ip)
    }

    #[inline]
    pub fn remove(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.write().remove(ip)
    }

    pub fn clear(&self) {
        self.blocked_ips.write().clear();
        debug!("Block cache cleared");
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.blocked_ips.read().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.blocked_ips.read().is_empty()
    }
}