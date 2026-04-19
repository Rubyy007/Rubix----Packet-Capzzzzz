//! Packet drop handling and statistics

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::info;

pub struct PacketDrop {
    total_dropped: AtomicU64,
    drops_by_ip: RwLock<HashMap<IpAddr, u64>>,
    last_reset: RwLock<Instant>,
    reset_interval: Duration,
}

impl PacketDrop {
    pub fn new(reset_interval_secs: u64) -> Self {
        Self {
            total_dropped: AtomicU64::new(0),
            drops_by_ip: RwLock::new(HashMap::new()),
            last_reset: RwLock::new(Instant::now()),
            reset_interval: Duration::from_secs(reset_interval_secs),
        }
    }
    
    pub fn record_drop(&self, ip: IpAddr) {
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
        
        let mut drops = self.drops_by_ip.write().unwrap();
        *drops.entry(ip).or_insert(0) += 1;
        
        // Check if we should reset stats
        let mut last = self.last_reset.write().unwrap();
        if last.elapsed() >= self.reset_interval {
            *last = Instant::now();
            drops.clear();
            info!("Packet drop statistics reset");
        }
    }
    
    pub fn get_total_dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }
    
    pub fn get_drops_by_ip(&self) -> HashMap<IpAddr, u64> {
        self.drops_by_ip.read().unwrap().clone()
    }
    
    pub fn get_top_blocked(&self, count: usize) -> Vec<(IpAddr, u64)> {
        let mut drops: Vec<(IpAddr, u64)> = self.drops_by_ip.read()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        
        drops.sort_by(|a, b| b.1.cmp(&a.1));
        drops.truncate(count);
        drops
    }
}