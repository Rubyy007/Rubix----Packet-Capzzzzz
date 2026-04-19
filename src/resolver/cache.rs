//! DNS resolution cache

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

pub struct DnsCache {
    cache: RwLock<HashMap<String, CachedEntry>>,
    ttl_secs: u64,
    max_size: usize,
}

struct CachedEntry {
    ips: Vec<IpAddr>,
    expires_at: u64,
}

impl DnsCache {
    pub fn new(ttl_secs: u64, max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_size)),
            ttl_secs,
            max_size,
        }
    }
    
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let cache = self.cache.read().unwrap();
        
        if let Some(entry) = cache.get(domain) {
            if entry.expires_at > now {
                return Some(entry.ips.clone());
            }
        }
        
        None
    }
    
    pub fn set(&self, domain: &str, ips: Vec<IpAddr>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut cache = self.cache.write().unwrap();
        
        // Evict oldest if at capacity
        if cache.len() >= self.max_size {
            if let Some(oldest) = cache.keys().next().cloned() {
                cache.remove(&oldest);
            }
        }
        
        cache.insert(domain.to_string(), CachedEntry {
            ips,
            expires_at: now + self.ttl_secs,
        });
    }
    
    pub fn clear(&self) {
        self.cache.write().unwrap().clear();
    }
    
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }
}