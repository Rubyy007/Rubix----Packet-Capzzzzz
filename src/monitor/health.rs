//! Health checking system

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

pub struct HealthChecker {
    is_healthy: Arc<AtomicBool>,
    last_check: Arc<AtomicBool>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            is_healthy: Arc::new(AtomicBool::new(true)),
            last_check: Arc::new(AtomicBool::new(true)),
        }
    }
    
    pub fn start(&self, check_interval_secs: u64) {
        let is_healthy = self.is_healthy.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(check_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Perform health checks
                let mut healthy = true;
                
                // Check memory
                if let Ok(mem) = MemoryMonitor::get_current_usage() {
                    if mem > 2048 {
                        warn!("High memory usage: {} MB", mem);
                        if mem > 4096 {
                            healthy = false;
                        }
                    }
                }
                
                // Check packet capture
                // (Would need to check capture status)
                
                is_healthy.store(healthy, Ordering::Relaxed);
                
                if !healthy {
                    warn!("Health check failed!");
                }
            }
        });
    }
    
    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::Relaxed)
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}