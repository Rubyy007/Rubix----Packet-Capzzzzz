//! Automatic rule cleanup for expired blocks

use super::{Blocker, BlockRule};
use std::time::{SystemTime, Duration};
use std::sync::Arc;
use tokio::time;
use tracing::{info, debug, error};

pub struct RuleCleaner {
    blocker: Arc<dyn Blocker + Send + Sync>,
    cleanup_interval: Duration,
    rule_timeout: Duration,
}

impl RuleCleaner {
    pub fn new(blocker: Arc<dyn Blocker + Send + Sync>, cleanup_interval: Duration, rule_timeout: Duration) -> Self {
        Self {
            blocker,
            cleanup_interval,
            rule_timeout,
        }
    }
    
    pub fn start(&self) {
        let blocker = self.blocker.clone();
        let cleanup_interval = self.cleanup_interval;
        let rule_timeout = self.rule_timeout;
        
        tokio::spawn(async move {
            let mut interval = time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                match blocker.list_rules().await {
                    Ok(rules) => {
                        let now = SystemTime::now();
                        let mut expired_ips = Vec::new();
                        
                        for rule in rules {
                            let is_expired = if let Some(expires_at) = rule.expires_at {
                                now > expires_at
                            } else {
                                now.duration_since(rule.created_at)
                                    .unwrap_or(Duration::from_secs(0)) > rule_timeout
                            };
                            
                            if is_expired {
                                expired_ips.push(rule.target);
                            }
                        }
                        
                        for ip in expired_ips.iter() {
                            debug!("Cleaning up expired rule for {}", ip);
                            if let Err(e) = blocker.unblock_ip(*ip).await {
                                error!("Failed to cleanup rule for {}: {}", ip, e);
                            }
                        }
                        
                        if !expired_ips.is_empty() {
                            info!("Cleaned up {} expired rules", expired_ips.len());
                        }
                    }
                    Err(e) => {
                        error!("Failed to list rules for cleanup: {}", e);
                    }
                }
            }
        });
    }
}