//! Windows placeholder for blocking (monitor mode only)

use super::{Blocker, BlockRule, BlockerError};
use async_trait::async_trait;
use std::net::IpAddr;
use tracing::{info, warn};

pub struct WindowsBlocker {
    enabled: bool,
}

impl WindowsBlocker {
    pub fn new() -> Self {
        info!("Initializing Windows Blocker (Monitor Mode)");
        info!("Windows does not support kernel-level blocking, running in monitor mode");
        Self {
            enabled: false,
        }
    }
    
    pub fn enable(&mut self) {
        info!("Windows blocking is not available - running in monitor mode only");
        self.enabled = true;
    }
}

#[async_trait]
impl Blocker for WindowsBlocker {
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError> {
        if !self.enabled {
            warn!("Blocking attempted but Windows blocker is disabled (monitor mode)");
            return Ok("monitor-mode".to_string());
        }
        
        warn!("Windows kernel blocking not implemented - would block IP: {}", ip);
        Ok("not-implemented".to_string())
    }
    
    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError> {
        warn!("Windows unblocking not implemented - would unblock IP: {}", ip);
        Ok(false)
    }
    
    async fn is_blocked(&self, _ip: &IpAddr) -> Result<bool, BlockerError> {
        Ok(false)
    }
    
    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        Ok(Vec::new())
    }
    
    async fn cleanup(&self) -> Result<(), BlockerError> {
        info!("Windows cleanup complete (no rules to clean)");
        Ok(())
    }
}

impl Default for WindowsBlocker {
    fn default() -> Self {
        Self::new()
    }
}