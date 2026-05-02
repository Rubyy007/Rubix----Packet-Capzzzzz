// src/blocker/cleaner.rs
//! Background rule cleaner — removes expired timed blocks

#![allow(dead_code)]

use super::Blocker;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info};

pub struct RuleCleaner {
    blocker: Arc<dyn Blocker + Send + Sync>,
    cleanup_interval: Duration,
}

impl RuleCleaner {
    pub fn new(
        blocker: Arc<dyn Blocker + Send + Sync>,
        cleanup_interval: Duration,
    ) -> Self {
        Self { blocker, cleanup_interval }
    }

    pub fn start(&self) {
        let blocker          = self.blocker.clone();
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = time::interval(cleanup_interval);

            loop {
                interval.tick().await;

                match blocker.list_rules().await {
                    Ok(rules) => {
                        let expired: Vec<_> = rules
                            .iter()
                            .filter(|r| {
                                r.expires_at
                                    .map(|exp| std::time::SystemTime::now() >= exp)
                                    .unwrap_or(false)
                            })
                            .map(|r| r.target)
                            .collect();

                        for ip in &expired {
                            debug!(ip = %ip, "Cleaning up expired rule");
                            if let Err(e) = blocker.unblock_ip(*ip).await {
                                error!(ip = %ip, error = %e, "Failed to cleanup rule");
                            }
                        }

                        if !expired.is_empty() {
                            info!(count = expired.len(), "Cleaned up expired block rules");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to list rules for cleanup");
                    }
                }
            }
        });
    }
}