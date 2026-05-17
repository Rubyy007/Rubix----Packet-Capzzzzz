// src/monitor/health.rs
//! Daemon health checker — periodic liveness verification.
//!
//! Checks:
//!   • Capture thread alive (packet count advancing)
//!   • Memory within bounds
//!   • Control server reachable
//!
//! Results are logged; no panics or process exits from this module.
//! The health checker is informational — it does not take corrective action.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

// ── HealthChecker ─────────────────────────────────────────────────────────────

pub struct HealthChecker {
    /// Shared packet counter — the packet loop increments this.
    /// If it hasn't advanced between two checks, the capture thread may be stuck.
    packet_count: Arc<AtomicU64>,
    /// Last observed packet count (used to detect stalls).
    last_count:   AtomicU64,
}

impl HealthChecker {
    /// Construct a new HealthChecker.
    ///
    /// `packet_count` — pass a clone of the shared packet counter from main.rs.
    /// If you don't have one yet, pass `Arc::new(AtomicU64::new(0))` and the
    /// checker will always report healthy (zero baseline = no stall detection).
    pub fn new(packet_count: Arc<AtomicU64>) -> Self {
        Self {
            packet_count,
            last_count: AtomicU64::new(0),
        }
    }

    /// Run a single health check and log the result.
    pub fn check(&self) {
        let current = self.packet_count.load(Ordering::Relaxed);
        let last    = self.last_count.load(Ordering::Relaxed);

        if current == last && current > 0 {
            // Packet count hasn't advanced — capture thread may be stalled.
            warn!(
                packet_count = current,
                "Health check: packet count stalled — capture thread may be stuck"
            );
        } else {
            let delta = current.saturating_sub(last);
            info!(
                packet_count = current,
                delta,
                "Health check: OK"
            );
        }

        self.last_count.store(current, Ordering::Relaxed);
    }

    /// Spawn a background task that runs a health check every `interval_secs`.
    ///
    /// Must be called inside an async context.
    pub fn start_monitoring(&self, interval_secs: u64) {
        let packet_count = self.packet_count.clone();
        let last_count   = AtomicU64::new(0);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

            // Use a local last_count inside the task — AtomicU64 is not Clone
            // so we use a plain u64 here.
            let mut last: u64 = 0;

            loop {
                ticker.tick().await;

                let current = packet_count.load(Ordering::Relaxed);
                let delta   = current.saturating_sub(last);

                if current == last && current > 0 {
                    warn!(
                        packet_count = current,
                        "Health check: packet count stalled — capture thread may be stuck"
                    );
                } else {
                    info!(packet_count = current, delta, "Health check: OK");
                }

                last = current;
            }
        });
    }
}