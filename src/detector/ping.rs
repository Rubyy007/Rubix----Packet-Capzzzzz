//! Ping and ICMP sweep detection

use std::net::IpAddr;
use super::{ThreatEvent, ThreatKind};
use super::tracker::{ThreatTracker, PING_THRESHOLD};
use std::time::Instant;

pub struct PingDetector;

impl PingDetector {
    /// Analyze an ICMP packet and return threat events if detected
    #[inline]
    pub fn analyze(
        tracker: &mut ThreatTracker,
        src_ip:  IpAddr,
        is_echo_request: bool,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let now         = Instant::now();

        let state = tracker.get_or_create(src_ip);
        state.last_seen   = now;
        state.total_packets += 1;

        if !is_echo_request {
            return threats; // Only care about echo requests
        }

        state.icmp_count += 1;
        state.icmp_times.push_back(now);
        state.icmp_count += 1;

        // ── Ping sweep detection ───────────────────────────────────────────────
        // Multiple ICMP echo requests from same IP within window
        if state.icmp_times.len() >= PING_THRESHOLD
            && !state.already_alerted("ping_sweep")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::PingSweep,
                format!(
                    "{} ICMP echo requests in {}s window",
                    state.icmp_times.len(),
                    super::tracker::TRACK_WINDOW_SECS,
                ),
            ));
        }

        // ── Ping flood detection ───────────────────────────────────────────────
        // High rate ICMP — more than 50 in window
        if state.icmp_times.len() >= 50
            && !state.already_alerted("ping_flood")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::PingFlood,
                format!(
                    "FLOOD: {} ICMP packets/{}s from {}",
                    state.icmp_times.len(),
                    super::tracker::TRACK_WINDOW_SECS,
                    src_ip,
                ),
            ));
        }

        threats
    }
}