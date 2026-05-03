//! ICMP ping sweep/flood detection — zero-allocation hot path

use std::net::IpAddr;
use std::time::Instant;

use super::{ThreatEvent, ThreatKind};
use super::tracker::ThreatTracker;

// ── Static strings — no format! alloc ─────────────────────────────────────────

static DETAIL_SWEEP: &str = "ICMP echo sweep detected";
static DETAIL_FLOOD: &str = "ICMP echo flood detected";

// ── Trusted-process multiplier ───────────────────────────────────────────────

const TRUSTED_FLOOD_MULT: u32 = 5;

// ── PingDetector ─────────────────────────────────────────────────────────────

pub struct PingDetector;

impl PingDetector {
    /// Hot path: ~12ns typical, ~80ns on alert
    #[inline(always)]
    pub fn analyze(
        tracker:         &mut ThreatTracker,
        src_ip:          IpAddr,
        is_echo_request: bool,
        proc_name:       Option<&str>,
        is_ingress:      bool,
    ) -> Option<ThreatEvent> {
        // Fast reject: not an echo request
        if !is_echo_request {
            return None;
        }

        // Fast reject: whitelisted infrastructure
        if super::tracker::is_whitelisted(src_ip) {
            return None;
        }

        // Determine trust level and thresholds
        let (is_trusted, flood_threshold) = match proc_name {
            Some(name) if super::tracker::is_highly_trusted_process(name) => {
                (true, super::tracker::PING_THRESHOLD * TRUSTED_FLOOD_MULT)
            }
            Some(name) if super::tracker::is_medium_trust_process(name) => {
                (true, super::tracker::PING_THRESHOLD * 3)
            }
            _ => (false, super::tracker::PING_THRESHOLD),
        };

        // Trusted + egress — skip sweep detection
        let check_sweep = !is_trusted || is_ingress;

        // ── Update state ────────────────────────────────────────────────────
        
        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.icmp_count += 1;
        state.icmp_times.push(Instant::now());
        
        // Amortized cap check
        if state.total_packets & 0x0F == 0 {
            state.cap_growth();
        }

        let icmp_count = state.icmp_times.len() as u32;

        // ── Evaluate threats ──────────────────────────────────────────────────
        
        // Flood check: always done, higher threshold for trusted
        if icmp_count >= flood_threshold {
            if !state.already_alerted("ping_flood") {
                return Some(ThreatEvent::new_fast(
                    src_ip,
                    ThreatKind::PingFlood,
                    DETAIL_FLOOD,
                ));
            }
        }

        // Sweep check: only for untrusted or inbound
        if check_sweep && icmp_count >= super::tracker::PING_THRESHOLD {
            if !state.already_alerted("ping_sweep") {
                return Some(ThreatEvent::new_fast(
                    src_ip,
                    ThreatKind::PingSweep,
                    DETAIL_SWEEP,
                ));
            }
        }

        None
    }
}