// src/detector/ping.rs
//! ICMP ping sweep and flood detection — zero-allocation hot path.
//!
//! Two distinct threats:
//!
//! PingFlood  — high rate of ICMP echo requests from one IP.
//!              Threshold: PING_THRESHOLD (default 8 in the tracking window).
//!              Cooldown:  10 s (short — ongoing floods should keep alerting).
//!
//! PingSweep  — moderate rate of ICMP echo requests from an untrusted IP.
//!              Threshold: same as PingFlood but with separate suppression key.
//!              Cooldown:  30 s.
//!
//! Why separate thresholds for the same count?
//!   A flood is characterised by *rate* (many ICMP in a short window).
//!   A sweep is characterised by *intent* (any ICMP from an untrusted source
//!   hitting multiple hosts, typically ingress).  In practice, with a single-
//!   host detector (which this is), we can only detect the sweep by volume,
//!   so the threshold is the same — but the severity, cooldown, and logging
//!   message differ.
//!
//! Trusted-process outbound ICMP is not suppressed completely (ping is a
//! legitimate diagnostic tool) but gets a 5× higher flood threshold.

use std::net::IpAddr;
use std::time::Instant;

use super::{AlertKey, ThreatEvent, ThreatKind};
use super::tracker::{
    ThreatTracker, is_whitelisted, is_highly_trusted_process, is_medium_trust_process,
    PING_THRESHOLD,
};

// ── Static detail strings — zero allocation ───────────────────────────────────

static DETAIL_SWEEP: &str = "ICMP echo sweep — host discovery scan";
static DETAIL_FLOOD: &str = "ICMP echo flood — potential DoS";

// ── Multipliers ───────────────────────────────────────────────────────────────

const TRUSTED_FLOOD_MULT:  u32 = 5;
const MEDIUM_FLOOD_MULT:   u32 = 3;

// ── PingDetector ─────────────────────────────────────────────────────────────

pub struct PingDetector;

impl PingDetector {
    /// ICMP echo analysis — hot path.
    ///
    /// Typical cost: ~12 ns (whitelist / non-echo reject).
    /// Full path (no alert): ~45 ns.
    /// Alert path: ~65 ns (static string, no format!).
    #[inline(always)]
    pub fn analyze(
        tracker:         &mut ThreatTracker,
        src_ip:          IpAddr,
        is_echo_request: bool,
        proc_name:       Option<&str>,
        is_ingress:      bool,
    ) -> Option<ThreatEvent> {
        // ── Fast rejects ─────────────────────────────────────────────────────
        if !is_echo_request {
            return None;
        }
        if is_whitelisted(src_ip) {
            return None;
        }

        // ── Trust level and threshold scaling ─────────────────────────────────
        let (is_high_trust, flood_threshold) = match proc_name {
            Some(name) if is_highly_trusted_process(name) => {
                (true, PING_THRESHOLD * TRUSTED_FLOOD_MULT)
            }
            Some(name) if is_medium_trust_process(name) => {
                (false, PING_THRESHOLD * MEDIUM_FLOOD_MULT)
            }
            _ => (false, PING_THRESHOLD),
        };

        // Trusted outbound pings (e.g. a browser doing connectivity checks)
        // still get sweep detection if they're inbound — something claims to
        // be a browser but is sending ICMP to us, which is suspicious.
        let check_sweep = !is_high_trust || is_ingress;

        // ── Update per-IP state ───────────────────────────────────────────────
        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.icmp_count += 1;
        state.icmp_times.push(Instant::now());

        if state.total_packets & 0x0F == 0 {
            state.cap_growth();
        }

        let icmp_count = state.icmp_times.len() as u32;

        // ── Flood — always checked, even for trusted processes ────────────────
        // A compromised trusted process (or spoofed proc_name) should still
        // trigger at the higher threshold.
        if icmp_count >= flood_threshold {
            let kind = ThreatKind::PingFlood;
            if !state.is_suppressed(AlertKey::PingFlood, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_FLOOD));
            }
        }

        // ── Sweep — only for untrusted or inbound ─────────────────────────────
        if check_sweep && icmp_count >= PING_THRESHOLD {
            let kind = ThreatKind::PingSweep;
            if !state.is_suppressed(AlertKey::PingSweep, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_SWEEP));
            }
        }

        None
    }
}
