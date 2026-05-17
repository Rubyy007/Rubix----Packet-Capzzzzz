// src/detector/ping.rs
//! ICMP ping sweep and flood detection — zero-allocation hot path.
//!
//! Two distinct threats:
//!
//! PingFlood  — high rate of ICMP echo requests from one IP in the window.
//!              Threshold: PING_THRESHOLD (now 5 — lowered from 8).
//!              Cooldown:  10 s.
//!
//! PingSweep  — any ICMP echo requests from an untrusted external IP.
//!              Threshold: PING_THRESHOLD with separate suppression key.
//!              Cooldown:  30 s.
//!
//! PING_THRESHOLD = 5 rationale:
//!   Default `ping -n 4` / `ping -c 4` sends exactly 4 packets.
//!   Old threshold of 8 meant a normal ping between two devices was never
//!   caught.  5 triggers on a second ping run or any automated tool.
//!
//! ICMPv6 caller note (main.rs):
//!   This function receives `is_echo_request` from the caller.  The caller
//!   MUST pass true only for ICMPv6 type 128 (Echo Request).  ICMPv6
//!   Neighbor Discovery packets (type 135/136) and DAD packets (src = ::)
//!   must NOT set is_echo_request=true.  If the caller passes all ICMPv6
//!   as is_echo_request=true, DAD packets will reach this function with
//!   src_ip = :: — those are now caught by is_whitelisted() which returns
//!   true for :: (IPv6 unspecified address per RFC 4861).
//!
//! Ingress-only sweep detection:
//!   Outbound ICMP from this machine (ping 8.8.8.8) has src_ip = our IP
//!   and is rejected by local_ips.contains() before reaching sweep logic.
//!   Inbound ICMP (another machine pinging us) has src_ip = remote IP and
//!   is_ingress = true — this is what we want to detect.
//!   The check_sweep flag ensures we only alert on ingress pings from
//!   untrusted sources.

use std::net::IpAddr;
use std::time::Instant;

use super::{AlertKey, ThreatEvent, ThreatKind};
use super::tracker::{
    ThreatTracker, LocalIpSet, is_whitelisted, is_highly_trusted_process,
    is_medium_trust_process, PING_THRESHOLD,
};

static DETAIL_SWEEP: &str = "ICMP echo sweep — host discovery scan";
static DETAIL_FLOOD: &str = "ICMP echo flood — potential DoS";

const TRUSTED_FLOOD_MULT: u32 = 5;
const MEDIUM_FLOOD_MULT:  u32 = 3;

pub struct PingDetector;

impl PingDetector {
    /// ICMP/ICMPv6 echo analysis — hot path.
    ///
    /// `is_echo_request` — caller must set true ONLY for:
    ///   ICMPv4 type 8  (Echo Request)
    ///   ICMPv6 type 128 (Echo Request)
    ///   NOT for ICMPv6 ND (type 135/136) or DAD packets (src = ::).
    ///
    /// `is_ingress` — true when the packet came FROM an external IP TO us.
    ///   Sweep detection only fires on ingress (someone pinging us).
    ///   Flood detection fires regardless of direction.
    #[inline(always)]
    pub fn analyze(
        tracker:         &mut ThreatTracker,
        src_ip:          IpAddr,
        is_echo_request: bool,
        proc_name:       Option<&str>,
        is_ingress:      bool,
        local_ips:       &LocalIpSet,
    ) -> Option<ThreatEvent> {
        // ── Fast reject: non-echo ICMP (replies, unreachables, ND, etc.) ──────
        if !is_echo_request {
            return None;
        }

        // ── Gate 1: self-IP ───────────────────────────────────────────────────
        // Catches our own outbound pings (src_ip = our interface IP).
        if local_ips.contains(src_ip) {
            return None;
        }

        // ── Gate 2: static whitelist ──────────────────────────────────────────
        // Catches :: (DAD), ::1, fe80::, RFC-1918, CDN ranges.
        // This is the backstop for ICMPv6 DAD false positives even if the
        // caller incorrectly passes is_echo_request=true for DAD packets.
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

        // Sweep detection:
        //   - Always enabled for ingress (someone pinging us from outside).
        //   - Disabled for high-trust outbound (browser connectivity checks).
        //   - For untrusted processes: enabled regardless of direction.
        //
        // Note: outbound pings from our own IP are already rejected by Gate 1
        // (local_ips.contains).  What reaches here is always from an external
        // IP.  is_ingress=true means the external IP is sending to US.
        let check_sweep = !is_high_trust || is_ingress;

        // ── Update per-IP state ───────────────────────────────────────────────
        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.icmp_count += 1;
        state.icmp_times.push(Instant::now());

        if state.total_packets & 0x0F == 0 { state.cap_growth(); }

        let icmp_count = state.icmp_times.len() as u32;

        // ── Flood — checked for all untrusted sources, even outbound ──────────
        if icmp_count >= flood_threshold {
            let kind = ThreatKind::PingFlood;
            if !state.is_suppressed(AlertKey::PingFlood, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_FLOOD));
            }
        }

        // ── Sweep — ingress from untrusted source ─────────────────────────────
        //
        // PING_THRESHOLD = 5 (lowered from 8).
        // Catches: second `ping -n 4` run, or any tool sending 5+ echo requests.
        // Allows:  a single `ping -n 4` (4 packets < 5 threshold).
        if check_sweep && icmp_count >= PING_THRESHOLD {
            let kind = ThreatKind::PingSweep;
            if !state.is_suppressed(AlertKey::PingSweep, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_SWEEP));
            }
        }

        None
    }
}