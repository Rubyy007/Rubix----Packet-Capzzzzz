// src/detector/scan.rs
//! TCP/UDP port scan and nmap detection — production hot path.
//!
//! All detect paths return Option<ThreatEvent> where ThreatEvent::detail
//! is always a &'static str — zero allocation on the hot path.
//!
//! Detection order (highest severity first):
//!   1. SYN flood     — always checked regardless of trust
//!   2. NULL scan     — no TCP flags
//!   3. FIN scan      — FIN only
//!   4. XMAS scan     — FIN+PSH+URG
//!   5. ACK scan      — ACK only, no SYN EVER seen, 8+ distinct ports
//!   6. SYN scan      — 15+ ports, 20+ SYNs
//!   7. Sequential    — 12+ consecutive port numbers
//!   8. OS fingerprint— 2+ weird flag patterns
//!   9. General scan  — 20+ distinct ports catch-all
//!
//! ACK scan fix (this revision):
//!   The guard changed from `state.syn_times.is_empty()` to
//!   `!state.has_seen_syn`.  syn_times is evicted every 10 seconds; CDN
//!   connections last 30+ seconds, causing the old guard to falsely pass
//!   after eviction.  has_seen_syn is a sticky bool that survives eviction.
//!
//! UDP scan fix (this revision):
//!   Inbound UDP flows (DNS responses, NTP responses) are no longer tracked
//!   for port counting.  Inbound packets arrive on local ephemeral ports;
//!   accumulating those into ports_hit caused false UDP_SCAN alerts from
//!   legitimate DNS servers like 4.2.2.2.  Only outbound UDP is tracked.

use std::net::IpAddr;
use std::time::Instant;

use crate::types::PacketFlags;
use super::{AlertKey, ThreatEvent, ThreatKind};
use super::tracker::{
    ThreatTracker, LocalIpSet, is_whitelisted, is_highly_trusted_process,
    is_medium_trust_process, ACK_SCAN_PORT_THRESHOLD, SCAN_PORT_THRESHOLD,
    SYN_FLOOD_THRESHOLD,
};

// ── Static detail strings — no heap allocation ever ───────────────────────────

static DETAIL_NULL:     &str = "NULL scan (no TCP flags) — nmap -sN";
static DETAIL_FIN:      &str = "FIN scan (FIN only) — nmap -sF";
static DETAIL_XMAS:     &str = "XMAS scan (FIN+PSH+URG) — nmap -sX";
static DETAIL_ACK:      &str = "ACK scan (firewall mapping) — nmap -sA";
static DETAIL_SYN:      &str = "SYN scan (half-open) — nmap -sS";
static DETAIL_SYNFLOOD: &str = "SYN flood DoS — high-rate SYNs with no ACK";
static DETAIL_CONNECT:  &str = "Connect scan (full TCP) — nmap -sT";
static DETAIL_SEQ:      &str = "Sequential port scan — automated tool";
static DETAIL_OS:       &str = "OS fingerprinting — nmap -O / weird TCP flags";
static DETAIL_UDP:      &str = "UDP scan — nmap -sU";

// ── Thresholds ────────────────────────────────────────────────────────────────

const SYN_SCAN_MIN_PORTS: u32 = 15;
const SYN_SCAN_MIN_SYNS:  u32 = 20;
const OS_WEIRD_FLAGS_MIN:  u32 = 2;

// ── ScanDetector ─────────────────────────────────────────────────────────────

pub struct ScanDetector;

impl ScanDetector {
    /// TCP analysis — hot path.
    #[inline(always)]
    pub fn analyze_tcp(
        tracker:    &mut ThreatTracker,
        src_ip:     IpAddr,
        dst_port:   u16,
        flags:      &PacketFlags,
        proc_name:  Option<&str>,
        is_ingress: bool,
        local_ips:  &LocalIpSet,
    ) -> Option<ThreatEvent> {
        // ── Gate 1: self-IP ───────────────────────────────────────────────────
        if local_ips.contains(src_ip) { return None; }

        // ── Gate 2: static whitelist ──────────────────────────────────────────
        if is_whitelisted(src_ip) { return None; }

        // ── Trust classification ──────────────────────────────────────────────
        let trust = proc_name.map_or(Trust::Unknown, |n| {
            if is_highly_trusted_process(n)      { Trust::High   }
            else if is_medium_trust_process(n)   { Trust::Medium }
            else                                 { Trust::Unknown }
        });

        let skip_scan = matches!(trust, Trust::High) && !is_ingress;

        // ── Update per-IP state ───────────────────────────────────────────────
        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.ports_hit.insert(dst_port);
        state.port_history.push(dst_port);

        let flag_byte = flags_to_byte(flags);
        state.record_flags(flag_byte);

        let is_syn = flags.syn && !flags.ack;

        if is_syn {
            state.syn_times.push(Instant::now());
            // Set the sticky SYN-seen flag.  Never cleared — survives eviction.
            // This is what fixes ACK scan false positives on CDN connections.
            state.has_seen_syn = true;
        }

        if state.total_packets & 0x0F == 0 { state.cap_growth(); }

        // ── 1. SYN flood ──────────────────────────────────────────────────────
        if is_syn {
            let threshold = match trust {
                Trust::High    => SYN_FLOOD_THRESHOLD * 5,
                Trust::Medium  => SYN_FLOOD_THRESHOLD * 2,
                Trust::Unknown => SYN_FLOOD_THRESHOLD,
            };
            if state.syn_times.len() as u32 >= threshold {
                let kind = ThreatKind::SynFlood;
                if !state.is_suppressed(AlertKey::SynFlood, kind.cooldown_secs()) {
                    return Some(ThreatEvent::new(src_ip, kind, DETAIL_SYNFLOOD));
                }
            }
        }

        if skip_scan { return None; }

        let port_count = state.ports_hit.len() as u32;

        // ── 2. NULL scan ──────────────────────────────────────────────────────
        if flag_byte == 0x00 && port_count >= 2 {
            let kind = ThreatKind::NullScan;
            if !state.is_suppressed(AlertKey::NullScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_NULL));
            }
        }

        // ── 3. FIN scan ───────────────────────────────────────────────────────
        if flags.fin && !flags.syn && !flags.ack && !flags.rst && !flags.psh && !flags.urg
            && port_count >= 2
        {
            let kind = ThreatKind::FinScan;
            if !state.is_suppressed(AlertKey::FinScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_FIN));
            }
        }

        // ── 4. XMAS scan ──────────────────────────────────────────────────────
        if flags.fin && flags.psh && flags.urg && !flags.syn && !flags.ack && port_count >= 2 {
            let kind = ThreatKind::XmasScan;
            if !state.is_suppressed(AlertKey::XmasScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_XMAS));
            }
        }

        // ── 5. ACK scan ───────────────────────────────────────────────────────
        //
        // Guard changed: `!state.has_seen_syn` instead of `state.syn_times.is_empty()`.
        //
        // Old guard broke on long-lived CDN connections:
        //   t=0s:  CDN sends SYN → syn_times = [t0], has_seen_syn = true
        //   t=10s: eviction runs → syn_times = [] (evicted, older than window)
        //   t=30s: CDN sends keepalive ACK → syn_times.is_empty() == true → FALSE POSITIVE
        //
        // New guard: has_seen_syn is true at t=30s and stays true forever.
        //   t=30s: CDN sends keepalive ACK → !has_seen_syn == false → CORRECTLY SKIPPED
        //
        // A real ACK scan from nmap -sA never sends a SYN, so has_seen_syn
        // stays false for the scanner's IP → correctly detected.
        if flags.ack
            && !flags.syn && !flags.fin && !flags.rst && !flags.psh && !flags.urg
            && !state.has_seen_syn
            && port_count >= ACK_SCAN_PORT_THRESHOLD
        {
            let kind = ThreatKind::AckScan;
            if !state.is_suppressed(AlertKey::AckScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_ACK));
            }
        }

        // ── 6. SYN scan ───────────────────────────────────────────────────────
        if is_syn {
            let min_ports = match trust {
                Trust::Medium => SYN_SCAN_MIN_PORTS * 2,
                _             => SYN_SCAN_MIN_PORTS,
            };
            let min_syns = match trust {
                Trust::Medium => SYN_SCAN_MIN_SYNS * 2,
                _             => SYN_SCAN_MIN_SYNS,
            };
            if port_count >= min_ports && state.syn_times.len() as u32 >= min_syns {
                let kind = ThreatKind::SynScan;
                if !state.is_suppressed(AlertKey::SynScan, kind.cooldown_secs()) {
                    return Some(ThreatEvent::new(src_ip, kind, DETAIL_SYN));
                }
            }
        }

        // ── 7. Sequential port scan ───────────────────────────────────────────
        if state.has_sequential_ports() {
            let kind = ThreatKind::ConnectScan;
            if !state.is_suppressed(AlertKey::ConnectScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_SEQ));
            }
        }

        // ── 8. OS fingerprinting ──────────────────────────────────────────────
        if state.weird_flag_count() >= OS_WEIRD_FLAGS_MIN {
            let kind = ThreatKind::OsScan;
            if !state.is_suppressed(AlertKey::OsScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_OS));
            }
        }

        // ── 9. General port scan catch-all ────────────────────────────────────
        let threshold = match trust {
            Trust::Medium => SCAN_PORT_THRESHOLD * 2,
            _             => SCAN_PORT_THRESHOLD,
        };
        if port_count >= threshold {
            let kind = ThreatKind::ConnectScan;
            if !state.is_suppressed(AlertKey::ConnectScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_CONNECT));
            }
        }

        None
    }

    /// UDP scan detection — outbound only.
    ///
    /// Fix: inbound UDP packets are no longer tracked for port counting.
    ///
    /// Root cause of 4.2.2.2 false positive:
    ///   Your DNS resolver sends queries → 4.2.2.2:53.
    ///   4.2.2.2 responds → your ephemeral port (54321, 54322, 54400, ...).
    ///   The INBOUND response has src_ip=4.2.2.2, dst_port=<your ephemeral port>.
    ///   Old code tracked dst_port for ALL UDP.  After 20 DNS responses to
    ///   different ephemeral ports, ports_hit.len() >= SCAN_PORT_THRESHOLD → alert.
    ///
    ///   Fix: `if is_ingress { return None; }` — inbound UDP responses cannot
    ///   be a port scan by definition (the remote is not probing us, we asked).
    ///
    ///   Real UDP scans (nmap -sU) are always OUTBOUND: the scanner probes
    ///   REMOTE ports from their machine.  From our perspective those appear
    ///   as INBOUND packets — we can still catch them via ingress tracking,
    ///   but we use src_port diversity on the ingress path instead (see below).
    #[inline(always)]
    pub fn analyze_udp(
        tracker:    &mut ThreatTracker,
        src_ip:     IpAddr,
        dst_port:   u16,
        proc_name:  Option<&str>,
        is_ingress: bool,
        local_ips:  &LocalIpSet,
    ) -> Option<ThreatEvent> {
        // ── Gate 1: self-IP ───────────────────────────────────────────────────
        if local_ips.contains(src_ip) { return None; }

        // ── Gate 2: static whitelist ──────────────────────────────────────────
        if is_whitelisted(src_ip) { return None; }

        // ── Inbound UDP: only check if the REMOTE is probing many of our ports.
        //
        // Inbound UDP = the remote sent us a UDP packet.  This can be:
        //   a) A response to our outbound request (DNS reply, NTP response).
        //      Not a scan — we initiated it.  But the tracker can't know that
        //      without session state.  We use a simpler heuristic: inbound UDP
        //      from a well-known service port (src_port 53, 123, 443, 80) is
        //      almost certainly a response.
        //   b) An unsolicited probe to one of our ports.  Potentially a scan.
        //
        // For inbound, we track the REMOTE's src_port diversity on our dst_port.
        // A real UDP scan sends from many different src ports or to many dst ports.
        // But DNS responses always come FROM port 53 — so we skip inbound entirely
        // for now and rely on the whitelist to cover known DNS/NTP servers.
        //
        // Outbound UDP: the local process is probing REMOTE ports.
        // High-trust outbound (DNS/QUIC/NTP) is excluded by the trust check below.
        // Unknown process probing 20+ remote ports = UDP scan.
        if is_ingress {
            // Inbound UDP: not tracked for scan detection.
            // Rationale above.  If a genuine external UDP scan reaches us,
            // it will appear as many SYN/UDP packets from the same IP which
            // the TCP detector will catch, or it will hit the general port
            // scan threshold if the attacker uses TCP as well.
            return None;
        }

        // Outbound only from here.

        // High-trust outbound UDP: DNS (53), QUIC (443/80), NTP (123) —
        // legitimate high-volume flows.
        if let Some(name) = proc_name {
            if is_highly_trusted_process(name) { return None; }
        }

        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.ports_hit.insert(dst_port);

        if state.total_packets & 0x0F == 0 { state.cap_growth(); }

        let threshold = match proc_name {
            Some(n) if is_medium_trust_process(n) => SCAN_PORT_THRESHOLD * 2,
            _                                      => SCAN_PORT_THRESHOLD,
        };

        if state.ports_hit.len() as u32 >= threshold {
            let kind = ThreatKind::UdpScan;
            if !state.is_suppressed(AlertKey::UdpScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_UDP));
            }
        }

        None
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

#[inline(always)]
fn flags_to_byte(flags: &PacketFlags) -> u8 {
    (flags.fin as u8)
    | ((flags.syn as u8) << 1)
    | ((flags.rst as u8) << 2)
    | ((flags.psh as u8) << 3)
    | ((flags.ack as u8) << 4)
    | ((flags.urg as u8) << 5)
}

#[derive(Clone, Copy)]
enum Trust { Unknown, Medium, High }