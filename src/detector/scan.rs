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
//!   5. ACK scan      — ACK only, no SYN history, 8+ distinct ports
//!   6. SYN scan      — 15+ ports, 20+ SYNs
//!   7. Sequential    — 12+ consecutive port numbers
//!   8. OS fingerprint— 2+ weird flag patterns
//!   9. General scan  — 20+ distinct ports catch-all
//!
//! Trust levels adjust thresholds but never skip SYN flood detection.
//! High-trust egress skips scan detection (not flood detection).

use std::net::IpAddr;
use std::time::Instant;

use crate::types::PacketFlags;
use super::{AlertKey, ThreatEvent, ThreatKind};
use super::tracker::{
    ThreatTracker, is_whitelisted, is_highly_trusted_process, is_medium_trust_process,
    ACK_SCAN_PORT_THRESHOLD, SCAN_PORT_THRESHOLD, SYN_FLOOD_THRESHOLD,
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
    ///
    /// Typical cost: ~20 ns (whitelist hit), ~60 ns (full path, no alert).
    /// Alert path: ~80 ns (static string, no format!).
    #[inline(always)]
    pub fn analyze_tcp(
        tracker:    &mut ThreatTracker,
        src_ip:     IpAddr,
        dst_port:   u16,
        flags:      &PacketFlags,
        proc_name:  Option<&str>,
        is_ingress: bool,
    ) -> Option<ThreatEvent> {
        // ── Fast reject: whitelisted infrastructure ───────────────────────────
        if is_whitelisted(src_ip) {
            return None;
        }

        // ── Trust classification ──────────────────────────────────────────────
        // Security note: trust reduces thresholds but never eliminates flood
        // detection. A compromised trusted process (browser, Teams) can still
        // trigger a SYN flood alert.
        let trust = proc_name.map_or(Trust::Unknown, |n| {
            if is_highly_trusted_process(n) { Trust::High }
            else if is_medium_trust_process(n) { Trust::Medium }
            else { Trust::Unknown }
        });

        // High-trust outbound traffic skips scan detection but NOT flood.
        // Rationale: browsers make many TCP connections legitimately; they
        // do not send NULL/FIN/XMAS scans or ACK sweeps.
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
        }

        // Amortized growth cap — every 16 packets
        if state.total_packets & 0x0F == 0 {
            state.cap_growth();
        }

        // ── 1. SYN flood — highest priority, always checked ───────────────────
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

        // ── Skip scan detection for trusted outbound traffic ──────────────────
        if skip_scan {
            return None;
        }

        let port_count = state.ports_hit.len() as u32;

        // ── 2. NULL scan — zero TCP flags ─────────────────────────────────────
        if flag_byte == 0x00 && port_count >= 2 {
            let kind = ThreatKind::NullScan;
            if !state.is_suppressed(AlertKey::NullScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_NULL));
            }
        }

        // ── 3. FIN scan — FIN only (no SYN, no ACK, no RST, no PSH) ─────────
        if flags.fin && !flags.syn && !flags.ack && !flags.rst && !flags.psh && !flags.urg
            && port_count >= 2
        {
            let kind = ThreatKind::FinScan;
            if !state.is_suppressed(AlertKey::FinScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_FIN));
            }
        }

        // ── 4. XMAS scan — FIN + PSH + URG ───────────────────────────────────
        if flags.fin && flags.psh && flags.urg && !flags.syn && !flags.ack
            && port_count >= 2
        {
            let kind = ThreatKind::XmasScan;
            if !state.is_suppressed(AlertKey::XmasScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_XMAS));
            }
        }

        // ── 5. ACK scan ───────────────────────────────────────────────────────
        //
        // Detection criteria (all must hold):
        //   a) Pure ACK: ACK set, SYN/FIN/RST/PSH all clear
        //   b) No SYN ever seen from this IP (rules out normal TCP handshakes)
        //   c) At least ACK_SCAN_PORT_THRESHOLD distinct destination ports
        //
        // The no-SYN guard is the key false-positive reducer: legitimate TCP
        // connections always start with SYN, so an IP we've seen do a normal
        // handshake is not doing an ACK scan. CDN keepalives are whitelisted
        // by IP so they never reach this point.
        if flags.ack
            && !flags.syn && !flags.fin && !flags.rst && !flags.psh && !flags.urg
            && state.syn_times.is_empty()
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
                Trust::Medium  => SYN_SCAN_MIN_PORTS * 2,
                _              => SYN_SCAN_MIN_PORTS,
            };
            let min_syns = match trust {
                Trust::Medium  => SYN_SCAN_MIN_SYNS * 2,
                _              => SYN_SCAN_MIN_SYNS,
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

        // ── 8. OS fingerprinting — weird flag combinations ────────────────────
        if state.weird_flag_count() >= OS_WEIRD_FLAGS_MIN {
            let kind = ThreatKind::OsScan;
            if !state.is_suppressed(AlertKey::OsScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_OS));
            }
        }

        // ── 9. General port scan catch-all ────────────────────────────────────
        let threshold = match trust {
            Trust::Medium  => SCAN_PORT_THRESHOLD * 2,
            _              => SCAN_PORT_THRESHOLD,
        };
        if port_count >= threshold {
            let kind = ThreatKind::ConnectScan;
            if !state.is_suppressed(AlertKey::ConnectScan, kind.cooldown_secs()) {
                return Some(ThreatEvent::new(src_ip, kind, DETAIL_CONNECT));
            }
        }

        None
    }

    /// UDP scan detection.
    ///
    /// Simpler than TCP: no flag analysis, just port count threshold.
    #[inline(always)]
    pub fn analyze_udp(
        tracker:    &mut ThreatTracker,
        src_ip:     IpAddr,
        dst_port:   u16,
        proc_name:  Option<&str>,
        is_ingress: bool,
    ) -> Option<ThreatEvent> {
        if is_whitelisted(src_ip) {
            return None;
        }

        // High-trust outbound UDP: DNS (53), QUIC (443/80), NTP (123) —
        // these are legitimate high-volume UDP flows.
        if let Some(name) = proc_name {
            if is_highly_trusted_process(name) && !is_ingress {
                return None;
            }
        }

        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.ports_hit.insert(dst_port);

        if state.total_packets & 0x0F == 0 {
            state.cap_growth();
        }

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

/// Pack a PacketFlags struct into a single byte using the standard TCP bit layout:
///   bit 0 = FIN, bit 1 = SYN, bit 2 = RST, bit 3 = PSH,
///   bit 4 = ACK, bit 5 = URG
///
/// This matches the wire format so the byte values are portable and match
/// what tcpdump/wireshark would show.
#[inline(always)]
fn flags_to_byte(flags: &PacketFlags) -> u8 {
    (flags.fin as u8)       // bit 0
    | ((flags.syn as u8) << 1)  // bit 1
    | ((flags.rst as u8) << 2)  // bit 2
    | ((flags.psh as u8) << 3)  // bit 3
    | ((flags.ack as u8) << 4)  // bit 4
    | ((flags.urg as u8) << 5)  // bit 5
}

// ── Trust level (packet-loop-local enum) ─────────────────────────────────────

#[derive(Clone, Copy)]
enum Trust {
    Unknown,
    Medium,
    High,
}
