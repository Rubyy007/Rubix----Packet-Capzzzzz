//! TCP/UDP port scan and nmap detection — production hot path

use std::net::IpAddr;
use std::time::Instant;

use crate::types::PacketFlags;
use super::{ThreatEvent, ThreatKind};
use super::tracker::ThreatTracker;

// ── Static detail strings ───────────────────────────────────────────────────

static DETAIL_NULL:     &str = "NULL scan detected (no TCP flags)";
static DETAIL_FIN:      &str = "FIN scan detected (nmap -sF)";
static DETAIL_XMAS:     &str = "XMAS scan detected (nmap -sX, FIN+PSH+URG)";
static DETAIL_ACK:      &str = "ACK scan detected (nmap -sA, firewall mapping)";
static DETAIL_SYN:      &str = "SYN scan detected (nmap -sS, half-open)";
static DETAIL_SYNFLOOD: &str = "SYN flood DoS detected";
static DETAIL_CONNECT:  &str = "Connect scan detected (nmap -sT)";
static DETAIL_SEQ:      &str = "Sequential port scan detected";
static DETAIL_OS:       &str = "OS fingerprinting detected (nmap -O)";
static DETAIL_UDP:      &str = "UDP scan detected (nmap -sU)";

// ── Thresholds for specific scans ────────────────────────────────────────────

const NULL_MIN_PORTS: u32     = 2;
const FIN_MIN_PORTS: u32      = 2;
const XMAS_MIN_PORTS: u32     = 2;
const ACK_MIN_PORTS: u32      = 5;
const SYN_SCAN_MIN_PORTS: u32 = 15;
const SYN_SCAN_MIN_SYNS: u32  = 20;
const OS_WEIRD_FLAGS_MIN: u32 = 2;

// ── ScanDetector ─────────────────────────────────────────────────────────────

pub struct ScanDetector;

impl ScanDetector {
    /// TCP analysis — hot path, ~20ns typical
    #[inline(always)]
    pub fn analyze_tcp(
        tracker:    &mut ThreatTracker,
        src_ip:     IpAddr,
        dst_port:   u16,
        flags:      &PacketFlags,
        proc_name:  Option<&str>,
        is_ingress: bool,
    ) -> Option<ThreatEvent> {
        // Fast reject: whitelisted
        if super::tracker::is_whitelisted(src_ip) {
            return None;
        }

        // Determine trust level
        let trust = match proc_name {
            Some(name) if super::tracker::is_highly_trusted_process(name) => TrustLevel::High,
            Some(name) if super::tracker::is_medium_trust_process(name) => TrustLevel::Medium,
            _ => TrustLevel::Unknown,
        };

        // High trust + egress — skip deep inspection
        let skip_deep = matches!(trust, TrustLevel::High) && !is_ingress;

        // ── Update state ──────────────────────────────────────────────────────
        
        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.ports_hit.insert(dst_port);
        state.port_history.push(dst_port);
        
        if state.port_history.len() > 64 {
            state.port_history.remove(0);
        }

        let flag_byte = flags_to_byte(flags);
        state.tcp_flags_seen.insert(flag_byte);

        let is_syn = flags.syn && !flags.ack;
        if is_syn {
            state.syn_times.push(Instant::now());
        }

        // Amortized maintenance
        if state.total_packets & 0x0F == 0 {
            state.cap_growth();
        }

        // ── Detection heuristics (ordered by severity) ────────────────────────
        
        // 1. SYN flood — always check, most severe
        if is_syn {
            let syn_count = state.syn_times.len() as u32;
            let threshold = match trust {
                TrustLevel::High => super::tracker::SYN_FLOOD_THRESHOLD * 5,
                TrustLevel::Medium => super::tracker::SYN_FLOOD_THRESHOLD * 2,
                TrustLevel::Unknown => super::tracker::SYN_FLOOD_THRESHOLD,
            };
            if syn_count >= threshold && !state.already_alerted("syn_flood") {
                return Some(ThreatEvent::new_fast(src_ip, ThreatKind::SynFlood, DETAIL_SYNFLOOD));
            }
        }

        // Skip deep inspection for trusted egress
        if skip_deep {
            return None;
        }

        // 2. NULL scan
        if flag_byte == 0x00 {
            let port_count = state.ports_hit.len() as u32;
            if port_count >= NULL_MIN_PORTS && !state.already_alerted("null_scan") {
                return Some(ThreatEvent::new_fast(src_ip, ThreatKind::NullScan, DETAIL_NULL));
            }
        }

        // 3. FIN scan
        if flags.fin && !flags.syn && !flags.ack && !flags.rst && !flags.psh && !flags.urg {
            let port_count = state.ports_hit.len() as u32;
            if port_count >= FIN_MIN_PORTS && !state.already_alerted("fin_scan") {
                return Some(ThreatEvent::new_fast(src_ip, ThreatKind::FinScan, DETAIL_FIN));
            }
        }

        // 4. XMAS scan
        if flags.fin && flags.psh && flags.urg && !flags.syn && !flags.ack {
            let port_count = state.ports_hit.len() as u32;
            if port_count >= XMAS_MIN_PORTS && !state.already_alerted("xmas_scan") {
                return Some(ThreatEvent::new_fast(src_ip, ThreatKind::XmasScan, DETAIL_XMAS));
            }
        }

        // 5. ACK scan — ONLY ACK, no SYN ever seen, 5+ ports
        if flags.ack && !flags.syn && !flags.fin && !flags.rst && !flags.psh {
            let no_syn_history = state.syn_times.is_empty();
            let port_count = state.ports_hit.len() as u32;
            if no_syn_history && port_count >= ACK_MIN_PORTS && !state.already_alerted("ack_scan") {
                return Some(ThreatEvent::new_fast(src_ip, ThreatKind::AckScan, DETAIL_ACK));
            }
        }

        // 6. SYN scan
        if is_syn {
            let port_count = state.ports_hit.len() as u32;
            let syn_count = state.syn_times.len() as u32;
            let threshold_ports = match trust {
                TrustLevel::Medium => SYN_SCAN_MIN_PORTS * 2,
                _ => SYN_SCAN_MIN_PORTS,
            };
            let threshold_syns = match trust {
                TrustLevel::Medium => SYN_SCAN_MIN_SYNS * 2,
                _ => SYN_SCAN_MIN_SYNS,
            };
            if port_count >= threshold_ports 
                && syn_count >= threshold_syns 
                && !state.already_alerted("syn_scan") 
            {
                return Some(ThreatEvent::new_fast(src_ip, ThreatKind::SynScan, DETAIL_SYN));
            }
        }

        // 7. Sequential scan
        if state.has_sequential_ports() && !state.already_alerted("sequential_scan") {
            return Some(ThreatEvent::new_fast(src_ip, ThreatKind::ConnectScan, DETAIL_SEQ));
        }

        // 8. OS fingerprinting — weird flag patterns
        let weird = state.weird_flag_count();
        if weird >= OS_WEIRD_FLAGS_MIN && !state.already_alerted("os_scan") {
            return Some(ThreatEvent::new_fast(src_ip, ThreatKind::OsScan, DETAIL_OS));
        }

        // 9. General port scan catch-all
        let port_count = state.ports_hit.len() as u32;
        let threshold = match trust {
            TrustLevel::Medium => super::tracker::SCAN_PORT_THRESHOLD * 2,
            _ => super::tracker::SCAN_PORT_THRESHOLD,
        };
        if port_count >= threshold && !state.already_alerted("port_scan") {
            return Some(ThreatEvent::new_fast(src_ip, ThreatKind::ConnectScan, DETAIL_CONNECT));
        }

        None
    }

    /// UDP scan detection — minimal
    #[inline(always)]
    pub fn analyze_udp(
        tracker:    &mut ThreatTracker,
        src_ip:     IpAddr,
        dst_port:   u16,
        proc_name:  Option<&str>,
        is_ingress: bool,
    ) -> Option<ThreatEvent> {
        if super::tracker::is_whitelisted(src_ip) {
            return None;
        }

        // High trust outbound UDP — DNS, QUIC, etc.
        if let Some(name) = proc_name {
            if super::tracker::is_highly_trusted_process(name) && !is_ingress {
                return None;
            }
        }

        let state = tracker.get_or_create(src_ip);
        state.touch();
        state.ports_hit.insert(dst_port);

        let port_count = state.ports_hit.len() as u32;
        let threshold = match proc_name {
            Some(name) if super::tracker::is_medium_trust_process(name) => super::tracker::SCAN_PORT_THRESHOLD * 2,
            _ => super::tracker::SCAN_PORT_THRESHOLD,
        };

        if port_count >= threshold && !state.already_alerted("udp_scan") {
            return Some(ThreatEvent::new_fast(src_ip, ThreatKind::UdpScan, DETAIL_UDP));
        }

        None
    }
}

// ── Internal ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum TrustLevel {
    Unknown,
    Medium,
    High,
}

#[inline(always)]
fn flags_to_byte(flags: &PacketFlags) -> u8 {
    let mut b = 0u8;
    b |= (flags.fin as u8) << 0;
    b |= (flags.syn as u8) << 1;
    b |= (flags.rst as u8) << 2;
    b |= (flags.psh as u8) << 3;
    b |= (flags.ack as u8) << 4;
    b |= (flags.urg as u8) << 5;
    b
}