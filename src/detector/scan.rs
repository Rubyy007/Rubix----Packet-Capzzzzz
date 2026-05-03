//! Port scan and nmap detection engine
//!
//! Detects all major nmap scan types by analyzing TCP flag combinations
//! and packet patterns within sliding time windows.

use std::net::IpAddr;
use crate::types::PacketFlags;
use super::{ThreatEvent, ThreatKind};
use super::tracker::{
    ThreatTracker, SCAN_PORT_THRESHOLD,
    SEQUENTIAL_PORT_THRESHOLD, SYN_FLOOD_THRESHOLD,
};
use std::time::Instant;

pub struct ScanDetector;

impl ScanDetector {
    /// Analyze a TCP packet and return threat events if detected.
    /// Call this on every TCP packet in the hot path.
    #[inline]
    pub fn analyze_tcp(
        tracker:  &mut ThreatTracker,
        src_ip:   IpAddr,
        dst_port: u16,
        flags:    &PacketFlags,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let now         = Instant::now();

        let state = tracker.get_or_create(src_ip);
        state.last_seen     = now;
        state.total_packets += 1;

        // Track port hit
        state.ports_hit.insert(dst_port);
        state.port_history.push_back(dst_port);
        if state.port_history.len() > 128 {
            state.port_history.pop_front();
        }

        // Build flag byte for pattern matching
        let flag_byte = Self::flags_to_byte(flags);
        state.tcp_flags_seen.insert(flag_byte);

        // ── nmap NULL scan: no flags set ──────────────────────────────────────
        // nmap -sN
        if flag_byte == 0x00 && !state.already_alerted("null_scan") {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::NullScan,
                format!(
                    "NULL scan detected (no TCP flags) from {} → port {}",
                    src_ip, dst_port
                ),
            ));
        }

        // ── nmap FIN scan: only FIN set ───────────────────────────────────────
        // nmap -sF
        if flags.fin && !flags.syn && !flags.ack && !flags.rst && !flags.psh && !flags.urg
            && !state.already_alerted("fin_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::FinScan,
                format!(
                    "FIN scan detected (nmap -sF) from {} → port {}",
                    src_ip, dst_port
                ),
            ));
        }

        // ── nmap XMAS scan: FIN+PSH+URG set ──────────────────────────────────
        // nmap -sX — "lights up like a christmas tree"
        if flags.fin && flags.psh && flags.urg && !flags.syn && !flags.ack
            && !state.already_alerted("xmas_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::XmasScan,
                format!(
                    "XMAS scan detected (nmap -sX, FIN+PSH+URG) from {} → port {}",
                    src_ip, dst_port
                ),
            ));
        }

        // ── nmap ACK scan: only ACK set ───────────────────────────────────────
        // nmap -sA — used to map firewall rules
        if flags.ack && !flags.syn && !flags.fin && !flags.rst && !flags.psh
            && !state.already_alerted("ack_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::AckScan,
                format!(
                    "ACK scan detected (nmap -sA, firewall mapping) from {}",
                    src_ip
                ),
            ));
        }

        // ── SYN tracking (for SYN scan + flood detection) ─────────────────────
        if flags.syn && !flags.ack {
            state.syn_times.push_back(now);

            // ── nmap SYN scan: many SYNs, no completions ──────────────────────
            // nmap -sS (half-open scan)
            if state.ports_hit.len() >= 10
                && !state.already_alerted("syn_scan")
            {
                threats.push(ThreatEvent::new(
                    src_ip,
                    ThreatKind::SynScan,
                    format!(
                        "SYN scan detected (nmap -sS) from {}: {} ports probed",
                        src_ip,
                        state.ports_hit.len(),
                    ),
                ));
            }

            // ── SYN flood: high rate SYN packets ─────────────────────────────
            if state.syn_rate() >= SYN_FLOOD_THRESHOLD
                && !state.already_alerted("syn_flood")
            {
                threats.push(ThreatEvent::new(
                    src_ip,
                    ThreatKind::SynFlood,
                    format!(
                        "SYN FLOOD: {} SYN/{}s from {}",
                        state.syn_rate(),
                        super::tracker::TRACK_WINDOW_SECS,
                        src_ip,
                    ),
                ));
            }
        }

        // ── Port scan threshold: many unique ports ────────────────────────────
        // Catches nmap -sT (connect scan) and other scanners
        if state.ports_hit.len() >= SCAN_PORT_THRESHOLD
            && !state.already_alerted("port_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::ConnectScan,
                format!(
                    "Port scan detected from {}: {} unique ports in {}s",
                    src_ip,
                    state.ports_hit.len(),
                    super::tracker::TRACK_WINDOW_SECS,
                ),
            ));
        }

        // ── Sequential port scan ──────────────────────────────────────────────
        // nmap default scans ports sequentially
        if state.has_sequential_ports()
            && !state.already_alerted("sequential_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::SequentialScan,
                format!(
                    "Sequential port scan detected from {}: {}+ consecutive ports",
                    src_ip,
                    SEQUENTIAL_PORT_THRESHOLD,
                ),
            ));
        }

        // ── OS fingerprinting detection ───────────────────────────────────────
        // nmap -O sends packets with unusual flag combos to fingerprint the OS.
        // Heuristic: if we see 4+ different flag combinations from same IP,
        // it's almost certainly OS detection.
        if state.tcp_flags_seen.len() >= 4
            && !state.already_alerted("os_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::OsScan,
                format!(
                    "OS fingerprinting detected (nmap -O) from {}: {} flag patterns",
                    src_ip,
                    state.tcp_flags_seen.len(),
                ),
            ));
        }

        threats
    }

    /// Analyze a UDP packet for UDP scan detection.
    /// nmap -sU sends UDP packets to closed ports — they respond with ICMP unreachable.
    #[inline]
    pub fn analyze_udp(
        tracker:  &mut ThreatTracker,
        src_ip:   IpAddr,
        dst_port: u16,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();
        let now         = Instant::now();

        let state = tracker.get_or_create(src_ip);
        state.last_seen     = now;
        state.total_packets += 1;
        state.ports_hit.insert(dst_port);

        // UDP scan: many unique UDP ports from same IP
        if state.ports_hit.len() >= SCAN_PORT_THRESHOLD
            && !state.already_alerted("udp_scan")
        {
            threats.push(ThreatEvent::new(
                src_ip,
                ThreatKind::UdpScan,
                format!(
                    "UDP scan detected (nmap -sU) from {}: {} ports probed",
                    src_ip,
                    state.ports_hit.len(),
                ),
            ));
        }

        threats
    }

    /// Convert PacketFlags to a single byte for pattern matching
    #[inline(always)]
    fn flags_to_byte(flags: &PacketFlags) -> u8 {
        let mut byte = 0u8;
        if flags.fin { byte |= 0x01; }
        if flags.syn { byte |= 0x02; }
        if flags.rst { byte |= 0x04; }
        if flags.psh { byte |= 0x08; }
        if flags.ack { byte |= 0x10; }
        if flags.urg { byte |= 0x20; }
        byte
    }
}