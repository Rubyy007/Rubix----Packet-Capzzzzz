// src/parser/mod.rs
//! Zero-copy packet parsing for RUBIX.
//!
//! Decodes raw Ethernet frames into typed `Packet` structs using the
//! etherparse 0.15 API (NetHeaders / TransportHeader).
//!
//! Design constraints:
//!   • No heap allocation on the success path beyond the Packet itself.
//!   • All TCP flags extracted — scan detection depends on them.
//!   • IPv4 + IPv6 fully supported.
//!   • ICMPv4 + ICMPv6 distinguished (Protocol::Icmp vs Protocol::Icmpv6).
//!   • TTL / hop-limit extracted — used by OS fingerprinting heuristics.
//!   • Non-IP frames (ARP, VLAN untagged, malformed) return None silently.
//!
//! Two public surfaces:
//!   `Parser`       — stateless, zero-overhead, used by capture backends.
//!   `PacketParser` — stateful wrapper that accumulates parse statistics;
//!                    used for diagnostics and CLI metric display.

mod parser;

pub use parser::PacketParser;
pub use parser::ParseStats;

use crate::types::{Packet, PacketFlags, Protocol};
use etherparse::NetHeaders;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ── Parser ────────────────────────────────────────────────────────────────────

/// Stateless Ethernet frame → `Packet` decoder.
///
/// All methods are `#[inline]` — the compiler can eliminate the call entirely
/// when the capture backends inline `parse_packet` into their hot loop.
pub struct Parser;

impl Parser {
    /// Parse a raw Ethernet frame into a typed `Packet`.
    ///
    /// Returns `None` for:
    ///   • Non-Ethernet frames
    ///   • Non-IP frames (ARP, VLAN-untagged, etc.)
    ///   • Malformed / truncated headers
    ///
    /// Never panics; all slice indexing is bounds-checked by etherparse.
    ///
    /// # Performance
    /// Typical cost on the success path: ~25 ns (no allocation, no syscall).
    /// etherparse operates on the original slice — no copy of packet data.
    #[inline]
    pub fn parse_packet(data: &[u8]) -> Option<Packet> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(data).ok()?;

        // ── Network layer ─────────────────────────────────────────────────────
        let (src_ip, dst_ip, ttl) = match &parsed.net {
            Some(NetHeaders::Ipv4(ref hdr, _)) => (
                IpAddr::V4(Ipv4Addr::from(hdr.source)),
                IpAddr::V4(Ipv4Addr::from(hdr.destination)),
                Some(hdr.time_to_live),
            ),
            Some(NetHeaders::Ipv6(ref hdr, _)) => (
                IpAddr::V6(Ipv6Addr::from(hdr.source)),
                IpAddr::V6(Ipv6Addr::from(hdr.destination)),
                Some(hdr.hop_limit),
            ),
            // Non-IP (ARP, etc.) or missing network header — drop silently.
            _ => return None,
        };

        // ── Transport layer ───────────────────────────────────────────────────
        let (src_port, dst_port, protocol) = match &parsed.transport {
            Some(etherparse::TransportHeader::Tcp(ref tcp)) => (
                tcp.source_port,
                tcp.destination_port,
                Protocol::Tcp,
            ),
            Some(etherparse::TransportHeader::Udp(ref udp)) => (
                udp.source_port,
                udp.destination_port,
                Protocol::Udp,
            ),
            // ICMPv4 and ICMPv6 are distinguished — the detector treats them
            // separately (PingDetector handles both, but ThreatKind differs).
            Some(etherparse::TransportHeader::Icmpv4(_)) => (0, 0, Protocol::Icmp),
            Some(etherparse::TransportHeader::Icmpv6(_)) => (0, 0, Protocol::Icmpv6),
            // Unknown transport (ESP, GRE, etc.) — preserve IP addresses but
            // mark protocol as Other so the policy engine can still match.
            None => (0, 0, Protocol::Other(0)),
        };

        // ── Assemble Packet ───────────────────────────────────────────────────
        let mut pkt = Packet::new(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            data.len(),
        );

        pkt.ttl = ttl;

        // ── TCP flags — critical for scan detection ───────────────────────────
        //
        // ScanDetector::analyze_tcp() depends on all six flags being correct.
        // A parser that leaves them all false would silently break:
        //   • NULL scan detection  (flag_byte == 0x00)
        //   • FIN scan detection   (flags.fin && !flags.syn && ...)
        //   • XMAS scan detection  (flags.fin && flags.psh && flags.urg)
        //   • ACK scan detection   (flags.ack && !flags.syn && ...)
        //   • SYN flood detection  (flags.syn && !flags.ack)
        //   • OS fingerprinting    (weird_flag_count())
        if let Some(etherparse::TransportHeader::Tcp(ref tcp)) = parsed.transport {
            pkt.flags = PacketFlags {
                syn: tcp.syn,
                ack: tcp.ack,
                fin: tcp.fin,
                rst: tcp.rst,
                psh: tcp.psh,
                urg: tcp.urg,
            };
        }

        Some(pkt)
    }
}
