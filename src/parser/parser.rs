// src/parser/parser.rs
//! Stateful `PacketParser` — wraps `Parser` and accumulates parse statistics.
//!
//! `PacketParser` is the public surface used anywhere that wants both packet
//! decoding AND metrics (CLI diagnostics, pipeline health monitoring).
//!
//! For hot-path capture backends that only need decoding and not statistics,
//! call `Parser::parse_packet()` directly — zero overhead, no struct state.
//!
//! Statistics tracked:
//!   • Total frames attempted / successfully parsed / failed
//!   • Protocol breakdown: TCP / UDP / ICMPv4 / ICMPv6 / Other
//!   • IP version breakdown: IPv4 / IPv6
//!   • Byte totals: parsed bytes / dropped bytes
//!
//! All counters are plain `u64` — `PacketParser` is owned by a single task
//! (the packet loop) and never shared across threads.  No atomics needed.

use super::Parser;
use crate::types::Packet;

// ── ParseStats ────────────────────────────────────────────────────────────────

/// Cumulative parse statistics since construction or last `reset_stats()`.
///
/// All fields are `pub` so the CLI can read them directly without getters.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    // ── Frame totals ──────────────────────────────────────────────────────────
    /// Raw frames passed to `parse()`.
    pub total_attempted: u64,
    /// Frames successfully decoded into a `Packet`.
    pub total_parsed:    u64,
    /// Frames that failed decoding (non-IP, malformed, ARP, etc.).
    pub total_failed:    u64,

    // ── Protocol breakdown ────────────────────────────────────────────────────
    pub tcp_count:    u64,
    pub udp_count:    u64,
    /// ICMPv4 echo / unreachable / time-exceeded packets.
    pub icmp4_count:  u64,
    /// ICMPv6 packets (neighbor discovery, echo, etc.).
    pub icmp6_count:  u64,
    /// Other IP protocols (ESP, GRE, IGMP, SCTP, etc.).
    pub other_count:  u64,

    // ── IP version breakdown ──────────────────────────────────────────────────
    pub ipv4_count: u64,
    pub ipv6_count: u64,

    // ── Byte totals ───────────────────────────────────────────────────────────
    /// Total bytes from successfully parsed frames.
    pub parsed_bytes: u64,
    /// Total bytes from frames that failed to parse.
    pub failed_bytes: u64,
}

impl ParseStats {
    /// Parse success rate as a value in [0.0, 1.0].
    /// Returns 1.0 when no frames have been attempted yet.
    #[inline]
    pub fn success_rate(&self) -> f64 {
        if self.total_attempted == 0 {
            return 1.0;
        }
        self.total_parsed as f64 / self.total_attempted as f64
    }

    /// Drop rate as a value in [0.0, 1.0].
    #[inline]
    pub fn drop_rate(&self) -> f64 {
        1.0 - self.success_rate()
    }
}

// ── PacketParser ──────────────────────────────────────────────────────────────

/// Stateful packet parser with accumulated statistics.
///
/// Owns a `ParseStats` that is updated on every `parse()` call.
/// Thread-safety: not `Sync` — intended to be owned by a single async task.
pub struct PacketParser {
    stats: ParseStats,
}

impl PacketParser {
    /// Construct a new `PacketParser` with zeroed statistics.
    #[inline]
    pub fn new() -> Self {
        Self {
            stats: ParseStats::default(),
        }
    }

    /// Parse a raw Ethernet frame, updating internal statistics.
    ///
    /// Returns `Some(Packet)` on success, `None` on failure.
    /// Statistics are updated regardless of outcome.
    ///
    /// # Hot-path note
    /// This adds ~5 ns of counter increments on top of `Parser::parse_packet`.
    /// For the absolute fastest path (no stats needed), call
    /// `Parser::parse_packet()` directly.
    #[inline]
    pub fn parse(&mut self, data: &[u8]) -> Option<Packet> {
        self.stats.total_attempted = self.stats.total_attempted.saturating_add(1);

        match Parser::parse_packet(data) {
            Some(packet) => {
                self.stats.total_parsed    = self.stats.total_parsed.saturating_add(1);
                self.stats.parsed_bytes    = self.stats.parsed_bytes
                    .saturating_add(packet.size as u64);

                // ── Protocol counters ─────────────────────────────────────────
                match packet.protocol {
                    crate::types::Protocol::Tcp      => {
                        self.stats.tcp_count = self.stats.tcp_count.saturating_add(1);
                    }
                    crate::types::Protocol::Udp      => {
                        self.stats.udp_count = self.stats.udp_count.saturating_add(1);
                    }
                    crate::types::Protocol::Icmp     => {
                        self.stats.icmp4_count = self.stats.icmp4_count.saturating_add(1);
                    }
                    crate::types::Protocol::Icmpv6   => {
                        self.stats.icmp6_count = self.stats.icmp6_count.saturating_add(1);
                    }
                    crate::types::Protocol::Igmp
                    | crate::types::Protocol::Other(_) => {
                        self.stats.other_count = self.stats.other_count.saturating_add(1);
                    }
                }

                // ── IP version counters ───────────────────────────────────────
                if packet.src_ip.is_ipv4() {
                    self.stats.ipv4_count = self.stats.ipv4_count.saturating_add(1);
                } else {
                    self.stats.ipv6_count = self.stats.ipv6_count.saturating_add(1);
                }

                Some(packet)
            }

            None => {
                self.stats.total_failed  = self.stats.total_failed.saturating_add(1);
                self.stats.failed_bytes  = self.stats.failed_bytes
                    .saturating_add(data.len() as u64);
                None
            }
        }
    }

    /// Immutable reference to the accumulated statistics.
    #[inline]
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Reset all statistics counters to zero.
    ///
    /// Typically called at the start of each 5-second stats window in the
    /// packet loop, matching `ProcStats::reset_window()` cadence.
    #[inline]
    pub fn reset_stats(&mut self) {
        self.stats = ParseStats::default();
    }

    /// Snapshot the current statistics and reset all counters.
    ///
    /// Useful when you want to publish the window stats and immediately
    /// start a fresh window without two separate calls.
    #[inline]
    pub fn take_stats(&mut self) -> ParseStats {
        let snapshot = self.stats.clone();
        self.stats   = ParseStats::default();
        snapshot
    }
}

impl Default for PacketParser {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid Ethernet + IPv4 + TCP frame (54 bytes).
    /// Source: hand-crafted, verified with wireshark byte layout.
    ///
    /// Ethernet: dst=00:11:22:33:44:55  src=66:77:88:99:aa:bb  type=0x0800
    /// IPv4:     src=192.168.1.1  dst=192.168.1.2  proto=TCP  ttl=64
    /// TCP:      src=12345  dst=80  SYN set
    fn syn_frame() -> Vec<u8> {
        vec![
            // Ethernet header (14 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
            0x08, 0x00,                          // EtherType: IPv4
            // IPv4 header (20 bytes, no options)
            0x45,                   // version=4, IHL=5
            0x00,                   // DSCP/ECN
            0x00, 0x28,             // total length = 40 (20 IP + 20 TCP)
            0x00, 0x01,             // identification
            0x40, 0x00,             // flags=DF, fragment offset=0
            0x40,                   // TTL = 64
            0x06,                   // protocol = TCP
            0x00, 0x00,             // checksum (zeroed — etherparse doesn't verify)
            0xc0, 0xa8, 0x01, 0x01, // src = 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02, // dst = 192.168.1.2
            // TCP header (20 bytes, no options)
            0x30, 0x39,             // src port = 12345
            0x00, 0x50,             // dst port = 80
            0x00, 0x00, 0x00, 0x01, // seq number
            0x00, 0x00, 0x00, 0x00, // ack number
            0x50,                   // data offset = 5 (20 bytes), reserved = 0
            0x02,                   // flags: SYN
            0xff, 0xff,             // window size
            0x00, 0x00,             // checksum (zeroed)
            0x00, 0x00,             // urgent pointer
        ]
    }

    #[test]
    fn test_syn_frame_parses() {
        let data = syn_frame();
        let pkt  = Parser::parse_packet(&data).expect("SYN frame must parse");

        assert!(pkt.src_ip.is_ipv4());
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 80);
        assert!(pkt.flags.syn,  "SYN flag must be set");
        assert!(!pkt.flags.ack, "ACK flag must not be set");
        assert!(!pkt.flags.fin, "FIN flag must not be set");
        assert!(!pkt.flags.rst, "RST flag must not be set");
        assert!(!pkt.flags.psh, "PSH flag must not be set");
        assert!(!pkt.flags.urg, "URG flag must not be set");
        assert_eq!(pkt.ttl, Some(64));
    }

    #[test]
    fn test_empty_slice_returns_none() {
        assert!(Parser::parse_packet(&[]).is_none());
    }

    #[test]
    fn test_truncated_frame_returns_none() {
        // Only 8 bytes — not enough for an Ethernet header (14 bytes minimum)
        assert!(Parser::parse_packet(&[0u8; 8]).is_none());
    }

    #[test]
    fn test_packet_parser_stats_success() {
        let mut pp   = PacketParser::new();
        let data     = syn_frame();
        let result   = pp.parse(&data);

        assert!(result.is_some());
        assert_eq!(pp.stats().total_attempted, 1);
        assert_eq!(pp.stats().total_parsed,    1);
        assert_eq!(pp.stats().total_failed,    0);
        assert_eq!(pp.stats().tcp_count,       1);
        assert_eq!(pp.stats().udp_count,       0);
        assert_eq!(pp.stats().ipv4_count,      1);
        assert_eq!(pp.stats().ipv6_count,      0);
        assert!(pp.stats().parsed_bytes > 0);
        assert_eq!(pp.stats().failed_bytes, 0);
    }

    #[test]
    fn test_packet_parser_stats_failure() {
        let mut pp = PacketParser::new();
        let result = pp.parse(&[0u8; 4]);   // too short to be a valid frame

        assert!(result.is_none());
        assert_eq!(pp.stats().total_attempted, 1);
        assert_eq!(pp.stats().total_parsed,    0);
        assert_eq!(pp.stats().total_failed,    1);
        assert_eq!(pp.stats().failed_bytes,    4);
        assert_eq!(pp.stats().parsed_bytes,    0);
    }

    #[test]
    fn test_reset_stats() {
        let mut pp = PacketParser::new();
        pp.parse(&syn_frame());
        assert_eq!(pp.stats().total_parsed, 1);

        pp.reset_stats();
        assert_eq!(pp.stats().total_attempted, 0);
        assert_eq!(pp.stats().total_parsed,    0);
        assert_eq!(pp.stats().tcp_count,       0);
    }

    #[test]
    fn test_take_stats() {
        let mut pp = PacketParser::new();
        pp.parse(&syn_frame());

        let snap = pp.take_stats();
        assert_eq!(snap.total_parsed, 1);

        // After take, counters are zeroed
        assert_eq!(pp.stats().total_parsed, 0);
        assert_eq!(pp.stats().total_attempted, 0);
    }

    #[test]
    fn test_success_rate() {
        let mut pp = PacketParser::new();
        pp.parse(&syn_frame());                // success
        pp.parse(&[0u8; 4]);                   // failure

        let stats = pp.stats();
        assert_eq!(stats.total_attempted, 2);
        assert_eq!(stats.total_parsed,    1);
        assert_eq!(stats.total_failed,    1);
        assert!((stats.success_rate() - 0.5).abs() < f64::EPSILON);
        assert!((stats.drop_rate()    - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_success_rate_empty() {
        let pp = PacketParser::new();
        // No frames attempted → success rate defined as 1.0
        assert!((pp.stats().success_rate() - 1.0).abs() < f64::EPSILON);
    }
}