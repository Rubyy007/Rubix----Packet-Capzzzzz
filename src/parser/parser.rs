//! Packet parsing utilities

use super::Parser;
use crate::types::Packet;

pub struct PacketParser {
    stats: ParseStats,
}

#[derive(Default)]
pub struct ParseStats {
    pub total_parsed: u64,
    pub total_failed: u64,
    pub ipv4_count: u64,
    pub ipv6_count: u64,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
}

impl PacketParser {
    pub fn new() -> Self {
        Self {
            stats: ParseStats::default(),
        }
    }
    
    pub fn parse(&mut self, data: &[u8]) -> Option<Packet> {
        match Parser::parse_packet(data) {
            Some(packet) => {
                self.stats.total_parsed += 1;
                match packet.protocol {
                    crate::types::Protocol::Tcp => self.stats.tcp_count += 1,
                    crate::types::Protocol::Udp => self.stats.udp_count += 1,
                    crate::types::Protocol::Icmp => self.stats.icmp_count += 1,
                    crate::types::Protocol::Other(_) => {}
                }
                
                if packet.src_ip.is_ipv4() {
                    self.stats.ipv4_count += 1;
                } else {
                    self.stats.ipv6_count += 1;
                }
                
                Some(packet)
            }
            None => {
                self.stats.total_failed += 1;
                None
            }
        }
    }
    
    pub fn get_stats(&self) -> &ParseStats {
        &self.stats
    }
    
    pub fn reset_stats(&mut self) {
        self.stats = ParseStats::default();
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new()
    }
}