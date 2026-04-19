//! Advanced packet parsing

mod parser;

pub use parser::PacketParser;

use crate::types::Packet;
use etherparse::{IpHeader, TransportHeader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Parser;

impl Parser {
    pub fn parse_packet(data: &[u8]) -> Option<Packet> {
        match etherparse::SlicedPacket::from_ethernet(data) {
            Ok(packet) => {
                let (src_ip, dst_ip, src_port, dst_port, protocol) = Self::extract_ip_info(&packet);
                
                Some(Packet::new(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    data.to_vec(),
                ))
            }
            Err(_) => None,
        }
    }
    
    fn extract_ip_info(packet: &etherparse::SlicedPacket) -> (IpAddr, IpAddr, u16, u16, crate::types::Protocol) {
        let mut src_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut dst_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut src_port = 0;
        let mut dst_port = 0;
        let mut protocol = crate::types::Protocol::Other(0);
        
        if let Some(ip) = packet.ip {
            match ip {
                IpHeader::Version4(header, _) => {
                    src_ip = IpAddr::V4(Ipv4Addr::from(header.source));
                    dst_ip = IpAddr::V4(Ipv4Addr::from(header.destination));
                    protocol = crate::types::Protocol::Other(header.protocol);
                }
                IpHeader::Version6(header, _) => {
                    src_ip = IpAddr::V6(Ipv6Addr::from(header.source));
                    dst_ip = IpAddr::V6(Ipv6Addr::from(header.destination));
                    protocol = crate::types::Protocol::Other(header.next_header);
                }
            }
        }
        
        if let Some(transport) = packet.transport {
            match transport {
                TransportHeader::Tcp(header) => {
                    src_port = header.source_port;
                    dst_port = header.destination_port;
                    protocol = crate::types::Protocol::Tcp;
                }
                TransportHeader::Udp(header) => {
                    src_port = header.source_port;
                    dst_port = header.destination_port;
                    protocol = crate::types::Protocol::Udp;
                }
                TransportHeader::Icmp(_, _) => {
                    protocol = crate::types::Protocol::Icmp;
                }
            }
        }
        
        (src_ip, dst_ip, src_port, dst_port, protocol)
    }
}