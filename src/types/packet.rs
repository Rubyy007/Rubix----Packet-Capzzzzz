//! Core packet data structures for RUBIX
//! Optimized for zero-copy and minimal memory footprint

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, SystemTime};
use serde::{Serialize, Deserialize};

// FIXED: Removed Deserialize derive, added manual Default impl
#[derive(Debug, Clone, Serialize)]
pub struct Packet {
    #[serde(skip)]
    pub timestamp: Instant,
    pub system_time: SystemTime,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub size: usize,
    pub flags: PacketFlags,
    pub ttl: Option<u8>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            system_time: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Tcp,
            size: 0,
            flags: PacketFlags::default(),
            ttl: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Igmp,
    Other(u8),
}

impl Protocol {
    pub fn from_u8(value: u8) -> Self {
        match value {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            58 => Protocol::Icmpv6,
            2 => Protocol::Igmp,
            _ => Protocol::Other(value),
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Icmpv6 => "ICMPv6",
            Protocol::Igmp => "IGMP",
            Protocol::Other(_) => "OTHER",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl Packet {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        size: usize,
    ) -> Self {
        Self {
            timestamp: Instant::now(),
            system_time: SystemTime::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            size,
            flags: PacketFlags::default(),
            ttl: None,
        }
    }
    
    pub fn key(&self) -> String {
        format!("{}:{}->{}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
    
    pub fn reverse_key(&self) -> String {
        format!("{}:{}->{}:{}", self.dst_ip, self.dst_port, self.src_ip, self.src_port)
    }
}