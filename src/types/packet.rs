//! Core packet data structures for RUBIX
//! Optimized for zero-copy and minimal memory footprint

use std::net::IpAddr;
use std::time::{Instant, SystemTime};
use serde::Serialize;

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
    pub payload: Option<Vec<u8>>,
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
            payload: None,
        }
    }
    
    // FIXED: Get length BEFORE moving data
    pub fn with_payload(mut self, data: Vec<u8>) -> Self {
        self.size = data.len();      // Get length first
        self.payload = Some(data);   // Then move data
        self
    }
    
    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }
    
    pub fn payload_len(&self) -> usize {
        self.payload.as_ref().map(|p| p.len()).unwrap_or(0)
    }
    
    pub fn key(&self) -> String {
        format!("{}:{}->{}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
    
    pub fn reverse_key(&self) -> String {
        format!("{}:{}->{}:{}", self.dst_ip, self.dst_port, self.src_ip, self.src_port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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

#[derive(Debug, Clone, Default, Serialize)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}