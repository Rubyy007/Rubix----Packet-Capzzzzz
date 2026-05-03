//! High-performance process attribution engine.
//! Zero-allocation hot path, batched syscalls, lock-free reads.

mod cache;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

use std::net::IpAddr;
use std::collections::HashMap;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid:  u32,
    pub name: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub local_ip:   IpAddr,
    pub local_port: u16,
    pub protocol:   Protocol,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(u8)]
pub enum Protocol {
    Tcp  = 6,
    Udp  = 17,
    Icmp = 1,
    Other(u8),
}

impl Protocol {
    #[inline(always)]
    pub fn from_str(s: &str) -> Self {
        match s.as_bytes() {
            b"TCP" | b"tcp" => Protocol::Tcp,
            b"UDP" | b"udp" => Protocol::Udp,
            b"ICMP" | b"icmp" => Protocol::Icmp,
            _ => Protocol::Other(0),
        }
    }

    #[inline(always)]
    pub const fn from_u8(proto: u8) -> Self {
        match proto {
            6  => Protocol::Tcp,
            17 => Protocol::Udp,
            1  => Protocol::Icmp,
            p  => Protocol::Other(p),
        }
    }

    #[inline(always)]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Protocol::Tcp      => 6,
            Protocol::Udp      => 17,
            Protocol::Icmp     => 1,
            Protocol::Other(n) => *n,
        }
    }

    #[inline(always)]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp  => "TCP",
            Protocol::Udp  => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Other(_) => "OTHER",
        }
    }
}

impl std::fmt::Display for Protocol {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Other(n) => write!(f, "PROTO({})", n),
            _ => f.write_str(self.as_str()),
        }
    }
}

pub use cache::ProcessResolver;

pub(crate) type SnapshotResult = Result<HashMap<FlowKey, ProcessInfo>, Box<dyn std::error::Error>>;

#[inline]
pub(crate) fn snapshot() -> SnapshotResult {
    #[cfg(target_os = "linux")]
    { linux::snapshot() }
    
    #[cfg(target_os = "windows")]
    { windows::snapshot() }
}