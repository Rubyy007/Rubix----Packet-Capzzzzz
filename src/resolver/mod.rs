// src/resolver/mod.rs
//! High-performance process attribution engine.
//!
//! Answers one question per packet: which process on this machine owns the
//! socket that sent or received this traffic?
//!
//! Architecture:
//!   mod.rs      — public types (FlowKey, ProcessInfo, Protocol) + platform
//!                 dispatch for snapshot().
//!   cache.rs    — ProcessResolver: 1-second TTL cache with background async
//!                 refresh.  This is the only type main.rs touches.
//!   linux.rs    — /proc/net/{tcp,udp,tcp6,udp6} → inode → /proc/<pid>/fd
//!   windows.rs  — GetExtendedTcpTable / GetExtendedUdpTable + OpenProcess
//!
//! Hot-path guarantee:
//!   ProcessResolver::lookup() is ~5 ns on the fast path (TTL not expired).
//!   It never calls snapshot() directly — that happens in a background task.
//!
//! Cross-platform: all platform-specific code is gated behind cfg attributes.
//!   The public API (ProcessResolver, FlowKey, ProcessInfo, Protocol) is
//!   identical on Linux and Windows.

mod cache;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

use std::collections::HashMap;
use std::net::IpAddr;

// ── Public types ──────────────────────────────────────────────────────────────

/// The resolved process that owns a socket.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// OS process ID.
    pub pid:  u32,
    /// Process image name.
    ///   Windows: "chrome.exe" (filename component of the full image path)
    ///   Linux:   "chrome"     (/proc/{pid}/stat comm field, max 15 chars)
    pub name: String,
}

/// Lookup key: uniquely identifies a local socket endpoint.
///
/// The resolver maps (local_ip, local_port, protocol) → ProcessInfo.
/// In main.rs the packet loop tries src side first, then dst side — one of
/// them will be the local socket.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub local_ip:   IpAddr,
    pub local_port: u16,
    pub protocol:   Protocol,
}

/// Transport protocol discriminant used in FlowKey.
///
/// `repr(u8)` with explicit wire values so `from_u8` is a const match with
/// no branches for the common TCP/UDP/ICMP cases.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(u8)]
pub enum Protocol {
    Tcp      = 6,
    Udp      = 17,
    Icmp     = 1,
    Other(u8),
}

impl Protocol {
    /// Convert a protocol name string to a Protocol variant.
    ///
    /// Matches on raw bytes to avoid UTF-8 overhead — the strings come from
    /// `packet.protocol.to_string()` which always produces ASCII.
    #[inline(always)]
    pub fn from_str(s: &str) -> Self {
        match s.as_bytes() {
            b"TCP"  | b"tcp"  => Protocol::Tcp,
            b"UDP"  | b"udp"  => Protocol::Udp,
            b"ICMP" | b"icmp" => Protocol::Icmp,
            _                 => Protocol::Other(0),
        }
    }

    /// Convert an IP protocol number to a Protocol variant.
    #[inline(always)]
    pub const fn from_u8(proto: u8) -> Self {
        match proto {
            6  => Protocol::Tcp,
            17 => Protocol::Udp,
            1  => Protocol::Icmp,
            p  => Protocol::Other(p),
        }
    }

    /// Return the IP protocol number for this variant.
    #[inline(always)]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Protocol::Tcp      => 6,
            Protocol::Udp      => 17,
            Protocol::Icmp     => 1,
            Protocol::Other(n) => *n,
        }
    }

    /// Return a static ASCII string for this variant.
    #[inline(always)]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp      => "TCP",
            Protocol::Udp      => "UDP",
            Protocol::Icmp     => "ICMP",
            Protocol::Other(_) => "OTHER",
        }
    }
}

impl std::fmt::Display for Protocol {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Other(n) => write!(f, "PROTO({})", n),
            _                  => f.write_str(self.as_str()),
        }
    }
}

// ── Public surface ────────────────────────────────────────────────────────────

pub use cache::ProcessResolver;

// ── Internal snapshot type ────────────────────────────────────────────────────

/// A full point-in-time snapshot of all local sockets → owning process.
/// Produced by linux::snapshot() or windows::snapshot() and stored in the
/// ProcessResolver cache.
pub(crate) type SnapshotResult =
    Result<HashMap<FlowKey, ProcessInfo>, Box<dyn std::error::Error + Send + Sync>>;

/// Platform dispatch: call the correct snapshot implementation.
///
/// Called from the background refresh task in cache.rs — never from the
/// hot path directly.
pub(crate) fn snapshot() -> SnapshotResult {
    #[cfg(target_os = "linux")]
    { linux::snapshot() }

    #[cfg(target_os = "windows")]
    { windows::snapshot() }
}