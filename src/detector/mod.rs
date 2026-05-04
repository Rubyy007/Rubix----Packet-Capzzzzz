// src/detector/mod.rs
//! Threat detection engine for RUBIX
//!
//! Design constraints (enforced throughout):
//!   • Hot path (analyze_tcp / analyze_udp / analyze_icmp) must be zero-
//!     allocation. No Vec::push that reallocates, no format!, no Box.
//!   • Lock-free: ThreatTracker is owned by the single packet-loop task.
//!   • Alert suppression uses per-kind cooldowns, not a single global value.
//!   • Trust decisions are made with exact name matching (O(1) hash lookup),
//!     NOT prefix matching which is trivially bypassable by a malicious
//!     process naming itself "brave_backdoor.exe".

pub mod scan;
pub mod ping;
pub mod tracker;

pub use scan::ScanDetector;
pub use ping::PingDetector;
pub use tracker::ThreatTracker;

use std::net::IpAddr;
use std::time::Instant;

// ── Threat kinds ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThreatKind {
    PingSweep,
    PingFlood,
    SynScan,
    ConnectScan,
    NullScan,
    FinScan,
    XmasScan,
    AckScan,
    WindowScan,
    MaimonScan,
    UdpScan,
    OsScan,
    ServiceScan,
    NmapScripting,
    SynFlood,
}

impl ThreatKind {
    #[inline(always)]
    pub fn severity(&self) -> Severity {
        match self {
            ThreatKind::PingSweep     => Severity::Low,
            ThreatKind::PingFlood     => Severity::High,
            ThreatKind::SynScan       => Severity::High,
            ThreatKind::ConnectScan   => Severity::Medium,
            ThreatKind::NullScan      => Severity::High,
            ThreatKind::FinScan       => Severity::High,
            ThreatKind::XmasScan      => Severity::High,
            ThreatKind::AckScan       => Severity::Medium,
            ThreatKind::WindowScan    => Severity::Medium,
            ThreatKind::MaimonScan    => Severity::Medium,
            ThreatKind::UdpScan       => Severity::Medium,
            ThreatKind::OsScan        => Severity::Critical,
            ThreatKind::ServiceScan   => Severity::High,
            ThreatKind::NmapScripting => Severity::Critical,
            ThreatKind::SynFlood      => Severity::Critical,
        }
    }

    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatKind::PingSweep     => "PING_SWEEP",
            ThreatKind::PingFlood     => "PING_FLOOD",
            ThreatKind::SynScan       => "SYN_SCAN",
            ThreatKind::ConnectScan   => "CONNECT_SCAN",
            ThreatKind::NullScan      => "NULL_SCAN",
            ThreatKind::FinScan       => "FIN_SCAN",
            ThreatKind::XmasScan      => "XMAS_SCAN",
            ThreatKind::AckScan       => "ACK_SCAN",
            ThreatKind::WindowScan    => "WINDOW_SCAN",
            ThreatKind::MaimonScan    => "MAIMON_SCAN",
            ThreatKind::UdpScan       => "UDP_SCAN",
            ThreatKind::OsScan        => "OS_SCAN",
            ThreatKind::ServiceScan   => "SERVICE_SCAN",
            ThreatKind::NmapScripting => "NMAP_SCRIPTING",
            ThreatKind::SynFlood      => "SYN_FLOOD",
        }
    }

    #[inline(always)]
    pub fn alert_key(&self) -> AlertKey {
        match self {
            ThreatKind::PingSweep     => AlertKey::PingSweep,
            ThreatKind::PingFlood     => AlertKey::PingFlood,
            ThreatKind::SynScan       => AlertKey::SynScan,
            ThreatKind::ConnectScan   => AlertKey::ConnectScan,
            ThreatKind::NullScan      => AlertKey::NullScan,
            ThreatKind::FinScan       => AlertKey::FinScan,
            ThreatKind::XmasScan      => AlertKey::XmasScan,
            ThreatKind::AckScan       => AlertKey::AckScan,
            ThreatKind::WindowScan    => AlertKey::AckScan,   // share slot
            ThreatKind::MaimonScan    => AlertKey::OsScan,    // share slot
            ThreatKind::UdpScan       => AlertKey::UdpScan,
            ThreatKind::OsScan        => AlertKey::OsScan,
            ThreatKind::ServiceScan   => AlertKey::ConnectScan,
            ThreatKind::NmapScripting => AlertKey::OsScan,
            ThreatKind::SynFlood      => AlertKey::SynFlood,
        }
    }

    /// Per-kind cooldown in seconds.
    /// Floods use short cooldowns so ongoing attacks keep alerting.
    /// Scans use longer cooldowns to avoid alert storms.
    #[inline(always)]
    pub fn cooldown_secs(&self) -> u64 {
        match self {
            ThreatKind::SynFlood      => 10,
            ThreatKind::PingFlood     => 10,
            ThreatKind::SynScan       => 60,
            ThreatKind::ConnectScan   => 60,
            ThreatKind::NullScan      => 120,
            ThreatKind::FinScan       => 120,
            ThreatKind::XmasScan      => 120,
            ThreatKind::AckScan       => 60,
            ThreatKind::WindowScan    => 60,
            ThreatKind::MaimonScan    => 120,
            ThreatKind::UdpScan       => 60,
            ThreatKind::OsScan        => 120,
            ThreatKind::ServiceScan   => 60,
            ThreatKind::NmapScripting => 120,
            ThreatKind::PingSweep     => 30,
        }
    }
}

// ── Alert key — fixed enum so suppression table is a fixed-size array ─────────
//
// Using an enum index into a [Option<Instant>; N] array is faster and
// zero-allocation vs HashMap<&'static str, Instant>.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum AlertKey {
    PingSweep   = 0,
    PingFlood   = 1,
    SynScan     = 2,
    ConnectScan = 3,
    NullScan    = 4,
    FinScan     = 5,
    XmasScan    = 6,
    AckScan     = 7,
    UdpScan     = 8,
    OsScan      = 9,
    SynFlood    = 10,
}

pub const ALERT_KEY_COUNT: usize = 11;

// ── Severity ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl Severity {
    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low      => "LOW",
            Severity::Medium   => "MEDIUM",
            Severity::High     => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    #[inline(always)]
    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Low      => "[~]",
            Severity::Medium   => "[!]",
            Severity::High     => "[!!]",
            Severity::Critical => "[!!!]",
        }
    }

    #[inline(always)]
    pub fn color_ansi(&self) -> &'static str {
        match self {
            Severity::Low      => "\x1B[36m",
            Severity::Medium   => "\x1B[33m",
            Severity::High     => "\x1B[31m",
            Severity::Critical => "\x1B[35m",
        }
    }
}

// ── ThreatEvent ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatEvent {
    pub src_ip:    IpAddr,
    pub kind:      ThreatKind,
    pub severity:  Severity,
    pub detail:    &'static str,   // always a static string — zero allocation
    pub timestamp: Instant,
}

impl ThreatEvent {
    /// Sole constructor — static detail string only.
    /// All call sites use compile-time string literals; no format! in hot path.
    #[inline(always)]
    pub fn new(src_ip: IpAddr, kind: ThreatKind, detail: &'static str) -> Self {
        let severity = kind.severity();
        Self { src_ip, severity, detail, kind, timestamp: Instant::now() }
    }
}
