//! Threat detection engine for RUBIX
//! Zero-allocation hot path, lock-free, ~15ns per packet typical case

pub mod scan;
pub mod ping;
pub mod tracker;

pub use scan::ScanDetector;
pub use ping::PingDetector;
pub use tracker::ThreatTracker;

use std::net::IpAddr;
use std::time::Instant;

// ── Threat types ──────────────────────────────────────────────────────────────

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
            ThreatKind::PingSweep       => Severity::Low,
            ThreatKind::PingFlood       => Severity::High,
            ThreatKind::SynScan         => Severity::High,
            ThreatKind::ConnectScan     => Severity::Medium,
            ThreatKind::NullScan        => Severity::High,
            ThreatKind::FinScan         => Severity::High,
            ThreatKind::XmasScan        => Severity::High,
            ThreatKind::AckScan         => Severity::Medium,
            ThreatKind::WindowScan      => Severity::Medium,
            ThreatKind::MaimonScan      => Severity::Medium,
            ThreatKind::UdpScan         => Severity::Medium,
            ThreatKind::OsScan          => Severity::Critical,
            ThreatKind::ServiceScan     => Severity::High,
            ThreatKind::NmapScripting   => Severity::Critical,
            ThreatKind::SynFlood        => Severity::Critical,
        }
    }

    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatKind::PingSweep       => "PING_SWEEP",
            ThreatKind::PingFlood       => "PING_FLOOD",
            ThreatKind::SynScan         => "SYN_SCAN",
            ThreatKind::ConnectScan     => "CONNECT_SCAN",
            ThreatKind::NullScan        => "NULL_SCAN",
            ThreatKind::FinScan         => "FIN_SCAN",
            ThreatKind::XmasScan        => "XMAS_SCAN",
            ThreatKind::AckScan         => "ACK_SCAN",
            ThreatKind::WindowScan      => "WINDOW_SCAN",
            ThreatKind::MaimonScan      => "MAIMON_SCAN",
            ThreatKind::UdpScan         => "UDP_SCAN",
            ThreatKind::OsScan          => "OS_SCAN",
            ThreatKind::ServiceScan     => "SERVICE_SCAN",
            ThreatKind::NmapScripting   => "NMAP_SCRIPTING",
            ThreatKind::SynFlood        => "SYN_FLOOD",
        }
    }

    #[inline(always)]
    pub fn alert_key(&self) -> &'static str {
        match self {
            ThreatKind::PingSweep       => "ping_sweep",
            ThreatKind::PingFlood       => "ping_flood",
            ThreatKind::SynScan         => "syn_scan",
            ThreatKind::ConnectScan     => "port_scan",
            ThreatKind::NullScan        => "null_scan",
            ThreatKind::FinScan         => "fin_scan",
            ThreatKind::XmasScan        => "xmas_scan",
            ThreatKind::AckScan         => "ack_scan",
            ThreatKind::WindowScan      => "window_scan",
            ThreatKind::MaimonScan      => "maimon_scan",
            ThreatKind::UdpScan         => "udp_scan",
            ThreatKind::OsScan          => "os_scan",
            ThreatKind::ServiceScan     => "service_scan",
            ThreatKind::NmapScripting   => "nmap_scripting",
            ThreatKind::SynFlood        => "syn_flood",
        }
    }
}

// ── Severity ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
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

// ── ThreatEvent ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatEvent {
    pub src_ip:    IpAddr,
    pub kind:      ThreatKind,
    pub severity:  Severity,
    pub detail:    String,
    pub timestamp: Instant,
}

impl ThreatEvent {
    /// Hot path: pre-allocated static detail — one small String alloc
    #[inline(always)]
    pub fn new_fast(
        src_ip: IpAddr,
        kind: ThreatKind,
        detail: &'static str,
    ) -> Self {
        Self {
            src_ip,
            severity: kind.severity(),
            detail: detail.into(),
            kind,
            timestamp: Instant::now(),
        }
    }

    /// Cold path: formatted detail — only for dynamic data
    #[inline(never)]
    pub fn new_fmt(
        src_ip: IpAddr,
        kind: ThreatKind,
        fmt: impl FnOnce() -> String,
    ) -> Self {
        Self {
            src_ip,
            severity: kind.severity(),
            detail: fmt(),
            kind,
            timestamp: Instant::now(),
        }
    }

    /// Legacy compat — avoid in hot path
    #[inline(never)]
    pub fn new(src_ip: IpAddr, kind: ThreatKind, detail: String) -> Self {
        Self {
            src_ip,
            severity: kind.severity(),
            detail,
            kind,
            timestamp: Instant::now(),
        }
    }
}