//! Threat detection engine for RUBIX
//! Detects: ping sweeps, port scans, nmap fingerprinting, SYN floods

pub mod scan;
pub mod ping;
pub mod tracker;

pub use scan::ScanDetector;
pub use ping::PingDetector;
pub use tracker::ThreatTracker;

use std::net::IpAddr;
use crate::types::Packet;

// ── Threat types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatKind {
    // Ping / ICMP
    PingSweep,          // ICMP echo requests from same IP
    PingFlood,          // High-rate ICMP

    // Port scanning
    SynScan,            // nmap -sS (half-open SYN scan)
    ConnectScan,        // nmap -sT (full connect scan)
    NullScan,           // nmap -sN (no flags set)
    FinScan,            // nmap -sF (only FIN flag)
    XmasScan,           // nmap -sX (FIN+PSH+URG)
    UdpScan,            // nmap -sU (UDP scan)
    WindowScan,         // nmap -sW
    AckScan,            // nmap -sA (firewall mapping)
    PortSweep,          // Same port, many IPs (horizontal scan)
    SequentialScan,     // Sequential port scan (vertical scan)

    // Fingerprinting
    OsScan,             // nmap -O (OS detection)
    ServiceScan,        // nmap -sV (service version detection)
    NmapScripting,      // nmap -sC (default scripts)

    // Floods
    SynFlood,           // SYN flood DoS attempt
}

impl ThreatKind {
    pub fn severity(&self) -> Severity {
        match self {
            ThreatKind::PingSweep       => Severity::Low,
            ThreatKind::PingFlood       => Severity::Medium,
            ThreatKind::SynScan         => Severity::High,
            ThreatKind::ConnectScan     => Severity::Medium,
            ThreatKind::NullScan        => Severity::High,
            ThreatKind::FinScan         => Severity::High,
            ThreatKind::XmasScan        => Severity::High,
            ThreatKind::UdpScan         => Severity::Medium,
            ThreatKind::WindowScan      => Severity::Medium,
            ThreatKind::AckScan         => Severity::Medium,
            ThreatKind::PortSweep       => Severity::High,
            ThreatKind::SequentialScan  => Severity::High,
            ThreatKind::OsScan          => Severity::Critical,
            ThreatKind::ServiceScan     => Severity::High,
            ThreatKind::NmapScripting   => Severity::Critical,
            ThreatKind::SynFlood        => Severity::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatKind::PingSweep       => "PING_SWEEP",
            ThreatKind::PingFlood       => "PING_FLOOD",
            ThreatKind::SynScan         => "SYN_SCAN",
            ThreatKind::ConnectScan     => "CONNECT_SCAN",
            ThreatKind::NullScan        => "NULL_SCAN",
            ThreatKind::FinScan         => "FIN_SCAN",
            ThreatKind::XmasScan        => "XMAS_SCAN",
            ThreatKind::UdpScan         => "UDP_SCAN",
            ThreatKind::WindowScan      => "WINDOW_SCAN",
            ThreatKind::AckScan         => "ACK_SCAN",
            ThreatKind::PortSweep       => "PORT_SWEEP",
            ThreatKind::SequentialScan  => "SEQUENTIAL_SCAN",
            ThreatKind::OsScan          => "OS_SCAN",
            ThreatKind::ServiceScan     => "SERVICE_SCAN",
            ThreatKind::NmapScripting   => "NMAP_SCRIPTING",
            ThreatKind::SynFlood        => "SYN_FLOOD",
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low      => "LOW",
            Severity::Medium   => "MEDIUM",
            Severity::High     => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Low      => "[~]",
            Severity::Medium   => "[!]",
            Severity::High     => "[!!]",
            Severity::Critical => "[!!!]",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatEvent {
    pub src_ip:    IpAddr,
    pub kind:      ThreatKind,
    pub severity:  Severity,
    pub detail:    String,
    pub timestamp: std::time::Instant,
}

impl ThreatEvent {
    pub fn new(src_ip: IpAddr, kind: ThreatKind, detail: String) -> Self {
        let severity = kind.severity();
        Self {
            src_ip,
            kind,
            severity,
            detail,
            timestamp: std::time::Instant::now(),
        }
    }
}