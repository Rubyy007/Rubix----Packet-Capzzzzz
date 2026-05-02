// src/capture/mod.rs
//! Production-grade packet capture module for RUBIX
//! Supports Linux (AF_PACKET/libpcap) and Windows (NPcap)

#![allow(dead_code)]

pub mod filter;

use async_trait::async_trait;
use crate::types::Packet;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

// ── Error types ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub enum CaptureError {
    InterfaceNotFound(String),
    PermissionDenied(String),
    InvalidFilter(String),
    AlreadyStarted,
    NotStarted,
    PcapError(String),
    UnsupportedPlatform(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::InterfaceNotFound(name) =>
                write!(f, "Network interface '{}' not found", name),
            CaptureError::PermissionDenied(msg) =>
                write!(f, "Permission denied: {}", msg),
            CaptureError::InvalidFilter(filter) =>
                write!(f, "Invalid BPF filter: {}", filter),
            CaptureError::AlreadyStarted =>
                write!(f, "Capture already started"),
            CaptureError::NotStarted =>
                write!(f, "Capture not started"),
            CaptureError::PcapError(msg) =>
                write!(f, "PCAP error: {}", msg),
            CaptureError::UnsupportedPlatform(msg) =>
                write!(f, "Unsupported platform: {}", msg),
        }
    }
}

impl Error for CaptureError {}

// ── Stats ─────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub packets_filtered: u64,
    pub bytes_received: u64,
    pub interface_speed_mbps: u64,
}

// ── Config ────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub promiscuous: bool,
    pub buffer_size_mb: usize,
    pub timeout_ms: i32,
    pub snaplen: i32,
    pub bpf_filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "auto".to_string(),
            promiscuous: true,
            buffer_size_mb: 64,
            timeout_ms: 10,
            snaplen: 65535,
            bpf_filter: Some("ip or ip6".to_string()),
        }
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────
#[async_trait]
pub trait CaptureBackend: Send + Sync {
    async fn start(&mut self) -> Result<(), CaptureError>;
    async fn stop(&mut self) -> Result<(), CaptureError>;
    async fn next_packet(&mut self) -> Option<Packet>;
    fn stats(&self) -> CaptureStats;
    fn config(&self) -> &CaptureConfig;
    fn is_running(&self) -> bool;
}

// ── Platform type alias ───────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub type PlatformCapture = linux::LinuxCapture;

#[cfg(target_os = "windows")]
pub type PlatformCapture = windows::WindowsCapture;

// ── Platform modules ──────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

// ── Interface info ────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    /// Human-readable display name (e.g. "Ethernet (Up)" on Windows)
    pub description: Option<String>,
    pub addresses: Vec<std::net::IpAddr>,
    pub is_loopback: bool,
    pub is_up: bool,
    /// Score used by auto-selection (higher = better)
    pub score: i32,
}

impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(desc) = &self.description {
            write!(f, " ({})", desc)?;
        }
        write!(f, " — up: {}, loopback: {}", self.is_up, self.is_loopback)
    }
}

// ── Windows adapter map via PowerShell ────────────────────────────────────────
// Returns UPPERCASE GUID → "FriendlyName (Status) [InterfaceDescription]"
// Including InterfaceDescription is critical — it contains "VirtualBox",
// "VMware" etc. which the friendly name alone may not reveal.
//
// Example output:
//   "04A954EE-..." → "Ethernet (Up) [Realtek PCIe GbE Family Controller]"
//   "1EACB5DE-..." → "Ethernet 3 (Up) [VirtualBox Host-Only Ethernet Adapter]"
#[cfg(target_os = "windows")]
fn get_windows_adapter_map() -> HashMap<String, String> {
    use std::process::Command;
    let mut map = HashMap::new();

    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            // 4 fields separated by | — GUID, Name, Status, InterfaceDescription
            "Get-NetAdapter | ForEach-Object { \
                $_.InterfaceGuid + '|' + \
                $_.Name + '|' + \
                $_.Status + '|' + \
                $_.InterfaceDescription \
            }",
        ])
        .output();

    if let Ok(out) = out {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.trim().splitn(4, '|').collect();
            if parts.len() == 4 {
                let guid = parts[0]
                    .trim()
                    .trim_matches('{')
                    .trim_matches('}')
                    .to_uppercase();

                // Full label includes description in brackets for virtual detection
                // Display label shows only "Name (Status)" for the banner
                let full_label = format!(
                    "{} ({}) [{}]",
                    parts[1].trim(),
                    parts[2].trim(),
                    parts[3].trim()
                );

                map.insert(guid, full_label);
            }
        }
    }

    map
}

#[cfg(not(target_os = "windows"))]
fn get_windows_adapter_map() -> HashMap<String, String> {
    HashMap::new()
}

// ── Extract display name from full label ──────────────────────────────────────
// Full label: "Ethernet (Up) [Realtek PCIe GbE Family Controller]"
// Display:    "Ethernet (Up)"
fn display_name_from_label(label: &str) -> String {
    label
        .split('[')
        .next()
        .unwrap_or(label)
        .trim()
        .to_string()
}

// ── Virtual adapter detection ─────────────────────────────────────────────────
// Checks both the friendly name AND the InterfaceDescription (in brackets).
// This catches "Ethernet 3 (Up) [VirtualBox Host-Only Ethernet Adapter]"
// which would otherwise score as physical because the friendly name looks real.
fn is_virtual_adapter(full_label: &str) -> bool {
    let n = full_label.to_lowercase();
    n.contains("virtualbox")
        || n.contains("vmware")
        || n.contains("hyper-v")
        || n.contains("vethernet")
        || n.contains("loopback")
        || n.contains("pseudo")
        || n.contains("tunnel")
        || n.contains("teredo")
        || n.contains("isatap")
        || n.contains("6to4")
        || n.contains("wan miniport")
        || n.contains("miniport")
        || n.contains("host-only")
        || n.contains("host only")
        || n.contains("nat network")
        || n.contains("internal network")
}

// ── Score a single device ─────────────────────────────────────────────────────
// Returns -1 to skip, otherwise 1-4 (higher = better candidate).
fn score_device(device: &pcap::Device, adapter_map: &HashMap<String, String>) -> i32 {
    let name_lower = device.name.to_lowercase();

    // Hard skip — never capture on these
    if name_lower.contains("loopback")
        || name_lower.contains("npf_lo")
        || name_lower == "lo"
        || name_lower.contains("any")
        || name_lower.starts_with("docker")
        || name_lower.starts_with("br-")
        || name_lower.starts_with("virbr")
        || name_lower.starts_with("veth")
    {
        return -1;
    }

    // Extract GUID from \Device\NPF_{GUID}
    let guid = device.name
        .split('{')
        .nth(1)
        .and_then(|s| s.split('}').next())
        .map(|s| s.to_uppercase());

    match &guid {
        Some(g) => match adapter_map.get(g) {
            Some(full_label) => {
                if is_virtual_adapter(full_label) {
                    -1 // virtual — skip entirely
                } else if full_label.to_lowercase().contains("(up)") {
                    4  // physical + confirmed Up — best possible
                } else {
                    3  // physical, status not confirmed Up
                }
            }
            None => {
                // GUID not in Windows adapter list
                if device.addresses.is_empty() { 1 } else { 2 }
            }
        },
        None => {
            // Linux-style name (eth0, enp3s0, wlan0, etc.)
            if device.addresses.is_empty() { 1 } else { 2 }
        }
    }
}

// ── Factory ───────────────────────────────────────────────────────────────────
pub struct CaptureFactory;

impl CaptureFactory {
    /// Create a capture backend for the current platform.
    pub fn create(config: CaptureConfig) -> Result<Box<dyn CaptureBackend>, CaptureError> {
        #[cfg(target_os = "linux")]
        { Ok(Box::new(linux::LinuxCapture::new(config)?)) }

        #[cfg(target_os = "windows")]
        { Ok(Box::new(windows::WindowsCapture::new(config)?)) }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        { Err(CaptureError::UnsupportedPlatform(std::env::consts::OS.to_string())) }
    }

    /// Automatically select the best interface for packet capture.
    ///
    /// Scoring (higher wins):
    ///   4 = physical adapter, confirmed Up
    ///   3 = physical adapter, status unknown
    ///   2 = non-loopback pcap device with IP addresses
    ///   1 = non-loopback pcap device without addresses
    ///  -1 = skip (loopback, virtual, docker, bridge)
    pub fn auto_select_interface() -> Option<String> {
        let devices = pcap::Device::list().ok()?;
        let adapter_map = get_windows_adapter_map();

        devices
            .iter()
            .filter_map(|d| {
                let s = score_device(d, &adapter_map);
                if s >= 0 { Some((s, &d.name)) } else { None }
            })
            .max_by_key(|(score, _)| *score)
            .map(|(_, name)| name.clone())
    }

    /// List all interfaces scored and sorted best-first.
    /// Used by both the banner display and interactive selection.
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
        let devices = pcap::Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;

        let adapter_map = get_windows_adapter_map();

        let mut interfaces: Vec<InterfaceInfo> = devices
            .into_iter()
            .filter(|d| {
                let name = d.name.to_lowercase();
                !name.starts_with("lo")
                    && !name.contains("loopback")
                    && !name.contains("any")
                    && !name.contains("dummy")
                    && !name.contains("virbr")
                    && !name.starts_with("docker")
                    && !name.starts_with("br-")
            })
            .map(|d| {
                let is_loopback = d.flags.is_loopback();
                let is_up       = d.flags.is_up();
                let score       = score_device(&d, &adapter_map);

                // Resolve display name from adapter map
                let description = {
                    let guid = d.name
                        .split('{')
                        .nth(1)
                        .and_then(|s| s.split('}').next())
                        .map(|s| s.to_uppercase());

                    guid.and_then(|g| adapter_map.get(&g))
                        // Show "Name (Status)" only — strip "[Description]" bracket
                        .map(|label| display_name_from_label(label))
                        .or(d.desc)
                };

                InterfaceInfo {
                    name: d.name,
                    description,
                    addresses: d.addresses.into_iter().map(|a| a.addr).collect(),
                    is_loopback,
                    is_up,
                    score,
                }
            })
            .collect();

        // Sort best-first so banner and selection list are in priority order
        interfaces.sort_by(|a, b| b.score.cmp(&a.score));

        Ok(interfaces)
    }

    /// Print all available interfaces to stdout for user selection.
    /// Called when no interface is configured and user needs to choose manually.
    pub fn print_interface_menu() {
        println!();
        println!("┌─ AVAILABLE NETWORK INTERFACES ───────────────────────────────┐");

        match Self::list_interfaces() {
            Ok(interfaces) => {
                if interfaces.is_empty() {
                    println!("│ ⚠️  No interfaces found — check Npcap/libpcap installation    │");
                } else {
                    for (i, iface) in interfaces.iter().enumerate() {
                        let display = iface.description
                            .as_deref()
                            .unwrap_or(&iface.name);

                        let display = if display.len() > 35 {
                            format!("{}...", &display[..32])
                        } else {
                            display.to_string()
                        };

                        let recommended = if i == 0 { " ← recommended" } else { "" };

                        println!(
                            "│  [{}] {:<35} {:<14} │",
                            i + 1,
                            display,
                            format!("{} addrs{}", iface.addresses.len(), recommended)
                        );
                    }
                }
            }
            Err(e) => {
                println!("│ ⚠️  Error listing interfaces: {:<30} │", e);
            }
        }

        println!("└──────────────────────────────────────────────────────────────┘");
        println!();
        println!("Set capture_interface in configs/rubix.windows.yaml to use a specific interface.");
        println!("Example: capture_interface: \"\\\\Device\\\\NPF_{{YOUR-GUID-HERE}}\"");
        println!();
    }
}