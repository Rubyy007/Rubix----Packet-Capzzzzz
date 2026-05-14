// src/capture/mod.rs
//! Production-grade packet capture module for RUBIX
//! Supports Linux (AF_PACKET/libpcap) and Windows (NPcap)
//!
//! Bug fixes applied in this file:
//!   #7  Windows adapter status detection assumed English locale — now uses
//!       numeric IfOperStatus (1 = Up) from PowerShell, locale-independent.
//!   #8  resolve_interface filtered interfaces with no IP — now only skips
//!       loopback and down interfaces (handled in linux.rs score function).
//!   #9  score_device ignored is_up on Linux — Linux scoring now calls
//!       score_linux_device() in linux.rs; mod.rs score_device is Windows-only.

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
//
// Bug #7 fix: the previous version emitted `$_.Status` which returns a
// locale-dependent string ("Up", "Operational", translated strings on
// non-English Windows).
//
// The fix uses `$_.IfOperStatus` which is a numeric NDIS enum:
//   1 = Up
//   2 = Down
//   3 = Testing
//   4 = Unknown
//   5 = Dormant
//   6 = NotPresent
//   7 = LowerLayerDown
//
// We emit the raw integer and compare against 1 in `score_device_windows()`.
// This is locale-independent and guaranteed stable across all Windows
// versions that expose the Get-NetAdapter cmdlet (Windows 8+ / Server 2012+).
//
// Output format: UPPERCASE_GUID|FriendlyName|IfOperStatus(int)|InterfaceDescription
// Example:
//   "04A954EE-...|Ethernet|1|Realtek PCIe GbE Family Controller"
//   "1EACB5DE-...|Ethernet 3|1|VirtualBox Host-Only Ethernet Adapter"
#[cfg(target_os = "windows")]
fn get_windows_adapter_map() -> HashMap<String, WindowsAdapterInfo> {
    use std::process::Command;
    let mut map = HashMap::new();

    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            // 4 fields separated by | — GUID, Name, IfOperStatus(int), InterfaceDescription
            "Get-NetAdapter | ForEach-Object { \
                $_.InterfaceGuid + '|' + \
                $_.Name + '|' + \
                [int]$_.IfOperStatus + '|' + \
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

                // Parse IfOperStatus as integer — Bug #7 fix.
                let if_oper_status: u32 = parts[2].trim().parse().unwrap_or(0);

                let info = WindowsAdapterInfo {
                    friendly_name:        parts[1].trim().to_string(),
                    if_oper_status,
                    interface_description: parts[3].trim().to_string(),
                };

                map.insert(guid, info);
            }
        }
    }

    map
}

/// Parsed Windows adapter information from Get-NetAdapter.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct WindowsAdapterInfo {
    /// Friendly name: "Ethernet", "Wi-Fi", "Ethernet 3", etc.
    friendly_name:        String,
    /// NDIS IfOperStatus numeric value.
    ///   1 = Up, 2 = Down, 3+ = degraded states.
    /// Bug #7 fix: integer comparison replaces string comparison.
    if_oper_status:       u32,
    /// Full InterfaceDescription: "Realtek PCIe GbE Family Controller", etc.
    interface_description: String,
}

#[cfg(target_os = "windows")]
impl WindowsAdapterInfo {
    /// Returns true only when IfOperStatus == 1 (Up), regardless of locale.
    /// Bug #7 fix: replaces the old contains("(up)") string check.
    fn is_up(&self) -> bool {
        self.if_oper_status == 1
    }

    /// Full label for display and virtual-adapter detection.
    /// Format: "FriendlyName [InterfaceDescription]"
    fn full_label(&self) -> String {
        format!("{} [{}]", self.friendly_name, self.interface_description)
    }

    /// Display label for the interface menu.
    /// Format: "FriendlyName (Up)" or "FriendlyName (Down)"
    fn display_label(&self) -> String {
        let status = if self.is_up() { "Up" } else { "Down" };
        format!("{} ({})", self.friendly_name, status)
    }
}

#[cfg(not(target_os = "windows"))]
fn get_windows_adapter_map() -> HashMap<String, ()> {
    HashMap::new()
}

// ── Virtual adapter detection ─────────────────────────────────────────────────
// Checks both the friendly name AND the InterfaceDescription.
// This catches "Ethernet 3 [VirtualBox Host-Only Ethernet Adapter]" which
// would otherwise score as physical because the friendly name looks real.
#[cfg(target_os = "windows")]
fn is_virtual_adapter(info: &WindowsAdapterInfo) -> bool {
    let n = info.full_label().to_lowercase();
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

// ── Score a single device (Windows path) ─────────────────────────────────────
//
// Returns -1 to skip, otherwise 1–4 (higher = better candidate).
//
// Bug #7 fix: is_up() now compares IfOperStatus == 1 (integer) rather than
// checking for the English string "(up)".
#[cfg(target_os = "windows")]
fn score_device(
    device:      &pcap::Device,
    adapter_map: &HashMap<String, WindowsAdapterInfo>,
) -> i32 {
    let name_lower = device.name.to_lowercase();

    // Hard skip — never capture on these.
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

    // Extract GUID from \Device\NPF_{GUID}.
    let guid = device.name
        .split('{')
        .nth(1)
        .and_then(|s| s.split('}').next())
        .map(|s| s.to_uppercase());

    match &guid {
        Some(g) => match adapter_map.get(g) {
            Some(info) => {
                if is_virtual_adapter(info) {
                    -1 // virtual — skip entirely
                } else if info.is_up() {
                    // Bug #7 fix: integer comparison, not locale string.
                    4  // physical + confirmed Up — best possible
                } else {
                    3  // physical, status not Up
                }
            }
            None => {
                // GUID not in Windows adapter list.
                if device.addresses.is_empty() { 1 } else { 2 }
            }
        },
        None => {
            // No GUID in device name — shouldn't happen on Windows NPcap but
            // handle gracefully.
            if device.addresses.is_empty() { 1 } else { 2 }
        }
    }
}

// ── Linux score_device shim ───────────────────────────────────────────────────
//
// On Linux, scoring lives in linux.rs (score_linux_device) where it has
// access to pcap::DeviceFlags.  This shim is used only by list_interfaces()
// for display purposes when building the InterfaceInfo list on Linux.
//
// Bug #9 fix: is_up() flag is checked via d.flags.is_up(); down interfaces
// return -1.
#[cfg(not(target_os = "windows"))]
fn score_device(device: &pcap::Device, _adapter_map: &HashMap<String, ()>) -> i32 {
    let name = device.name.to_lowercase();

    if name == "lo"
        || name.starts_with("lo:")
        || name.contains("loopback")
        || name.contains("any")
        || name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("virbr")
        || name.starts_with("veth")
    {
        return -1;
    }

    // Bug #9 fix: exclude down interfaces from scoring.
    if !device.flags.is_up() {
        return -1;
    }

    if !device.addresses.is_empty() { 3 } else { 2 }
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
    ///   4 = physical adapter, confirmed Up  (Windows: IfOperStatus == 1)
    ///   3 = physical adapter, status unknown / Linux up + has IPs
    ///   2 = non-loopback pcap device with IP addresses (Linux up + no IPs)
    ///   1 = non-loopback pcap device without addresses
    ///  -1 = skip (loopback, virtual, docker, bridge, down)
    pub fn auto_select_interface() -> Option<String> {
        let devices     = pcap::Device::list().ok()?;
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
        let devices     = pcap::Device::list()
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

                // Resolve display name from adapter map (Windows only).
                // On Linux, d.desc is the fallback.
                #[cfg(target_os = "windows")]
                let description = {
                    let guid = d.name
                        .split('{')
                        .nth(1)
                        .and_then(|s| s.split('}').next())
                        .map(|s| s.to_uppercase());

                    guid.and_then(|g| adapter_map.get(&g))
                        // Bug #7 fix: display_label() uses IfOperStatus integer.
                        .map(|info| info.display_label())
                        .or(d.desc)
                };

                #[cfg(not(target_os = "windows"))]
                let description = d.desc;

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

        // Sort best-first so banner and selection list are in priority order.
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
