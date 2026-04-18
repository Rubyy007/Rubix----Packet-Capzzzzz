//! Production-grade packet capture module for RUBIX
//! Supports Linux (AF_PACKET/libpcap) and Windows (NPcap)

use async_trait::async_trait;
use crate::types::Packet;
use std::error::Error;
use std::fmt;

// Custom error types for capture module
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
            CaptureError::InterfaceNotFound(name) => write!(f, "Network interface '{}' not found", name),
            CaptureError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            CaptureError::InvalidFilter(filter) => write!(f, "Invalid BPF filter: {}", filter),
            CaptureError::AlreadyStarted => write!(f, "Capture already started"),
            CaptureError::NotStarted => write!(f, "Capture not started"),
            CaptureError::PcapError(msg) => write!(f, "PCAP error: {}", msg),
            CaptureError::UnsupportedPlatform(msg) => write!(f, "Unsupported platform: {}", msg),
        }
    }
}

impl Error for CaptureError {}

// Statistics structure
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub packets_filtered: u64,
    pub bytes_received: u64,
    pub interface_speed_mbps: u64,
}

// Capture configuration
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

// Main capture trait
#[async_trait]
pub trait CaptureBackend: Send + Sync {
    async fn start(&mut self) -> Result<(), CaptureError>;
    async fn stop(&mut self) -> Result<(), CaptureError>;
    async fn next_packet(&mut self) -> Option<Packet>;
    fn stats(&self) -> CaptureStats;
    fn config(&self) -> &CaptureConfig;
    fn is_running(&self) -> bool;
}

// Factory pattern for creating capture backends
pub struct CaptureFactory;

impl CaptureFactory {
    pub fn create(config: CaptureConfig) -> Result<Box<dyn CaptureBackend>, CaptureError> {
        #[cfg(target_os = "linux")]
        {
            use crate::capture::linux::LinuxCapture;
            Ok(Box::new(LinuxCapture::new(config)?))
        }
        
        #[cfg(target_os = "windows")]
        {
            use crate::capture::windows::WindowsCapture;
            Ok(Box::new(WindowsCapture::new(config)?))
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(CaptureError::UnsupportedPlatform(
                std::env::consts::OS.to_string()
            ))
        }
    }
    
    // List available interfaces - platform agnostic
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
        let devices = pcap::Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;
        
        let interfaces: Vec<InterfaceInfo> = devices
            .into_iter()
            .filter(|d| {
                let name_lower = d.name.to_lowercase();
                !name_lower.starts_with("lo") && 
                !name_lower.contains("any") &&
                !name_lower.contains("dummy") &&
                !name_lower.contains("virbr")
            })
            .map(|d| InterfaceInfo {
                name: d.name,
                description: d.desc,
                addresses: d.addresses.into_iter()
                    .map(|a| a.addr)  // FIXED: was filter_map, now map
                    .collect(),
                is_loopback: d.flags.is_loopback(),
                is_up: d.flags.is_up(),
            })
            .collect();
        
        Ok(interfaces)
    }
}

// Rich interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<std::net::IpAddr>,
    pub is_loopback: bool,
    pub is_up: bool,
}

impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (", self.name)?;
        if let Some(desc) = &self.description {
            write!(f, "{}, ", desc)?;
        }
        write!(f, "up: {}, loopback: {})", self.is_up, self.is_loopback)
    }
}

// Platform-specific modules
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;