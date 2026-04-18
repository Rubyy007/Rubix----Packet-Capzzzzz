//! Linux production implementation using libpcap with AF_PACKET
//! Optimized for high-throughput packet capture

use super::*;
use crate::types::Protocol;  // FIXED: Added missing import
use async_trait::async_trait;
use pcap::{Capture, Device, Active};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
//use std::time::Instant;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use tracing::{info, debug};  // FIXED: Removed unused warn, error

pub struct LinuxCapture {
    config: CaptureConfig,
    capture: Arc<Mutex<Option<Capture<Active>>>>,
    stats: Arc<CaptureStatsInternal>,
    running: Arc<AtomicBool>,
}

struct CaptureStatsInternal {
    packets_received: AtomicU64,
    packets_dropped: AtomicU64,
    packets_filtered: AtomicU64,
    bytes_received: AtomicU64,
    current_second_packets: AtomicU64,
}

impl LinuxCapture {
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        let device = Self::resolve_interface(&config.interface)?;
        
        info!("Initializing capture on interface: {}", device.name);
        
        Ok(Self {
            config,
            capture: Arc::new(Mutex::new(None)),
            stats: Arc::new(CaptureStatsInternal {
                packets_received: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
                packets_filtered: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                current_second_packets: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(false)),
        })
    }
    
    fn resolve_interface(interface: &str) -> Result<Device, CaptureError> {
        let devices = Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;
        
        if interface == "auto" {
            devices.into_iter()
                .find(|d| {
                    !d.name.starts_with("lo") && 
                    !d.name.contains("any") &&
                    !d.addresses.is_empty()  // FIXED: Check if addresses vec is not empty
                })
                .ok_or(CaptureError::InterfaceNotFound("No suitable interface found".to_string()))
        } else {
            devices.into_iter()
                .find(|d| d.name == interface)
                .ok_or_else(|| CaptureError::InterfaceNotFound(interface.to_string()))
        }
    }
    
    fn create_capture_handle(&self, device: Device) -> Result<Capture<Active>, CaptureError> {
        let mut cap = Capture::from_device(device)
            .map_err(|e| CaptureError::PcapError(e.to_string()))?
            .timeout(self.config.timeout_ms)
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen)
            .buffer_size((self.config.buffer_size_mb * 1024 * 1024) as i32)  // FIXED: Cast to i32
            .open()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;
        
        if let Some(filter) = &self.config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| CaptureError::InvalidFilter(e.to_string()))?;
            debug!("Applied BPF filter: {}", filter);
        }
        
        Ok(cap)
    }
    
    #[inline]
    fn parse_packet(data: &[u8]) -> Option<Packet> {
        // FIXED: Use from_ethernet_slice instead of from_ethernet
        let parsed = match etherparse::PacketHeaders::from_ethernet_slice(data) {
            Ok(p) => p,
            Err(_) => return None,
        };
        
        let (src_ip, dst_ip) = match parsed.ip {
            Some(etherparse::IpHeader::Version4(ip, _)) => (
                IpAddr::V4(Ipv4Addr::from(ip.source)),
                IpAddr::V4(Ipv4Addr::from(ip.destination)),
            ),
            Some(etherparse::IpHeader::Version6(ip, _)) => (
                IpAddr::V6(Ipv6Addr::from(ip.source)),
                IpAddr::V6(Ipv6Addr::from(ip.destination)),
            ),
            None => return None,
        };
        
        // FIXED: Use correct field names (source_port, destination_port)
        let (src_port, dst_port, protocol) = match parsed.transport {
            Some(etherparse::TransportHeader::Tcp(tcp)) => {
                (tcp.source_port, tcp.destination_port, Protocol::Tcp)
            }
            Some(etherparse::TransportHeader::Udp(udp)) => {
                (udp.source_port, udp.destination_port, Protocol::Udp)
            }
            Some(etherparse::TransportHeader::Icmpv4(_)) => {  // FIXED: Icmpv4 not Icmp
                (0, 0, Protocol::Icmp)
            }
            Some(etherparse::TransportHeader::Icmpv6(_)) => {  // FIXED: Added Icmpv6
                (0, 0, Protocol::Icmpv6)
            }
            _ => (0, 0, Protocol::Other(0)),
        };
        
        Some(Packet::new(
            src_ip, dst_ip, src_port, dst_port, protocol, data.len()
        ))
    }
}

#[async_trait]
impl CaptureBackend for LinuxCapture {
    async fn start(&mut self) -> Result<(), CaptureError> {
        if self.is_running() {
            return Err(CaptureError::AlreadyStarted);
        }
        
        let device = Self::resolve_interface(&self.config.interface)?;
        let cap = self.create_capture_handle(device)?;
        
        let mut capture_guard = self.capture.lock().await;
        *capture_guard = Some(cap);
        drop(capture_guard);
        
        self.running.store(true, Ordering::SeqCst);
        
        let stats = self.stats.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            while running.load(Ordering::Relaxed) {
                interval.tick().await;
                stats.current_second_packets.store(0, Ordering::Relaxed);
            }
        });
        
        info!("Packet capture started on {}", self.config.interface);
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<(), CaptureError> {
        if !self.is_running() {
            return Err(CaptureError::NotStarted);
        }
        
        self.running.store(false, Ordering::SeqCst);
        let mut capture_guard = self.capture.lock().await;
        *capture_guard = None;
        
        info!("Packet capture stopped");
        Ok(())
    }
    
    async fn next_packet(&mut self) -> Option<Packet> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }
        
        let capture = self.capture.clone();
        let stats = self.stats.clone();
        
        let result = spawn_blocking(move || {
            let mut guard = capture.blocking_lock();
            let cap = guard.as_mut()?;
            
            match cap.next_packet() {
                Ok(packet) => {
                    let packet_len = packet.data.len();
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_received.fetch_add(packet_len as u64, Ordering::Relaxed);
                    stats.current_second_packets.fetch_add(1, Ordering::Relaxed);
                    Some(packet.data.to_vec())
                }
                Err(pcap::Error::TimeoutExpired) => None,
                Err(e) => {
                    stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    debug!("Capture error: {}", e);
                    None
                }
            }
        }).await.ok()??;
        
        Self::parse_packet(&result)
    }
    
    fn stats(&self) -> CaptureStats {
        let pps = self.stats.current_second_packets.load(Ordering::Relaxed);
        
        CaptureStats {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            packets_filtered: self.stats.packets_filtered.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            interface_speed_mbps: pps.saturating_mul(1500 * 8) / 1_000_000,
        }
    }
    
    fn config(&self) -> &CaptureConfig {
        &self.config
    }
    
    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}