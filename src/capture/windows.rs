// src/capture/windows.rs
//! Windows production packet capture using NPcap (libpcap-compatible API)

use super::{CaptureBackend, CaptureConfig, CaptureError, CaptureStats};
use crate::types::{Packet, Protocol};
use async_trait::async_trait;
use pcap::{Active, Capture, Device};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use tracing::{debug, info};

pub struct WindowsCapture {
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

impl WindowsCapture {
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        // Validate the interface exists at construction time
        let device = Self::resolve_interface(&config.interface)?;
        info!("Initialising Windows capture on: {}", device.name);

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

    /// Resolve interface name to a pcap Device.
    /// Accepts full NPcap device names (\Device\NPF_{GUID})
    /// or "auto" to pick the best available interface.
    fn resolve_interface(interface: &str) -> Result<Device, CaptureError> {
        let devices = Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;

        if interface == "auto" {
            // Use the same scoring logic as CaptureFactory::auto_select_interface
            // but inline here since we need a Device not just a name
            devices
                .into_iter()
                .find(|d| {
                    let n = d.name.to_lowercase();
                    !n.contains("loopback")
                        && !n.contains("npf_lo")
                        && !n.contains("any")
                })
                .ok_or_else(|| {
                    CaptureError::InterfaceNotFound(
                        "No suitable interface found".to_string()
                    )
                })
        } else {
            devices
                .into_iter()
                .find(|d| d.name == interface)
                .ok_or_else(|| CaptureError::InterfaceNotFound(interface.to_string()))
        }
    }

    /// Open and configure the pcap capture handle.
    fn open_capture(&self, device: Device) -> Result<Capture<Active>, CaptureError> {
        let mut cap = Capture::from_device(device)
            .map_err(|e| CaptureError::PcapError(e.to_string()))?
            .timeout(self.config.timeout_ms)
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen)
            .buffer_size((self.config.buffer_size_mb * 1024 * 1024) as i32)
            .open()
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("permission") || msg.contains("access") {
                    CaptureError::PermissionDenied(
                        "Run as Administrator for packet capture".to_string()
                    )
                } else {
                    CaptureError::PcapError(msg)
                }
            })?;

        if let Some(filter) = &self.config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| CaptureError::InvalidFilter(e.to_string()))?;
            debug!("Applied BPF filter: {}", filter);
        }

        Ok(cap)
    }

    /// Parse raw packet bytes into a typed Packet struct.
    /// Returns None if the packet is not IP or cannot be parsed.
    #[inline]
    fn parse_packet(data: &[u8]) -> Option<Packet> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(data).ok()?;

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

        let (src_port, dst_port, protocol) = match parsed.transport {
            Some(etherparse::TransportHeader::Tcp(tcp)) => {
                (tcp.source_port, tcp.destination_port, Protocol::Tcp)
            }
            Some(etherparse::TransportHeader::Udp(udp)) => {
                (udp.source_port, udp.destination_port, Protocol::Udp)
            }
            Some(etherparse::TransportHeader::Icmpv4(_)) => {
                (0, 0, Protocol::Icmp)
            }
            Some(etherparse::TransportHeader::Icmpv6(_)) => {
                (0, 0, Protocol::Icmpv6)
            }
            _ => (0, 0, Protocol::Other(0)),
        };

        Some(Packet::new(
            src_ip, dst_ip, src_port, dst_port, protocol, data.len(),
        ))
    }
}

#[async_trait]
impl CaptureBackend for WindowsCapture {
    async fn start(&mut self) -> Result<(), CaptureError> {
        if self.is_running() {
            return Err(CaptureError::AlreadyStarted);
        }

        let device = Self::resolve_interface(&self.config.interface)?;
        let cap = self.open_capture(device)?;

        {
            let mut guard = self.capture.lock().await;
            *guard = Some(cap);
        }

        self.running.store(true, Ordering::SeqCst);

        // Background task: reset per-second counter every second for pps stats
        let stats = self.stats.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(1));
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

        let mut guard = self.capture.lock().await;
        *guard = None; // Drops the Capture handle, closing the device

        info!("Packet capture stopped");
        Ok(())
    }

    async fn next_packet(&mut self) -> Option<Packet> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }

        let capture = self.capture.clone();
        let stats = self.stats.clone();

        // pcap's next_packet() is blocking — run it on the blocking thread pool
        // so it doesn't stall the async runtime
        let raw = spawn_blocking(move || {
            let mut guard = capture.blocking_lock();
            let cap = guard.as_mut()?;

            match cap.next_packet() {
                Ok(packet) => {
                    let len = packet.data.len() as u64;
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_received.fetch_add(len, Ordering::Relaxed);
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
        })
        .await
        .ok()??;

        Self::parse_packet(&raw)
    }

    fn stats(&self) -> CaptureStats {
        let pps = self.stats.current_second_packets.load(Ordering::Relaxed);
        CaptureStats {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            packets_filtered: self.stats.packets_filtered.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            // Rough estimate: pps × avg_frame_size × bits_per_byte / bits_per_megabit
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