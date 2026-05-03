// src/capture/windows.rs
//! Windows production packet capture using NPcap (libpcap-compatible API)
//!
//! Uses etherparse 0.15+ API:
//!   - parsed.net              (was parsed.ip)
//!   - NetHeaders::Ipv4        (was IpHeader::Version4)
//!   - NetHeaders::Ipv6        (was IpHeader::Version6)

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

// ── Capture handle ────────────────────────────────────────────────────────────

pub struct WindowsCapture {
    config:  CaptureConfig,
    capture: Arc<Mutex<Option<Capture<Active>>>>,
    stats:   Arc<CaptureStatsInternal>,
    running: Arc<AtomicBool>,
}

// ── Internal stats (all atomic — hot path safe) ───────────────────────────────

struct CaptureStatsInternal {
    packets_received:        AtomicU64,
    packets_dropped:         AtomicU64,
    packets_filtered:        AtomicU64,
    bytes_received:          AtomicU64,
    current_second_packets:  AtomicU64,
}

impl CaptureStatsInternal {
    fn new() -> Self {
        Self {
            packets_received:        AtomicU64::new(0),
            packets_dropped:         AtomicU64::new(0),
            packets_filtered:        AtomicU64::new(0),
            bytes_received:          AtomicU64::new(0),
            current_second_packets:  AtomicU64::new(0),
        }
    }
}

// ── Implementation ────────────────────────────────────────────────────────────

impl WindowsCapture {
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        let device = Self::resolve_interface(&config.interface)?;
        info!("Initialising Windows capture on: {}", device.name);

        Ok(Self {
            config,
            capture: Arc::new(Mutex::new(None)),
            stats:   Arc::new(CaptureStatsInternal::new()),
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    // ── Interface resolution ──────────────────────────────────────────────────

    /// Resolve interface name → pcap Device.
    /// Accepts full NPcap device names (\Device\NPF_{GUID}) or "auto".
    fn resolve_interface(interface: &str) -> Result<Device, CaptureError> {
        let devices = Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;

        if interface == "auto" {
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
                        "No suitable interface found for auto-selection".to_string(),
                    )
                })
        } else {
            devices
                .into_iter()
                .find(|d| d.name == interface)
                .ok_or_else(|| {
                    CaptureError::InterfaceNotFound(interface.to_string())
                })
        }
    }

    // ── Capture handle setup ──────────────────────────────────────────────────

    /// Open and configure the pcap handle using settings from config.
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
                        "Run as Administrator for packet capture".to_string(),
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

    // ── Packet parsing ────────────────────────────────────────────────────────

    /// Parse raw Ethernet frame → typed Packet.
    ///
    /// FIX: All pattern bindings use `ref` to borrow instead of move,
    /// allowing `parsed.net` and `parsed.transport` to be read multiple
    /// times (once for IPs/ports, once for TTL/flags).
    ///
    /// Returns None for non-IP frames or malformed data.
    #[inline]
    fn parse_packet(data: &[u8]) -> Option<Packet> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(data).ok()?;

        // ── Network layer: extract IP addresses + TTL ─────────────────────────
        // Use `ref` on all inner bindings so we don't move out of `parsed.net`.
        let (src_ip, dst_ip, ttl) = match &parsed.net {
            Some(etherparse::NetHeaders::Ipv4(ref ip, _)) => (
                IpAddr::V4(Ipv4Addr::from(ip.source)),
                IpAddr::V4(Ipv4Addr::from(ip.destination)),
                Some(ip.time_to_live),
            ),
            Some(etherparse::NetHeaders::Ipv6(ref ip, _)) => (
                IpAddr::V6(Ipv6Addr::from(ip.source)),
                IpAddr::V6(Ipv6Addr::from(ip.destination)),
                Some(ip.hop_limit),
            ),
            // Non-IP frame (ARP, VLAN, etc.) — skip silently
            _ => return None,
        };

        // ── Transport layer: extract ports + protocol ─────────────────────────
        // Use `ref` on all inner bindings so we don't move out of
        // `parsed.transport` — we need it again below for TCP flags.
        let (src_port, dst_port, protocol) = match &parsed.transport {
            Some(etherparse::TransportHeader::Tcp(ref tcp)) => (
                tcp.source_port,
                tcp.destination_port,
                Protocol::Tcp,
            ),
            Some(etherparse::TransportHeader::Udp(ref udp)) => (
                udp.source_port,
                udp.destination_port,
                Protocol::Udp,
            ),
            Some(etherparse::TransportHeader::Icmpv4(_)) => (
                0,
                0,
                Protocol::Icmp,
            ),
            Some(etherparse::TransportHeader::Icmpv6(_)) => (
                0,
                0,
                Protocol::Icmpv6,
            ),
            // Unknown or missing transport
            _ => (0, 0, Protocol::Other(0)),
        };

        // ── Assemble Packet ───────────────────────────────────────────────────
        let mut pkt = Packet::new(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            data.len(),
        );

        // Populate TTL (safe: extracted by ref above, no move)
        pkt.ttl = ttl;

        // ── TCP flags ─────────────────────────────────────────────────────────
        // Second read of parsed.transport — safe because we used `ref` above.
        if let Some(etherparse::TransportHeader::Tcp(ref tcp)) = parsed.transport {
            pkt.flags.syn = tcp.syn;
            pkt.flags.ack = tcp.ack;
            pkt.flags.fin = tcp.fin;
            pkt.flags.rst = tcp.rst;
            pkt.flags.psh = tcp.psh;
            pkt.flags.urg = tcp.urg;
        }

        Some(pkt)
    }
}

// ── CaptureBackend trait implementation ───────────────────────────────────────

#[async_trait]
impl CaptureBackend for WindowsCapture {
    async fn start(&mut self) -> Result<(), CaptureError> {
        if self.is_running() {
            return Err(CaptureError::AlreadyStarted);
        }

        let device = Self::resolve_interface(&self.config.interface)?;
        let cap    = self.open_capture(device)?;

        {
            let mut guard = self.capture.lock().await;
            *guard = Some(cap);
        }

        self.running.store(true, Ordering::SeqCst);

        // ── Per-second packet counter reset ───────────────────────────────────
        // Background task resets current_second_packets every 1s so the
        // main loop can compute a live pps figure cheaply.
        let stats   = self.stats.clone();
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

        // Dropping Capture closes the pcap device handle
        let mut guard = self.capture.lock().await;
        *guard = None;

        info!("Packet capture stopped on {}", self.config.interface);
        Ok(())
    }

    async fn next_packet(&mut self) -> Option<Packet> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }

        let capture = self.capture.clone();
        let stats   = self.stats.clone();

        // pcap::next_packet() is blocking — run on blocking thread pool
        // so async runtime workers are never stalled waiting on I/O.
        let raw = spawn_blocking(move || {
            let mut guard = capture.blocking_lock();
            let cap       = guard.as_mut()?;

            match cap.next_packet() {
                Ok(packet) => {
                    let len = packet.data.len() as u64;
                    stats.packets_received      .fetch_add(1,   Ordering::Relaxed);
                    stats.bytes_received        .fetch_add(len, Ordering::Relaxed);
                    stats.current_second_packets.fetch_add(1,   Ordering::Relaxed);
                    Some(packet.data.to_vec())
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal — no packet arrived within the timeout window
                    None
                }
                Err(e) => {
                    stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    debug!("Capture read error: {}", e);
                    None
                }
            }
        })
        .await
        .ok()??;

        // Parse on calling thread — pure memory ops, no I/O, very cheap
        match Self::parse_packet(&raw) {
            Some(pkt) => Some(pkt),
            None => {
                // Valid frame but not IP (ARP etc.) — count as filtered
                self.stats.packets_filtered.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn stats(&self) -> CaptureStats {
        let pps = self.stats.current_second_packets.load(Ordering::Relaxed);

        CaptureStats {
            packets_received:     self.stats.packets_received.load(Ordering::Relaxed),
            packets_dropped:      self.stats.packets_dropped .load(Ordering::Relaxed),
            packets_filtered:     self.stats.packets_filtered.load(Ordering::Relaxed),
            bytes_received:       self.stats.bytes_received  .load(Ordering::Relaxed),
            // pps × avg_frame_size(1500B) × 8 bits ÷ 1_000_000 bps_per_mbps
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