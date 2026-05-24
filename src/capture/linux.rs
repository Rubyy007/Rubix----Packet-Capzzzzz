// src/capture/linux.rs
//! Linux production packet capture using libpcap over AF_PACKET.
//!
//! FIX: LinuxCapture now wraps the mpsc::Receiver in a Mutex<Option<...>>
//! instead of Option<Receiver<...>> directly.
//!
//! Root cause: the CaptureBackend trait requires Send + Sync.
//! mpsc::Receiver<T> is Send but NOT Sync — holding it as a bare field
//! makes LinuxCapture non-Sync.  Wrapping in Mutex<Option<...>> makes it
//! Sync because Mutex<T>: Sync whenever T: Send, which Receiver is.
//!
//! next_packet() acquires the mutex, calls try_recv(), and drops the guard
//! immediately — the lock is never held across an await point.  The lock
//! cost is one uncontested pthread_mutex_trylock (~5 ns) per packet, which
//! is negligible compared to pcap overhead.
//!
//! All other logic is unchanged from the original.

use super::{CaptureBackend, CaptureConfig, CaptureError, CaptureStats};
use crate::types::{Packet, Protocol};
use async_trait::async_trait;
use pcap::{Active, Capture, Device};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

const CHANNEL_CAPACITY: usize = 4096;

// ── Public handle ─────────────────────────────────────────────────────────────

pub struct LinuxCapture {
    config:  CaptureConfig,
    /// FIX: Mutex<Option<Receiver>> makes LinuxCapture Sync.
    /// Receiver<T> is Send but not Sync; Mutex<T> is Sync when T: Send.
    receiver: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    stats:    Arc<CaptureStatsInternal>,
    running:  Arc<AtomicBool>,
}

// ── Internal stats ────────────────────────────────────────────────────────────

struct CaptureStatsInternal {
    packets_received:       AtomicU64,
    packets_dropped_kernel: AtomicU64,
    packets_dropped_app:    AtomicU64,
    packets_filtered:       AtomicU64,
    bytes_received:         AtomicU64,
    current_second_packets: AtomicU64,
}

impl CaptureStatsInternal {
    fn new() -> Self {
        Self {
            packets_received:       AtomicU64::new(0),
            packets_dropped_kernel: AtomicU64::new(0),
            packets_dropped_app:    AtomicU64::new(0),
            packets_filtered:       AtomicU64::new(0),
            bytes_received:         AtomicU64::new(0),
            current_second_packets: AtomicU64::new(0),
        }
    }
}

// ── Implementation ────────────────────────────────────────────────────────────

impl LinuxCapture {
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        let device = Self::resolve_interface(&config.interface)?;
        info!("Initialising Linux capture on: {}", device.name);

        Ok(Self {
            config,
            receiver: Mutex::new(None),   // FIX: Mutex<Option<...>>
            stats:    Arc::new(CaptureStatsInternal::new()),
            running:  Arc::new(AtomicBool::new(false)),
        })
    }

    fn resolve_interface(interface: &str) -> Result<Device, CaptureError> {
        let devices = Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;

        if interface == "auto" {
            devices
                .into_iter()
                .filter_map(|d| {
                    let score = Self::score_linux_device(&d);
                    if score >= 0 { Some((score, d)) } else { None }
                })
                .max_by_key(|(score, _)| *score)
                .map(|(_, device)| device)
                .ok_or_else(|| {
                    CaptureError::InterfaceNotFound(
                        "No suitable interface found for auto-selection".to_string(),
                    )
                })
        } else {
            devices
                .into_iter()
                .find(|d| d.name == interface)
                .ok_or_else(|| CaptureError::InterfaceNotFound(interface.to_string()))
        }
    }

    fn score_linux_device(d: &Device) -> i32 {
        let name = d.name.to_lowercase();

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

        if !d.flags.is_up() { return -1; }
        if !d.addresses.is_empty() { return 3; }
        2
    }

    fn open_capture(config: &CaptureConfig, device: Device) -> Result<Capture<Active>, CaptureError> {
        let buf_bytes = config.buffer_size_mb.saturating_mul(1024 * 1024);
        let buf_i32   = i32::try_from(buf_bytes).unwrap_or(i32::MAX);

        let mut cap = Capture::from_device(device)
            .map_err(|e| CaptureError::PcapError(e.to_string()))?
            .timeout(config.timeout_ms)
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .buffer_size(buf_i32)
            .open()
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("permission") || msg.contains("Operation not permitted") {
                    CaptureError::PermissionDenied(
                        "Run as root (or grant CAP_NET_RAW) for packet capture".to_string(),
                    )
                } else {
                    CaptureError::PcapError(msg)
                }
            })?;

        if let Some(filter) = &config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| CaptureError::InvalidFilter(e.to_string()))?;
            debug!("Applied BPF filter: {}", filter);
        }

        Ok(cap)
    }

    fn spawn_capture_thread(
        cap:     Capture<Active>,
        tx:      SyncSender<Vec<u8>>,
        stats:   Arc<CaptureStatsInternal>,
        running: Arc<AtomicBool>,
    ) {
        thread::Builder::new()
            .name("rubix-capture".to_string())
            .spawn(move || {
                let mut cap = cap;
                let mut last_stats_poll = std::time::Instant::now();
                let stats_interval      = Duration::from_secs(1);

                info!("Capture thread started");

                while running.load(Ordering::Relaxed) {
                    if last_stats_poll.elapsed() >= stats_interval {
                        if let Ok(s) = cap.stats() {
                            stats.packets_dropped_kernel
                                .store(s.dropped as u64, Ordering::Relaxed);
                        }
                        stats.current_second_packets.store(0, Ordering::Relaxed);
                        last_stats_poll = std::time::Instant::now();
                    }

                    match cap.next_packet() {
                        Ok(packet) => {
                            let len = packet.data.len() as u64;
                            stats.packets_received      .fetch_add(1,   Ordering::Relaxed);
                            stats.bytes_received        .fetch_add(len, Ordering::Relaxed);
                            stats.current_second_packets.fetch_add(1,   Ordering::Relaxed);

                            let raw = packet.data.to_vec();
                            if tx.send(raw).is_err() {
                                debug!("Capture channel closed; stopping thread");
                                break;
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(e) => {
                            stats.packets_dropped_app.fetch_add(1, Ordering::Relaxed);
                            warn!("Capture read error: {}", e);
                        }
                    }
                }

                info!("Capture thread exiting");
            })
            .expect("Failed to spawn rubix-capture thread");
    }

    #[inline]
    fn parse_packet(data: &[u8]) -> Option<Packet> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(data).ok()?;

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
            _ => return None,
        };

        let (src_port, dst_port, protocol) = match &parsed.transport {
            Some(etherparse::TransportHeader::Tcp(ref tcp)) => (
                tcp.source_port, tcp.destination_port, Protocol::Tcp,
            ),
            Some(etherparse::TransportHeader::Udp(ref udp)) => (
                udp.source_port, udp.destination_port, Protocol::Udp,
            ),
            Some(etherparse::TransportHeader::Icmpv4(_)) => (0, 0, Protocol::Icmp),
            Some(etherparse::TransportHeader::Icmpv6(_)) => (0, 0, Protocol::Icmpv6),
            _ => (0, 0, Protocol::Other(0)),
        };

        let mut pkt = Packet::new(src_ip, dst_ip, src_port, dst_port, protocol, data.len());
        pkt.ttl = ttl;

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
impl CaptureBackend for LinuxCapture {
    async fn start(&mut self) -> Result<(), CaptureError> {
        if self.is_running() {
            return Err(CaptureError::AlreadyStarted);
        }

        let device = Self::resolve_interface(&self.config.interface)?;
        let cap    = Self::open_capture(&self.config, device)?;
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_CAPACITY);

        Self::spawn_capture_thread(cap, tx, self.stats.clone(), self.running.clone());

        // FIX: store receiver inside the Mutex.
        *self.receiver.lock().unwrap() = Some(rx);
        self.running.store(true, Ordering::SeqCst);

        info!("Packet capture started on {}", self.config.interface);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), CaptureError> {
        if !self.is_running() {
            return Err(CaptureError::NotStarted);
        }

        self.running.store(false, Ordering::SeqCst);

        // Drop the receiver — the capture thread sees a send error and exits.
        *self.receiver.lock().unwrap() = None;

        info!("Packet capture stopped on {}", self.config.interface);
        Ok(())
    }

    async fn next_packet(&mut self) -> Option<Packet> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }

        // FIX: lock the Mutex, do a non-blocking try_recv, drop the guard.
        // The guard is never held across an await point — it is dropped at
        // the end of this block before we return.
        let result = {
            let guard = self.receiver.lock().unwrap();
            match guard.as_ref() {
                None     => return None,
                Some(rx) => rx.try_recv(),
            }
        }; // guard dropped here

        match result {
            Ok(raw) => {
                match Self::parse_packet(&raw) {
                    Some(pkt) => Some(pkt),
                    None => {
                        self.stats.packets_filtered.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                warn!("Capture channel disconnected unexpectedly");
                self.running.store(false, Ordering::SeqCst);
                None
            }
        }
    }

    fn stats(&self) -> CaptureStats {
        let pps          = self.stats.current_second_packets.load(Ordering::Relaxed);
        let kernel_drops = self.stats.packets_dropped_kernel.load(Ordering::Relaxed);
        let app_drops    = self.stats.packets_dropped_app   .load(Ordering::Relaxed);

        CaptureStats {
            packets_received:     self.stats.packets_received.load(Ordering::Relaxed),
            packets_dropped:      kernel_drops.saturating_add(app_drops),
            packets_filtered:     self.stats.packets_filtered.load(Ordering::Relaxed),
            bytes_received:       self.stats.bytes_received  .load(Ordering::Relaxed),
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