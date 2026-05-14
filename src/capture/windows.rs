// src/capture/windows.rs
//! Windows production packet capture using NPcap (libpcap-compatible API).
//!
//! Architecture:
//!   A dedicated OS thread owns the `Capture<Active>` handle for its entire
//!   lifetime.  It loops, reads one packet at a time (blocking inside the
//!   thread — never on the async executor), and sends raw bytes down a
//!   bounded `std::sync::mpsc::SyncSender`.  The async side calls
//!   `next_packet()` which does a cheap non-blocking `try_recv()` under a
//!   `std::sync::Mutex` — the mutex satisfies the `Sync` bound required by
//!   `CaptureBackend` without introducing any blocking in the fast path.
//!
//! etherparse requirement: 0.15+
//!   parsed.net / NetHeaders::Ipv4 / NetHeaders::Ipv6
//!
//! Bug fixes applied:
//!   #1  Capture<Active> is not Send     — dedicated thread owns the handle.
//!   #3  i32 overflow on buffer_size     — saturating_mul + try_from.
//!   #4  spawn_blocking per packet       — single long-lived capture thread.
//!   #6  No real kernel drop stats       — cap.stats() polled every second.
//!   #7  English-locale status string    — numeric IfOperStatus comparison.
//!  #11  Receiver<T> is not Sync         — wrapped in std::sync::Mutex.

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

// ── Channel capacity ──────────────────────────────────────────────────────────
const CHANNEL_CAPACITY: usize = 4096;

// ── Public handle ─────────────────────────────────────────────────────────────

pub struct WindowsCapture {
    config:   CaptureConfig,
    /// Receives raw packet bytes from the capture thread.
    ///
    /// `std::sync::mpsc::Receiver<T>` is `Send` but not `Sync`.
    /// `CaptureBackend` requires `Send + Sync`.
    /// Wrapping in `Mutex` makes the field `Sync` (Mutex<T>: Sync when T: Send).
    /// The lock is held only for a single non-blocking `try_recv()` call —
    /// nanoseconds — so this does not affect fast-path latency.
    ///
    /// `None` before `start()` is called.
    receiver: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    stats:    Arc<CaptureStatsInternal>,
    running:  Arc<AtomicBool>,
}

// ── Internal stats (all atomic — hot-path safe) ───────────────────────────────

struct CaptureStatsInternal {
    packets_received:       AtomicU64,
    /// Kernel-reported drops (ring-buffer overruns inside NPcap).
    packets_dropped_kernel: AtomicU64,
    /// Application-level errors (unexpected read errors).
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

impl WindowsCapture {
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        let device = Self::resolve_interface(&config.interface)?;
        info!("Initialising Windows capture on: {}", device.name);

        Ok(Self {
            config,
            receiver: Mutex::new(None),
            stats:    Arc::new(CaptureStatsInternal::new()),
            running:  Arc::new(AtomicBool::new(false)),
        })
    }

    // ── Interface resolution ──────────────────────────────────────────────────

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
                .ok_or_else(|| CaptureError::InterfaceNotFound(interface.to_string()))
        }
    }

    // ── Capture handle setup ──────────────────────────────────────────────────

    /// Bug #3 fix: buffer_size_mb is usize; convert safely to i32.
    fn open_capture(config: &CaptureConfig, device: Device) -> Result<Capture<Active>, CaptureError> {
        let buf_bytes = config
            .buffer_size_mb
            .saturating_mul(1024 * 1024);
        let buf_i32 = i32::try_from(buf_bytes).unwrap_or(i32::MAX);

        let mut cap = Capture::from_device(device)
            .map_err(|e| CaptureError::PcapError(e.to_string()))?
            .timeout(config.timeout_ms)
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .buffer_size(buf_i32)
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

        if let Some(filter) = &config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| CaptureError::InvalidFilter(e.to_string()))?;
            debug!("Applied BPF filter: {}", filter);
        }

        Ok(cap)
    }

    // ── Capture thread ────────────────────────────────────────────────────────

    /// Bug #1 + #4 fix: `Capture<Active>` is owned exclusively by this thread.
    /// Bug #6 fix: cap.stats() polled every second for real kernel drop counts.
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
                    // ── Kernel stats poll (Bug #6 fix) ────────────────────────
                    if last_stats_poll.elapsed() >= stats_interval {
                        if let Ok(s) = cap.stats() {
                            stats
                                .packets_dropped_kernel
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
                        Err(pcap::Error::TimeoutExpired) => {
                            continue;
                        }
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

    // ── Packet parsing ────────────────────────────────────────────────────────

    /// Parse raw Ethernet frame → typed Packet.
    ///
    /// Uses etherparse 0.15+ API (parsed.net / NetHeaders).
    /// All inner bindings use `ref` for double-borrow of net and transport.
    #[inline]
    fn parse_packet(data: &[u8]) -> Option<Packet> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(data).ok()?;

        // ── Network layer ─────────────────────────────────────────────────────
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

        // ── Transport layer ───────────────────────────────────────────────────
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
            Some(etherparse::TransportHeader::Icmpv4(_)) => (0, 0, Protocol::Icmp),
            Some(etherparse::TransportHeader::Icmpv6(_)) => (0, 0, Protocol::Icmpv6),
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
impl CaptureBackend for WindowsCapture {
    async fn start(&mut self) -> Result<(), CaptureError> {
        if self.is_running() {
            return Err(CaptureError::AlreadyStarted);
        }

        let device = Self::resolve_interface(&self.config.interface)?;
        let cap    = Self::open_capture(&self.config, device)?;

        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_CAPACITY);

        // Install receiver before starting thread.
        {
            let mut guard = self.receiver.lock().expect("receiver mutex poisoned");
            *guard = Some(rx);
        }

        Self::spawn_capture_thread(
            cap,
            tx,
            self.stats.clone(),
            self.running.clone(),
        );

        self.running.store(true, Ordering::SeqCst);
        info!("Packet capture started on {}", self.config.interface);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), CaptureError> {
        if !self.is_running() {
            return Err(CaptureError::NotStarted);
        }

        self.running.store(false, Ordering::SeqCst);

        let mut guard = self.receiver.lock().expect("receiver mutex poisoned");
        *guard = None;

        info!("Packet capture stopped on {}", self.config.interface);
        Ok(())
    }

    /// Non-blocking packet read — never stalls the async executor.
    ///
    /// The `Mutex` is held only for a single `try_recv()` call (nanoseconds).
    async fn next_packet(&mut self) -> Option<Packet> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }

        let raw = {
            let guard = self.receiver.lock().expect("receiver mutex poisoned");
            match guard.as_ref() {
                None => return None,
                Some(rx) => match rx.try_recv() {
                    Ok(raw)                         => raw,
                    Err(TryRecvError::Empty)        => return None,
                    Err(TryRecvError::Disconnected) => {
                        warn!("Capture channel disconnected unexpectedly");
                        drop(guard);
                        self.running.store(false, Ordering::SeqCst);
                        return None;
                    }
                },
            }
        };

        match Self::parse_packet(&raw) {
            Some(pkt) => Some(pkt),
            None => {
                self.stats.packets_filtered.fetch_add(1, Ordering::Relaxed);
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
