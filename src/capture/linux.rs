// src/capture/linux.rs
//! Linux production packet capture using libpcap over AF_PACKET.
//!
//! Architecture (fixes Bug #1 + #4):
//!   A dedicated OS thread owns the `Capture<Active>` handle for its entire
//!   lifetime.  It loops, reads one packet at a time (blocking inside the
//!   thread — never on the async executor), and sends raw bytes down a
//!   bounded `std::sync::mpsc::SyncSender`.  The async side calls
//!   `next_packet()` which does a cheap non-blocking `try_recv()`.
//!
//! Bug fixes applied:
//!   #1  Capture<Active> is not Send — fixed by dedicated thread ownership.
//!   #2  Old etherparse API (parsed.ip) — replaced with parsed.net / NetHeaders.
//!   #3  i32 overflow on buffer_size cast — fixed with saturating_mul + try_from.
//!   #4  spawn_blocking per packet — replaced with single long-lived capture thread.
//!   #5  Missing TTL + TCP flags on Linux — full parity with windows.rs parser.
//!   #6  No real kernel drop stats — pcap stats() polled every second from thread.
//!   #8  Auto-select skips valid no-IP interfaces — filter changed to down/loopback only.
//!   #9  score_device ignores is_up on Linux — down interfaces now return -1.
//!  #10  Unused imports / commented code — cleaned up.

use super::{CaptureBackend, CaptureConfig, CaptureError, CaptureStats};
use crate::types::{Packet, Protocol};
use async_trait::async_trait;
use pcap::{Active, Capture, Device};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

// ── Channel capacity ──────────────────────────────────────────────────────────
//
// 4096 slots × ~1500 bytes avg frame ≈ 6 MB peak buffer between the capture
// thread and the async consumer.  If the consumer falls behind, the capture
// thread blocks inside `send()` which naturally provides back-pressure and
// avoids unbounded heap growth.
const CHANNEL_CAPACITY: usize = 4096;

// ── Public handle ─────────────────────────────────────────────────────────────

pub struct LinuxCapture {
    config:  CaptureConfig,
    /// Receives raw packet bytes from the capture thread.
    /// `None` before `start()` is called.
    receiver: Option<mpsc::Receiver<Vec<u8>>>,
    stats:    Arc<CaptureStatsInternal>,
    running:  Arc<AtomicBool>,
}

// ── Internal stats (all atomic — hot-path safe) ───────────────────────────────

struct CaptureStatsInternal {
    packets_received:       AtomicU64,
    /// Kernel-reported drops (ring-buffer overruns inside libpcap).
    packets_dropped_kernel: AtomicU64,
    /// Application-level drops (send() blocked / channel full).
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
        // Validate interface exists at construction time for early error reporting.
        // We do not open the capture handle here; that happens in start().
        let device = Self::resolve_interface(&config.interface)?;
        info!("Initialising Linux capture on: {}", device.name);

        Ok(Self {
            config,
            receiver: None,
            stats:    Arc::new(CaptureStatsInternal::new()),
            running:  Arc::new(AtomicBool::new(false)),
        })
    }

    // ── Interface resolution ──────────────────────────────────────────────────

    /// Resolve interface name → pcap Device.
    ///
    /// Bug #8 fix: auto-selection no longer rejects interfaces with no IP
    /// address.  Only loopback and administratively-down interfaces are
    /// excluded.  A SPAN port or tap device is valid even without an IP.
    ///
    /// Bug #9 fix: interfaces that are not up receive score -1 and are
    /// excluded from auto-selection.
    fn resolve_interface(interface: &str) -> Result<Device, CaptureError> {
        let devices = Device::list()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;

        if interface == "auto" {
            // Score every device and take the highest non-negative score.
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

    /// Score a Linux pcap device for auto-selection.
    ///
    /// Returns -1 to unconditionally skip, otherwise:
    ///   3 = up + has IP addresses (best)
    ///   2 = up + no IP addresses  (valid raw-capture target — Bug #8 fix)
    ///   1 = unknown up/down state + has addresses
    ///  -1 = loopback / down / virtual bridge / docker
    fn score_linux_device(d: &Device) -> i32 {
        let name = d.name.to_lowercase();

        // Hard skip — these are never valid capture targets.
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

        // Bug #9 fix: skip interfaces the kernel reports as down.
        // `is_up()` maps to PCAP_IF_UP flag set by libpcap from SIOCGIFFLAGS.
        if !d.flags.is_up() {
            return -1;
        }

        // Up + has addresses → best Linux candidate.
        if !d.addresses.is_empty() {
            return 3;
        }

        // Up but no IP (raw capture target — Bug #8 fix).
        2
    }

    // ── Capture handle setup ──────────────────────────────────────────────────

    /// Open and configure the pcap handle from config.
    ///
    /// Bug #3 fix: buffer_size_mb is usize; convert safely to i32.
    fn open_capture(config: &CaptureConfig, device: Device) -> Result<Capture<Active>, CaptureError> {
        // Safe conversion: saturate at i32::MAX (~2 GiB) instead of wrapping.
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

    // ── Capture thread ────────────────────────────────────────────────────────

    /// Spawn the dedicated capture thread.
    ///
    /// Bug #1 + #4 fix: `Capture<Active>` is owned exclusively by this thread.
    /// It never crosses a thread boundary.  Communication back to the async
    /// side happens via a bounded `SyncSender<Vec<u8>>`.
    ///
    /// The thread also polls `cap.stats()` every second to harvest real
    /// kernel-level drop counts (Bug #6 fix).
    fn spawn_capture_thread(
        cap:     Capture<Active>,
        tx:      SyncSender<Vec<u8>>,
        stats:   Arc<CaptureStatsInternal>,
        running: Arc<AtomicBool>,
    ) {
        thread::Builder::new()
            .name("rubix-capture".to_string())
            .spawn(move || {
                // `cap` is owned here — never shared, never behind a lock.
                let mut cap = cap;

                // Track when to next poll kernel stats.
                let mut last_stats_poll = std::time::Instant::now();
                let stats_interval = Duration::from_secs(1);

                info!("Capture thread started");

                while running.load(Ordering::Relaxed) {
                    // ── Kernel stats poll (Bug #6 fix) ────────────────────────
                    // pcap::Stats contains if_recv (received by kernel),
                    // if_drop (dropped by kernel ring), ps_ifdrop (dropped by
                    // the network interface itself).
                    if last_stats_poll.elapsed() >= stats_interval {
                        if let Ok(s) = cap.stats() {
                            stats
                                .packets_dropped_kernel
                                .store(s.dropped as u64, Ordering::Relaxed);
                        }
                        stats.current_second_packets.store(0, Ordering::Relaxed);
                        last_stats_poll = std::time::Instant::now();
                    }

                    // ── Read one packet (blocking inside this thread) ──────────
                    match cap.next_packet() {
                        Ok(packet) => {
                            let len = packet.data.len() as u64;
                            stats.packets_received      .fetch_add(1,   Ordering::Relaxed);
                            stats.bytes_received        .fetch_add(len, Ordering::Relaxed);
                            stats.current_second_packets.fetch_add(1,   Ordering::Relaxed);

                            // Copy raw bytes — unavoidable; pcap reuses the
                            // DMA buffer on the next call.
                            let raw = packet.data.to_vec();

                            // Bounded send provides back-pressure.
                            // If the channel is full the thread blocks here
                            // which is correct — we slow capture rather than
                            // OOM the process.
                            if tx.send(raw).is_err() {
                                // Receiver was dropped — stop thread.
                                debug!("Capture channel closed; stopping thread");
                                break;
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => {
                            // Normal — no packet arrived within the timeout.
                            // Loop back and check `running` flag.
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
    /// Bug #2 fix: uses etherparse 0.15+ API (parsed.net / NetHeaders).
    /// Bug #5 fix: extracts TTL and all TCP flags, matching windows.rs exactly.
    ///
    /// All bindings use `ref` so `parsed.net` and `parsed.transport` can be
    /// read twice without moves — once for addresses/ports, once for
    /// TTL/flags.
    ///
    /// Returns None for non-IP frames or malformed data.
    #[inline]
    fn parse_packet(data: &[u8]) -> Option<Packet> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(data).ok()?;

        // ── Network layer: extract IP addresses + TTL ─────────────────────────
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
            // Non-IP frame (ARP, VLAN untagged, etc.) — skip silently.
            _ => return None,
        };

        // ── Transport layer: extract ports + protocol ─────────────────────────
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

        // Bug #5 fix: populate TTL (ref-borrowed above — no move).
        pkt.ttl = ttl;

        // Bug #5 fix: populate TCP flags.
        // Second borrow of parsed.transport is safe because we used `ref` above.
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

        // Create the bounded channel.  The capture thread owns the sender;
        // the async side holds the receiver.  The Capture handle is moved
        // into the thread closure — it never escapes (Bug #1 fix).
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_CAPACITY);

        Self::spawn_capture_thread(
            cap,
            tx,
            self.stats.clone(),
            self.running.clone(),
        );

        self.receiver = Some(rx);
        self.running.store(true, Ordering::SeqCst);

        info!("Packet capture started on {}", self.config.interface);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), CaptureError> {
        if !self.is_running() {
            return Err(CaptureError::NotStarted);
        }

        // Signal the capture thread to exit on its next loop iteration.
        self.running.store(false, Ordering::SeqCst);

        // Drop the receiver — when the capture thread calls tx.send() it
        // will see a disconnected error and exit cleanly.
        self.receiver = None;

        info!("Packet capture stopped on {}", self.config.interface);
        Ok(())
    }

    /// Non-blocking packet read — never stalls the async executor.
    ///
    /// Bug #4 fix: no spawn_blocking.  We do a `try_recv()` which returns
    /// immediately whether or not a packet is available.  The caller is
    /// responsible for driving the polling loop (e.g. inside a select! or
    /// with tokio::time::sleep back-off).
    async fn next_packet(&mut self) -> Option<Packet> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }

        let rx = self.receiver.as_ref()?;

        match rx.try_recv() {
            Ok(raw) => {
                match Self::parse_packet(&raw) {
                    Some(pkt) => Some(pkt),
                    None => {
                        // Valid frame but not IP (ARP etc.) — count as filtered.
                        self.stats.packets_filtered.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }
            Err(TryRecvError::Empty) => {
                // No packet available right now — non-blocking, no error.
                None
            }
            Err(TryRecvError::Disconnected) => {
                // Capture thread exited unexpectedly.
                warn!("Capture channel disconnected unexpectedly");
                self.running.store(false, Ordering::SeqCst);
                None
            }
        }
    }

    fn stats(&self) -> CaptureStats {
        let pps = self.stats.current_second_packets.load(Ordering::Relaxed);

        // Bug #6 fix: report real kernel drops, not just application errors.
        let kernel_drops = self.stats.packets_dropped_kernel.load(Ordering::Relaxed);
        let app_drops    = self.stats.packets_dropped_app   .load(Ordering::Relaxed);

        CaptureStats {
            packets_received:     self.stats.packets_received.load(Ordering::Relaxed),
            packets_dropped:      kernel_drops.saturating_add(app_drops),
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