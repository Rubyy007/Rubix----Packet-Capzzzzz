// src/main.rs
//! RUBIX - Production Network Blocking Engine with Process Attribution
//!
//! After the startup banner the daemon is completely silent on stdout.
//! All runtime metrics flow into `shared_stats` (Arc<RwLock<LiveStats>>)
//! which is served to the CLI on demand via the control socket.

mod types;
mod capture;
mod policy;
mod config;
mod blocker;
mod logger;
mod control;
mod resolver;
mod detector;

use detector::{ScanDetector, PingDetector, ThreatTracker, ThreatEvent};
use policy::{PolicyEngine, PolicyReloader, RuleAction};
use config::loader::ConfigLoader;
use blocker::{PlatformBlocker, Blocker};
use capture::{CaptureConfig, CaptureFactory};
use capture::filter::FilterBuilder;
use logger::AlertLogger;
use control::{CommandHandler, ControlServer};
use resolver::{ProcessResolver, FlowKey, Protocol};
use types::stats::{LiveStats, ProcStatSnapshot};

use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::time::{Duration, timeout, sleep};
use tracing::{info, warn, error};

// ── Platform constants ────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";
#[cfg(target_os = "windows")]
const OS_NAME: &str = "windows";

// ── Per-process statistics (packet-loop-private) ──────────────────────────────
//
// Separated into window counters (reset every 5 s) and lifetime totals.
// Only window counters are published to the CLI table — lifetime totals are
// used to decide whether a process entry should survive cleanup.

#[derive(Clone)]
struct ProcStats {
    name:     String,

    // 5-second window — reset by reset_window()
    packets:  u64,
    bytes:    u64,
    blocked:  u64,
    alerted:  u64,

    // Unique sets — kept for the window; not reset (used for DST/PRO columns)
    unique_dsts: HashSet<IpAddr>,
    unique_srcs: HashSet<IpAddr>,
    protocols:   HashSet<String>,

    // Lifetime totals — never reset; used for cleanup heuristics
    total_packets: u64,
    total_blocked: u64,
    total_alerted: u64,
}

impl ProcStats {
    #[inline]
    fn new(name: String) -> Self {
        Self {
            name,
            packets:  0,
            bytes:    0,
            blocked:  0,
            alerted:  0,
            unique_dsts: HashSet::with_capacity(16),
            unique_srcs: HashSet::with_capacity(16),
            protocols:   HashSet::with_capacity(4),
            total_packets: 0,
            total_blocked: 0,
            total_alerted: 0,
        }
    }

    /// Reset the 5-second window counters; leave lifetime totals untouched.
    #[inline]
    fn reset_window(&mut self) {
        self.packets = 0;
        self.bytes   = 0;
        self.blocked = 0;
        self.alerted = 0;
        // Sets are NOT cleared — they represent "seen in last window" which
        // is still valid for the duration calculation between resets.
    }
}

// ── Heartbeat wave ────────────────────────────────────────────────────────────

struct Heartbeat {
    samples:  Vec<f64>,
    capacity: usize,
}

impl Heartbeat {
    fn new(capacity: usize) -> Self {
        Self { samples: Vec::with_capacity(capacity), capacity }
    }

    #[inline]
    fn push(&mut self, pps: f64) {
        if self.samples.len() >= self.capacity {
            // Remove front is O(n) but n=30 — acceptable; avoids heap churn
            // of a VecDeque for such a tiny buffer.
            self.samples.remove(0);
        }
        self.samples.push(pps);
    }

    fn render(&self) -> String {
        let padding = self.capacity.saturating_sub(self.samples.len());
        let pad_str = "_".repeat(padding);

        if self.samples.is_empty() {
            return pad_str;
        }

        let max  = self.samples.iter().cloned().fold(1.0_f64, f64::max);
        let bars = ['_', '.', '-', '^', '|'];

        let wave: String = self.samples.iter().map(|&v| {
            let ratio = (v / max).clamp(0.0, 1.0);
            let idx   = (ratio * (bars.len() - 1) as f64).round() as usize;
            bars[idx]
        }).collect();

        format!("{}{}", pad_str, wave)
    }
}

// ── Graceful shutdown signal ──────────────────────────────────────────────────

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint  = signal(SignalKind::interrupt()).expect("SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM");
        tokio::select! {
            _ = sigint.recv()  => println!("\n[!] Shutdown signal received (Ctrl+C / SIGINT)..."),
            _ = sigterm.recv() => println!("\n[!] Shutdown signal received (SIGTERM)..."),
        }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await.expect("Ctrl+C");
        println!("\n[!] Shutdown signal received (Ctrl+C)...");
    }
}

// ── Extract pre-block IPs from rules.yaml ─────────────────────────────────────

fn extract_malicious_ips_from_rules() -> Vec<String> {
    let rules_path = "configs/rules.yaml";
    let mut ips    = Vec::new();

    if let Ok(contents) = std::fs::read_to_string(rules_path) {
        if let Ok(rules) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(&contents) {
            for rule in rules {
                let enabled = rule.get("enabled")
                    .and_then(|e| e.as_bool())
                    .unwrap_or(true);
                if !enabled { continue; }

                if let Some("Block") = rule.get("action").and_then(|a| a.as_str()) {
                    if let Some(dst_ips) = rule
                        .get("conditions")
                        .and_then(|c| c.get("dst_ips"))
                        .and_then(|i| i.as_sequence())
                    {
                        for ip in dst_ips {
                            if let Some(s) = ip.as_str() {
                                if !s.contains('/') && s != "0.0.0.0" && s != "255.255.255.255" {
                                    ips.push(s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ips
}

// ── BPF filter ────────────────────────────────────────────────────────────────

fn build_bpf_filter(
    config_filter: &Option<String>,
    malicious_ips: &[String],
) -> Option<String> {
    if let Some(f) = config_filter {
        match capture::filter::validate_filter(f) {
            Ok(()) => {
                info!(filter = %f, "Using config-provided BPF filter");
                return Some(f.clone());
            }
            Err(e) => warn!("Config BPF filter invalid: {} — falling back to auto-built", e),
        }
    }

    let filter = FilterBuilder::from_block_list(malicious_ips, &[])
        .unwrap_or_else(FilterBuilder::default_filter);

    info!(filter = %filter, "Using auto-built BPF filter");
    Some(filter)
}

// ── Startup banner (shown exactly once, then total silence) ───────────────────

pub async fn print_banner(
    config:          &config::RubixConfig,
    rules_count:     usize,
    kernel_rules:    usize,
    interface:       &str,
    interface_label: &str,
    bpf_filter:      &str,
    malicious_ips:   &[String],
) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                                                              ║");
    println!("║   ██████  ██    ██ ██████  ██ ██   ██                        ║");
    println!("║   ██   ██ ██    ██ ██   ██ ██  ██ ██                         ║");
    println!("║   ██████  ██    ██ ██████  ██   ███                          ║");
    println!("║   ██   ██ ██    ██ ██   ██ ██  ██ ██                         ║");
    println!("║   ██   ██  ██████  ██████  ██ ██   ██                        ║");
    println!("║                                                              ║");
    println!("║              RUBIX by Uniq                                   ║");
    println!("║          Network Defense Engine v1.0.0                       ║");
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    sleep(Duration::from_millis(300)).await;

    println!("┌─ SYSTEM CONFIG ──────────────────────────────────────────────┐");
    sleep(Duration::from_millis(120)).await;
    println!("│ Mode           : {:<43} │", config.mode);
    sleep(Duration::from_millis(120)).await;
    println!("│ Interface      : {:<43} │", interface_label);
    sleep(Duration::from_millis(120)).await;
    println!("│ Promiscuous    : {:<43} │",
        if config.promiscuous { "ENABLED" } else { "DISABLED" });
    sleep(Duration::from_millis(120)).await;
    let filter_display = if bpf_filter.len() > 43 {
        format!("{}...", &bpf_filter[..40])
    } else {
        bpf_filter.to_string()
    };
    println!("│ BPF Filter     : {:<43} │", filter_display);
    sleep(Duration::from_millis(120)).await;
    println!("│ Buffer Size    : {:<43} │", format!("{} MB", config.buffer_size_mb));
    sleep(Duration::from_millis(120)).await;
    println!("│ Platform       : {:<43} │", OS_NAME.to_uppercase());
    sleep(Duration::from_millis(120)).await;
    #[cfg(unix)]
    println!("│ Control Socket : {:<43} │", "/var/run/rubix.sock");
    #[cfg(windows)]
    println!("│ Control Socket : {:<43} │", "127.0.0.1:9876");
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(250)).await;

    println!("┌─ SECURITY STATUS ────────────────────────────────────────────┐");
    sleep(Duration::from_millis(120)).await;
    println!("│ Policy Rules    : {:<41} │", rules_count);
    sleep(Duration::from_millis(120)).await;
    println!("│ Kernel Rules    : {:<41} │", kernel_rules);
    sleep(Duration::from_millis(120)).await;
    println!("│ Default Action  : {:<41} │",
        config.blocking.default_action.to_uppercase());
    sleep(Duration::from_millis(120)).await;
    println!("│ Auto Cleanup    : {:<41} │",
        if config.blocking.auto_cleanup { "ENABLED" } else { "DISABLED" });
    sleep(Duration::from_millis(120)).await;
    println!("│ Block Timeout   : {:<41} │",
        format!("{} sec", config.blocking.block_timeout_seconds));
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(250)).await;

    if !malicious_ips.is_empty() {
        println!("┌─ ACTIVE THREATS ─────────────────────────────────────────────┐");
        sleep(Duration::from_millis(150)).await;
        println!("│ [!] {} IPs pre-blocked at kernel level{:>23} │",
            malicious_ips.len(), "");
        for ip in malicious_ips.iter().take(5) {
            sleep(Duration::from_millis(80)).await;
            println!("│   + {:<57} │", ip);
        }
        if malicious_ips.len() > 5 {
            sleep(Duration::from_millis(80)).await;
            println!("│   ... and {} more{:>39} │", malicious_ips.len() - 5, "");
        }
        println!("└──────────────────────────────────────────────────────────────┘");
        println!();
    }

    sleep(Duration::from_millis(250)).await;

    println!("┌─ NETWORK INTERFACES ─────────────────────────────────────────┐");
    match CaptureFactory::list_interfaces() {
        Ok(interfaces) => {
            for iface in interfaces.iter().take(10) {
                let is_active    = iface.name == interface;
                let status       = if is_active { "(*) ACTIVE" } else { "( ) IDLE  " };
                let display_name = iface.description.as_deref().unwrap_or(&iface.name);
                let display_name = if display_name.len() > 28 {
                    format!("{}...", &display_name[..25])
                } else {
                    display_name.to_string()
                };
                sleep(Duration::from_millis(80)).await;
                println!("│ {:<10} {:<28} {:<20} │",
                    status, display_name, format!("{} addrs", iface.addresses.len()));
            }
        }
        Err(e) => println!("│ [!] {:<56} │", format!("Interface error: {}", e)),
    }
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(200)).await;

    println!("[*] RUBIX ACTIVE — monitoring on {} (Ctrl+C to stop)", interface_label);
    println!("[*] Run 'rubix-cli monitor' in another terminal for live stats");
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline(always)]
fn is_ingress_packet(src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    dst_ip.is_loopback() || (is_private_ip(dst_ip) && !is_private_ip(src_ip))
}

#[inline(always)]
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false,
    }
}

// ── Stats publisher ───────────────────────────────────────────────────────────
//
// Called from the packet loop every ~500 ms.
// Uses try_write() so the hot path is never blocked by a CLI reader.
// If the lock is contended, we simply skip this publish cycle — the CLI
// receives data that is at most one extra interval stale (≤1 s total).

#[inline]
fn publish_stats(
    shared:         &Arc<RwLock<LiveStats>>,
    packet_count:   u64,
    block_count:    u64,
    alert_count:    u64,
    pps:            f64,
    avg_pps:        f64,
    runtime_secs:   f64,
    wave:           String,
    proc_stats:     &HashMap<u32, ProcStats>,
    recent_threats: &VecDeque<String>,
) {
    // Build top-8 snapshot — sorted by blocked → alerted → packets
    let mut top: Vec<ProcStatSnapshot> = proc_stats
        .iter()
        .filter(|(_, s)| s.total_packets > 0 || s.total_blocked > 0 || s.total_alerted > 0)
        .map(|(&pid, s)| ProcStatSnapshot {
            pid,
            name:         s.name.clone(),
            packets:      s.packets,
            bytes:        s.bytes,
            blocked:      s.blocked,
            alerted:      s.alerted,
            unique_dsts:  s.unique_dsts.len(),
            protocol_cnt: s.protocols.len(),
        })
        .collect();

    top.sort_unstable_by(|a, b| {
        b.blocked.cmp(&a.blocked)
            .then_with(|| b.alerted.cmp(&a.alerted))
            .then_with(|| b.packets.cmp(&a.packets))
    });
    top.truncate(8);

    let threats: Vec<String> = recent_threats.iter().cloned().collect();

    // try_write: if a CLI reader holds the lock we skip — never block the loop
    if let Some(mut guard) = shared.try_write() {
        guard.packet_count   = packet_count;
        guard.block_count    = block_count;
        guard.alert_count    = alert_count;
        guard.pps            = pps;
        guard.avg_pps        = avg_pps;
        guard.runtime_secs   = runtime_secs;
        guard.heartbeat      = wave;
        guard.top_procs      = top;
        guard.recent_threats = threats;
    }
    // else: silently skip — next publish is ≤500 ms away
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _logger = logger::Logger::init_dual()?;
    _logger.start_cleanup_task();

    let start_time = std::time::Instant::now();

    // ── Config ────────────────────────────────────────────────────────────────
    let config_dir    = std::path::Path::new("configs");
    let config_loader = ConfigLoader::load(config_dir, OS_NAME)?;
    let config        = config_loader.get();

    // ── Policy engine ─────────────────────────────────────────────────────────
    let policy_engine = Arc::new(PolicyEngine::new());
    let reloader = Arc::new(PolicyReloader::new(
        policy_engine.clone(),
        "configs/rules.yaml".to_string(),
    ));
    let _ = reloader.load_initial();
    let rules_count = policy_engine.rule_count();

    // ── Kernel blocker ────────────────────────────────────────────────────────
    let blocker       = Arc::new(PlatformBlocker::new());
    let malicious_ips = extract_malicious_ips_from_rules();

    let mut kernel_rules = 0usize;
    for ip_str in &malicious_ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match blocker.block_ip(ip).await {
                Ok(_)  => { kernel_rules += 1; info!(ip = %ip_str, "Kernel block rule installed"); }
                Err(e) => error!(ip = %ip_str, error = %e, "Failed to install kernel block rule"),
            }
        } else {
            warn!(ip = %ip_str, "Skipping invalid IP in rules.yaml");
        }
    }

    // ── Process resolver ──────────────────────────────────────────────────────
    let resolver = Arc::new(ProcessResolver::new());
    info!("Process resolver initialized");

    // ── Interface ─────────────────────────────────────────────────────────────
    let interface_name = if config.capture_interface == "auto" {
        match CaptureFactory::auto_select_interface() {
            Some(iface) => { info!(interface = %iface, "Auto-selected network interface"); iface }
            None => {
                error!("Could not auto-detect a suitable network interface");
                error!("Set capture_interface manually in configs/rubix.{}.yaml", OS_NAME);
                std::process::exit(1);
            }
        }
    } else {
        info!(interface = %config.capture_interface, "Using manually configured interface");
        config.capture_interface.clone()
    };

    let interface_label = CaptureFactory::list_interfaces()
        .ok()
        .and_then(|ifaces| ifaces.into_iter()
            .find(|i| i.name == interface_name)
            .map(|i| i.description.unwrap_or_else(|| i.name.clone())))
        .unwrap_or_else(|| interface_name.clone());

    // ── BPF filter ────────────────────────────────────────────────────────────
    let bpf_filter         = build_bpf_filter(&config.bpf_filter, &malicious_ips);
    let bpf_filter_display = bpf_filter.as_deref().unwrap_or("none").to_string();

    // ── Banner — printed once, then silence ───────────────────────────────────
    print_banner(
        &config, rules_count, kernel_rules,
        &interface_name, &interface_label,
        &bpf_filter_display, &malicious_ips,
    ).await;

    // ── Shared live stats — parking_lot RwLock ────────────────────────────────
    // Arc<RwLock<T>> with parking_lot: readers never block each other,
    // writers use try_write so the hot path is never stalled.
    let shared_stats: Arc<RwLock<LiveStats>> = Arc::new(RwLock::new(LiveStats::default()));

    // ── Capture ───────────────────────────────────────────────────────────────
    let capture_config = CaptureConfig {
        interface:      interface_name.clone(),
        promiscuous:    config.promiscuous,
        buffer_size_mb: config.buffer_size_mb as usize,
        timeout_ms:     config.timeout_ms as i32,
        snaplen:        config.snaplen as i32,
        bpf_filter,
    };
    let mut capture = CaptureFactory::create(capture_config)?;
    capture.start().await?;

    // ── Control server ────────────────────────────────────────────────────────
    let ctrl_handler = Arc::new(CommandHandler::new(
        blocker.clone(),
        policy_engine.clone(),
        reloader.clone(),
        start_time,
        shared_stats.clone(),   // handler gets a reader handle
    ));
    let ctrl_server = ControlServer::new(ctrl_handler);
    ctrl_server.start().await;
    info!("Control server started — CLI commands are active");

    // ── Shutdown flag ─────────────────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        tokio::spawn(async move {
            wait_for_shutdown().await;
            r.store(false, Ordering::SeqCst);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  PACKET LOOP — hot path, completely silent on stdout.
    //
    //  Nothing writes to stdout/stderr inside this loop.
    //  • AlertLogger writes to the log file only.
    //  • Threat events go into `recent_threats` deque.
    //  • All metrics go into `shared_stats` via publish_stats().
    // ─────────────────────────────────────────────────────────────────────────

    let mut packet_count:      u64 = 0;
    let mut block_count:       u64 = 0;
    let mut alert_count:       u64 = 0;
    let mut last_stats_time        = start_time;
    let mut last_packet_count: u64 = 0;
    let mut last_window_reset      = start_time;

    let mut heartbeat  = Heartbeat::new(30);
    let mut proc_stats: HashMap<u32, ProcStats> = HashMap::with_capacity(128);
    let mut threat_tracker = ThreatTracker::new();

    // Pre-formatted threat strings — newest last, capped at 20.
    let mut recent_threats: VecDeque<String> = VecDeque::with_capacity(20);

    while running.load(Ordering::Relaxed) {
        match timeout(Duration::from_millis(100), capture.next_packet()).await {

            // ── Packet received ───────────────────────────────────────────────
            Ok(Some(packet)) => {
                packet_count += 1;

                // ── HOT PATH: process resolution ──────────────────────────────
                let proto = Protocol::from_str(&packet.protocol.to_string());

                let proc_info = resolver.lookup(&FlowKey {
                    local_ip:   packet.src_ip,
                    local_port: packet.src_port,
                    protocol:   proto,
                }).or_else(|| resolver.lookup(&FlowKey {
                    local_ip:   packet.dst_ip,
                    local_port: packet.dst_port,
                    protocol:   proto,
                }));

                // ── Per-process accounting ────────────────────────────────────
                if let Some(ref info) = proc_info {
                    let entry = proc_stats
                        .entry(info.pid)
                        .or_insert_with(|| ProcStats::new(info.name.clone()));

                    if entry.name.is_empty() {
                        entry.name.clone_from(&info.name);
                    }

                    entry.packets        += 1;
                    entry.bytes          += packet.size as u64;
                    entry.total_packets  += 1;
                    entry.unique_dsts.insert(packet.dst_ip);
                    entry.unique_srcs.insert(packet.src_ip);
                    entry.protocols.insert(packet.protocol.to_string());
                }

                // ── Threat detection ──────────────────────────────────────────
                let proc_name  = proc_info.as_ref().map(|p| p.name.as_str());
                let is_ingress = is_ingress_packet(packet.src_ip, packet.dst_ip);

                let threat: Option<ThreatEvent> = match packet.protocol {
                    crate::types::Protocol::Tcp => ScanDetector::analyze_tcp(
                        &mut threat_tracker, packet.src_ip, packet.dst_port,
                        &packet.flags, proc_name, is_ingress,
                    ),
                    crate::types::Protocol::Udp => ScanDetector::analyze_udp(
                        &mut threat_tracker, packet.src_ip, packet.dst_port,
                        proc_name, is_ingress,
                    ),
                    crate::types::Protocol::Icmp | crate::types::Protocol::Icmpv6 =>
                        PingDetector::analyze(
                            &mut threat_tracker, packet.src_ip,
                            true, proc_name, is_ingress,
                        ),
                    _ => None,
                };

                if let Some(ref threat) = threat {
                    // Log to file — NO stdout
                    AlertLogger::log_block(
                        &threat.src_ip.to_string(), "local", 0, 0, "DETECT",
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                    );

                    // Store formatted for CLI display
                    let line = format!(
                        "{} {} | src={} | {}",
                        threat.severity.icon(),
                        threat.kind.as_str(),
                        threat.src_ip,
                        threat.detail,
                    );
                    if recent_threats.len() == 20 { recent_threats.pop_front(); }
                    recent_threats.push_back(line);

                    alert_count += 1;

                    if let Some(ref info) = proc_info {
                        if let Some(s) = proc_stats.get_mut(&info.pid) {
                            s.alerted       += 1;
                            s.total_alerted += 1;
                        }
                    }
                }

                // Periodic eviction of stale tracker buckets
                if packet_count % 1_000 == 0 {
                    threat_tracker.maybe_evict();
                }

                // ── Policy evaluation ─────────────────────────────────────────
                match policy_engine.evaluate(&packet) {
                    RuleAction::Block => {
                        block_count += 1;

                        if let Some(ref info) = proc_info {
                            if let Some(s) = proc_stats.get_mut(&info.pid) {
                                s.blocked       += 1;
                                s.total_blocked += 1;
                            }
                        }

                        // Log to file — NO stdout
                        let proc_label = proc_info.as_ref()
                            .map(|p| format!("{}({})", p.name, p.pid))
                            .unwrap_or_else(|| "unknown".into());
                        AlertLogger::log_block(
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port,
                            packet.dst_port,
                            &packet.protocol.to_string(),
                            &format!("proc={}", proc_label),
                        );
                    }

                    RuleAction::Alert => {
                        alert_count += 1;

                        if let Some(ref info) = proc_info {
                            if let Some(s) = proc_stats.get_mut(&info.pid) {
                                s.alerted       += 1;
                                s.total_alerted += 1;
                            }
                        }

                        let proc_label = proc_info.as_ref()
                            .map(|p| format!("{}({})", p.name, p.pid))
                            .unwrap_or_else(|| "unknown".into());
                        AlertLogger::log_alert(
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port,
                            packet.dst_port,
                            &packet.protocol.to_string(),
                            &format!("proc={}", proc_label),
                        );
                    }

                    RuleAction::Allow => { /* hot path — intentionally empty */ }
                }

                // ── Stats publish (every ~500 ms, no I/O) ────────────────────
                let check_interval = if packet_count < 1_000 { 50 } else { 500 };

                if packet_count % check_interval == 0 {
                    let now = std::time::Instant::now();

                    if now.duration_since(last_stats_time).as_secs_f64() >= 0.5 {
                        let elapsed   = now.duration_since(start_time).as_secs_f64();
                        let int_pkts  = packet_count - last_packet_count;
                        let int_secs  = now.duration_since(last_stats_time)
                            .as_secs_f64().max(0.001);
                        let pps       = int_pkts as f64 / int_secs;
                        let avg_pps   = packet_count as f64 / elapsed.max(0.001);

                        heartbeat.push(pps);

                        publish_stats(
                            &shared_stats,
                            packet_count, block_count, alert_count,
                            pps, avg_pps, elapsed,
                            heartbeat.render(),
                            &proc_stats,
                            &recent_threats,
                        );

                        // 5-second window reset
                        if now.duration_since(last_window_reset).as_secs() >= 5 {
                            for s in proc_stats.values_mut() { s.reset_window(); }

                            // Trim stale entries: keep processes seen at least once
                            if proc_stats.len() > 64 {
                                proc_stats.retain(|_, s| s.total_packets > 0);
                            }

                            last_window_reset = now;
                        }

                        last_stats_time   = now;
                        last_packet_count = packet_count;
                    }
                }
            }

            // ── Quiet period (no packets) ─────────────────────────────────────
            Ok(None) => {
                let now = std::time::Instant::now();

                if now.duration_since(last_stats_time).as_secs() >= 2 {
                    heartbeat.push(0.0);

                    let elapsed = start_time.elapsed().as_secs_f64();
                    let avg_pps = packet_count as f64 / elapsed.max(0.001);

                    publish_stats(
                        &shared_stats,
                        packet_count, block_count, alert_count,
                        0.0, avg_pps, elapsed,
                        heartbeat.render(),
                        &proc_stats,
                        &recent_threats,
                    );

                    last_stats_time = now;
                }

                sleep(Duration::from_micros(100)).await;
            }

            // ── 100 ms timeout — just continue ───────────────────────────────
            Err(_) => continue,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  GRACEFUL SHUTDOWN
    // ─────────────────────────────────────────────────────────────────────────

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     SHUTTING DOWN RUBIX                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    info!("Cleaning up kernel rules...");
    if let Err(e) = blocker.cleanup().await {
        error!(error = %e, "Failed to clean up kernel rules — manual flush may be needed");
    }

    if timeout(Duration::from_secs(2), capture.stop()).await.is_err() {
        warn!("Capture did not stop cleanly within 2 seconds");
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let avg_pps = packet_count as f64 / elapsed.max(0.001);

    println!();
    println!("┌─ FINAL STATISTICS ──────────────────────────────────────────────┐");
    println!("│ Total Packets:  {:<48} │", packet_count);
    println!("│ Total Blocked:  {:<48} │", block_count);
    println!("│ Total Alerts:   {:<48} │", alert_count);
    println!("│ Average Rate:   {:<48} │", format!("{:.0} pps", avg_pps));
    println!("│ Runtime:        {:<48} │", format!("{:.1} seconds", elapsed));
    println!("└──────────────────────────────────────────────────────────────────┘");

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                                                                  ║");
    println!("║         GOODBYE BUDDY! RUBIX IS SIGNING OFF...                   ║");
    println!("║                                                                  ║");
    println!("║              Stay safe out there!                                ║");
    println!("║                                                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    info!("RUBIX stopped successfully - Goodbye Buddy!");
    Ok(())
}
