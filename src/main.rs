// src/main.rs
//! RUBIX - Production Network Blocking Engine with Process Attribution

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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use tokio::time::{Duration, timeout, sleep};
use tracing::{info, warn, error};
use std::io::Write;

// ── Platform constants ────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";

#[cfg(target_os = "windows")]
const OS_NAME: &str = "windows";

// ── Per-process statistics ────────────────────────────────────────────────────
#[derive(Clone)]
struct ProcStats {
    name:        String,
    packets:     u64,
    bytes:       u64,
    blocked:     u64,
    alerted:     u64,
    unique_dsts: HashSet<IpAddr>,
    unique_srcs: HashSet<IpAddr>,
    protocols:   HashSet<String>,
}

impl ProcStats {
    fn new(name: String) -> Self {
        Self {
            name,
            packets:     0,
            bytes:       0,
            blocked:     0,
            alerted:     0,
            unique_dsts: HashSet::with_capacity(16),
            unique_srcs: HashSet::with_capacity(16),
            protocols:   HashSet::with_capacity(4),
        }
    }

    #[inline]
    fn reset_window(&mut self) {
        self.packets = 0;
        self.bytes   = 0;
        self.blocked = 0;
        self.alerted = 0;
    }
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────
struct Heartbeat {
    samples:  Vec<f64>,
    capacity: usize,
}

impl Heartbeat {
    fn new(capacity: usize) -> Self {
        Self {
            samples:  Vec::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, pps: f64) {
        if self.samples.len() >= self.capacity {
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

        let wave: String = self.samples
            .iter()
            .map(|&v| {
                let ratio = (v / max).clamp(0.0, 1.0);
                let idx   = (ratio * (bars.len() - 1) as f64).round() as usize;
                bars[idx]
            })
            .collect();

        format!("{}{}", pad_str, wave)
    }

    fn status_label(block_count: u64, alert_count: u64) -> &'static str {
        if block_count > 0 {
            "[BLOCKING]"
        } else if alert_count > 0 {
            "[ALERTING]"
        } else {
            "[ CLEAN  ]"
        }
    }
}

// ── Top talkers table ─────────────────────────────────────────────────────────
fn render_top_talkers(stats: &HashMap<u32, ProcStats>) {
    let mut top: Vec<_> = stats.iter()
        .filter(|(_, s)| s.packets > 0 || s.blocked > 0 || s.alerted > 0)
        .collect();

    if top.is_empty() {
        return;
    }

    top.sort_by(|a, b| {
        b.1.blocked.cmp(&a.1.blocked)
            .then(b.1.alerted.cmp(&a.1.alerted))
            .then(b.1.packets.cmp(&a.1.packets))
    });

    println!("┌─ TOP PROCESSES (5s window) ──────────────────────────────────┐");
    println!("│ {:<5} {:<20} {:>7} {:>8} {:>4} {:>4} {:>4} {:>4} │",
             "PID", "PROCESS", "PKTS", "BYTES", "BLK", "ALT", "DST", "PRO");
    println!("├──────────────────────────────────────────────────────────────┤");

    for (pid, s) in top.iter().take(8) {
        let name = if s.name.len() > 20 {
            format!("{}~", &s.name[..19])
        } else {
            s.name.clone()
        };

        let bytes_str = if s.bytes >= 1_000_000 {
            format!("{:.1}M", s.bytes as f64 / 1_000_000.0)
        } else if s.bytes >= 1_000 {
            format!("{:.1}K", s.bytes as f64 / 1_000.0)
        } else {
            format!("{}B", s.bytes)
        };

        let blk_str = if s.blocked > 0 {
            format!("!{}", s.blocked)
        } else {
            "0".to_string()
        };

        let alrt_str = if s.alerted > 0 {
            format!("!{}", s.alerted)
        } else {
            "0".to_string()
        };

        println!("│ {:<5} {:<20} {:>7} {:>8} {:>4} {:>4} {:>4} {:>4} │",
                 pid,
                 name,
                 s.packets,
                 bytes_str,
                 blk_str,
                 alrt_str,
                 s.unique_dsts.len(),
                 s.protocols.len());
    }

    println!("└──────────────────────────────────────────────────────────────┘");
}

// ── Cross-platform shutdown ───────────────────────────────────────────────────
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint  = signal(SignalKind::interrupt()).expect("Failed to register SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
        tokio::select! {
            _ = sigint.recv() => {
                println!();
                println!("[!] Shutdown signal received (Ctrl+C / SIGINT)...");
            }
            _ = sigterm.recv() => {
                println!();
                println!("[!] Shutdown signal received (SIGTERM)...");
            }
        }
    }

    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await.expect("Failed to register Ctrl+C handler");
        println!();
        println!("[!] Shutdown signal received (Ctrl+C)...");
    }
}

// ── Extract malicious IPs from rules.yaml ─────────────────────────────────────
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

                if let Some(action) = rule.get("action").and_then(|a| a.as_str()) {
                    if action == "Block" {
                        if let Some(conditions) = rule.get("conditions") {
                            if let Some(dst_ips) = conditions
                                .get("dst_ips")
                                .and_then(|i| i.as_sequence())
                            {
                                for ip in dst_ips {
                                    if let Some(ip_str) = ip.as_str() {
                                        if !ip_str.contains('/')
                                            && ip_str != "0.0.0.0"
                                            && ip_str != "255.255.255.255"
                                        {
                                            ips.push(ip_str.to_string());
                                        }
                                    }
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

// ── Build BPF filter ──────────────────────────────────────────────────────────
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
            Err(e) => {
                warn!("Config BPF filter invalid: {} — falling back to auto-built", e);
            }
        }
    }

    let filter = FilterBuilder::from_block_list(malicious_ips, &[])
        .unwrap_or_else(FilterBuilder::default_filter);

    info!(filter = %filter, "Using auto-built BPF filter");
    Some(filter)
}

// ── Banner ────────────────────────────────────────────────────────────────────
pub async fn print_banner(
    config: &config::RubixConfig,
    rules_count: usize,
    kernel_rules: usize,
    interface: &str,
    interface_label: &str,
    bpf_filter: &str,
    malicious_ips: &[String],
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
    println!(
        "│ Promiscuous    : {:<43} │",
        if config.promiscuous { "ENABLED" } else { "DISABLED" }
    );
    sleep(Duration::from_millis(120)).await;
    let filter_display = if bpf_filter.len() > 43 {
        format!("{}...", &bpf_filter[..40])
    } else {
        bpf_filter.to_string()
    };
    println!("│ BPF Filter     : {:<43} │", filter_display);
    sleep(Duration::from_millis(120)).await;
    println!(
        "│ Buffer Size    : {:<43} │",
        format!("{} MB", config.buffer_size_mb)
    );
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
    println!(
        "│ Default Action  : {:<41} │",
        config.blocking.default_action.to_uppercase()
    );
    sleep(Duration::from_millis(120)).await;
    println!(
        "│ Auto Cleanup    : {:<41} │",
        if config.blocking.auto_cleanup { "ENABLED" } else { "DISABLED" }
    );
    sleep(Duration::from_millis(120)).await;
    println!(
        "│ Block Timeout   : {:<41} │",
        format!("{} sec", config.blocking.block_timeout_seconds)
    );
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(250)).await;

    if !malicious_ips.is_empty() {
        println!("┌─ ACTIVE THREATS ─────────────────────────────────────────────┐");
        sleep(Duration::from_millis(150)).await;
        println!(
            "│ [!] {} IPs pre-blocked at kernel level{:>23} │",
            malicious_ips.len(), ""
        );
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
                println!(
                    "│ {:<10} {:<28} {:<20} │",
                    status,
                    display_name,
                    format!("{} addrs", iface.addresses.len())
                );
            }
        }
        Err(e) => {
            println!("│ [!] {:<56} │", format!("Interface error: {}", e));
        }
    }
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(200)).await;
    println!(
        "[*] RUBIX ACTIVE -- Monitoring on {} (Ctrl+C to stop)",
        interface_label
    );
    println!();
}

// ── Helper: determine if packet is ingress ────────────────────────────────────
#[inline(always)]
fn is_ingress_packet(src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    // Ingress: destination is local (private/loopback), source is external
    dst_ip.is_loopback() || is_private_ip(dst_ip) && !is_private_ip(src_ip)
}

#[inline(always)]
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(_) => false, // IPv6 private ranges more complex, skip for now
    }
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
                Ok(_) => {
                    kernel_rules += 1;
                    info!(ip = %ip_str, "Kernel block rule installed");
                }
                Err(e) => {
                    error!(ip = %ip_str, error = %e, "Failed to install kernel block rule");
                }
            }
        } else {
            warn!(ip = %ip_str, "Skipping invalid IP in rules.yaml");
        }
    }

    // ── Process resolver ──────────────────────────────────────────────────────
    let resolver = Arc::new(ProcessResolver::new());
    info!("Process resolver initialized");

    // ── Interface auto-detection ──────────────────────────────────────────────
    let interface_name = if config.capture_interface == "auto" {
        match CaptureFactory::auto_select_interface() {
            Some(iface) => {
                info!(interface = %iface, "Auto-selected network interface");
                iface
            }
            None => {
                error!("Could not auto-detect a suitable network interface");
                error!(
                    "Set capture_interface manually in configs/rubix.{}.yaml",
                    OS_NAME
                );
                std::process::exit(1);
            }
        }
    } else {
        info!(
            interface = %config.capture_interface,
            "Using manually configured interface"
        );
        config.capture_interface.clone()
    };

    let interface_label = CaptureFactory::list_interfaces()
        .ok()
        .and_then(|ifaces| {
            ifaces.into_iter()
                .find(|i| i.name == interface_name)
                .map(|i| i.description.unwrap_or_else(|| i.name.clone()))
        })
        .unwrap_or_else(|| interface_name.clone());

    // ── BPF filter ────────────────────────────────────────────────────────────
    let bpf_filter         = build_bpf_filter(&config.bpf_filter, &malicious_ips);
    let bpf_filter_display = bpf_filter.as_deref().unwrap_or("none").to_string();

    // ── Banner ────────────────────────────────────────────────────────────────
    print_banner(
        &config,
        rules_count,
        kernel_rules,
        &interface_name,
        &interface_label,
        &bpf_filter_display,
        &malicious_ips,
    ).await;

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
    ));
    let ctrl_server = ControlServer::new(ctrl_handler);
    ctrl_server.start().await;
    info!("Control server started — CLI commands are active");

    // ── Signal handling ───────────────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r       = running.clone();

    tokio::spawn(async move {
        wait_for_shutdown().await;
        r.store(false, Ordering::SeqCst);
    });

    // ── Packet loop ───────────────────────────────────────────────────────────
    let mut packet_count      = 0u64;
    let mut block_count       = 0u64;
    let mut alert_count       = 0u64;
    let mut last_stats_time   = start_time;
    let mut last_packet_count = 0u64;
    let mut last_top_render   = start_time;

    let mut heartbeat = Heartbeat::new(30);
    let mut proc_stats: HashMap<u32, ProcStats> = HashMap::with_capacity(128);

    let mut threat_tracker = ThreatTracker::new();
    let mut recent_threats: std::collections::VecDeque<ThreatEvent> =
        std::collections::VecDeque::with_capacity(50);

    while running.load(Ordering::SeqCst) {
        match timeout(Duration::from_millis(100), capture.next_packet()).await {

            // ── Packet received ───────────────────────────────────────────────
            Ok(Some(packet)) => {
                packet_count += 1;

                // ── HOT PATH: Process resolution (~20ns) ──────────────────────
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

                // ── Update per-process stats ──────────────────────────────────
                if let Some(ref info) = proc_info {
                    let entry = proc_stats
                        .entry(info.pid)
                        .or_insert_with(|| ProcStats::new(info.name.clone()));

                    if entry.name.is_empty() {
                        entry.name.clone_from(&info.name);
                    }

                    entry.packets += 1;
                    entry.bytes   += packet.size as u64;
                    entry.unique_dsts.insert(packet.dst_ip);
                    entry.unique_srcs.insert(packet.src_ip);
                    entry.protocols.insert(packet.protocol.to_string());
                }

                // ── Threat detection ────────────────────────────────────────
                // NEW API: single Option<ThreatEvent>, with proc_name and is_ingress
                let proc_name = proc_info.as_ref().map(|p| p.name.as_str());
                let is_ingress = is_ingress_packet(packet.src_ip, packet.dst_ip);

                let threat: Option<ThreatEvent> = match packet.protocol {
                    crate::types::Protocol::Tcp => {
                        ScanDetector::analyze_tcp(
                            &mut threat_tracker,
                            packet.src_ip,
                            packet.dst_port,
                            &packet.flags,
                            proc_name,
                            is_ingress,
                        )
                    }
                    crate::types::Protocol::Udp => {
                        ScanDetector::analyze_udp(
                            &mut threat_tracker,
                            packet.src_ip,
                            packet.dst_port,
                            proc_name,
                            is_ingress,
                        )
                    }
                    crate::types::Protocol::Icmp | crate::types::Protocol::Icmpv6 => {
                        PingDetector::analyze(
                            &mut threat_tracker,
                            packet.src_ip,
                            true, // treat all ICMP as echo request for simplicity
                            proc_name,
                            is_ingress,
                        )
                    }
                    _ => None,
                };

                // ── Handle detected threat ───────────────────────────────────
                if let Some(threat) = threat {
                    println!(
                        "\n{} {} DETECTED: {} | src={} | {}",
                        threat.severity.icon(),
                        threat.severity.as_str(),
                        threat.kind.as_str(),
                        threat.src_ip,
                        threat.detail,
                    );

                    AlertLogger::log_block(
                        &threat.src_ip.to_string(),
                        "local",
                        0,
                        0,
                        "DETECT",
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                    );

                    recent_threats.push_back(threat.clone());
                    if recent_threats.len() > 50 {
                        recent_threats.pop_front();
                    }

                    alert_count += 1;

                    // Update per-process alert counter
                    if let Some(ref info) = proc_info {
                        if let Some(s) = proc_stats.get_mut(&info.pid) {
                            s.alerted += 1;
                        }
                    }
                }

                // Periodic eviction of stale tracker state
                if packet_count % 1000 == 0 {
                    threat_tracker.maybe_evict();
                }

                // ── Policy evaluation ──────────────────────────────────────────
                match policy_engine.evaluate(&packet) {
                    RuleAction::Block => {
                        block_count += 1;

                        if let Some(ref info) = proc_info {
                            if let Some(s) = proc_stats.get_mut(&info.pid) {
                                s.blocked += 1;
                            }
                        }

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
                                s.alerted += 1;
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

                    RuleAction::Allow => {
                        // Hot path — no logging for allowed packets
                    }
                }

                // ── Stats / heartbeat ─────────────────────────────────────────
                let check_interval = if packet_count < 1000 { 50 } else { 500 };

                if packet_count % check_interval == 0 {
                    let now = std::time::Instant::now();

                    if now.duration_since(last_stats_time).as_secs_f64() >= 0.5 {
                        let elapsed          = now.duration_since(start_time).as_secs_f64();
                        let interval_packets = packet_count - last_packet_count;
                        let interval_secs    = now
                            .duration_since(last_stats_time)
                            .as_secs_f64()
                            .max(0.001);
                        let pps     = interval_packets as f64 / interval_secs;
                        let avg_pps = packet_count as f64 / elapsed;

                        heartbeat.push(pps);

                        let wave   = heartbeat.render();
                        let status = Heartbeat::status_label(block_count, alert_count);

                        print!(
                            "\r\x1B[2K{status} |{wave}| {pps:>5.0} pps | pkts:{pkts:>8} blk:{blk:>4} alrt:{alrt:>4} | avg:{avg:>5.0}",
                            status = status,
                            wave   = wave,
                            pps    = pps,
                            pkts   = packet_count,
                            blk    = block_count,
                            alrt   = alert_count,
                            avg    = avg_pps,
                        );
                        let _ = std::io::stdout().flush();

                        // ── Top talkers every 5s ──────────────────────────────
                        if now.duration_since(last_top_render).as_secs() >= 5
                            && proc_stats.values().any(|s| s.packets > 0)
                        {
                            println!();
                            render_top_talkers(&proc_stats);
                            last_top_render = now;

                            for s in proc_stats.values_mut() {
                                s.reset_window();
                            }

                            if proc_stats.len() > 64 {
                                proc_stats.retain(|_, s| !s.unique_dsts.is_empty());
                            }
                        }

                        last_stats_time   = now;
                        last_packet_count = packet_count;
                    }
                }
            }

            // ── No packet (quiet period) ──────────────────────────────────────
            Ok(None) => {
                let now = std::time::Instant::now();

                if now.duration_since(last_stats_time).as_secs() >= 2 {
                    heartbeat.push(0.0);

                    let wave   = heartbeat.render();
                    let status = Heartbeat::status_label(block_count, alert_count);
                    let avg    = if start_time.elapsed().as_secs_f64() > 0.0 {
                        packet_count as f64 / start_time.elapsed().as_secs_f64()
                    } else {
                        0.0
                    };

                    print!(
                        "\r\x1B[2K{status} |{wave}|     0 pps | pkts:{pkts:>8} blk:{blk:>4} alrt:{alrt:>4} | avg:{avg:>5.0}",
                        status = status,
                        wave   = wave,
                        pkts   = packet_count,
                        blk    = block_count,
                        alrt   = alert_count,
                        avg    = avg,
                    );
                    let _ = std::io::stdout().flush();

                    if now.duration_since(last_top_render).as_secs() >= 5
                        && proc_stats.values().any(|s| s.packets > 0)
                    {
                        println!();
                        render_top_talkers(&proc_stats);
                        last_top_render = now;

                        for s in proc_stats.values_mut() {
                            s.reset_window();
                        }

                        if proc_stats.len() > 64 {
                            proc_stats.retain(|_, s| !s.unique_dsts.is_empty());
                        }
                    }

                    last_stats_time = now;
                }

                sleep(Duration::from_micros(100)).await;
            }

            // ── 100ms timeout ──────────────────────────────────────────────────
            Err(_) => {
                continue;
            }
        }
    }

    // ── Graceful shutdown ─────────────────────────────────────────────────────
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     SHUTTING DOWN RUBIX                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    info!("Cleaning up kernel rules...");
    if let Err(e) = blocker.cleanup().await {
        error!(
            error = %e,
            "Failed to clean up kernel rules — manual flush may be needed"
        );
    }

    if timeout(Duration::from_secs(2), capture.stop()).await.is_err() {
        warn!("Capture did not stop cleanly within 2 seconds");
    }

    if proc_stats.values().any(|s| !s.unique_dsts.is_empty()) {
        render_top_talkers(&proc_stats);
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let avg_pps = if elapsed > 0.0 { packet_count as f64 / elapsed } else { 0.0 };

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