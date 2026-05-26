// src/main.rs
//! RUBIX - Production Network Blocking Engine with Process Attribution
//!
//! FIX-A — Export calls moved out of the fast path.
//! FIX-B — Kernel block calls moved out of the fast path.
//! FIX-C — publish_stats RwLock write moved out of the fast path.
//! FIX-D — chrono::Local::now() removed from the hot path.
//! FIX-E — Process table blink fixed (total_* fields in snapshot).
//! FIX-F — Pre-flight checks (privilege + Npcap/libpcap) before any init.
//! FIX-G — Tracing subscriber set to WARN level — no debug noise at startup.
//! FIX-H — Logger init unified: single YAML parse drives both tracing
//!         subscriber AND AlertLogger channel (no hardcoded defaults).

mod preflight;   // FIX-F: must be declared before use in main()
mod types;
mod capture;
mod policy;
mod config;
mod blocker;
mod logger;
mod control;
mod resolver;
mod detector;
mod export;
mod banner;
#[path = "../dashboard/mod.rs"]
mod dashboard;

use banner::{
    detect_and_init_terminal,
    select_banner_style,
    print_banner,
    print_shutdown_banner,
    print_offline_banner,
};
use detector::{
    ScanDetector, PingDetector, ThreatTracker, ThreatEvent,
    LocalIpSet, enumerate_local_ips,
};
use export::{ExportDispatcher, ExportEvent};
use policy::{PolicyEngine, PolicyReloader, PolicyWatcher, RuleAction};
use config::loader::ConfigLoader;
use blocker::{PlatformBlocker, Blocker, ProcessBlocklist, BlockOrigin};
use capture::{CaptureConfig, CaptureFactory};
use capture::filter::FilterBuilder;
use logger::AlertLogger;
use control::{CommandHandler, ControlServer};
use dashboard::{DashboardServer, generate_dashboard_token};
use resolver::{ProcessResolver, FlowKey, Protocol};
use types::stats::{LiveStats, LogEntry, LogLevel, ProcStatSnapshot, LOG_RING_CAPACITY};

use parking_lot::RwLock;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::net::IpAddr;
use std::path::PathBuf;
use std::collections::VecDeque;
use std::time::Instant;
use tokio::time::{Duration, timeout, sleep};
use tracing::{info, warn, error};

// ── Platform ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";
#[cfg(target_os = "windows")]
const OS_NAME: &str = "windows";

// ── Packet-loop constants ─────────────────────────────────────────────────────

const MAX_PROC_ENTRIES:       usize    = 512;
const MAX_UNIQUE_DSTS:        usize    = 256;
const MAX_UNIQUE_SRCS:        usize    = 256;
const MAX_UNIQUE_PROTOCOLS:   usize    = 16;
const PROC_TTL_SECS:          u64      = 300;
const PROC_TTL_DURATION:      Duration = Duration::from_secs(PROC_TTL_SECS);
const IDLE_SLEEP_MS:          u64      = 10;
const TIMEOUT_WARN_THRESHOLD: u32      = 3000;

// ── Slow-path channel capacities ──────────────────────────────────────────────

const EXPORT_CHANNEL_DEPTH: usize = 4_096;
const BLOCK_CHANNEL_DEPTH:  usize = 1_024;

// ── Slow-path event types ─────────────────────────────────────────────────────

type ExportCmd = ExportEvent;

struct BlockCmd {
    ip:     IpAddr,
    origin: BlockOrigin,
    pid:    u32,
}

// ── Per-process statistics ────────────────────────────────────────────────────

#[derive(Clone)]
struct ProcStats {
    name:    String,
    // 5-second window fields — reset by reset_window(), NOT used in snapshots.
    packets: u64,
    bytes:   u64,
    blocked: u64,
    alerted: u64,
    unique_dsts: FxHashSet<IpAddr>,
    unique_srcs: FxHashSet<IpAddr>,
    protocols:   FxHashSet<String>,
    // Lifetime total fields — NEVER reset, used in all snapshots (FIX-E).
    total_packets:          u64,
    total_bytes:            u64,
    total_blocked:          u64,
    total_alerted:          u64,
    total_unique_dsts:      usize,
    total_unique_srcs:      usize,
    total_unique_protocols: usize,
    last_active: Instant,
}

impl ProcStats {
    #[inline]
    fn new(name: String) -> Self {
        Self {
            name,
            packets: 0, bytes: 0, blocked: 0, alerted: 0,
            unique_dsts: FxHashSet::default(),
            unique_srcs: FxHashSet::default(),
            protocols:   FxHashSet::default(),
            total_packets: 0, total_bytes: 0,
            total_blocked: 0, total_alerted: 0,
            total_unique_dsts: 0, total_unique_srcs: 0, total_unique_protocols: 0,
            last_active: Instant::now(),
        }
    }

    #[inline]
    fn reset_window(&mut self) {
        self.packets = 0;
        self.bytes   = 0;
        self.blocked = 0;
        self.alerted = 0;
        self.unique_dsts.clear();
        self.unique_srcs.clear();
        self.protocols.clear();
        // total_* fields intentionally NOT reset here.
    }
}

// ── proc_stats insertion ──────────────────────────────────────────────────────

#[inline]
fn proc_stats_insert_or_get<'a>(
    map:  &'a mut FxHashMap<u32, ProcStats>,
    pid:  u32,
    name: &str,
    now:  Instant,
) -> Option<&'a mut ProcStats> {
    if map.contains_key(&pid) { return map.get_mut(&pid); }
    if map.len() >= MAX_PROC_ENTRIES {
        map.retain(|_, s| now.duration_since(s.last_active) <= PROC_TTL_DURATION);
    }
    if map.len() >= MAX_PROC_ENTRIES {
        map.retain(|_, s| s.total_packets > 0 || s.total_blocked > 0 || s.total_alerted > 0);
    }
    if map.len() >= MAX_PROC_ENTRIES {
        warn!(pid, max = MAX_PROC_ENTRIES, "proc_stats full — dropping attribution");
        return None;
    }
    Some(map.entry(pid).or_insert_with(|| ProcStats::new(name.to_string())))
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

struct Heartbeat { samples: VecDeque<f64>, capacity: usize }

impl Heartbeat {
    fn new(capacity: usize) -> Self {
        Self { samples: VecDeque::with_capacity(capacity), capacity }
    }
    #[inline]
    fn push(&mut self, pps: f64) {
        if self.samples.len() >= self.capacity { self.samples.pop_front(); }
        self.samples.push_back(pps);
    }
    fn render(&self) -> String {
        let padding = self.capacity.saturating_sub(self.samples.len());
        let pad_str = "_".repeat(padding);
        if self.samples.is_empty() { return pad_str; }
        let max  = self.samples.iter().cloned().fold(1.0_f64, f64::max);
        let bars = ['_', '.', '-', '^', '|'];
        let wave: String = self.samples.iter().map(|&v| {
            let idx = ((v / max).clamp(0.0, 1.0) * (bars.len() - 1) as f64).round() as usize;
            bars[idx]
        }).collect();
        format!("{}{}", pad_str, wave)
    }
}

// ── Shutdown signal ───────────────────────────────────────────────────────────

async fn wait_for_shutdown() {
    #[cfg(unix)] {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint  = signal(SignalKind::interrupt()).expect("SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM");
        tokio::select! {
            _ = sigint.recv()  => println!("\n[!] Shutdown signal received (SIGINT)..."),
            _ = sigterm.recv() => println!("\n[!] Shutdown signal received (SIGTERM)..."),
        }
    }
    #[cfg(windows)] {
        tokio::signal::ctrl_c().await.expect("Ctrl+C");
        println!("\n[!] Shutdown signal received (Ctrl+C)...");
    }
}

// ── Config directory resolution ───────────────────────────────────────────────

fn resolve_configs_dir() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            for base in &[
                exe_dir.to_path_buf(),
                exe_dir.join(".."),
                exe_dir.join("../.."),
            ] {
                let candidate = base.join("configs");
                if let Ok(resolved) = candidate.canonicalize() {
                    if resolved.is_dir() { return resolved; }
                }
            }
        }
    }
    PathBuf::from("configs")
}

// ── Extract pre-block IPs from rules.yaml ─────────────────────────────────────

fn extract_malicious_ips_from_rules(configs_dir: &std::path::Path) -> Vec<String> {
    let mut ips = Vec::new();
    let Ok(contents) = std::fs::read_to_string(configs_dir.join("rules.yaml")) else { return ips; };
    let Ok(rules) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(&contents) else { return ips; };
    for rule in rules {
        if !rule.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true) { continue; }
        if rule.get("action").and_then(|a| a.as_str()) != Some("Block") { continue; }
        if let Some(dst_ips) = rule.get("conditions")
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
    ips
}

// ── BPF filter ────────────────────────────────────────────────────────────────

fn build_bpf_filter(config_filter: &Option<String>, malicious_ips: &[String]) -> Option<String> {
    if let Some(f) = config_filter {
        match capture::filter::validate_filter(f) {
            Ok(()) => { info!(filter = %f, "Using config BPF filter"); return Some(f.clone()); }
            Err(e) => warn!("Config BPF filter invalid: {} — falling back", e),
        }
    }
    let filter = FilterBuilder::from_block_list(malicious_ips, &[])
        .unwrap_or_else(FilterBuilder::default_filter);
    info!(filter = %filter, "Using auto-built BPF filter");
    Some(filter)
}

// ── Log ring helpers ──────────────────────────────────────────────────────────

#[inline]
fn push_log_entry(
    ring: &mut VecDeque<LogEntry>, time: String, level: LogLevel,
    src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16,
    proto: &str, process: &str, detail: &str,
) {
    let process: String = if process.len() > 32 { process.chars().take(32).collect() } else { process.to_string() };
    let detail:  String = if detail.len()  > 64 { detail.chars().take(64).collect()  } else { detail.to_string()  };
    let entry = LogEntry { time, level, src_ip: src_ip.to_string(), dst_ip: dst_ip.to_string(),
        src_port, dst_port, proto: proto.to_string(), process, detail };
    if ring.len() >= LOG_RING_CAPACITY { ring.pop_front(); }
    ring.push_back(entry);
}

#[inline]
fn push_normal_entry(
    ring: &mut VecDeque<LogEntry>, capacity: usize, time: String, level: LogLevel,
    src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16,
    proto: &str, process: &str, detail: &str,
) {
    let process: String = if process.len() > 32 { process.chars().take(32).collect() } else { process.to_string() };
    let detail:  String = if detail.len()  > 64 { detail.chars().take(64).collect()  } else { detail.to_string()  };
    let entry = LogEntry { time, level, src_ip: src_ip.to_string(), dst_ip: dst_ip.to_string(),
        src_port, dst_port, proto: proto.to_string(), process, detail };
    if ring.len() >= capacity { ring.pop_front(); }
    ring.push_back(entry);
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
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() { return true; }
            let o = v6.octets();
            (o[0] == 0xfe && (o[1] & 0xc0) == 0x80) || ((o[0] & 0xfe) == 0xfc)
        }
    }
}

// ── Snapshot builder helper ───────────────────────────────────────────────────
// Extracted so both the packet-received and idle branches share the same
// consistent logic.  Always uses total_* fields — never blinks.

#[inline]
fn build_top_procs(proc_stats: &FxHashMap<u32, ProcStats>) -> Vec<ProcStatSnapshot> {
    let mut top: Vec<ProcStatSnapshot> = proc_stats
        .iter()
        .filter(|(_, s)| s.total_packets > 0 || s.total_blocked > 0 || s.total_alerted > 0)
        .map(|(&pid, s)| ProcStatSnapshot {
            pid,
            name:         s.name.clone(),
            packets:      s.total_packets,
            bytes:        s.total_bytes,
            blocked:      s.total_blocked,
            alerted:      s.total_alerted,
            unique_dsts:  s.total_unique_dsts,
            protocol_cnt: s.total_unique_protocols,
        })
        .collect();
    top.sort_unstable_by(|a, b| {
        b.blocked.cmp(&a.blocked)
            .then_with(|| b.alerted.cmp(&a.alerted))
            .then_with(|| b.packets.cmp(&a.packets))
    });
    top.truncate(8);
    top
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // ── FIX-F: Pre-flight checks ──────────────────────────────────────────────
    //
    // MUST be the first thing that runs — before terminal detection, before
    // the logger, before tokio tasks, before any OS resource is opened.
    preflight::run();

    // ── Terminal capability detection ─────────────────────────────────────────
    let term_caps = detect_and_init_terminal();

    // ── FIX-H: Unified YAML-aware logger init ────────────────────────────────
    //
    // One call parses the platform YAML (rubix.linux.yaml / rubix.windows.yaml)
    // and configures BOTH the tracing subscriber (level, file_path, json_format,
    // console_output) AND the AlertLogger channel (normal_channel_depth,
    // max_file_size_mb, rotation_count).  No hardcoded defaults, no init race.
    //
    // Searches, in order:
    //   1. configs/rubix.{linux,windows}.yaml  (platform-specific)
    //   2. configs/rubix.common.yaml            (fallback)
    //   3. RUBIX_CONFIG env var               (override)
    let configs_dir = resolve_configs_dir();
    let platform_yaml = configs_dir.join(format!("rubix.{}.yaml", OS_NAME));
    let _logger = if platform_yaml.exists() {
        logger::Logger::init_from_yaml(&platform_yaml)?
    } else {
        logger::Logger::init_auto()?
    };
    _logger.start_cleanup_task();

    let start_time = Instant::now();

    // ── Load runtime config (rules, capture, export, etc.) ────────────────────
    let config_loader = ConfigLoader::load(&configs_dir, OS_NAME)?;
    let config        = config_loader.get();

    // AlertLogger already initialised by Logger::init_from_yaml above.
    // Just start the 1 ms timestamp refresh task.
    AlertLogger::start_timestamp_refresh();

    let log_normal:            bool  = config.logging.log_normal_traffic;
    let normal_sample_divisor: u64   = config.logging.normal_sample_divisor.max(1);
    let normal_ring_capacity:  usize = config.logging.normal_ring_capacity.max(1).min(2048);

    let local_ips = LocalIpSet::new(enumerate_local_ips(), &config.trusted_cidrs);

    let exporter = Arc::new(
        ExportDispatcher::build(&config.export).await
            .unwrap_or_else(|e| {
                warn!(error = %e, "Export pipeline failed — running without export");
                ExportDispatcher::default()
            })
    );
    let export_active = exporter.is_active();

    let (export_tx, mut export_rx) = tokio::sync::mpsc::channel::<ExportCmd>(EXPORT_CHANNEL_DEPTH);
    {
        let exporter = exporter.clone();
        tokio::spawn(async move {
            while let Some(event) = export_rx.recv().await { exporter.export(event).await; }
        });
    }

    let (block_tx, mut block_rx) = tokio::sync::mpsc::channel::<BlockCmd>(BLOCK_CHANNEL_DEPTH);

    let policy_engine = Arc::new(PolicyEngine::new());
    let rules_yaml    = configs_dir.join("rules.yaml").to_string_lossy().into_owned();
    let reloader      = Arc::new(PolicyReloader::new(policy_engine.clone(), rules_yaml));
    let _             = reloader.load_initial();
    let rules_count   = policy_engine.rule_count();

    let rules_yaml_path = configs_dir.join("rules.yaml");
    match PolicyWatcher::new(&rules_yaml_path, reloader.clone()).start() {
        Ok(())  => info!(path = %rules_yaml_path.display(), "Policy hot-reload active"),
        Err(e)  => warn!(error = %e, "Policy watcher failed — restart required"),
    }

    let blocker        = Arc::new(PlatformBlocker::new());
    let proc_blocklist = ProcessBlocklist::new();
    let malicious_ips  = extract_malicious_ips_from_rules(&configs_dir);

    {
        let blocker        = blocker.clone();
        let proc_blocklist = proc_blocklist.clone();
        tokio::spawn(async move {
            while let Some(cmd) = block_rx.recv().await {
                if blocker.block_ip_with_origin(cmd.ip, cmd.origin).await.is_ok() {
                    proc_blocklist.record_kernel_ip(cmd.pid, cmd.ip);
                }
            }
        });
    }

    let mut kernel_rules = 0usize;
    for ip_str in &malicious_ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match blocker.block_ip(ip).await {
                Ok(_)  => { kernel_rules += 1; }
                Err(e) => error!(ip = %ip_str, error = %e, "Kernel block failed"),
            }
        }
    }

    let resolver = Arc::new(ProcessResolver::new());

    let interface_name = if config.capture_interface == "auto" {
        match CaptureFactory::auto_select_interface() {
            Some(iface) => iface,
            None => {
                eprintln!();
                eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
                eprintln!("║              RUBIX  —  NO NETWORK INTERFACE FOUND                   ║");
                eprintln!("╠══════════════════════════════════════════════════════════════════════╣");
                eprintln!("║                                                                      ║");
                eprintln!("║  RUBIX could not auto-detect a network interface to capture on.      ║");
                eprintln!("║                                                                      ║");
                eprintln!("║  HOW TO FIX:                                                         ║");
                eprintln!("║    1. Run:  ip link show          (Linux)                            ║");
                eprintln!("║       or:  ipconfig /all          (Windows)                          ║");
                eprintln!("║       to list available interfaces.                                  ║");
                eprintln!("║                                                                      ║");
                eprintln!("║    2. Edit configs/rubix.{}.yaml and set:                    ║", OS_NAME);
                eprintln!("║         capture_interface: \"eth0\"   (replace with your interface)   ║");
                eprintln!("║                                                                      ║");
                eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
                eprintln!();
                std::process::exit(1);
            }
        }
    } else {
        config.capture_interface.clone()
    };

    let interface_label = CaptureFactory::list_interfaces()
        .ok()
        .and_then(|ifaces| ifaces.into_iter()
            .find(|i| i.name == interface_name)
            .map(|i| i.description.unwrap_or_else(|| i.name.clone())))
        .unwrap_or_else(|| interface_name.clone());

    let bpf_filter         = build_bpf_filter(&config.bpf_filter, &malicious_ips);
    let bpf_filter_display = bpf_filter.as_deref().unwrap_or("none").to_string();

    let shared_stats: Arc<RwLock<LiveStats>> = Arc::new(RwLock::new(LiveStats::default()));

    let mut capture = CaptureFactory::create(CaptureConfig {
        interface:      interface_name.clone(),
        promiscuous:    config.promiscuous,
        buffer_size_mb: config.buffer_size_mb as usize,
        timeout_ms:     config.timeout_ms as i32,
        snaplen:        config.snaplen as i32,
        bpf_filter,
    })?;
    capture.start().await?;

    let ctrl_handler = Arc::new(CommandHandler::new(
        blocker.clone(), proc_blocklist.clone(),
        policy_engine.clone(), reloader.clone(),
        start_time, shared_stats.clone(),
    ));
    ControlServer::new(ctrl_handler.clone()).start().await;

    let dashboard_token  = generate_dashboard_token();
    let dashboard_result = DashboardServer::new(
        config.dashboard.clone(), shared_stats.clone(),
        ctrl_handler.clone(), dashboard_token.clone(),
    ).start().await;

    let dashboard_url: Option<String> = dashboard_result.as_ref()
        .map(|r| format!("http://{}:{}", r.host, r.addr.port()));

    let banner_style = select_banner_style(term_caps).await;
    print_banner(
        &config, rules_count, kernel_rules,
        &interface_name, &interface_label,
        &bpf_filter_display, &malicious_ips, &configs_dir,
        export_active, banner_style, term_caps,
        dashboard_url.as_deref(),
        dashboard_result.as_ref().map(|_| dashboard_token.as_str()),
    ).await;

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        tokio::spawn(async move { wait_for_shutdown().await; r.store(false, Ordering::Release); });
    }

    let atomic_packets: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let atomic_blocks:  Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let atomic_alerts:  Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    // ── Packet loop state ─────────────────────────────────────────────────────

    let mut last_window_reset            = start_time;
    let mut normal_sample_counter: u64   = 0;
    let mut consecutive_timeouts:  u32   = 0;
    let mut timeout_warned:        bool  = false;

    let mut proc_stats: FxHashMap<u32, ProcStats> = FxHashMap::default();
    proc_stats.reserve(128);
    let mut threat_tracker  = ThreatTracker::new();
    let mut recent_threats: VecDeque<String>   = VecDeque::with_capacity(20);
    let mut recent_logs:    VecDeque<LogEntry> = VecDeque::with_capacity(LOG_RING_CAPACITY);
    let mut normal_logs:    VecDeque<LogEntry> = VecDeque::with_capacity(normal_ring_capacity);
    let mut heartbeat       = Heartbeat::new(30);

    // ── Stats snapshot channel ────────────────────────────────────────────────

    type StatsSnapshot = (
        u64, u64, u64, f64, f64, f64, String,
        Vec<ProcStatSnapshot>, Vec<String>, Vec<LogEntry>, Vec<LogEntry>,
    );

    let (snap_tx, mut snap_rx) = tokio::sync::mpsc::channel::<StatsSnapshot>(4);
    {
        let shared      = shared_stats.clone();
        let log_normal2 = log_normal;
        let div2        = normal_sample_divisor;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                let mut latest: Option<StatsSnapshot> = None;
                while let Ok(s) = snap_rx.try_recv() { latest = Some(s); }
                if let Some((pc, bc, ac, pps, avg_pps, rt, wave, top, threats, logs, nlogs)) = latest {
                    let mut g = shared.write();
                    g.packet_count           = pc;
                    g.block_count            = bc;
                    g.alert_count            = ac;
                    g.pps                    = pps;
                    g.avg_pps                = avg_pps;
                    g.runtime_secs           = rt;
                    g.heartbeat              = wave;
                    g.top_procs              = top;
                    g.recent_threats         = threats;
                    g.recent_logs            = logs;
                    g.normal_logs            = nlogs;
                    g.normal_logging_enabled = log_normal2;
                    g.normal_sample_divisor  = div2;
                }
            }
        });
    }

    let mut last_stats_time    = start_time;
    let mut last_packet_count: u64 = 0;
    let mut local_packet_count: u64 = 0;

    // ─────────────────────────────────────────────────────────────────────────
    //  HOT PACKET LOOP
    // ─────────────────────────────────────────────────────────────────────────

    while running.load(Ordering::Acquire) {
        match timeout(Duration::from_millis(100), capture.next_packet()).await {

            Ok(Some(packet)) => {
                consecutive_timeouts = 0;
                timeout_warned       = false;

                atomic_packets.fetch_add(1, Ordering::Relaxed);
                local_packet_count = local_packet_count.saturating_add(1);

                let cached_ts: String = logger::alert::global_timestamp()
                    .map(|c| c.get().as_ref().clone())
                    .unwrap_or_else(|| chrono::Local::now().format("%H:%M:%S%.3f").to_string());

                let proto = Protocol::from_str(&packet.protocol.to_string());
                let proc_info = resolver.lookup(&FlowKey {
                    local_ip: packet.src_ip, local_port: packet.src_port, protocol: proto,
                }).or_else(|| resolver.lookup(&FlowKey {
                    local_ip: packet.dst_ip, local_port: packet.dst_port, protocol: proto,
                }));

                let now_instant = Instant::now();
                if let Some(ref info) = proc_info {
                    if let Some(entry) = proc_stats_insert_or_get(
                        &mut proc_stats, info.pid, &info.name, now_instant,
                    ) {
                        if entry.name.is_empty() { entry.name.clone_from(&info.name); }
                        entry.packets     = entry.packets.saturating_add(1);
                        entry.bytes       = entry.bytes.saturating_add(packet.size as u64);
                        entry.last_active = now_instant;
                        entry.total_packets = entry.total_packets.saturating_add(1);
                        entry.total_bytes   = entry.total_bytes.saturating_add(packet.size as u64);
                        if entry.unique_dsts.len() < MAX_UNIQUE_DSTS {
                            if entry.unique_dsts.insert(packet.dst_ip) {
                                entry.total_unique_dsts = entry.total_unique_dsts.saturating_add(1);
                            }
                        }
                        if entry.unique_srcs.len() < MAX_UNIQUE_SRCS {
                            if entry.unique_srcs.insert(packet.src_ip) {
                                entry.total_unique_srcs = entry.total_unique_srcs.saturating_add(1);
                            }
                        }
                        if entry.protocols.len() < MAX_UNIQUE_PROTOCOLS {
                            if entry.protocols.insert(packet.protocol.to_string()) {
                                entry.total_unique_protocols = entry.total_unique_protocols.saturating_add(1);
                            }
                        }
                    }
                }

                let proc_name  = proc_info.as_ref().map(|p| p.name.as_str());
                let is_ingress = is_ingress_packet(packet.src_ip, packet.dst_ip);

                // ── Threat detection ──────────────────────────────────────────
                let threat: Option<ThreatEvent> = match packet.protocol {
                    crate::types::Protocol::Tcp => ScanDetector::analyze_tcp(
                        &mut threat_tracker, packet.src_ip, packet.dst_port,
                        &packet.flags, proc_name, is_ingress, &local_ips,
                    ),
                    crate::types::Protocol::Udp => ScanDetector::analyze_udp(
                        &mut threat_tracker, packet.src_ip, packet.dst_port,
                        proc_name, is_ingress, &local_ips,
                    ),
                    crate::types::Protocol::Icmp | crate::types::Protocol::Icmpv6 =>
                        PingDetector::analyze(
                            &mut threat_tracker, packet.src_ip, true,
                            proc_name, is_ingress, &local_ips,
                        ),
                    _ => None,
                };

                if let Some(ref threat) = threat {
                    AlertLogger::log_block(
                        &threat.src_ip.to_string(), "local", 0, 0, "DETECT",
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                    );
                    let line = format!("{} {} | src={} | {}",
                        threat.severity.icon(), threat.kind.as_str(),
                        threat.src_ip, threat.detail);
                    if recent_threats.len() == 20 { recent_threats.pop_front(); }
                    recent_threats.push_back(line);
                    push_log_entry(
                        &mut recent_logs, cached_ts.clone(), LogLevel::Threat,
                        &threat.src_ip.to_string(), "local", 0, 0, "DETECT",
                        proc_name.unwrap_or("unknown"),
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                    );
                    atomic_alerts.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref info) = proc_info {
                        if let Some(s) = proc_stats.get_mut(&info.pid) {
                            s.alerted       = s.alerted.saturating_add(1);
                            s.total_alerted = s.total_alerted.saturating_add(1);
                            s.last_active   = now_instant;
                        }
                    }
                    let _ = export_tx.try_send(ExportEvent::from_threat(
                        &threat.src_ip.to_string(), "local",
                        packet.src_port, packet.dst_port,
                        &packet.protocol.to_string(), proc_name.unwrap_or("unknown"),
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                        threat.severity.as_str(),
                    ));
                }

                if local_packet_count % 1_000 == 0 { threat_tracker.maybe_evict(); }

                let proc_block_reason = proc_info.as_ref()
                    .and_then(|info| proc_blocklist.check(info.pid, &info.name));

                if let Some(ref reason) = proc_block_reason {
                    atomic_blocks.fetch_add(1, Ordering::Relaxed);
                    let remote_ip = if is_ingress { packet.src_ip } else { packet.dst_ip };
                    if let Some(ref info) = proc_info {
                        let _ = block_tx.try_send(BlockCmd {
                            ip: remote_ip,
                            origin: BlockOrigin::ProcessBlock {
                                pid: info.pid, name: info.name.clone(), exe: None,
                            },
                            pid: info.pid,
                        });
                        if let Some(s) = proc_stats.get_mut(&info.pid) {
                            s.blocked       = s.blocked.saturating_add(1);
                            s.total_blocked = s.total_blocked.saturating_add(1);
                            s.last_active   = now_instant;
                        }
                    }
                    let proc_label = proc_info.as_ref()
                        .map(|p| format!("{}({})", p.name, p.pid))
                        .unwrap_or_else(|| "unknown".into());
                    let detail = format!("proc-block={} reason={:?}", proc_label, reason);
                    AlertLogger::log_block(
                        &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                        packet.src_port, packet.dst_port, &packet.protocol.to_string(), &detail,
                    );
                    push_log_entry(
                        &mut recent_logs, cached_ts.clone(), LogLevel::Block,
                        &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                        packet.src_port, packet.dst_port, &packet.protocol.to_string(),
                        proc_name.unwrap_or("unknown"), &format!("process-blocked: {:?}", reason),
                    );
                    let _ = export_tx.try_send(ExportEvent::from_block(
                        &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                        packet.src_port, packet.dst_port, &packet.protocol.to_string(),
                        proc_name.unwrap_or("unknown"), &detail,
                    ));
                } else {
                    match policy_engine.evaluate(&packet, proc_name) {
                        RuleAction::Block => {
                            atomic_blocks.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref info) = proc_info {
                                if let Some(s) = proc_stats.get_mut(&info.pid) {
                                    s.blocked       = s.blocked.saturating_add(1);
                                    s.total_blocked = s.total_blocked.saturating_add(1);
                                    s.last_active   = now_instant;
                                }
                            }
                            let proc_label = proc_info.as_ref()
                                .map(|p| format!("{}({})", p.name, p.pid))
                                .unwrap_or_else(|| "unknown".into());
                            let detail = format!("proc={}", proc_label);
                            AlertLogger::log_block(
                                &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                packet.src_port, packet.dst_port, &packet.protocol.to_string(), &detail,
                            );
                            push_log_entry(
                                &mut recent_logs, cached_ts.clone(), LogLevel::Block,
                                &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                packet.src_port, packet.dst_port, &packet.protocol.to_string(),
                                proc_name.unwrap_or("unknown"), &detail,
                            );
                            let _ = export_tx.try_send(ExportEvent::from_block(
                                &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                packet.src_port, packet.dst_port, &packet.protocol.to_string(),
                                proc_name.unwrap_or("unknown"), &detail,
                            ));
                        }
                        RuleAction::Alert => {
                            atomic_alerts.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref info) = proc_info {
                                if let Some(s) = proc_stats.get_mut(&info.pid) {
                                    s.alerted       = s.alerted.saturating_add(1);
                                    s.total_alerted = s.total_alerted.saturating_add(1);
                                    s.last_active   = now_instant;
                                }
                            }
                            let proc_label = proc_info.as_ref()
                                .map(|p| format!("{}({})", p.name, p.pid))
                                .unwrap_or_else(|| "unknown".into());
                            let detail = format!("proc={}", proc_label);
                            AlertLogger::log_alert(
                                &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                packet.src_port, packet.dst_port, &packet.protocol.to_string(), &detail,
                            );
                            push_log_entry(
                                &mut recent_logs, cached_ts.clone(), LogLevel::Alert,
                                &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                packet.src_port, packet.dst_port, &packet.protocol.to_string(),
                                proc_name.unwrap_or("unknown"), &detail,
                            );
                            let _ = export_tx.try_send(ExportEvent::from_alert(
                                &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                packet.src_port, packet.dst_port, &packet.protocol.to_string(),
                                proc_name.unwrap_or("unknown"), &detail,
                            ));
                        }
                        RuleAction::Allow => {
                            if log_normal {
                                normal_sample_counter = normal_sample_counter.saturating_add(1);
                                if normal_sample_counter >= normal_sample_divisor {
                                    normal_sample_counter = 0;
                                    let pname = proc_name.unwrap_or("unknown");
                                    AlertLogger::log_normal(
                                        &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                        packet.src_port, packet.dst_port,
                                        &packet.protocol.to_string(), pname,
                                    );
                                    push_normal_entry(
                                        &mut normal_logs, normal_ring_capacity,
                                        cached_ts.clone(), LogLevel::Normal,
                                        &packet.src_ip.to_string(), &packet.dst_ip.to_string(),
                                        packet.src_port, packet.dst_port,
                                        &packet.protocol.to_string(), pname, "allow",
                                    );
                                }
                            }
                        }
                    }
                }

                // ── Stats snapshot (FIX-E) ────────────────────────────────────
                let check_interval = if local_packet_count < 1_000 { 50 } else { 500 };
                if local_packet_count % check_interval == 0 {
                    let now = Instant::now();
                    if now.duration_since(last_stats_time).as_secs_f64() >= 0.5 {
                        let elapsed  = now.duration_since(start_time).as_secs_f64();
                        let pc       = atomic_packets.load(Ordering::Relaxed);
                        let bc       = atomic_blocks.load(Ordering::Relaxed);
                        let ac       = atomic_alerts.load(Ordering::Relaxed);
                        let int_pkts = pc.saturating_sub(last_packet_count);
                        let int_secs = now.duration_since(last_stats_time).as_secs_f64().max(0.001);
                        let pps      = int_pkts as f64 / int_secs;
                        let avg_pps  = pc as f64 / elapsed.max(0.001);
                        heartbeat.push(pps);

                        let snap = (
                            pc, bc, ac, pps, avg_pps, elapsed,
                            heartbeat.render(),
                            build_top_procs(&proc_stats),   // always total_* fields
                            recent_threats.iter().cloned().collect(),
                            recent_logs.iter().cloned().collect(),
                            normal_logs.iter().cloned().collect(),
                        );
                        let _ = snap_tx.try_send(snap);     // send BEFORE reset

                        // Window reset AFTER snapshot is sent (FIX-E).
                        if now.duration_since(last_window_reset).as_secs() >= 5 {
                            for s in proc_stats.values_mut() { s.reset_window(); }
                            proc_stats.retain(|_, s| {
                                now.duration_since(s.last_active) <= PROC_TTL_DURATION
                            });
                            last_window_reset = now;
                        }

                        last_stats_time   = now;
                        last_packet_count = pc;
                    }
                }
            }

            Ok(None) => {
                consecutive_timeouts = 0;
                timeout_warned       = false;
                let now = Instant::now();
                if now.duration_since(last_stats_time).as_secs() >= 2 {
                    heartbeat.push(0.0);
                    let pc      = atomic_packets.load(Ordering::Relaxed);
                    let bc      = atomic_blocks.load(Ordering::Relaxed);
                    let ac      = atomic_alerts.load(Ordering::Relaxed);
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let snap = (
                        pc, bc, ac, 0.0_f64,
                        pc as f64 / elapsed.max(0.001), elapsed,
                        heartbeat.render(),
                        build_top_procs(&proc_stats),   // always total_* fields
                        recent_threats.iter().cloned().collect(),
                        recent_logs.iter().cloned().collect(),
                        normal_logs.iter().cloned().collect(),
                    );
                    let _ = snap_tx.try_send(snap);
                    last_stats_time = now;
                }
                sleep(Duration::from_millis(IDLE_SLEEP_MS)).await;
            }

            Err(_) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                if consecutive_timeouts >= TIMEOUT_WARN_THRESHOLD && !timeout_warned {
                    warn!(
                        "No packets for ~{}s — verify interface is up",
                        (TIMEOUT_WARN_THRESHOLD as u64 * 100) / 1000,
                    );
                    timeout_warned = true;
                }
            }
        }
    }

    // ── Graceful shutdown ─────────────────────────────────────────────────────

    print_shutdown_banner(term_caps);
    drop(export_tx);
    drop(block_tx);
    drop(snap_tx);

    let elapsed = start_time.elapsed().as_secs_f64();
    let pc      = atomic_packets.load(Ordering::Relaxed);
    let bc      = atomic_blocks.load(Ordering::Relaxed);
    let ac      = atomic_alerts.load(Ordering::Relaxed);
    let avg_pps = pc as f64 / elapsed.max(0.001);

    println!();
    println!("\x1b[93m[+] Stopping packet capture engine...\x1b[0m");
    if timeout(Duration::from_secs(2), capture.stop()).await.is_err() {
        println!("\x1b[91m[!] Capture shutdown timeout exceeded\x1b[0m");
    } else {
        println!("\x1b[92m[✓] Packet capture engine stopped\x1b[0m");
    }

    println!("\x1b[93m[+] Cleaning kernel filtering rules...\x1b[0m");
    if let Err(e) = blocker.cleanup().await {
        error!(error = %e, "Kernel cleanup failed");
        println!("\x1b[91m[!] Kernel cleanup failed — manual flush may be required\x1b[0m");
    } else {
        println!("\x1b[92m[✓] Kernel rules cleaned successfully\x1b[0m");
    }

    println!();
    println!("\x1b[96m");
    println!("+--------------------  FINAL OPERATION REPORT  ---------------------------+");
    println!("|                                                                          |");
    println!("|  Total Packets Processed : {:>12}                                  |", pc);
    println!("|  Threats Blocked         : {:>12}                                  |", bc);
    println!("|  Security Alerts Raised  : {:>12}                                  |", ac);
    println!("|  Average Throughput      : {:>9} pps                              |", format!("{:.0}", avg_pps));
    println!("|  Total Runtime           : {:>9} seconds                          |", format!("{:.1}", elapsed));
    if export_active {
        println!("|  Webhook Export Drops    : {:>12}                                  |", exporter.webhook_drop_count());
        println!("|  Active Socket Clients   : {:>12}                                  |", exporter.socket_client_count());
    }
    println!("|                                                                          |");
    println!("+--------------------------------------------------------------------------+");
    println!("\x1b[0m");
    println!();

    print_offline_banner(term_caps);
    info!("RUBIX stopped successfully - Goodbye Buddy!");
    Ok(())
}