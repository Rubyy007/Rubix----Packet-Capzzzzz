// src/main.rs
//! RUBIX - Production Network Blocking Engine with Kernel Blocking

mod types;
mod capture;
mod policy;
mod config;
mod blocker;
mod logger;
mod control;

use policy::{PolicyEngine, PolicyReloader, RuleAction};
use config::loader::ConfigLoader;
use blocker::{PlatformBlocker, Blocker};
use capture::{CaptureConfig, CaptureFactory};
use capture::filter::FilterBuilder;
use logger::AlertLogger;
use control::{CommandHandler, ControlServer};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::IpAddr;
use tokio::time::{Duration, timeout, sleep};
use tracing::{info, warn, error};
use std::io::Write;

// ── Platform constants ────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";

#[cfg(target_os = "windows")]
const OS_NAME: &str = "windows";

// ── Heartbeat ─────────────────────────────────────────────────────────────────
// Rolling window of pps samples rendered as a scrolling ASCII waveform.
// Uses only basic ASCII so it renders correctly in every Windows terminal
// regardless of font (cmd.exe, PowerShell, Windows Terminal).
//
// Height levels (low → high):
//   _  .  -  ^  |
//
// Example:
//   _._.-^|^-._._.-^||^-._._
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
// Parses only enabled Block rules with explicit IPs (no CIDR ranges).
// TODO: Replace with policy_engine.get_block_ips() once engine exposes it.
fn extract_malicious_ips_from_rules() -> Vec<String> {
    let rules_path = "configs/rules.yaml";
    let mut ips    = Vec::new();

    if let Ok(contents) = std::fs::read_to_string(rules_path) {
        if let Ok(rules) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(&contents) {
            for rule in rules {
                // Skip disabled rules
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
                                        // Skip CIDR ranges and placeholder IPs
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

    // ── System config ─────────────────────────────────────────────────────────
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

    // Show control server address
    sleep(Duration::from_millis(120)).await;
    #[cfg(unix)]
    println!("│ Control Socket : {:<43} │", "/var/run/rubix.sock");
    #[cfg(windows)]
    println!("│ Control Socket : {:<43} │", "127.0.0.1:9876");

    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(250)).await;

    // ── Security status ───────────────────────────────────────────────────────
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

    // ── Active threats ────────────────────────────────────────────────────────
    if !malicious_ips.is_empty() {
        println!("┌─ ACTIVE THREATS ─────────────────────────────────────────────┐");

        sleep(Duration::from_millis(150)).await;
        println!("│ [!] {} IPs pre-blocked at kernel level{:>23} │", malicious_ips.len(), "");

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

    // ── Network interfaces ────────────────────────────────────────────────────
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

// ── Entry point ───────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // _logger MUST be a named binding — anonymous `let _ =` drops WorkerGuard
    // immediately and silently discards all buffered log lines.
    let _logger = logger::Logger::init_dual()?;

    // Record start time early — used by control server for uptime reporting
    let start_time = std::time::Instant::now();

    // ── Config ───────────────────────────────────────────────────────────────
    let config_dir    = std::path::Path::new("configs");
    let config_loader = ConfigLoader::load(config_dir, OS_NAME)?;
    let config        = config_loader.get();

    // ── Policy engine ────────────────────────────────────────────────────────
    let policy_engine = Arc::new(PolicyEngine::new());

    // Arc-wrap the reloader so it can be shared with the control server
    // for hot-reload support via `rubix reload`
    let reloader = Arc::new(PolicyReloader::new(
        policy_engine.clone(),
        "configs/rules.yaml".to_string(),
    ));
    let _ = reloader.load_initial();
    let rules_count = policy_engine.rule_count();

    // ── Kernel blocker ────────────────────────────────────────────────────────
    // PlatformBlocker → LinuxBlocker on Linux, WindowsBlocker on Windows.
    // main.rs never needs to know which one it is.
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

    // Resolve human-readable label — shows "Ethernet (Up)" not raw GUID
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

    // ── Banner ───────────────────────────────────────────────────────────────
    print_banner(
        &config,
        rules_count,
        kernel_rules,
        &interface_name,
        &interface_label,
        &bpf_filter_display,
        &malicious_ips,
    ).await;

    // ── Capture ──────────────────────────────────────────────────────────────
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
    // Listens for CLI commands:
    //   Linux   → Unix socket /var/run/rubix.sock
    //   Windows → TCP loopback 127.0.0.1:9876
    //
    // Enables: rubix status / block / unblock / list / reload / rules / stop
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

    // ── Packet loop ──────────────────────────────────────────────────────────
    let mut packet_count  = 0u64;
    let mut block_count   = 0u64;
    let mut alert_count   = 0u64;
    let mut last_stats_time   = start_time;
    let mut last_packet_count = 0u64;

    // 30-sample rolling heartbeat waveform
    let mut heartbeat = Heartbeat::new(30);

    while running.load(Ordering::SeqCst) {
        match timeout(Duration::from_millis(100), capture.next_packet()).await {
            Ok(Some(packet)) => {
                packet_count += 1;

                match policy_engine.evaluate(&packet) {
                    RuleAction::Block => {
                        block_count += 1;
                        // TODO: push to channel export layer
                        AlertLogger::log_block(
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port,
                            packet.dst_port,
                            &packet.protocol.to_string(),
                            "policy-block",
                        );
                    }
                    RuleAction::Alert => {
                        alert_count += 1;
                        // TODO: push to channel export layer
                        AlertLogger::log_alert(
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port,
                            packet.dst_port,
                            &packet.protocol.to_string(),
                            "policy-alert",
                        );
                    }
                    RuleAction::Allow => {
                        // Hot path — no logging
                    }
                }

                // ── Stats / heartbeat ─────────────────────────────────────────
                // Sample every 500 packets, redraw only if 0.5s elapsed.
                // Avoids calling Instant::now() on every single packet.
                if packet_count % 500 == 0 {
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
                            "\r{status} |{wave}| {pps:>5.0} pps | pkts:{pkts:>8} blk:{blk:>4} alrt:{alrt:>4} | avg:{avg:>5.0}",
                            status = status,
                            wave   = wave,
                            pps    = pps,
                            pkts   = packet_count,
                            blk    = block_count,
                            alrt   = alert_count,
                            avg    = avg_pps,
                        );
                        let _ = std::io::stdout().flush();

                        last_stats_time   = now;
                        last_packet_count = packet_count;
                    }
                }
            }

            Ok(None) => {
                // No packet — drop waveform to baseline during quiet periods
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
                        "\r{status} |{wave}|     0 pps | pkts:{pkts:>8} blk:{blk:>4} alrt:{alrt:>4} | avg:{avg:>5.0}",
                        status = status,
                        wave   = wave,
                        pkts   = packet_count,
                        blk    = block_count,
                        alrt   = alert_count,
                        avg    = avg,
                    );
                    let _ = std::io::stdout().flush();

                    last_stats_time = now;
                }

                sleep(Duration::from_micros(100)).await;
            }

            Err(_) => {
                // 100ms timeout — loop back to check running flag
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

    // Reduced from 5s to 2s for faster graceful shutdown
    if timeout(Duration::from_secs(2), capture.stop()).await.is_err() {
        warn!("Capture did not stop cleanly within 2 seconds");
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let avg_pps = if elapsed > 0.0 { packet_count as f64 / elapsed } else { 0.0 };

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