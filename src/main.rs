//! RUBIX - Production Network Blocking Engine with Kernel Blocking

mod types;
mod capture;
mod policy;
mod config;
mod blocker;
mod logger;

use policy::{PolicyEngine, PolicyReloader, RuleAction};
use config::loader::ConfigLoader;
use blocker::{LinuxBlocker, Blocker};
use capture::{CaptureConfig, CaptureFactory};
use logger::AlertLogger;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::IpAddr;
use tokio::time::{Duration, timeout, sleep};
use tokio::signal;
use tracing::{info, warn, error};
use std::io::Write;

fn extract_malicious_ips_from_rules() -> Vec<String> {
    let rules_path = "configs/rules.yaml";
    let mut ips = Vec::new();

    if let Ok(contents) = std::fs::read_to_string(rules_path) {
        if let Ok(rules) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(&contents) {
            for rule in rules {
                if let Some(action) = rule.get("action").and_then(|a| a.as_str()) {
                    if action == "Block" {
                        if let Some(conditions) = rule.get("conditions") {
                            if let Some(dst_ips) = conditions
                                .get("dst_ips")
                                .and_then(|i| i.as_sequence())
                            {
                                for ip in dst_ips {
                                    if let Some(ip_str) = ip.as_str() {
                                        if !ip_str.contains('/') {
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

pub async fn print_banner(
    config: &config::RubixConfig,
    rules_count: usize,
    kernel_rules: usize,
    interface: &str,
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
    println!("│ Interface      : {:<43} │", interface);

    sleep(Duration::from_millis(120)).await;
    println!(
        "│ Promiscuous    : {:<43} │",
        if config.promiscuous { "ENABLED" } else { "DISABLED" }
    );

    sleep(Duration::from_millis(120)).await;
    println!(
        "│ BPF Filter     : {:<43} │",
        config.bpf_filter.as_deref().unwrap_or("none")
    );

    sleep(Duration::from_millis(120)).await;
    println!(
        "│ Buffer Size    : {:<43} │",
        format!("{} MB", config.buffer_size_mb)
    );

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
        println!("│ 🚫 {} malicious IPs blocked{:>34} │", malicious_ips.len(), "");

        for ip in malicious_ips.iter().take(5) {
            sleep(Duration::from_millis(80)).await;
            println!("│   • {:<57} │", ip);
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
                let status = if iface.name == interface {
                    "● ACTIVE"
                } else {
                    "○ IDLE"
                };

                sleep(Duration::from_millis(80)).await;
                println!(
                    "│ {:<10} {:<20} {:<30} │",
                    status,
                    iface.name,
                    format!("{} addrs", iface.addresses.len())
                );
            }
        }
        Err(e) => {
            println!("│ ⚠️  {:<56} │", format!("Interface error: {}", e));
        }
    }

    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(200)).await;

    println!("🛡️  RUBIX ACTIVE — Monitoring traffic (Ctrl+C to stop)");
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Logger init ──────────────────────────────────────────────────────────
    // _logger MUST be a named binding. An anonymous `let _ =` would drop the
    // WorkerGuard immediately and silently discard all buffered log lines.
    let _logger = logger::Logger::init_dual()?;

    // ── Config ───────────────────────────────────────────────────────────────
    let config_dir = std::path::Path::new("configs");
    let config_loader = ConfigLoader::load(config_dir, "linux")?;
    let config = config_loader.get();

    // ── Policy engine ────────────────────────────────────────────────────────
    let policy_engine = Arc::new(PolicyEngine::new());
    let reloader = PolicyReloader::new(
        policy_engine.clone(),
        "configs/rules.yaml".to_string(),
    );
    let _ = reloader.load_initial();
    let rules_count = policy_engine.rule_count();

    // ── Kernel blocker ───────────────────────────────────────────────────────
    let blocker = Arc::new(LinuxBlocker::new());
    let malicious_ips = extract_malicious_ips_from_rules();

    let mut kernel_rules = 0usize;
    for ip_str in &malicious_ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if blocker.block_ip(ip).await.is_ok() {
                kernel_rules += 1;
            } else {
                error!(ip = %ip_str, "Failed to install kernel block rule");
            }
        } else {
            warn!(ip = %ip_str, "Skipping invalid IP in rules.yaml");
        }
    }

    // ── Interface selection ──────────────────────────────────────────────────
    let interface_name = if config.capture_interface == "auto" {
        match CaptureFactory::list_interfaces() {
            Ok(interfaces) => interfaces
                .into_iter()
                .find(|i| !i.name.starts_with("lo") && !i.name.starts_with("docker"))
                .map(|i| i.name)
                .unwrap_or_else(|| "eth0".to_string()),
            Err(_) => "eth0".to_string(),
        }
    } else {
        config.capture_interface.clone()
    };

    // ── Banner ───────────────────────────────────────────────────────────────
    print_banner(&config, rules_count, kernel_rules, &interface_name, &malicious_ips).await;

    // ── Capture ──────────────────────────────────────────────────────────────
    let capture_config = CaptureConfig {
        interface: interface_name,
        promiscuous: config.promiscuous,
        buffer_size_mb: config.buffer_size_mb as usize,
        timeout_ms: config.timeout_ms as i32,
        snaplen: config.snaplen as i32,
        bpf_filter: config.bpf_filter.clone(),
    };

    let mut capture = CaptureFactory::create(capture_config)?;
    capture.start().await?;

    // ── Signal handling ──────────────────────────────────────────────────────
    let mut sigint  = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = sigint.recv() => {
                println!();
                println!("🛑 Shutdown signal received (Ctrl+C)...");
            }
            _ = sigterm.recv() => {
                println!();
                println!("🛑 Shutdown signal received (SIGTERM)...");
            }
        }
        r.store(false, Ordering::SeqCst);
    });

    // ── Packet loop ──────────────────────────────────────────────────────────
    let start_time        = std::time::Instant::now();
    let mut packet_count  = 0u64;
    let mut block_count   = 0u64;
    let mut alert_count   = 0u64;
    let mut last_stats_time   = start_time;
    let mut last_packet_count = 0u64;

    while running.load(Ordering::SeqCst) {
        match timeout(Duration::from_millis(100), capture.next_packet()).await {
            Ok(Some(packet)) => {
                packet_count += 1;

                let action = policy_engine.evaluate(&packet);

                match action {
                    RuleAction::Block => {
                        block_count += 1;

                        // Write to alerts.log + structured tracing
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

                        // Write to alerts.log + structured tracing
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

                // ── Stats line (every 100 packets or every 2 seconds) ────────
                let now = std::time::Instant::now();
                if packet_count % 100 == 0
                    || now.duration_since(last_stats_time).as_secs() >= 2
                {
                    let elapsed          = now.duration_since(start_time).as_secs_f64();
                    let interval_packets = packet_count - last_packet_count;
                    let interval_secs    = now.duration_since(last_stats_time)
                                             .as_secs_f64()
                                             .max(0.001);
                    let pps     = interval_packets as f64 / interval_secs;
                    let avg_pps = packet_count as f64 / elapsed;

                    print!(
                        "\r📊 {:>8} packets | {:>4} blocked | {:>4} alerts | {:>6.0} pps (avg: {:.0})",
                        packet_count, block_count, alert_count, pps, avg_pps
                    );
                    let _ = std::io::stdout().flush();

                    last_stats_time   = now;
                    last_packet_count = packet_count;
                }
            }

            Ok(None) => {
                // Capture returned nothing — yield briefly before retrying
                sleep(Duration::from_micros(100)).await;
            }

            Err(_) => {
                // Timeout expired — loop back to check `running` flag
                continue;
            }
        }
    }

    // ── Graceful shutdown ────────────────────────────────────────────────────
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     SHUTTING DOWN RUBIX                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    info!("Cleaning up kernel rules...");
    if let Err(e) = blocker.cleanup().await {
        error!(error = %e, "Failed to clean up kernel rules — manual iptables flush may be needed");
    }

    if let Err(_) = timeout(Duration::from_secs(5), capture.stop()).await {
        warn!("Capture did not stop cleanly within 5 seconds");
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
    println!("║           👋 GOODBYE BUDDY! RUBIX IS SIGNING OFF...              ║");
    println!("║                                                                  ║");
    println!("║              Stay safe out there! 🛡️                             ║");
    println!("║                                                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    info!("✅ RUBIX stopped successfully - Goodbye Buddy!");

    Ok(())
}