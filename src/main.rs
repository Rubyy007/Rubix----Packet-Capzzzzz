//! RUBIX - Production Network Blocking Engine with Kernel Blocking

mod types;
mod capture;
mod policy;
mod config;
mod blocker;

use policy::{PolicyEngine, PolicyReloader, RuleAction};
use config::loader::ConfigLoader;
use blocker::{LinuxBlocker, Blocker};
use capture::{CaptureConfig, CaptureFactory};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{Duration, timeout, sleep};
use tokio::signal;
use tracing::{info, warn, error};
use std::io::Write;
use std::fs;

fn setup_logger() {
    let _ = fs::create_dir_all("/var/log/rubix");
    let file_appender = tracing_appender::rolling::daily("/var/log/rubix", "rubix.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    
    tracing_subscriber::fmt()
        .with_env_filter("rubix=info,pcap=warn")
        .with_target(false)
        .with_thread_ids(true)
        .with_writer(non_blocking)
        .init();
    
    info!("📝 Logging to /var/log/rubix/rubix.log");
}

fn extract_malicious_ips_from_rules() -> Vec<String> {
    let rules_path = "configs/rules.yaml";
    let mut ips = Vec::new();
    
    if let Ok(contents) = std::fs::read_to_string(rules_path) {
        if let Ok(rules) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(&contents) {
            for rule in rules {
                if let Some(action) = rule.get("action").and_then(|a| a.as_str()) {
                    if action == "Block" {
                        if let Some(conditions) = rule.get("conditions") {
                            if let Some(dst_ips) = conditions.get("dst_ips").and_then(|i| i.as_sequence()) {
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
    println!("║              RUBIX by Manik                                   ║");
    println!("║          Network Defense Engine v1.0.0                        ║");
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

    let malicious_ips = extract_malicious_ips_from_rules();
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
    setup_logger();
    
    let config_dir = std::path::Path::new("configs");
    let config_loader = ConfigLoader::load(config_dir, "linux")?;
    let config = config_loader.get();

    let policy_engine = Arc::new(PolicyEngine::new());
    let reloader = PolicyReloader::new(
        policy_engine.clone(),
        "configs/rules.yaml".to_string()
    );
    let _ = reloader.load_initial();
    
    let rules_count = policy_engine.rule_count();

    let blocker = Arc::new(LinuxBlocker::new());
    let malicious_ips = extract_malicious_ips_from_rules();
    
    let mut kernel_rules = 0;
    if !malicious_ips.is_empty() {
        for ip_str in &malicious_ips {
            if let Ok(ip) = ip_str.parse() {
                if blocker.block_ip(ip).await.is_ok() {
                    kernel_rules += 1;
                }
            }
        }
    }
    
    let interface_name = if config.capture_interface == "auto" {
        match CaptureFactory::list_interfaces() {
            Ok(interfaces) => {
                interfaces.into_iter()
                    .find(|i| !i.name.starts_with("lo") && !i.name.starts_with("docker"))
                    .map(|i| i.name)
                    .unwrap_or_else(|| "eth0".to_string())
            }
            Err(_) => "eth0".to_string()
        }
    } else {
        config.capture_interface.clone()
    };
    
    print_banner(config, rules_count, kernel_rules, &interface_name).await;

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

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        println!();
        println!("🛑 Shutdown signal received...");
        r.store(false, Ordering::SeqCst);
    });

    let start_time = std::time::Instant::now();
    let mut packet_count = 0u64;
    let mut block_count = 0u64;
    let mut last_stats_time = start_time;
    let mut last_packet_count = 0u64;

    while running.load(Ordering::SeqCst) {
        // Fixed: capture.next_packet() returns Option<Packet>, not Result
        match capture.next_packet().await {
            Some(packet) => {
                packet_count += 1;

                let action = policy_engine.evaluate(&packet);
                
                match action {
                    RuleAction::Block => {
                        block_count += 1;
                        warn!(
                            src_ip = %packet.src_ip,
                            dst_ip = %packet.dst_ip,
                            "🚫 BLOCKED"
                        );
                    }
                    RuleAction::Alert => {
                        warn!(
                            src_ip = %packet.src_ip,
                            dst_ip = %packet.dst_ip,
                            "⚠️ ALERT"
                        );
                    }
                    RuleAction::Allow => {}
                }

                let now = std::time::Instant::now();
                if packet_count % 100 == 0 || now.duration_since(last_stats_time).as_secs() >= 2 {
                    let elapsed = now.duration_since(start_time).as_secs_f64();
                    let interval_packets = packet_count - last_packet_count;
                    let interval_secs = now.duration_since(last_stats_time).as_secs_f64().max(0.001);
                    let pps = interval_packets as f64 / interval_secs;
                    let avg_pps = packet_count as f64 / elapsed;

                    print!("\r📊 {:>8} packets | {:>4} blocked | {:>6.0} pps (avg: {:.0})", 
                        packet_count, block_count, pps, avg_pps);
                    let _ = std::io::stdout().flush();

                    last_stats_time = now;
                    last_packet_count = packet_count;
                }
            }
            None => {
                sleep(Duration::from_micros(100)).await;
            }
        }
    }

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     SHUTTING DOWN RUBIX                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    
    info!("Cleaning up kernel rules...");
    let _ = blocker.cleanup().await;

    let _ = timeout(Duration::from_secs(5), capture.stop()).await;

    let elapsed = start_time.elapsed().as_secs_f64();
    let avg_pps = if elapsed > 0.0 { packet_count as f64 / elapsed } else { 0.0 };

    println!("┌─ FINAL STATISTICS ──────────────────────────────────────────────┐");
    println!("│ Total Packets:  {:<48} │", packet_count);
    println!("│ Total Blocked:  {:<48} │", block_count);
    println!("│ Average Rate:   {:<48} │", format!("{:.0} pps", avg_pps));
    println!("│ Runtime:        {:<48} │", format!("{:.1} seconds", elapsed));
    println!("└──────────────────────────────────────────────────────────────────┘");
    
    info!("✅ RUBIX stopped successfully");

    Ok(())
}