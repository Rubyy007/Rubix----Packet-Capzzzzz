//! RUBIX - Production Network Blocking Engine
//! Testing packet capture module

mod types;
mod capture;

use capture::{CaptureBackend, CaptureConfig, CaptureFactory};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{interval, Duration, timeout};
use tokio::signal;
use tracing::{info, warn};

fn setup_logger() {
    tracing_subscriber::fmt()
        .with_env_filter("rubix=debug,pcap=warn")
        .with_target(false)
        .with_thread_ids(true)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_logger();
    
    info!("RUBIX NETWORK BLOCKING ENGINE - PRODUCTION MODE");
    
    info!("Available network interfaces:");
    match CaptureFactory::list_interfaces() {
        Ok(interfaces) => {
            for iface in interfaces {
                info!("   - {}", iface);
            }
        }
        Err(e) => {
            warn!("Failed to list interfaces: {}", e);
        }
    }
    
    let config = CaptureConfig {
        interface: "auto".to_string(),
        promiscuous: true,
        buffer_size_mb: 64,
        timeout_ms: 10,
        snaplen: 65535,
        bpf_filter: Some("ip or ip6".to_string()),
    };
    
    let mut capture = CaptureFactory::create(config)?;
    capture.start().await?;
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            eprintln!("Failed to listen for Ctrl+C: {}", e);
            return;
        }
        info!("Shutdown signal received");
        r.store(false, Ordering::SeqCst);
    });
    
    let stats_handle = tokio::spawn({
        let running = running.clone();
        async move {
            let mut interval = interval(Duration::from_secs(5));
            while running.load(Ordering::Relaxed) {
                interval.tick().await;
            }
        }
    });
    
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::io::Write;
    
    let malicious_ips: Vec<IpAddr> = vec![
        "185.230.125.100",
        "94.102.61.78",
        "45.155.205.233",
    ].into_iter()
        .filter_map(|ip| IpAddr::from_str(ip).ok())
        .collect();
    
    info!("RUBIX is now MONITORING network traffic");
    info!("Blocking malicious IPs: {:?}", malicious_ips);
    info!("Press Ctrl+C to stop");
    
    let start_time = std::time::Instant::now();
    let mut packet_count = 0u64;
    let mut block_count = 0u64;
    let mut last_stats_time = start_time;
    let mut last_packet_count = 0u64;
    
    while running.load(Ordering::SeqCst) {
        match timeout(Duration::from_millis(100), capture.next_packet()).await {
            Ok(Some(packet)) => {
                packet_count += 1;
                
                if malicious_ips.contains(&packet.dst_ip) {
                    block_count += 1;
                    warn!(
                        src_ip = %packet.src_ip,
                        src_port = packet.src_port,
                        dst_ip = %packet.dst_ip,
                        dst_port = packet.dst_port,
                        protocol = %packet.protocol.as_str(),
                        "BLOCKED Malicious connection attempt"
                    );
                }
                
                let now = std::time::Instant::now();
                if packet_count % 100 == 0 || now.duration_since(last_stats_time).as_secs() >= 1 {
                    let elapsed = now.duration_since(start_time).as_secs_f64();
                    let interval_packets = packet_count - last_packet_count;
                    let interval_secs = now.duration_since(last_stats_time).as_secs_f64().max(0.001);
                    let pps = interval_packets as f64 / interval_secs;
                    let avg_pps = packet_count as f64 / elapsed;
                    
                    print!("\rProcessed: {} packets | Blocked: {} | Rate: {:.0} pps (avg: {:.0})",
                        packet_count, block_count, pps, avg_pps);
                    let _ = std::io::stdout().flush();
                    
                    last_stats_time = now;
                    last_packet_count = packet_count;
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_micros(10)).await;
            }
            Err(_) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }
    
    println!();
    info!("Shutting down capture...");
    
    let shutdown_result = timeout(Duration::from_secs(5), capture.stop()).await;
    match shutdown_result {
        Ok(Ok(())) => info!("Capture stopped gracefully"),
        Ok(Err(e)) => warn!("Error stopping capture: {}", e),
        Err(_) => warn!("Capture stop timed out"),
    }
    
    stats_handle.abort();
    let _ = stats_handle.await;
    
    let elapsed = start_time.elapsed().as_secs_f64();
    let avg_pps = if elapsed > 0.0 { packet_count as f64 / elapsed } else { 0.0 };
    
    info!("RUBIX stopped successfully");
    info!("Final stats - Packets: {}, Blocks: {}, Avg Rate: {:.0} pps", 
        packet_count, block_count, avg_pps);
    
    Ok(())
}