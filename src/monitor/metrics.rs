// src/monitor/metrics.rs
//! Runtime metrics collection for RUBIX.
//!
//! The original implementation used the `prometheus` and `warp` crates which
//! are not in Cargo.toml and would pull in heavy dependency trees.
//!
//! This implementation uses:
//!   • Atomic counters/gauges — zero-cost on the hot path, no allocation.
//!   • A minimal HTTP server using `tokio::net::TcpListener` + raw text
//!     response — no external web framework required.
//!   • Output format: plain text Prometheus exposition format so existing
//!     Prometheus scrapers work without change.
//!
//! If you want to use the full Prometheus crate later, add to Cargo.toml:
//!   prometheus = "0.13"
//! and replace MetricsCollector with the prometheus-based implementation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

// ── Global atomic counters ────────────────────────────────────────────────────

static PACKETS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BLOCKS_TOTAL:  AtomicU64 = AtomicU64::new(0);
static ALERTS_TOTAL:  AtomicU64 = AtomicU64::new(0);
static ACTIVE_RULES:  AtomicU64 = AtomicU64::new(0);

// Per-protocol packet counters (TCP, UDP, ICMP, Other).
static PACKETS_TCP:   AtomicU64 = AtomicU64::new(0);
static PACKETS_UDP:   AtomicU64 = AtomicU64::new(0);
static PACKETS_ICMP:  AtomicU64 = AtomicU64::new(0);
static PACKETS_OTHER: AtomicU64 = AtomicU64::new(0);

// ── MetricsCollector ──────────────────────────────────────────────────────────

/// Hot-path metric recorder.  All methods are free functions that write to
/// global atomics — no allocation, no lock, safe to call from the packet loop.
pub struct MetricsCollector;

impl MetricsCollector {
    /// Record one processed packet.
    #[inline(always)]
    pub fn record_packet(protocol: &str, _size: usize) {
        PACKETS_TOTAL.fetch_add(1, Ordering::Relaxed);
        match protocol {
            "TCP"  => { PACKETS_TCP.fetch_add(1,   Ordering::Relaxed); }
            "UDP"  => { PACKETS_UDP.fetch_add(1,   Ordering::Relaxed); }
            "ICMP" => { PACKETS_ICMP.fetch_add(1,  Ordering::Relaxed); }
            _      => { PACKETS_OTHER.fetch_add(1, Ordering::Relaxed); }
        }
    }

    /// Record one blocked packet.
    #[inline(always)]
    pub fn record_block() {
        BLOCKS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one alert event.
    #[inline(always)]
    pub fn record_alert() {
        ALERTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the active rule count (called after policy reload).
    #[inline(always)]
    pub fn update_rules_count(count: usize) {
        ACTIVE_RULES.store(count as u64, Ordering::Relaxed);
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render() -> String {
        let packets = PACKETS_TOTAL.load(Ordering::Relaxed);
        let blocks  = BLOCKS_TOTAL .load(Ordering::Relaxed);
        let alerts  = ALERTS_TOTAL .load(Ordering::Relaxed);
        let rules   = ACTIVE_RULES .load(Ordering::Relaxed);
        let tcp     = PACKETS_TCP  .load(Ordering::Relaxed);
        let udp     = PACKETS_UDP  .load(Ordering::Relaxed);
        let icmp    = PACKETS_ICMP .load(Ordering::Relaxed);
        let other   = PACKETS_OTHER.load(Ordering::Relaxed);

        format!(
            "# HELP rubix_packets_total Total packets processed\n\
             # TYPE rubix_packets_total counter\n\
             rubix_packets_total {packets}\n\
             # HELP rubix_packets_by_protocol Packets by protocol\n\
             # TYPE rubix_packets_by_protocol counter\n\
             rubix_packets_by_protocol{{protocol=\"tcp\"}}   {tcp}\n\
             rubix_packets_by_protocol{{protocol=\"udp\"}}   {udp}\n\
             rubix_packets_by_protocol{{protocol=\"icmp\"}}  {icmp}\n\
             rubix_packets_by_protocol{{protocol=\"other\"}} {other}\n\
             # HELP rubix_blocks_total Total packets blocked\n\
             # TYPE rubix_blocks_total counter\n\
             rubix_blocks_total {blocks}\n\
             # HELP rubix_alerts_total Total alert events fired\n\
             # TYPE rubix_alerts_total counter\n\
             rubix_alerts_total {alerts}\n\
             # HELP rubix_active_rules Number of active policy rules\n\
             # TYPE rubix_active_rules gauge\n\
             rubix_active_rules {rules}\n",
        )
    }

    /// Start a minimal HTTP server on `port` that serves `/metrics`.
    ///
    /// No external web framework — uses raw TCP + tokio for minimal footprint.
    /// Compatible with Prometheus scraping (text/plain; version=0.0.4).
    pub async fn start_metrics_server(port: u16) {
        let addr = format!("0.0.0.0:{}", port);

        let listener = match TcpListener::bind(&addr).await {
            Ok(l)  => l,
            Err(e) => {
                warn!(error = %e, port, "Failed to bind metrics server — metrics disabled");
                return;
            }
        };

        info!(port, "Metrics server started — scrape at http://localhost:{}/metrics", port);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _peer)) => {
                        tokio::spawn(async move {
                            // Read the HTTP request (we ignore it — all paths serve metrics).
                            let mut buf = [0u8; 512];
                            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                            let body     = MetricsCollector::render();
                            let response = format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\
                                 \r\n\
                                 {}",
                                body.len(),
                                body,
                            );

                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.flush().await;
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "Metrics server accept error");
                    }
                }
            }
        });
    }
}