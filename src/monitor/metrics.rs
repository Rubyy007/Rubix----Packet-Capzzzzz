//! Prometheus metrics export

use prometheus::{
    register_counter, register_gauge, register_histogram_vec,
    Counter, Gauge, HistogramVec, Encoder, TextEncoder,
};
use warp::Filter;
use tracing::info;

lazy_static::lazy_static! {
    static ref PACKETS_TOTAL: Counter = register_counter!(
        "rubix_packets_total",
        "Total packets processed"
    ).unwrap();
    
    static ref BLOCKS_TOTAL: Counter = register_counter!(
        "rubix_blocks_total",
        "Total packets blocked"
    ).unwrap();
    
    static ref ACTIVE_RULES: Gauge = register_gauge!(
        "rubix_active_rules",
        "Number of active blocking rules"
    ).unwrap();
    
    static ref PACKET_SIZE: HistogramVec = register_histogram_vec!(
        "rubix_packet_size_bytes",
        "Packet size distribution",
        &["protocol"]
    ).unwrap();
}

pub struct MetricsCollector;

impl MetricsCollector {
    pub fn record_packet(protocol: &str, size: usize) {
        PACKETS_TOTAL.inc();
        PACKET_SIZE.with_label_values(&[protocol]).observe(size as f64);
    }
    
    pub fn record_block() {
        BLOCKS_TOTAL.inc();
    }
    
    pub fn update_rules_count(count: usize) {
        ACTIVE_RULES.set(count as f64);
    }
    
    pub async fn start_metrics_server(port: u16) {
        let metrics_route = warp::path!("metrics").map(|| {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            encoder.encode(&metric_families, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        });
        
        tokio::spawn(async move {
            warp::serve(metrics_route)
                .run(([0, 0, 0, 0], port))
                .await;
        });
        
        info!("Metrics server started on port {}", port);
    }
}