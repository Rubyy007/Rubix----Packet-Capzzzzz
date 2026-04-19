//! Webhook export for alerts and events

use reqwest::Client;
use serde_json::json;
use std::collections::VecDeque;
use tokio::time::{Duration, interval};
use tracing::{info, error};

pub struct WebhookExport {
    url: String,
    client: Client,
    queue: VecDeque<serde_json::Value>,
    batch_size: usize,
}

impl WebhookExport {
    pub fn new(url: String, batch_size: usize) -> Self {
        Self {
            url,
            client: Client::new(),
            queue: VecDeque::new(),
            batch_size,
        }
    }
    
    pub async fn send_alert(&mut self, alert: serde_json::Value) -> Result<(), String> {
        self.queue.push_back(alert);
        
        if self.queue.len() >= self.batch_size {
            self.flush().await?;
        }
        
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<(), String> {
        if self.queue.is_empty() {
            return Ok(());
        }
        
        let batch: Vec<serde_json::Value> = self.queue.drain(..).collect();
        let payload = json!({
            "timestamp": chrono::Utc::now(),
            "events": batch,
            "count": batch.len(),
        });
        
        match self.client.post(&self.url).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {
                info!("Sent {} events to webhook", batch.len());
                Ok(())
            }
            Ok(response) => Err(format!("Webhook returned error: {}", response.status())),
            Err(e) => Err(format!("Failed to send webhook: {}", e)),
        }
    }
    
    pub async fn start_background_flush(&mut self, interval_secs: u64) {
        let mut interval = interval(Duration::from_secs(interval_secs));
        
        loop {
            interval.tick().await;
            if let Err(e) = self.flush().await {
                error!("Background flush failed: {}", e);
            }
        }
    }
}