//! Export dispatcher for multiple outputs

use super::{WebhookExport, StorageExport};
use std::path::PathBuf;
use tracing::info;

pub struct ExportDispatcher {
    webhook: Option<WebhookExport>,
    storage: Option<StorageExport>,
}

impl ExportDispatcher {
    pub fn new() -> Self {
        Self {
            webhook: None,
            storage: None,
        }
    }
    
    pub fn with_webhook(mut self, url: String, batch_size: usize) -> Self {
        self.webhook = Some(WebhookExport::new(url, batch_size));
        info!("Webhook export enabled");
        self
    }
    
    pub fn with_storage(mut self, db_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = StorageExport::new(db_path)?;
        self.storage = Some(storage);
        info!("Storage export enabled");
        Ok(self)
    }
    
    pub async fn export_block(&mut self, ip: &str, reason: Option<&str>) -> Result<(), String> {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.record_blocked_ip(ip, reason) {
                tracing::error!("Failed to record blocked IP: {}", e);
            }
        }
        
        if let Some(webhook) = &mut self.webhook {
            let event = serde_json::json!({
                "type": "block",
                "ip": ip,
                "reason": reason,
                "timestamp": chrono::Utc::now(),
            });
            
            if let Err(e) = webhook.send_alert(event).await {
                tracing::error!("Failed to send webhook: {}", e);
            }
        }
        
        Ok(())
    }
    
    pub async fn export_alert(&mut self, alert_type: &str, src_ip: &str, dst_ip: &str, message: &str) -> Result<(), String> {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.record_alert(alert_type, src_ip, dst_ip, message) {
                tracing::error!("Failed to record alert: {}", e);
            }
        }
        
        if let Some(webhook) = &mut self.webhook {
            let event = serde_json::json!({
                "type": "alert",
                "alert_type": alert_type,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "message": message,
                "timestamp": chrono::Utc::now(),
            });
            
            if let Err(e) = webhook.send_alert(event).await {
                tracing::error!("Failed to send webhook: {}", e);
            }
        }
        
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<(), String> {
        if let Some(webhook) = &mut self.webhook {
            webhook.flush().await?;
        }
        Ok(())
    }
}

impl Default for ExportDispatcher {
    fn default() -> Self {
        Self::new()
    }
}