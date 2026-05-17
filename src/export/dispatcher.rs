// src/export/dispatcher.rs
//! Export dispatcher — fan-out hub for all configured export backends.
//!
//! ExportDispatcher is the single entry point the packet loop calls.
//! It holds optional instances of each backend and routes each event to
//! all active backends simultaneously.

use tracing::{error, info};

use super::{ExportConfig, ExportEvent};
use super::webhook::WebhookExport;
use super::socket::SocketExport;

// ── ExportDispatcher ──────────────────────────────────────────────────────────

pub struct ExportDispatcher {
    enabled: bool,
    webhook: Option<WebhookExport>,
    #[cfg(feature = "storage")]
    storage: Option<super::storage::StorageExport>,
    socket:  Option<SocketExport>,
}

impl ExportDispatcher {
    /// Construct from configuration, initialising all enabled backends.
    /// Returns a no-op dispatcher if `config.enabled == false`.
    pub async fn build(
        config: &ExportConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if !config.enabled {
            info!("Export disabled — dispatcher is a no-op");
            return Ok(Self::disabled());
        }

        // ── Webhook ───────────────────────────────────────────────────────────
        let webhook = if let Some(ref url) = config.webhook_url {
            let w = WebhookExport::new(
                url.clone(),
                config.batch_size,
                config.flush_interval_secs,
                config.webhook_timeout_secs,
                config.webhook_retry_count,
            );
            info!(url = %url, "Webhook export enabled");
            Some(w)
        } else {
            None
        };

        // ── Storage ───────────────────────────────────────────────────────────
        #[cfg(feature = "storage")]
        let storage = if let Some(ref path) = config.storage_path {
            match super::storage::StorageExport::new(path.clone()) {
                Ok(s) => {
                    info!(path = %path.display(), "Storage export enabled");
                    Some(s)
                }
                Err(e) => {
                    error!(error = %e, "Storage export failed to initialise — disabled");
                    None
                }
            }
        } else {
            None
        };

        // ── Socket ────────────────────────────────────────────────────────────
        let socket = if let Some(ref addr) = config.socket_addr {
            match SocketExport::bind(addr).await {
                Ok(s) => {
                    info!(addr = %addr, "Socket export enabled");
                    Some(s)
                }
                Err(e) => {
                    error!(error = %e, "Socket export failed to bind — disabled");
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            enabled: true,
            webhook,
            #[cfg(feature = "storage")]
            storage,
            socket,
        })
    }

    fn disabled() -> Self {
        Self {
            enabled: false,
            webhook: None,
            #[cfg(feature = "storage")]
            storage: None,
            socket:  None,
        }
    }

    // ── Hot-path entry point ──────────────────────────────────────────────────

    /// Fan an event out to all configured backends.
    ///
    /// Socket and webhook sends are non-blocking (~10 ns each).
    /// Storage dispatches to spawn_blocking — does not block the caller.
    #[inline]
    pub async fn export(&self, event: ExportEvent) {
        if !self.enabled { return; }

        if let Some(ref sock) = self.socket {
            sock.send(&event);
        }

        if let Some(ref wh) = self.webhook {
            wh.send(event.clone());
        }

        #[cfg(feature = "storage")]
        if let Some(ref store) = self.storage {
            if let Err(e) = store.record_event(event).await {
                error!(error = %e, "Storage export record_event failed");
            }
        }
    }

    // ── Convenience methods ───────────────────────────────────────────────────

    #[inline]
    pub async fn export_threat(
        &self, src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
        protocol: &str, process: &str, detail: &str, severity: &str,
    ) {
        if !self.enabled { return; }
        self.export(ExportEvent::from_threat(
            src_ip, dst_ip, src_port, dst_port, protocol, process, detail, severity,
        )).await;
    }

    #[inline]
    pub async fn export_block(
        &self, src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
        protocol: &str, process: &str, detail: &str,
    ) {
        if !self.enabled { return; }
        self.export(ExportEvent::from_block(
            src_ip, dst_ip, src_port, dst_port, protocol, process, detail,
        )).await;
    }

    #[inline]
    pub async fn export_alert(
        &self, src_ip: &str, dst_ip: &str,
        src_port: u16, dst_port: u16,
        protocol: &str, process: &str, detail: &str,
    ) {
        if !self.enabled { return; }
        self.export(ExportEvent::from_alert(
            src_ip, dst_ip, src_port, dst_port, protocol, process, detail,
        )).await;
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────

    pub fn socket_client_count(&self) -> usize {
        self.socket.as_ref().map(|s| s.client_count()).unwrap_or(0)
    }

    pub fn webhook_drop_count(&self) -> u64 {
        self.webhook.as_ref().map(|w| w.drop_count()).unwrap_or(0)
    }

    pub fn is_active(&self) -> bool {
        self.enabled && (
            self.webhook.is_some()
            || self.socket.is_some()
            || {
                #[cfg(feature = "storage")]
                { self.storage.is_some() }
                #[cfg(not(feature = "storage"))]
                { false }
            }
        )
    }
}

impl Default for ExportDispatcher {
    fn default() -> Self { Self::disabled() }
}