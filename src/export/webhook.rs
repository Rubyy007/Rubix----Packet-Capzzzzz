// src/export/webhook.rs
//! HTTP webhook export — sends batched ExportEvents as JSON POST requests.
//!
//! Requires the `webhook` Cargo feature (`reqwest` optional dependency).
//! Build with: cargo build --features webhook
//!
//! When the feature is disabled, WebhookExport is a zero-sized stub type
//! so the rest of the codebase compiles without conditional imports.

// ── Feature-gated real implementation ────────────────────────────────────────

#[cfg(feature = "webhook")]
mod inner {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::sync::mpsc::{self, SyncSender, TrySendError};
    use std::time::Duration;

    use reqwest::Client;
    use serde_json::json;
    use tracing::{debug, error, warn};

    use crate::export::{BatchProcessor, ExportEvent};

    pub struct WebhookExport {
        tx:    SyncSender<ExportEvent>,
        drops: Arc<AtomicU64>,
    }

    impl WebhookExport {
        pub fn new(
            url:           String,
            batch_size:    usize,
            interval_secs: u64,
            timeout_secs:  u64,
            retry_count:   u32,
        ) -> Self {
            let channel_depth = (batch_size * 4).max(256);
            let (tx, rx)      = mpsc::sync_channel::<ExportEvent>(channel_depth);
            let drops         = Arc::new(AtomicU64::new(0));

            let client = Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .build()
                .expect("Failed to build reqwest Client");

            let drops_clone = drops.clone();
            tokio::spawn(async move {
                run_sender(rx, url, client, batch_size, interval_secs, retry_count, drops_clone)
                    .await;
            });

            tracing::info!(batch_size, interval_secs, timeout_secs, retry_count,
                "Webhook export background sender started");

            Self { tx, drops }
        }

        #[inline]
        pub fn send(&self, event: ExportEvent) {
            match self.tx.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.drops.fetch_add(1, Ordering::Relaxed);
                    warn!(drops = self.drops.load(Ordering::Relaxed),
                        "Webhook channel full — event dropped");
                }
                Err(TrySendError::Disconnected(_)) => {
                    error!("Webhook background task has exited — events are being dropped");
                }
            }
        }

        #[inline]
        pub fn drop_count(&self) -> u64 {
            self.drops.load(Ordering::Relaxed)
        }
    }

    async fn run_sender(
        rx:            std::sync::mpsc::Receiver<ExportEvent>,
        url:           String,
        client:        Client,
        batch_size:    usize,
        interval_secs: u64,
        retry_count:   u32,
        drops:         Arc<AtomicU64>,
    ) {
        let mut batch = BatchProcessor::new(batch_size, interval_secs);

        loop {
            loop {
                match rx.try_recv() {
                    Ok(event) => { batch.push(event); }
                    Err(_)    => break,
                }
            }

            if batch.len() >= batch_size || batch.should_flush() {
                let events = batch.drain();
                if !events.is_empty() {
                    post_with_retry(&client, &url, events, retry_count, &drops).await;
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn post_with_retry(
        client:      &Client,
        url:         &str,
        events:      Vec<ExportEvent>,
        retry_count: u32,
        drops:       &AtomicU64,
    ) {
        let count   = events.len();
        let payload = json!({
            "source": "rubix",
            "count":  count,
            "events": events,
        });

        let mut attempt = 0u32;
        loop {
            match client.post(url).json(&payload).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(count, "Webhook POST successful");
                    return;
                }
                Ok(resp) => {
                    let status = resp.status();
                    if attempt >= retry_count {
                        tracing::error!(count, %status, attempt,
                            "Webhook POST failed after all retries — dropping batch");
                        drops.fetch_add(count as u64, Ordering::Relaxed);
                        return;
                    }
                    warn!(count, %status, attempt, "Webhook POST failed — retrying");
                }
                Err(e) => {
                    if attempt >= retry_count {
                        tracing::error!(count, error = %e, attempt,
                            "Webhook POST error after all retries — dropping batch");
                        drops.fetch_add(count as u64, Ordering::Relaxed);
                        return;
                    }
                    warn!(count, error = %e, attempt, "Webhook POST error — retrying");
                }
            }

            let backoff = Duration::from_secs(1 << attempt.min(4));
            tokio::time::sleep(backoff).await;
            attempt += 1;
        }
    }
}

// ── Public re-export ──────────────────────────────────────────────────────────

#[cfg(feature = "webhook")]
pub use inner::WebhookExport;

/// Stub when the `webhook` feature is not enabled.
/// Compiles to nothing — all methods are no-ops.
#[cfg(not(feature = "webhook"))]
pub struct WebhookExport;

#[cfg(not(feature = "webhook"))]
impl WebhookExport {
    pub fn new(
        _url:           String,
        _batch_size:    usize,
        _interval_secs: u64,
        _timeout_secs:  u64,
        _retry_count:   u32,
    ) -> Self {
        tracing::warn!(
            "webhook_url configured but webhook feature not enabled — \
             rebuild with: cargo build --features webhook"
        );
        Self
    }

    #[inline(always)]
    pub fn send(&self, _event: crate::export::ExportEvent) {}

    #[inline(always)]
    pub fn drop_count(&self) -> u64 { 0 }
}