//! Data export and integration system

mod batch;
mod dispatcher;
mod socket;
mod storage;
mod webhook;

pub use batch::BatchProcessor;
pub use dispatcher::ExportDispatcher;
pub use storage::StorageExport;
pub use webhook::WebhookExport;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub enabled: bool,
    pub webhook_url: Option<String>,
    pub storage_path: Option<PathBuf>,
    pub socket_path: Option<String>,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: None,
            storage_path: None,
            socket_path: None,
            batch_size: 100,
            flush_interval_secs: 5,
        }
    }
}