// src/config/watcher.rs
//! Hot reload configuration watcher

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[allow(dead_code)]
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
    rx: Receiver<Result<notify::Event, notify::Error>>,
    last_event: Option<Instant>,
}

#[allow(dead_code)]
impl ConfigWatcher {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, rx) = channel();

        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })?;

        watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;
        info!("Watching config file: {:?}", path.as_ref());

        Ok(Self {
            _watcher: watcher,
            rx,
            last_event: None,
        })
    }

    /// Returns true if the config file has changed since last check.
    /// Debounced to 500ms to avoid multiple rapid reloads.
    pub fn check_changes(&mut self) -> bool {
        let mut changed = false;

        while let Ok(result) = self.rx.try_recv() {
            match result {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        changed = true;
                    }
                }
                Err(e) => {
                    warn!("Config watcher error: {}", e);
                }
            }
        }

        if changed {
            let now = Instant::now();
            let debounce = self
                .last_event
                .map_or(true, |t| now.duration_since(t) > Duration::from_millis(500));

            if debounce {
                self.last_event = Some(now);
                info!("Config file changed — reload recommended");
                return true;
            }
        }

        false
    }
}