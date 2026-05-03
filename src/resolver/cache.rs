//! Lock-free read path with atomic refresh coordination.

use super::{FlowKey, ProcessInfo, snapshot};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;

pub struct ProcessResolver {
    table:           Arc<RwLock<HashMap<FlowKey, ProcessInfo>>>,
    last_refresh_ns: Arc<AtomicU64>,
    refreshing:      Arc<AtomicBool>,
    ttl_ns:          u64,
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_millis(1000))
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        let initial = HashMap::with_capacity(512);
        
        Self {
            table:           Arc::new(RwLock::new(initial)),
            last_refresh_ns: Arc::new(AtomicU64::new(0)),
            refreshing:      Arc::new(AtomicBool::new(false)),
            ttl_ns:          ttl.as_nanos() as u64,
        }
    }

    #[inline(always)]
    pub fn lookup(&self, key: &FlowKey) -> Option<ProcessInfo> {
        self.maybe_refresh_async();
        self.table.read().get(key).cloned()
    }

    pub fn all_processes(&self) -> Vec<ProcessInfo> {
        self.maybe_refresh_async();
        
        let guard = self.table.read();
        let mut seen = std::collections::HashSet::with_capacity(64);
        
        guard.values()
            .filter(|p| seen.insert(p.pid))
            .cloned()
            .collect()
    }

    #[inline]
    pub fn flow_count(&self) -> usize {
        self.table.read().len()
    }

    #[inline(always)]
    fn maybe_refresh_async(&self) {
        let now_ns = Self::now_nanos();
        let last   = self.last_refresh_ns.load(Ordering::Relaxed);
        
        if now_ns.saturating_sub(last) < self.ttl_ns {
            return;
        }

        if self.refreshing.compare_exchange(
            false, true,
            Ordering::Acquire,
            Ordering::Relaxed
        ).is_ok() {
            let table     = self.table.clone();
            let timestamp = self.last_refresh_ns.clone();
            let flag      = self.refreshing.clone();
            
            tokio::spawn(async move {
                if let Ok(snap) = snapshot() {
                    *table.write() = snap;
                    timestamp.store(Self::now_nanos(), Ordering::Release);
                }
                flag.store(false, Ordering::Release);
            });
        }
    }

    #[inline(always)]
    fn now_nanos() -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }
}

impl Default for ProcessResolver {
    #[inline]
    fn default() -> Self { Self::new() }
}