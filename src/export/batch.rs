// src/export/batch.rs
//! Event batching layer.
//!
//! BatchProcessor accumulates ExportEvents in a bounded VecDeque and
//! flushes them either when the batch is full or when the flush interval
//! elapses — whichever comes first.
//!
//! Design:
//!   • No allocation in the hot path — the caller pushes pre-built events.
//!   • Flush returns the drained batch as a Vec so the caller decides what
//!     to do with it (send to webhook, write to SQLite, stream to socket).
//!   • Capacity is bounded — if the batch fills before a flush, the oldest
//!     events are dropped and a drop counter is incremented.  The hot path
//!     never blocks waiting for a flush.

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::warn;

use super::ExportEvent;

// ── BatchProcessor ────────────────────────────────────────────────────────────

pub struct BatchProcessor {
    /// Pending events not yet flushed.
    queue:          VecDeque<ExportEvent>,
    /// Maximum events before an automatic flush.
    capacity:       usize,
    /// Flush when this duration has elapsed since the last flush.
    flush_interval: Duration,
    /// When the last flush occurred.
    last_flush:     Instant,
    /// Total events dropped due to a full queue between flushes.
    drops:          u64,
}

impl BatchProcessor {
    /// Construct a new BatchProcessor.
    ///
    /// `capacity`            — max events buffered before auto-flush.
    /// `flush_interval_secs` — max seconds between flushes.
    pub fn new(capacity: usize, flush_interval_secs: u64) -> Self {
        Self {
            queue:          VecDeque::with_capacity(capacity),
            capacity,
            flush_interval: Duration::from_secs(flush_interval_secs),
            last_flush:     Instant::now(),
            drops:          0,
        }
    }

    /// Push an event into the batch.
    ///
    /// Returns `true` if the batch is now full and should be flushed.
    /// Returns `false` if there is still room.
    ///
    /// If the queue is already at capacity (caller did not flush in time),
    /// the oldest event is dropped and the drop counter is incremented.
    #[inline]
    pub fn push(&mut self, event: ExportEvent) -> bool {
        if self.queue.len() >= self.capacity {
            // Drop oldest to make room — never block the caller.
            self.queue.pop_front();
            self.drops += 1;
            warn!(
                drops = self.drops,
                "Export batch full — oldest event dropped. \
                 Increase batch_size or decrease flush_interval_secs."
            );
        }
        self.queue.push_back(event);
        self.queue.len() >= self.capacity
    }

    /// Returns true if the flush interval has elapsed since the last flush.
    #[inline]
    pub fn should_flush(&self) -> bool {
        !self.queue.is_empty()
            && self.last_flush.elapsed() >= self.flush_interval
    }

    /// Drain all pending events and return them as a Vec.
    ///
    /// Resets the flush timer.  Returns an empty Vec if the queue is empty.
    #[inline]
    pub fn drain(&mut self) -> Vec<ExportEvent> {
        self.last_flush = Instant::now();
        self.queue.drain(..).collect()
    }

    /// Number of events currently buffered.
    #[inline]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Total events dropped since construction.
    #[inline]
    pub fn drop_count(&self) -> u64 {
        self.drops
    }

    /// True if the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}