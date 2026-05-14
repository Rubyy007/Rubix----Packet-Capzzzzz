// src/types/event.rs
//! Event data structures.
//!
//! `Priority` is the canonical priority type for the entire RUBIX system.
//! The `channel/` module re-exports it from here — there is exactly one
//! definition in the codebase.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use super::packet::Packet;

// ── Global event-ID counter ───────────────────────────────────────────────────
//
// AtomicU64 with Relaxed ordering: we only need uniqueness, not ordering
// guarantees between threads.  Wrapping on overflow is acceptable — at
// 200 k events/sec a u64 wraps in ~2.9 million years.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

// ── Priority ──────────────────────────────────────────────────────────────────

/// Canonical priority for events and bus messages across all of RUBIX.
///
/// Discriminant values are chosen so that numeric ordering matches urgency:
/// `HIGH (0) < MEDIUM (1) < LOW (2)` — i.e. lower number = higher priority.
///
/// `Ord` is derived; the derive uses declaration order, so `HIGH` sorts
/// before `MEDIUM` before `LOW`.  Do not reorder variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Security-critical: block decisions, confirmed threats.
    /// Never dropped under backpressure.
    HIGH   = 0,
    /// Informational alerts, policy matches.
    MEDIUM = 1,
    /// Stats, heartbeats, normal-traffic samples.
    LOW    = 2,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::MEDIUM
    }
}

// ── Event type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EventType {
    /// Raw packet captured from the wire.
    PacketCapture,
    /// A block rule was executed against this packet.
    BlockExecuted { rule_id: String },
    /// A policy alert rule fired.
    Alert { message: String },
    /// A threat-detector event (port scan, flood, etc.).
    Threat { message: String },
    /// Daemon-internal error (resolver failure, I/O error, etc.).
    InternalError { message: String },
}

// ── Event ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Event {
    /// Globally unique monotonic ID.  Assigned at construction; never 0.
    pub id:         u64,
    /// Wall-clock time the event was created.
    pub timestamp:  SystemTime,
    /// Priority determining channel routing and drop policy.
    pub priority:   Priority,
    /// Structured event category and associated metadata.
    pub event_type: EventType,
    /// Optional originating packet.  Present for PacketCapture,
    /// BlockExecuted, Alert, and Threat.  Absent for InternalError.
    pub packet:     Option<Packet>,
}

impl Event {
    /// Construct a new event.  ID is assigned atomically; never requires a lock.
    #[inline]
    pub fn new(priority: Priority, event_type: EventType) -> Self {
        Self {
            id:         NEXT_ID.fetch_add(1, Ordering::Relaxed),
            timestamp:  SystemTime::now(),
            priority,
            event_type,
            packet:     None,
        }
    }

    /// Attach the originating packet to this event.
    #[inline]
    pub fn with_packet(mut self, packet: Packet) -> Self {
        self.packet = Some(packet);
        self
    }

    /// True if this event must never be dropped under backpressure.
    #[inline]
    pub fn is_high_priority(&self) -> bool {
        self.priority == Priority::HIGH
    }
}