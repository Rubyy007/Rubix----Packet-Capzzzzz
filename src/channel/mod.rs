// src/channel/mod.rs
//! Internal message passing and event bus.
//!
//! # Design
//!
//! Messages carry typed `Event` values (not raw bytes).  The bus routes
//! messages to one of three priority lanes; consumers drain lanes in
//! HIGH → MEDIUM → LOW order, so security events are never head-of-line
//! blocked by stats or normal-traffic entries.
//!
//! # Fast-path contract
//!
//! `EventBus::publish` is **non-blocking**: it calls `try_send` on the
//! appropriate lane and returns `Err(BusError::Full)` if the lane is at
//! capacity.  The caller decides whether to drop or escalate.
//! HIGH-priority lanes are sized larger and are never the first to fill.

mod bus;
mod drop;
mod priority;

pub use bus::{BusError, BusReceiver, EventBus};
pub use drop::PacketDrop;
pub use priority::Priority;

use crate::types::event::{Event, EventType};
use std::time::SystemTime;

// ── Message ───────────────────────────────────────────────────────────────────

/// A routable message on the internal event bus.
///
/// Wraps a typed `Event`; the `priority` field mirrors `event.priority`
/// so routing decisions never need to unwrap the inner event.
#[derive(Debug, Clone)]
pub struct Message {
    /// Wall-clock time the message was enqueued.
    pub timestamp:    SystemTime,
    /// Priority lane this message will be placed on.
    pub priority:     Priority,
    /// The event payload.
    pub event:        Event,
}

impl Message {
    /// Construct a `Message` from an `Event`.
    /// Priority is taken from the event itself — no caller can accidentally
    /// mismatch the two.
    #[inline]
    pub fn from_event(event: Event) -> Self {
        Self {
            timestamp: SystemTime::now(),
            priority:  event.priority,
            event,
        }
    }
}