// src/channel/bus.rs
//! Priority-lane event bus for inter-component communication.
//!
//! # Architecture
//!
//! Three bounded `async_channel` queues — one per priority level:
//!
//!   HIGH   (security events, block decisions) — never dropped first
//!   MEDIUM (alerts, policy matches)
//!   LOW    (stats, heartbeats, normal-traffic samples)
//!
//! `async_channel::bounded` is chosen over `tokio::mpsc` because:
//!   - It is Clone-safe: every clone shares the *same* underlying channel.
//!     Cloning the bus gives you another producer handle, not a new channel.
//!   - `try_send` is non-blocking and lock-free on the hot path.
//!   - `recv` is async and integrates with Tokio naturally.
//!   - MPMC: multiple consumers are supported without coordination.
//!
//! # Backpressure
//!
//! `publish` uses `try_send`.  If the lane is full it returns
//! `BusError::Full { priority }` immediately — the fast path is never
//! blocked.  HIGH-priority messages that cannot be queued return
//! `BusError::HighPriorityDropped` so callers can record the loss
//! separately and alert operators.
//!
//! # Consumer ordering
//!
//! `BusReceiver::recv` polls HIGH first, then MEDIUM, then LOW using a
//! biased `tokio::select!` equivalent (explicit priority poll via
//! `try_recv` before falling back to async wait).  This guarantees that
//! a backlogged HIGH lane is drained before MEDIUM messages are delivered.

use super::{Message, Priority};
use async_channel::{bounded, Receiver, SendError, Sender, TryRecvError, TrySendError};
use std::sync::Arc;
use tracing::{debug, warn};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("channel closed")]
    Closed,

    #[error("lane full for priority {priority:?} — message dropped")]
    Full { priority: Priority },

    #[error("HIGH priority message could not be queued — capacity exhausted")]
    HighPriorityDropped,
}

// ── Lane capacities ───────────────────────────────────────────────────────────
//
// HIGH  is 4× larger than MEDIUM to absorb burst blocking decisions.
// LOW   is kept small; loss of a stats heartbeat is acceptable.
// These are overridden by the caller via `EventBus::with_capacities`.

const DEFAULT_HIGH_CAP:   usize = 8_192;
const DEFAULT_MEDIUM_CAP: usize = 4_096;
const DEFAULT_LOW_CAP:    usize = 1_024;

// ── Inner shared state ────────────────────────────────────────────────────────

struct Lanes {
    high_tx:   Sender<Message>,
    high_rx:   Receiver<Message>,
    medium_tx: Sender<Message>,
    medium_rx: Receiver<Message>,
    low_tx:    Sender<Message>,
    low_rx:    Receiver<Message>,
}

// ── EventBus ──────────────────────────────────────────────────────────────────

/// Cloneable event bus.  Every clone shares the same three priority lanes.
///
/// Cloning creates an additional *producer* handle.  Consumer handles are
/// obtained via `subscribe()`, which returns a `BusReceiver` that reads from
/// all three lanes with correct priority ordering.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<Lanes>,
}

impl EventBus {
    /// Create a bus with default lane capacities.
    pub fn new() -> Self {
        Self::with_capacities(DEFAULT_HIGH_CAP, DEFAULT_MEDIUM_CAP, DEFAULT_LOW_CAP)
    }

    /// Create a bus with explicit lane capacities.
    ///
    /// `high_cap` should be sized to absorb the worst-case burst of blocking
    /// decisions before the slow path can drain them.  A safe default is
    /// `8 × expected_peak_pps × expected_drain_latency_secs`.
    pub fn with_capacities(high_cap: usize, medium_cap: usize, low_cap: usize) -> Self {
        let (high_tx, high_rx)     = bounded(high_cap);
        let (medium_tx, medium_rx) = bounded(medium_cap);
        let (low_tx, low_rx)       = bounded(low_cap);

        Self {
            inner: Arc::new(Lanes {
                high_tx,
                high_rx,
                medium_tx,
                medium_rx,
                low_tx,
                low_rx,
            }),
        }
    }

    /// Publish a message onto the appropriate priority lane.
    ///
    /// **Non-blocking.**  Returns immediately with `BusError::Full` or
    /// `BusError::HighPriorityDropped` if the lane cannot accept the message.
    ///
    /// Callers on the fast path should match on the error and record the drop
    /// via `PacketDrop` — do not `.unwrap()` or log inline.
    #[inline]
    pub fn publish(&self, msg: Message) -> Result<(), BusError> {
        let priority = msg.priority;

        let result = match priority {
            Priority::HIGH   => self.inner.high_tx.try_send(msg),
            Priority::MEDIUM => self.inner.medium_tx.try_send(msg),
            Priority::LOW    => self.inner.low_tx.try_send(msg),
        };

        match result {
            Ok(()) => {
                debug!("message published on {:?} lane", priority);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                if priority == Priority::HIGH {
                    warn!("HIGH priority lane full — security event dropped");
                    Err(BusError::HighPriorityDropped)
                } else {
                    Err(BusError::Full { priority })
                }
            }
            Err(TrySendError::Closed(_)) => Err(BusError::Closed),
        }
    }

    /// Obtain a consumer handle.
    ///
    /// Multiple consumers may call `subscribe()` — `async_channel` is MPMC.
    /// Each consumer receives *distinct* messages (work-stealing semantics),
    /// not a broadcast.  For broadcast, create separate `EventBus` instances
    /// per subscriber and publish to each from a fan-out task.
    pub fn subscribe(&self) -> BusReceiver {
        BusReceiver {
            high_rx:   self.inner.high_rx.clone(),
            medium_rx: self.inner.medium_rx.clone(),
            low_rx:    self.inner.low_rx.clone(),
        }
    }

    /// Instantaneous fill level of each lane, in order [high, medium, low].
    /// Useful for metrics and backpressure dashboards.
    pub fn lane_lengths(&self) -> [usize; 3] {
        [
            self.inner.high_rx.len(),
            self.inner.medium_rx.len(),
            self.inner.low_rx.len(),
        ]
    }

    /// True if all three lanes are empty.
    pub fn is_empty(&self) -> bool {
        self.inner.high_rx.is_empty()
            && self.inner.medium_rx.is_empty()
            && self.inner.low_rx.is_empty()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ── BusReceiver ───────────────────────────────────────────────────────────────

/// Consumer handle for the event bus.
///
/// Drains lanes in strict HIGH → MEDIUM → LOW priority order:
///
/// 1. Try `HIGH` non-blocking first.
/// 2. If empty, try `MEDIUM` non-blocking.
/// 3. If empty, await any of the three lanes with a biased select —
///    HIGH is checked before MEDIUM, MEDIUM before LOW.
///
/// This means that as long as the HIGH lane is non-empty, the consumer
/// will never return a MEDIUM or LOW message.
#[derive(Clone)]
pub struct BusReceiver {
    high_rx:   Receiver<Message>,
    medium_rx: Receiver<Message>,
    low_rx:    Receiver<Message>,
}

impl BusReceiver {
    /// Receive the next message, respecting priority order.
    ///
    /// Yields to the async runtime only when all lanes are empty.
    /// Returns `Err(BusError::Closed)` when all senders have been dropped.
    pub async fn recv(&self) -> Result<Message, BusError> {
        loop {
            // ── Non-blocking fast poll: HIGH first ────────────────────────────
            match self.high_rx.try_recv() {
                Ok(msg)                      => return Ok(msg),
                Err(TryRecvError::Empty)     => {}
                Err(TryRecvError::Closed)    => return Err(BusError::Closed),
            }

            // ── Non-blocking fast poll: MEDIUM ────────────────────────────────
            match self.medium_rx.try_recv() {
                Ok(msg)                      => return Ok(msg),
                Err(TryRecvError::Empty)     => {}
                Err(TryRecvError::Closed)    => return Err(BusError::Closed),
            }

            // ── Non-blocking fast poll: LOW ───────────────────────────────────
            match self.low_rx.try_recv() {
                Ok(msg)                      => return Ok(msg),
                Err(TryRecvError::Empty)     => {}
                Err(TryRecvError::Closed)    => return Err(BusError::Closed),
            }

            // ── All lanes empty: yield and await any lane ─────────────────────
            //
            // `tokio::select!` with explicit branch ordering: HIGH is listed
            // first so that if multiple lanes become ready simultaneously,
            // Tokio's random branch selection is overridden by the try_recv
            // loop on the next iteration.  The select here purely parks the
            // task until at least one message arrives.
            tokio::select! {
                biased;                          // evaluate branches top-to-bottom

                result = self.high_rx.recv() => {
                    match result {
                        Ok(msg) => return Ok(msg),
                        Err(_)  => return Err(BusError::Closed),
                    }
                }

                result = self.medium_rx.recv() => {
                    match result {
                        Ok(msg) => return Ok(msg),
                        Err(_)  => return Err(BusError::Closed),
                    }
                }

                result = self.low_rx.recv() => {
                    match result {
                        Ok(msg) => return Ok(msg),
                        Err(_)  => return Err(BusError::Closed),
                    }
                }
            }
            // Loop: after waking, re-poll non-blocking before yielding again.
            // This drains any additional HIGH messages that arrived while we
            // were awaiting a MEDIUM/LOW message.
        }
    }

    /// Non-blocking receive.  Returns `None` if all lanes are currently empty.
    #[inline]
    pub fn try_recv(&self) -> Option<Message> {
        self.high_rx.try_recv().ok()
            .or_else(|| self.medium_rx.try_recv().ok())
            .or_else(|| self.low_rx.try_recv().ok())
    }
}