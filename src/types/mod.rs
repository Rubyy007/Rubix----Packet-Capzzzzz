// src/types/mod.rs
//! Types module — packet primitives + live-stats snapshot.

pub mod packet;
pub mod event;
pub mod stats;

pub use packet::*;
pub use stats::{LiveStats, ProcStatSnapshot};
// pub use event::*;   // uncomment when event consumers exist
