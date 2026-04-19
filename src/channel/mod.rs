//! Internal message passing and event bus

mod bus;
mod drop;
mod priority;

pub use bus::EventBus;
pub use drop::PacketDrop;
pub use priority::Priority;

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub priority: Priority,
    pub timestamp: SystemTime,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Packet,
    Alert,
    Block,
    Control,
    Stats,
}

impl Message {
    pub fn new(priority: Priority, message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            priority,
            timestamp: SystemTime::now(),
            message_type,
            payload,
        }
    }
}