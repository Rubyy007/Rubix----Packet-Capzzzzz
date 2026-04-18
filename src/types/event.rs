// src/types/event.rs
// Event data structures

use std::time::SystemTime;
use super::packet::Packet;

#[derive(Debug, Clone)]
pub struct Event {
    pub id: u64,
    pub timestamp: SystemTime,
    pub priority: Priority,
    pub event_type: EventType,
    pub packet: Option<Packet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    HIGH = 0,
    MEDIUM = 1,
    LOW = 2,
}

#[derive(Debug, Clone)]
pub enum EventType {
    PacketCapture,
    BlockExecuted { rule_id: String },
    Alert { message: String },
}

impl Event {
    pub fn new(priority: Priority, event_type: EventType) -> Self {
        static mut NEXT_ID: u64 = 0;
        let id = unsafe {
            NEXT_ID += 1;
            NEXT_ID
        };
        
        Self {
            id,
            timestamp: SystemTime::now(),
            priority,
            event_type,
            packet: None,
        }
    }
    
    pub fn with_packet(mut self, packet: Packet) -> Self {
        self.packet = Some(packet);
        self
    }
}