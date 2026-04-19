//! Event bus for inter-component communication

use super::{Message, Priority};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, Sender, Receiver};
use tracing::{info, debug, error};

pub struct EventBus {
    tx: Sender<Message>,
    rx: Arc<Mutex<Option<Receiver<Message>>>>,
    queue: Arc<Mutex<VecDeque<Message>>>,
    max_queue_size: usize,
}

impl EventBus {
    pub fn new(buffer_size: usize, max_queue_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer_size);
        
        Self {
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(max_queue_size))),
            max_queue_size,
        }
    }
    
    pub async fn publish(&self, message: Message) -> Result<(), String> {
        let priority = message.priority.clone();
        
        // Queue based on priority
        let mut queue = self.queue.lock().unwrap();
        
        if queue.len() >= self.max_queue_size {
            // Drop lowest priority message
            queue.pop_back();
        }
        
        match priority {
            Priority::High => queue.push_front(message),
            Priority::Normal | Priority::Low => queue.push_back(message),
        }
        
        // Try to send via channel
        if let Err(e) = self.tx.send(message).await {
            error!("Failed to send message: {}", e);
            return Err(e.to_string());
        }
        
        debug!("Message published with priority {:?}", priority);
        Ok(())
    }
    
    pub async fn subscribe(&self) -> Receiver<Message> {
        let mut rx_guard = self.rx.lock().unwrap();
        if let Some(rx) = rx_guard.take() {
            rx
        } else {
            let (_, new_rx) = mpsc::channel(1000);
            new_rx
        }
    }
    
    pub fn get_queue_len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        
        Self {
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
            queue: self.queue.clone(),
            max_queue_size: self.max_queue_size,
        }
    }
}