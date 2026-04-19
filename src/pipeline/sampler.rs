//! Packet sampling for high traffic scenarios

use std::sync::atomic::{AtomicU64, Ordering};

pub struct PacketSampler {
    sample_rate: u32,
    counter: AtomicU64,
}

impl PacketSampler {
    pub fn new(sample_rate: u32) -> Self {
        Self {
            sample_rate,
            counter: AtomicU64::new(0),
        }
    }
    
    pub fn should_sample(&self) -> bool {
        if self.sample_rate == 0 {
            return false;
        }
        
        if self.sample_rate == 1 {
            return true;
        }
        
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        count % self.sample_rate as u64 == 0
    }
    
    pub fn set_sample_rate(&mut self, rate: u32) {
        self.sample_rate = rate;
        self.counter.store(0, Ordering::Relaxed);
    }
    
    pub fn get_sample_rate(&self) -> u32 {
        self.sample_rate
    }
}