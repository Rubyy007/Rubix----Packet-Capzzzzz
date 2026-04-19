//! High-performance packet processing pipeline

mod aggregator;
mod pipeline;
mod sampler;

pub use aggregator::PacketAggregator;
pub use pipeline::Pipeline;
pub use sampler::PacketSampler;

use crate::types::Packet;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct PipelineStage {
    name: String,
    processor: Arc<dyn Fn(Packet) -> Option<Packet> + Send + Sync>,
}

impl PipelineStage {
    pub fn new<F>(name: &str, processor: F) -> Self
    where
        F: Fn(Packet) -> Option<Packet> + Send + Sync + 'static,
    {
        Self {
            name: name.to_string(),
            processor: Arc::new(processor),
        }
    }
    
    pub async fn process(&self, packet: Packet) -> Option<Packet> {
        (self.processor)(packet)
    }
}