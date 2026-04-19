//! Main packet processing pipeline

use super::{PipelineStage, PacketSampler, PacketAggregator};
use crate::types::Packet;
use crate::policy::PolicyEngine;
use crate::export::ExportDispatcher;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error};

pub struct Pipeline {
    stages: Vec<PipelineStage>,
    sampler: PacketSampler,
    aggregator: Option<PacketAggregator>,
    policy_engine: Arc<PolicyEngine>,
    export_dispatcher: Arc<tokio::sync::Mutex<ExportDispatcher>>,
}

impl Pipeline {
    pub fn new(
        policy_engine: Arc<PolicyEngine>,
        export_dispatcher: Arc<tokio::sync::Mutex<ExportDispatcher>>,
        sample_rate: u32,
        enable_aggregation: bool,
    ) -> Self {
        Self {
            stages: Vec::new(),
            sampler: PacketSampler::new(sample_rate),
            aggregator: if enable_aggregation {
                Some(PacketAggregator::new(60))
            } else {
                None
            },
            policy_engine,
            export_dispatcher,
        }
    }
    
    pub fn add_stage(&mut self, stage: PipelineStage) {
        info!("Added pipeline stage: {}", stage.name);
        self.stages.push(stage);
    }
    
    pub async fn process_packet(&mut self, packet: Packet) -> Option<Packet> {
        // Apply sampling
        if !self.sampler.should_sample() {
            return None;
        }
        
        // Apply aggregation
        if let Some(aggregator) = &mut self.aggregator {
            if let Some(flow) = aggregator.add_packet(&packet) {
                info!("New flow: {} -> {} ({} packets, {} bytes)",
                    flow.src_ip, flow.dst_ip, flow.packet_count, flow.byte_count);
            }
        }
        
        // Process through stages
        let mut current_packet = packet;
        for stage in &self.stages {
            match stage.process(current_packet).await {
                Some(p) => current_packet = p,
                None => return None,
            }
        }
        
        Some(current_packet)
    }
    
    pub fn set_sample_rate(&mut self, rate: u32) {
        self.sampler.set_sample_rate(rate);
        info!("Sample rate set to 1/{}", rate);
    }
}