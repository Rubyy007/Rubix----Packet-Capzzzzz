//! YAML configuration loader

use super::RubixConfig;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

pub struct ConfigLoader {
    config: RubixConfig,
}

impl ConfigLoader {
    // FIXED: Load platform-specific config with common fallback
    pub fn load(config_dir: &Path, platform: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try platform-specific first
        let platform_path = config_dir.join(format!("rubix.{}.yaml", platform));
        let common_path = config_dir.join("rubix.common.yaml");
        
        let config = if platform_path.exists() {
            let contents = fs::read_to_string(&platform_path)?;
            let mut config: RubixConfig = serde_yaml::from_str(&contents)?;
            
            // Merge with common if exists
            if common_path.exists() {
                let common_contents = fs::read_to_string(&common_path)?;
                let common_config: RubixConfig = serde_yaml::from_str(&common_contents)?;
                config = Self::merge(config, common_config);
            }
            
            info!("Loaded platform config: {:?}", platform_path);
            config
        } else if common_path.exists() {
            let contents = fs::read_to_string(&common_path)?;
            let config: RubixConfig = serde_yaml::from_str(&contents)?;
            info!("Loaded common config: {:?}", common_path);
            config
        } else {
            warn!("No config found, using defaults");
            RubixConfig::default()
        };
        
        Ok(Self { config })
    }
    
    fn merge(mut platform: RubixConfig, common: RubixConfig) -> RubixConfig {
        // Use platform values, fallback to common if default
        if platform.capture_interface == "auto" && common.capture_interface != "auto" {
            platform.capture_interface = common.capture_interface;
        }
        if platform.mode.to_string() == "Block" && common.mode.to_string() != "Block" {
            platform.mode = common.mode;
        }
        if platform.bpf_filter.is_none() && common.bpf_filter.is_some() {
            platform.bpf_filter = common.bpf_filter;
        }
        if !platform.promiscuous && common.promiscuous {
            platform.promiscuous = common.promiscuous;
        }
        if platform.buffer_size_mb == 0 && common.buffer_size_mb > 0 {
            platform.buffer_size_mb = common.buffer_size_mb;
        }
        // Add more merge logic as needed for other fields
        platform
    }
    
    pub fn get(&self) -> &RubixConfig {
        &self.config
    }
}