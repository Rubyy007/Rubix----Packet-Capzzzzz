// src/config/loader.rs
//! YAML configuration loader

use super::RubixConfig;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

pub struct ConfigLoader {
    config: RubixConfig,
}

impl ConfigLoader {
    /// Load config for the current platform.
    ///
    /// Resolution order:
    ///   1. configs/rubix.{platform}.yaml  (platform-specific)
    ///   2. configs/rubix.common.yaml      (fallback)
    ///   3. RubixConfig::default()         (last resort)
    ///
    /// Platform config takes priority — common fills in any missing fields
    /// via serde defaults, not by merging structs.
    pub fn load(config_dir: &Path, platform: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let platform_path = config_dir.join(format!("rubix.{}.yaml", platform));
        let common_path   = config_dir.join("rubix.common.yaml");

        let config = if platform_path.exists() {
            let contents = fs::read_to_string(&platform_path)?;
            let config: RubixConfig = serde_yaml::from_str(&contents)?;
            info!("Loaded platform config: {:?}", platform_path);
            config
        } else if common_path.exists() {
            let contents = fs::read_to_string(&common_path)?;
            let config: RubixConfig = serde_yaml::from_str(&contents)?;
            info!("Loaded common config: {:?}", common_path);
            config
        } else {
            warn!("No config file found in {:?} — using built-in defaults", config_dir);
            RubixConfig::default()
        };

        Ok(Self { config })
    }

    pub fn get(&self) -> &RubixConfig {
        &self.config
    }
}