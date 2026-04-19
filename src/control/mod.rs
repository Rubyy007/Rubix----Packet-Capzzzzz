//! Control system for managing RUBIX

mod commands;
mod handler;
mod server;

pub use commands::{Command, CommandResponse};
pub use handler::CommandHandler;
pub use server::ControlServer;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    pub enabled: bool,
    pub socket_path: String,
    pub api_port: Option<u16>,
    pub auth_token: Option<String>,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: "/tmp/rubix.sock".to_string(),
            api_port: Some(8080),
            auth_token: None,
        }
    }
}