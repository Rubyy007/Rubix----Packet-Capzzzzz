// src/control/mod.rs
//! Control system for RUBIX
//! Provides IPC between the daemon and CLI tools.

pub mod commands;
pub mod handler;
pub mod server;

pub use commands::{Command, CommandResponse};
pub use handler::CommandHandler;
pub use server::ControlServer;