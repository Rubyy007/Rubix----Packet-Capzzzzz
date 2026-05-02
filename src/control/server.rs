// src/control/server.rs
//! Control server — platform-aware listener for CLI IPC
//!
//! Linux/macOS : Unix domain socket at /var/run/rubix.sock
//! Windows     : TCP loopback at 127.0.0.1:9876

use super::commands::{Command, CommandResponse};
use super::handler::CommandHandler;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

pub struct ControlServer {
    handler: Arc<CommandHandler>,
}

impl ControlServer {
    pub fn new(handler: Arc<CommandHandler>) -> Self {
        Self { handler }
    }

    pub async fn start(&self) {
        let handler = self.handler.clone();

        #[cfg(unix)]
        tokio::spawn(run_unix_server(handler));

        #[cfg(windows)]
        tokio::spawn(run_tcp_server(handler));
    }
}

// ── Connection handler (shared by both transports) ────────────────────────────

async fn handle_connection(
    mut reader: impl AsyncReadExt + Unpin,
    mut writer: impl AsyncWriteExt + Unpin,
    handler:    Arc<CommandHandler>,
) {
    let mut buf = Vec::new();

    if let Err(e) = reader.read_to_end(&mut buf).await {
        warn!("Control connection read error: {}", e);
        return;
    }

    let raw = String::from_utf8_lossy(&buf);

    // Parse JSON command
    let response = match serde_json::from_str::<Command>(&raw) {
        Ok(cmd) => handler.handle(cmd).await,
        Err(e) => {
            warn!(error = %e, raw = %raw.trim(), "Malformed control command");
            CommandResponse::error(format!(
                "Invalid command JSON: {}\n\
                 Expected: {{\"cmd\": \"status\"}} | {{\"cmd\": \"block_ip\", \"ip\": \"1.2.3.4\"}} | ...",
                e
            ))
        }
    };

    let json = match serde_json::to_string_pretty(&response) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialise response: {}", e);
            return;
        }
    };

    let _ = writer.write_all(json.as_bytes()).await;
}

// ── Unix socket server ────────────────────────────────────────────────────────
#[cfg(unix)]
async fn run_unix_server(handler: Arc<CommandHandler>) {
    use tokio::net::UnixListener;

    const SOCKET_PATH: &str = "/var/run/rubix.sock";

    // Remove stale socket from previous run
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => {
            info!(path = SOCKET_PATH, "Control server listening (Unix socket)");
            l
        }
        Err(e) => {
            error!(
                error = %e,
                path = SOCKET_PATH,
                "Failed to bind control socket — CLI will be unavailable"
            );
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let (reader, writer) = stream.into_split();
                    handle_connection(reader, writer, handler).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Control server accept error");
            }
        }
    }
}

// ── TCP loopback server ───────────────────────────────────────────────────────
#[cfg(windows)]
async fn run_tcp_server(handler: Arc<CommandHandler>) {
    use tokio::net::TcpListener;

    const ADDR: &str = "127.0.0.1:9876";

    let listener = match TcpListener::bind(ADDR).await {
        Ok(l) => {
            info!(addr = ADDR, "Control server listening (TCP loopback)");
            l
        }
        Err(e) => {
            error!(
                error = %e,
                addr = ADDR,
                "Failed to bind control socket — CLI will be unavailable"
            );
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!(peer = %peer, "Control connection accepted");
                let handler = handler.clone();
                tokio::spawn(async move {
                    let (reader, writer) = stream.into_split();
                    handle_connection(reader, writer, handler).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Control server accept error");
            }
        }
    }
}