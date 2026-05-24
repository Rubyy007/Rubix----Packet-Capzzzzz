// src/control/server.rs
//! Control server — platform-aware listener for CLI IPC
//!
//! Linux/macOS : Unix domain socket at /var/run/rubix.sock
//! Windows     : TCP loopback at 127.0.0.1:9876
//!
//! FIX: on Linux the daemon runs as root.  UnixListener::bind() inherits the
//! process umask, producing a socket with mode 0600 or 0640 — only root can
//! connect.  Running `rubix-cli monitor` as a normal user then receives
//! "Permission denied" on every connect attempt.
//!
//! Fix: after a successful bind, chmod the socket to 0666 using
//! std::fs::set_permissions.  This allows any local user to connect to the
//! control socket, which is intentional — the commands the socket accepts
//! (status, stats, logs, block, unblock) are the same commands the CLI
//! exposes.  The socket is on localhost only (/var/run/), so there is no
//! network exposure.  Sensitive operations (block/unblock) already require
//! the daemon to be running as root to take effect in the kernel.

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
        Ok(j)  => j,
        Err(e) => { error!("Failed to serialise response: {}", e); return; }
    };

    let _ = writer.write_all(json.as_bytes()).await;
}

// ── Unix socket server ────────────────────────────────────────────────────────
#[cfg(unix)]
async fn run_unix_server(handler: Arc<CommandHandler>) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    const SOCKET_PATH: &str = "/var/run/rubix.sock";

    // Remove stale socket from a previous run.
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l)  => { info!(path = SOCKET_PATH, "Control server listening (Unix socket)"); l }
        Err(e) => {
            error!(
                error = %e,
                path  = SOCKET_PATH,
                "Failed to bind control socket — CLI will be unavailable"
            );
            return;
        }
    };

    // FIX: chmod the socket to 0666 so non-root users can connect.
    //
    // UnixListener::bind() inherits the process umask.  When the daemon runs
    // as root its umask is typically 022, producing a socket with mode 0644
    // (rw-r--r--), or 0600 if umask is 077.  Either way, a non-root user
    // running `rubix-cli monitor` receives EACCES on connect().
    //
    // 0o666 = rw-rw-rw- — any local user can read/write the socket.
    // The socket file is in /var/run/ which is owned by root and mode 0755,
    // so remote or unprivileged file creation is not possible.  The socket
    // itself carries no authentication — it is an internal IPC channel on
    // the local machine only.
    if let Err(e) = fs::set_permissions(
        SOCKET_PATH,
        fs::Permissions::from_mode(0o666),
    ) {
        // Non-fatal: the daemon continues but CLI will fail for non-root users.
        // Log clearly so the operator knows why `rubix-cli monitor` fails.
        warn!(
            error = %e,
            path  = SOCKET_PATH,
            "Could not set socket permissions to 0666 — \
             non-root users will get 'Permission denied' when running rubix-cli"
        );
    } else {
        info!(path = SOCKET_PATH, mode = "0666", "Control socket permissions set");
    }

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let (reader, writer) = stream.into_split();
                    handle_connection(reader, writer, handler).await;
                });
            }
            Err(e) => error!(error = %e, "Control server accept error"),
        }
    }
}

// ── TCP loopback server (Windows) ─────────────────────────────────────────────
#[cfg(windows)]
async fn run_tcp_server(handler: Arc<CommandHandler>) {
    use tokio::net::TcpListener;

    const ADDR: &str = "127.0.0.1:9876";

    let listener = match TcpListener::bind(ADDR).await {
        Ok(l)  => { info!(addr = ADDR, "Control server listening (TCP loopback)"); l }
        Err(e) => {
            error!(
                error = %e,
                addr  = ADDR,
                "Failed to bind control socket — CLI will be unavailable"
            );
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let (reader, writer) = stream.into_split();
                    handle_connection(reader, writer, handler).await;
                });
            }
            Err(e) => error!(error = %e, "Control server accept error"),
        }
    }
}