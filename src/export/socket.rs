// src/export/socket.rs
//! TCP socket event streaming for local consumers.
//!
//! SocketExport listens on a TCP address (e.g. 127.0.0.1:9877) and streams
//! newline-delimited JSON ExportEvents to every connected client in real time.
//!
//! Design:
//!   A broadcast channel distributes events to all connected clients.
//!   Each client gets its own task that reads from the broadcast receiver
//!   and writes JSON lines to the TCP stream.  Slow clients are detected
//!   by the broadcast channel's lag mechanism — lagged receivers are closed
//!   rather than blocking the sender.
//!
//!   On Windows:  TCP loopback (127.0.0.1:port) — works out of the box.
//!   On Linux:    TCP loopback or Unix socket — TCP used here for cross-platform
//!                simplicity; a Unix socket variant can be added later.
//!
//! Usage:
//!   Connect with: nc 127.0.0.1 9877
//!   Or:           websocat ws://127.0.0.1:9877  (if proxied)
//!   Each line is a complete JSON object representing one ExportEvent.

use std::net::SocketAddr;
use std::str::FromStr;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use super::ExportEvent;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Broadcast channel capacity.  If a client falls more than this many
/// events behind it is disconnected.
const BROADCAST_CAPACITY: usize = 512;

// ── SocketExport ──────────────────────────────────────────────────────────────

/// Real-time JSON event streamer over TCP.
pub struct SocketExport {
    /// Sender side of the broadcast channel.  Cheap to clone.
    tx: broadcast::Sender<String>,
}

impl SocketExport {
    /// Bind to `addr` and start listening for client connections.
    ///
    /// Returns immediately — the listener runs in a background Tokio task.
    /// Use `send()` to push events to all connected clients.
    pub async fn bind(addr: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sock_addr = SocketAddr::from_str(addr)
            .map_err(|e| format!("Invalid socket address '{}': {}", addr, e))?;

        let listener = TcpListener::bind(sock_addr).await
            .map_err(|e| format!("Cannot bind socket export to {}: {}", addr, e))?;

        let (tx, _) = broadcast::channel::<String>(BROADCAST_CAPACITY);
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            accept_loop(listener, tx_clone).await;
        });

        info!(addr, "Socket export listening");
        Ok(Self { tx })
    }

    /// Broadcast an ExportEvent to all connected clients.
    ///
    /// Serialises to JSON and sends as a single newline-terminated line.
    /// Non-blocking — if no clients are connected this is a single atomic
    /// check and returns immediately.
    #[inline]
    pub fn send(&self, event: &ExportEvent) {
        // Only serialise if there are active receivers.
        if self.tx.receiver_count() == 0 { return; }

        match serde_json::to_string(event) {
            Ok(mut line) => {
                line.push('\n');
                // send() fails only if there are no receivers — that's fine.
                let _ = self.tx.send(line);
            }
            Err(e) => {
                error!(error = %e, "Failed to serialise export event for socket");
            }
        }
    }

    /// Number of currently connected clients.
    #[inline]
    pub fn client_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

// ── Accept loop ───────────────────────────────────────────────────────────────

async fn accept_loop(listener: TcpListener, tx: broadcast::Sender<String>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(%peer, "Socket export client connected");
                let rx = tx.subscribe();
                tokio::spawn(handle_client(stream, rx, peer));
            }
            Err(e) => {
                error!(error = %e, "Socket export accept error");
                // Brief back-off to avoid a tight error loop.
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// ── Per-client handler ────────────────────────────────────────────────────────

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    mut rx:     broadcast::Receiver<String>,
    peer:       SocketAddr,
) {
    loop {
        match rx.recv().await {
            Ok(line) => {
                if let Err(e) = stream.write_all(line.as_bytes()).await {
                    debug!(%peer, error = %e, "Socket export client write error — disconnecting");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // Client is too slow — log and disconnect so it doesn't
                // block or degrade other clients.
                warn!(%peer, skipped = n, "Socket export client too slow — disconnecting");
                break;
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Sender dropped — server shutting down.
                break;
            }
        }
    }

    debug!(%peer, "Socket export client disconnected");
}