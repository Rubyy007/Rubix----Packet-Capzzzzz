// dashboard/backend/main.rs
//! RUBIX Dashboard Backend
//!
//! Bridges the React frontend to the RUBIX daemon control socket.
//!
//! Architecture:
//!   +-------------+   HTTP/WS    +--------------+   TCP/Unix   +--------------+
//!   | React front | ---------->  | This backend | ---------->  | RUBIX daemon |
//!   |  :3000      |  <---------- |   :8080      |  <---------- |  :9876/sock  |
//!   +-------------+              +--------------+              +--------------+
//!
//! Endpoints:
//!   GET  /api/stats          -- latest LiveStats snapshot (JSON)
//!   GET  /api/logs           -- recent security log entries
//!   GET  /api/rules          -- current policy rules
//!   POST /api/block          -- block an IP   {ip, duration_secs?, reason?}
//!   POST /api/unblock        -- unblock an IP {ip}
//!   GET  /api/blocked        -- list blocked IPs
//!   WS   /ws                 -- push live stats every 500ms
//!
//! The backend polls the daemon every 500ms and caches the result in an
//! Arc<RwLock<CachedState>>.  WebSocket clients receive the cached snapshot
//! immediately on connect, then receive diffs every 500ms.
//!
//! CORS is open (any origin) because the frontend runs on a different port
//! during development.  Lock this down for production deployment.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use warp::ws::{Message, WebSocket};
use warp::Filter;

// -- Re-use the exact types from the RUBIX crate --------------------------------
use rubix::types::stats::LiveStats;

// -- FIX: Define our own Command types (control module not public in rubix lib) -

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Command {
    Stats,
    ListBlocked,
    GetRules,
    BlockIp {
        ip: IpAddr,
        duration_secs: Option<u64>,
        reason: Option<String>,
    },
    UnblockIp {
        ip: IpAddr,
    },
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct CommandResponse {
    pub success: bool,
    pub message: Option<String>,
    pub live_stats: Option<LiveStats>,
    pub blocked_ips: Option<Vec<String>>,
    pub rules: Option<Vec<String>>,
}

// -- Constants ------------------------------------------------------------------

#[cfg(windows)]
const DAEMON_ADDR: &str = "127.0.0.1:9876";

#[cfg(unix)]
const DAEMON_SOCK: &str = "/var/run/rubix.sock";

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const BROADCAST_CAPACITY: usize = 64;
const BACKEND_PORT: u16 = 8080;

// -- Shared state ---------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct CachedState {
    stats:       LiveStats,
    last_update: Option<Instant>,
    daemon_ok:   bool,
}

type SharedState = Arc<RwLock<CachedState>>;

// -- Entry point ----------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let state: SharedState = Arc::new(RwLock::new(CachedState::default()));
    let (tx, _)            = broadcast::channel::<String>(BROADCAST_CAPACITY);
    let tx                 = Arc::new(tx);

    // -- Background poller --------------------------------------------------------
    {
        let state = state.clone();
        let tx    = tx.clone();
        tokio::spawn(poll_daemon(state, tx));
    }

    // -- Routes -------------------------------------------------------------------

    let state_filter = warp::any().map({
        let s = state.clone();
        move || s.clone()
    });
    let tx_filter = warp::any().map({
        let t = tx.clone();
        move || t.clone()
    });

    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(["GET", "POST", "OPTIONS"])
        .allow_headers(["Content-Type", "Authorization"]);

    let stats_route = warp::path!("api" / "stats")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(handle_stats);

    let logs_route = warp::path!("api" / "logs")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(handle_logs);

    let blocked_route = warp::path!("api" / "blocked")
        .and(warp::get())
        .and_then(handle_list_blocked);

    let rules_route = warp::path!("api" / "rules")
        .and(warp::get())
        .and_then(handle_get_rules);

    let block_route = warp::path!("api" / "block")
        .and(warp::post())
        .and(warp::body::json::<BlockRequest>())
        .and_then(handle_block);

    let unblock_route = warp::path!("api" / "unblock")
        .and(warp::post())
        .and(warp::body::json::<UnblockRequest>())
        .and_then(handle_unblock);

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(state_filter.clone())
        .and(tx_filter.clone())
        .map(|ws: warp::ws::Ws, state: SharedState, tx: Arc<broadcast::Sender<String>>| {
            ws.on_upgrade(move |socket| handle_ws(socket, state, tx))
        });

    let routes = stats_route
        .or(logs_route)
        .or(blocked_route)
        .or(rules_route)
        .or(block_route)
        .or(unblock_route)
        .or(ws_route)
        .with(cors)
        .recover(handle_rejection);

    let addr = SocketAddr::from(([0, 0, 0, 0], BACKEND_PORT));
    info!(port = BACKEND_PORT, "RUBIX dashboard backend started");
    warp::serve(routes).run(addr).await;
}

// -- Daemon poller --------------------------------------------------------------

async fn poll_daemon(state: SharedState, tx: Arc<broadcast::Sender<String>>) {
    let mut interval = tokio::time::interval(POLL_INTERVAL);

    loop {
        interval.tick().await;

        match send_command(Command::Stats).await {
            Ok(resp) => {
                if let Some(live) = resp.live_stats {
                    let serialised = match serde_json::to_string(&live) {
                        Ok(s)  => s,
                        Err(e) => { error!(error = %e, "Stats serialisation failed"); continue; }
                    };

                    {
                        let mut guard = state.write();
                        guard.stats       = live;
                        guard.last_update = Some(Instant::now());
                        guard.daemon_ok   = true;
                    }

                    let _ = tx.send(serialised);
                }
            }
            Err(e) => {
                debug!(error = %e, "Daemon poll failed -- is RUBIX running?");
                state.write().daemon_ok = false;
            }
        }
    }
}

// -- Daemon IPC -----------------------------------------------------------------

async fn send_command(cmd: Command) -> Result<CommandResponse, String> {
    let json = serde_json::to_string(&cmd)
        .map_err(|e| format!("Command serialisation failed: {}", e))?;

    #[cfg(windows)]
    let mut stream = TcpStream::connect(DAEMON_ADDR)
        .await
        .map_err(|e| format!("Cannot connect to daemon at {}: {}", DAEMON_ADDR, e))?;

    #[cfg(unix)]
    let mut stream = tokio::net::UnixStream::connect(DAEMON_SOCK)
        .await
        .map_err(|e| format!("Cannot connect to daemon at {}: {}", DAEMON_SOCK, e))?;

    stream
        .write_all(json.as_bytes())
        .await
        .map_err(|e| format!("Write failed: {}", e))?;

    #[cfg(windows)]
    stream
        .shutdown()
        .await
        .map_err(|e| format!("Shutdown failed: {}", e))?;

    #[cfg(unix)]
    {
        let (mut reader, writer) = stream.into_split();
        drop(writer);

        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("Read failed: {}", e))?;

        return serde_json::from_slice::<CommandResponse>(&buf)
            .map_err(|e| format!("Response parse failed: {}", e));
    }

    #[cfg(windows)]
    {
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("Read failed: {}", e))?;

        serde_json::from_slice::<CommandResponse>(&buf)
            .map_err(|e| format!("Response parse failed: {}", e))
    }
}

// -- HTTP handlers --------------------------------------------------------------

async fn handle_stats(state: SharedState) -> Result<impl warp::Reply, Infallible> {
    let guard = state.read();
    let body  = json!({
        "ok":          guard.daemon_ok,
        "last_update": guard.last_update.map(|t| t.elapsed().as_millis()),
        "stats":       &guard.stats,
    });
    Ok(warp::reply::json(&body))
}

async fn handle_logs(state: SharedState) -> Result<impl warp::Reply, Infallible> {
    let guard = state.read();
    let body  = json!({
        "security": &guard.stats.recent_logs,
        "normal":   &guard.stats.normal_logs,
        "threats":  &guard.stats.recent_threats,
    });
    Ok(warp::reply::json(&body))
}

async fn handle_list_blocked() -> Result<impl warp::Reply, Infallible> {
    match send_command(Command::ListBlocked).await {
        Ok(resp)  => Ok(warp::reply::json(&resp)),
        Err(e)    => Ok(warp::reply::json(&json!({"success": false, "message": e}))),
    }
}

async fn handle_get_rules() -> Result<impl warp::Reply, Infallible> {
    match send_command(Command::GetRules).await {
        Ok(resp)  => Ok(warp::reply::json(&resp)),
        Err(e)    => Ok(warp::reply::json(&json!({"success": false, "message": e}))),
    }
}

#[derive(Debug, Deserialize)]
struct BlockRequest {
    ip:           String,
    duration_secs: Option<u64>,
    reason:       Option<String>,
}

async fn handle_block(req: BlockRequest) -> Result<impl warp::Reply, Infallible> {
    let ip = match IpAddr::from_str(&req.ip) {
        Ok(ip) => ip,
        Err(_) => {
            return Ok(warp::reply::json(
                &json!({"success": false, "message": format!("Invalid IP: {}", req.ip)}),
            ));
        }
    };

    let cmd = Command::BlockIp {
        ip,
        duration_secs: req.duration_secs,
        reason:        req.reason,
    };

    match send_command(cmd).await {
        Ok(resp) => Ok(warp::reply::json(&resp)),
        Err(e)   => Ok(warp::reply::json(&json!({"success": false, "message": e}))),
    }
}

#[derive(Debug, Deserialize)]
struct UnblockRequest {
    ip: String,
}

async fn handle_unblock(req: UnblockRequest) -> Result<impl warp::Reply, Infallible> {
    let ip = match IpAddr::from_str(&req.ip) {
        Ok(ip) => ip,
        Err(_) => {
            return Ok(warp::reply::json(
                &json!({"success": false, "message": format!("Invalid IP: {}", req.ip)}),
            ));
        }
    };

    match send_command(Command::UnblockIp { ip }).await {
        Ok(resp) => Ok(warp::reply::json(&resp)),
        Err(e)   => Ok(warp::reply::json(&json!({"success": false, "message": e}))),
    }
}

// -- WebSocket handler ----------------------------------------------------------

async fn handle_ws(
    ws:    WebSocket,
    state: SharedState,
    tx:    Arc<broadcast::Sender<String>>,
) {
    let mut rx = tx.subscribe();
    let (mut ws_tx, _ws_rx) = ws.split();

    // Send the current snapshot immediately on connect.
    // Scope the lock so the guard is dropped before any await (Send requirement).
    let snapshot = {
        let guard = state.read();
        serde_json::to_string(&guard.stats).ok()
    };
    if let Some(s) = snapshot {
        let _ = ws_tx.send(Message::text(s)).await;
    }

    // Then forward every broadcast message until the client disconnects.
    loop {
        match rx.recv().await {
            Ok(msg) => {
                if ws_tx.send(Message::text(msg)).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "WebSocket client lagging -- skipping frames");
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}

// -- Error recovery -------------------------------------------------------------

async fn handle_rejection(
    err: warp::Rejection,
) -> Result<impl warp::Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (warp::http::StatusCode::NOT_FOUND, "Not found")
    } else if err.find::<warp::filters::body::BodyDeserializeError>().is_some() {
        (warp::http::StatusCode::BAD_REQUEST, "Invalid request body")
    } else {
        error!(rejection = ?err, "Unhandled rejection");
        (warp::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&json!({"success": false, "message": message})),
        code,
    ))
}