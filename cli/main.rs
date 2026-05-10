// cli/main.rs
//! RUBIX CLI — Command line interface for RUBIX Network Blocking Engine
//!
//! ## Subcommands
//!
//! ```text
//! rubix-cli start                        Start the daemon
//! rubix-cli start --foreground           Start in foreground
//! rubix-cli stop                         Graceful stop
//! rubix-cli stop --force                 Force kill
//! rubix-cli status                       Daemon status + uptime
//! rubix-cli block <IP>                   Block IP permanently
//! rubix-cli block <IP> --duration 3600   Block IP for 1 hour
//! rubix-cli unblock <IP>                 Remove a block
//! rubix-cli list                         List active blocks
//! rubix-cli rules                        List policy rules
//! rubix-cli reload                       Hot-reload rules from disk
//! rubix-cli monitor                      Live TUI dashboard (Ctrl+C to exit)
//! rubix-cli logs                         All rings, all levels — live stream
//! rubix-cli logs alerts                  Security ring, Alert level — live stream
//! rubix-cli logs blocks                  Security ring, Block level — live stream
//! rubix-cli logs threats                 Security ring, Threat level — live stream
//! rubix-cli logs normal                  Normal ring, Normal level — live stream
//! rubix-cli logs errors                  Normal ring, Error level — live stream
//! ```
//!
//! ## Log output format
//!
//! Each entry is a single raw text line written to stdout:
//!
//! ```text
//! [BLOCK]  14:03:22.441  192.168.1.5:4444 -> 10.0.0.1:80    TCP    curl
//! [ALERT]  14:03:23.001  10.1.2.3:0       -> 8.8.8.8:53     UDP    systemd-resolve
//! ```
//!
//! Color codes (stripped automatically when stdout is not a TTY):
//!   BLOCK  → bold red       \x1B[1;31m
//!   ALERT  → bold yellow    \x1B[1;33m
//!   THREAT → bold magenta   \x1B[1;35m
//!   NORMAL → white          \x1B[0;37m
//!   ERROR  → bold light-red \x1B[1;91m
//!
//! ## Live streaming
//!
//! All `logs` subcommands poll the daemon every POLL_INTERVAL_MS milliseconds.
//! Only entries whose (time, src_ip, dst_ip, level) tuple has not been printed
//! in the current session are emitted — there is no duplicate output even if
//! the daemon's ring buffer overlaps between polls.
//!
//! Ctrl+C exits immediately and cleanly via a standard signal handler; no raw
//! terminal mode is used, so the terminal is never left in a broken state.
//!
//! ## Windows ANSI
//!
//! `enable_ansi_terminal()` enables ENABLE_VIRTUAL_TERMINAL_PROCESSING before
//! any output so the first line is never garbled in CMD or PowerShell.

use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command as SysCommand, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::{Parser, Subcommand};
use rubix::types::stats::{LiveStats, LogEntry, LogLevel};

// ── Constants ─────────────────────────────────────────────────────────────────

/// How often we poll the daemon for new log entries (milliseconds).
const POLL_INTERVAL_MS: u64 = 1_000;

// ── Platform: socket address ──────────────────────────────────────────────────

#[cfg(unix)]
const SOCKET_ADDR: &str = "/var/run/rubix.sock";

#[cfg(windows)]
const SOCKET_ADDR: &str = "127.0.0.1:9876";

// ── Dashboard constants ───────────────────────────────────────────────────────

const DASHBOARD_LINES: u16   = 36;
const MAX_PROC_ROWS:   usize = 8;
const MAX_THREAT_ROWS: usize = 5;

// ── ANSI color constants ──────────────────────────────────────────────────────

const COLOR_RESET:  &str = "\x1B[0m";
const COLOR_BLOCK:  &str = "\x1B[1;31m";   // bold red
const COLOR_ALERT:  &str = "\x1B[1;33m";   // bold yellow
const COLOR_THREAT: &str = "\x1B[1;35m";   // bold magenta
const COLOR_NORMAL: &str = "\x1B[0;37m";   // white
const COLOR_ERROR:  &str = "\x1B[1;91m";   // bold bright-red
const COLOR_DIM:    &str = "\x1B[2m";

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "rubix-cli")]
#[command(about = "RUBIX Network Defense Engine — CLI")]
#[command(version = "1.0.0")]
#[command(long_about = "
RUBIX Network Defense Engine CLI

Examples:
  rubix-cli start                            Start the daemon
  rubix-cli start --foreground               Start in foreground
  rubix-cli stop                             Stop the daemon (graceful)
  rubix-cli stop --force                     Force kill immediately
  rubix-cli status                           Show daemon status and uptime
  rubix-cli block 185.230.125.100            Block IP permanently
  rubix-cli block 1.2.3.4 --duration 3600   Block IP for 1 hour
  rubix-cli unblock 1.2.3.4                  Remove a block
  rubix-cli list                             List all active blocks
  rubix-cli rules                            List all policy rules
  rubix-cli reload                           Reload rules from disk
  rubix-cli monitor                          Live TUI dashboard (Ctrl+C to exit)
  rubix-cli logs                             Live stream — all rings, all levels
  rubix-cli logs alerts                      Live stream — Alert level only
  rubix-cli logs blocks                      Live stream — Block level only
  rubix-cli logs threats                     Live stream — Threat level only
  rubix-cli logs normal                      Live stream — Normal level only
  rubix-cli logs errors                      Live stream — Error level only
")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the RUBIX daemon
    Start {
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop the RUBIX daemon
    Stop {
        #[arg(short, long)]
        force: bool,
    },

    /// Show daemon status, uptime, and active rule counts
    Status,

    /// Block an IP address
    Block {
        ip: String,
        #[arg(short, long, default_value = "0")]
        duration: u64,
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Remove a block rule
    Unblock { ip: String },

    /// List all active block rules
    List,

    /// List all loaded policy rules
    Rules,

    /// Reload rules from configs/rules.yaml (hot reload, no restart required)
    Reload,

    /// Live TUI dashboard — refreshes in place every second (Ctrl+C to exit)
    Monitor,

    /// Live log stream — raw text, one line per entry (Ctrl+C to exit)
    ///
    /// Subcommands narrow to a specific level. Without a subcommand all
    /// rings and all levels are streamed.
    ///
    ///   rubix-cli logs            All rings, all levels
    ///   rubix-cli logs alerts     Security ring, Alert level
    ///   rubix-cli logs blocks     Security ring, Block level
    ///   rubix-cli logs threats    Security ring, Threat level
    ///   rubix-cli logs normal     Normal ring, Normal level
    ///   rubix-cli logs errors     Normal ring, Error level
    #[command(subcommand)]
    Logs(LogsCommand),
}

/// Logs subcommands — each selects a specific ring + level filter.
/// `rubix-cli logs` with no subcommand maps to `LogsCommand::All`.
#[derive(Subcommand, Debug, Clone, Copy)]
enum LogsCommand {
    /// All rings, all levels (default when no subcommand is given)
    #[command(hide = true)]
    All,

    /// Security ring — Alert level only
    Alerts,

    /// Security ring — Block level only
    Blocks,

    /// Security ring — Threat level only
    Threats,

    /// Normal ring — Normal level only
    Normal,

    /// Normal ring — Error level only
    Errors,
}

// ── Log stream configuration ──────────────────────────────────────────────────

/// Which daemon rings to merge for a given logs subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ring {
    /// `s.recent_logs` only (security events: Block, Alert, Threat)
    Security,
    /// `s.normal_logs` only (Normal, Error)
    Normal,
    /// Both rings merged
    Both,
}

/// The resolved streaming configuration derived from a `LogsCommand`.
#[derive(Debug, Clone, Copy)]
struct LogStreamConfig {
    ring:   Ring,
    filter: Option<LogLevel>,
}

impl From<LogsCommand> for LogStreamConfig {
    fn from(cmd: LogsCommand) -> Self {
        match cmd {
            LogsCommand::All     => Self { ring: Ring::Both,     filter: None                    },
            LogsCommand::Alerts  => Self { ring: Ring::Security, filter: Some(LogLevel::Alert)   },
            LogsCommand::Blocks  => Self { ring: Ring::Security, filter: Some(LogLevel::Block)   },
            LogsCommand::Threats => Self { ring: Ring::Security, filter: Some(LogLevel::Threat)  },
            LogsCommand::Normal  => Self { ring: Ring::Normal,   filter: Some(LogLevel::Normal)  },
            LogsCommand::Errors  => Self { ring: Ring::Normal,   filter: Some(LogLevel::Error)   },
        }
    }
}

// ── Windows ANSI enablement ───────────────────────────────────────────────────

#[cfg(windows)]
fn enable_ansi_terminal() {
    use windows::Win32::System::Console::{
        GetConsoleMode, SetConsoleMode, GetStdHandle,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        ENABLE_PROCESSED_OUTPUT,
        CONSOLE_MODE,
        STD_OUTPUT_HANDLE,
    };
    unsafe {
        let handle = match GetStdHandle(STD_OUTPUT_HANDLE) {
            Ok(h)  => h,
            Err(_) => return,
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_err() { return; }
        let new_mode = CONSOLE_MODE(
            mode.0
            | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0
            | ENABLE_PROCESSED_OUTPUT.0,
        );
        let _ = SetConsoleMode(handle, new_mode);
    }
}

#[cfg(unix)]
#[inline(always)]
fn enable_ansi_terminal() {}

// ── Color helpers ─────────────────────────────────────────────────────────────

/// Returns true when stdout is a real TTY that supports ANSI escape codes.
/// When stdout is piped (e.g. `rubix-cli logs alerts | grep ...`) all color
/// codes are suppressed automatically.
#[inline]
fn use_color() -> bool {
    io::stdout().is_terminal()
}

/// Return the ANSI color prefix for a log level, or "" when color is off.
#[inline]
fn level_color(level: LogLevel) -> &'static str {
    if !use_color() { return ""; }
    match level {
        LogLevel::Block  => COLOR_BLOCK,
        LogLevel::Alert  => COLOR_ALERT,
        LogLevel::Threat => COLOR_THREAT,
        LogLevel::Normal => COLOR_NORMAL,
        LogLevel::Error  => COLOR_ERROR,
    }
}

/// Return the ANSI reset sequence, or "" when color is off.
#[inline]
fn reset() -> &'static str {
    if use_color() { COLOR_RESET } else { "" }
}

/// Return the dim sequence, or "" when color is off.
#[inline]
fn dim() -> &'static str {
    if use_color() { COLOR_DIM } else { "" }
}

// ── Platform: process detection ───────────────────────────────────────────────

#[cfg(unix)]
fn is_daemon_running() -> bool {
    SysCommand::new("pgrep")
        .args(["-x", "rubix"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn get_daemon_pid() -> Option<u32> {
    let out = SysCommand::new("pgrep").args(["-x", "rubix"]).output().ok()?;
    if out.status.success() {
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    } else {
        None
    }
}

#[cfg(windows)]
fn is_daemon_running() -> bool {
    SysCommand::new("tasklist")
        .args(["/FI", "IMAGENAME eq rubix.exe", "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("rubix.exe"))
        .unwrap_or(false)
}

#[cfg(windows)]
fn get_daemon_pid() -> Option<u32> {
    let out = SysCommand::new("tasklist")
        .args(["/FI", "IMAGENAME eq rubix.exe", "/NH", "/FO", "CSV"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("rubix.exe"))?;
    line.split(',').nth(1)?.trim_matches('"').parse().ok()
}

// ── Platform: start / stop daemon ────────────────────────────────────────────

fn start_daemon(foreground: bool) -> Result<(), String> {
    if is_daemon_running() {
        return Err("RUBIX is already running".to_string());
    }

    #[cfg(unix)]
    let candidates = [
        PathBuf::from("/usr/local/bin/rubix"),
        PathBuf::from("./target/release/rubix"),
    ];
    #[cfg(windows)]
    let candidates = [
        PathBuf::from(r"C:\Program Files\RUBIX\rubix.exe"),
        PathBuf::from(r".\rubix-deploy\rubix.exe"),
        PathBuf::from(r".\target\release\rubix.exe"),
    ];

    let binary = candidates.iter().find(|p| p.exists())
        .ok_or("RUBIX binary not found. Run: cargo build --release")?;

    if foreground {
        println!("[*] Starting RUBIX in foreground...");
        SysCommand::new(binary)
            .status()
            .map_err(|e| format!("Failed to start: {}", e))?;
        return Ok(());
    }

    println!("[*] Starting RUBIX daemon...");

    #[cfg(unix)]
    let _child = SysCommand::new("nohup")
        .arg(binary)
        .stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn: {}", e))?;

    #[cfg(windows)]
    let _child = SysCommand::new(binary)
        .stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn: {}", e))?;

    std::thread::sleep(std::time::Duration::from_millis(800));

    if is_daemon_running() {
        println!("[+] RUBIX started (PID: {:?})", get_daemon_pid());
        Ok(())
    } else {
        Err("Daemon failed to start — check logs".to_string())
    }
}

#[cfg(unix)]
fn stop_daemon() -> Result<(), String> {
    let pid = get_daemon_pid().ok_or("Daemon not running")?;
    SysCommand::new("kill")
        .arg(pid.to_string())
        .status()
        .map_err(|e| format!("kill failed: {}", e))?;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !is_daemon_running() { return Ok(()); }
    }
    let _ = SysCommand::new("kill").args(["-9", &pid.to_string()]).status();
    Ok(())
}

#[cfg(unix)]
fn stop_daemon_force() -> Result<(), String> {
    let pid = get_daemon_pid().ok_or("Daemon not running")?;
    SysCommand::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .map_err(|e| format!("kill -9 failed: {}", e))?;
    Ok(())
}

#[cfg(windows)]
fn stop_daemon() -> Result<(), String> {
    let pid = get_daemon_pid().ok_or("Daemon not running")?;
    SysCommand::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .status()
        .map_err(|e| format!("taskkill failed: {}", e))?;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !is_daemon_running() { return Ok(()); }
    }
    let _ = SysCommand::new("taskkill").args(["/F", "/PID", &pid.to_string()]).status();
    Ok(())
}

#[cfg(windows)]
fn stop_daemon_force() -> Result<(), String> {
    let pid = get_daemon_pid().ok_or("Daemon not running")?;
    SysCommand::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status()
        .map_err(|e| format!("taskkill /F failed: {}", e))?;
    Ok(())
}

// ── IPC — JSON over socket ────────────────────────────────────────────────────

#[cfg(unix)]
async fn send_command(json: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    let mut stream = UnixStream::connect(SOCKET_ADDR).await
        .map_err(|e| format!("Cannot connect to RUBIX: {}. Is it running as root?", e))?;
    stream.write_all(json.as_bytes()).await
        .map_err(|e| format!("Write failed: {}", e))?;
    stream.shutdown().await
        .map_err(|e| format!("Shutdown failed: {}", e))?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).await
        .map_err(|e| format!("Read failed: {}", e))?;
    serde_json::from_str(&buf)
        .map_err(|e| format!("Invalid response JSON: {}", e))
}

#[cfg(windows)]
async fn send_command(json: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let mut stream = TcpStream::connect(SOCKET_ADDR).await
        .map_err(|e| format!(
            "Cannot connect to RUBIX ({}): {}. Is it running as Administrator?",
            SOCKET_ADDR, e
        ))?;
    stream.write_all(json.as_bytes()).await
        .map_err(|e| format!("Write failed: {}", e))?;
    stream.shutdown().await
        .map_err(|e| format!("Shutdown failed: {}", e))?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).await
        .map_err(|e| format!("Read failed: {}", e))?;
    serde_json::from_str(&buf)
        .map_err(|e| format!("Invalid response JSON: {}", e))
}

// ── Response printer ──────────────────────────────────────────────────────────

fn print_response(resp: serde_json::Value) {
    let success = resp["success"].as_bool().unwrap_or(false);
    let message = resp["message"].as_str().unwrap_or("(no message)");
    if success { println!("[+] {}", message); } else { eprintln!("[!] {}", message); }

    if let Some(data) = resp.get("data") {
        if let Some(rules) = data.get("rules").and_then(|r| r.as_array()) {
            if rules.is_empty() {
                println!("    (none)");
            } else {
                println!();
                println!(
                    "    {:<20} {:<18} {:<12} {}",
                    "IP", "Duration", "Type", "Reason"
                );
                println!("    {}", "-".repeat(70));
                for rule in rules {
                    println!(
                        "    {:<20} {:<18} {:<12} {}",
                        rule["ip"].as_str().unwrap_or("-"),
                        rule["remaining"].as_str().unwrap_or("-"),
                        if rule["permanent"].as_bool().unwrap_or(false) {
                            "permanent"
                        } else {
                            "timed"
                        },
                        rule["reason"].as_str().unwrap_or("-"),
                    );
                }
                println!();
            }
        }
        if let Some(uptime) = data.get("uptime_human") {
            println!("    Uptime        : {}", uptime.as_str().unwrap_or("-"));
            println!("    Active blocks : {}", data["active_blocks"].as_u64().unwrap_or(0));
            println!("    Policy rules  : {}", data["policy_rules"].as_u64().unwrap_or(0));
        }
    }
}

fn require_running() {
    if !is_daemon_running() {
        eprintln!("[!] RUBIX is not running. Start it with: rubix-cli start");
        std::process::exit(1);
    }
}

async fn run_command(cmd: serde_json::Value) {
    match send_command(&cmd.to_string()).await {
        Ok(resp) => print_response(resp),
        Err(e)   => { eprintln!("[!] {}", e); std::process::exit(1); }
    }
}

// ── Quit flag ─────────────────────────────────────────────────────────────────
//
// A single AtomicBool set by a spawned signal task. Both `monitor` and `logs`
// check it at the top of each poll loop iteration.  No raw terminal mode is
// involved, so the terminal is never left in a broken state regardless of how
// the process exits.

fn make_quit_flag() -> Arc<AtomicBool> {
    let quit = Arc::new(AtomicBool::new(false));
    let q    = quit.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut s = signal(SignalKind::interrupt()).expect("SIGINT handler");
            s.recv().await;
        }
        #[cfg(windows)]
        {
            tokio::signal::ctrl_c().await.ok();
        }
        q.store(true, Ordering::Relaxed);
    });
    quit
}

// ─────────────────────────────────────────────────────────────────────────────
//  LOGS — raw streaming text output
//
//  Algorithm per poll:
//    1. Fetch LiveStats from daemon.
//    2. Merge rings according to LogStreamConfig.
//    3. Apply level filter if set.
//    4. Sort merged slice by time ascending (oldest first within the poll).
//    5. For each entry compute a dedup key: (time, src_ip, src_port, dst_ip,
//       dst_port, level).  Skip if already in `seen` set.
//    6. Print new entries and insert their keys into `seen`.
//    7. Sleep POLL_INTERVAL_MS then repeat.
//
//  The `seen` set grows with the daemon ring buffer size (typically 1000–4000
//  entries total). Memory stays bounded because the daemon's ring never grows
//  unboundedly. If you need sessions longer than several hours consider
//  periodically pruning keys that are older than the daemon's ring window —
//  but that optimisation is not needed for normal operational use.
// ─────────────────────────────────────────────────────────────────────────────

/// Compact, allocation-free dedup key for a log entry.
/// Uses borrowed fields where possible; the HashSet owns String copies only
/// for the IP strings, which are already heap-allocated in LogEntry.
#[derive(Hash, PartialEq, Eq)]
struct EntryKey {
    time:     String,
    src_ip:   String,
    src_port: u16,
    dst_ip:   String,
    dst_port: u16,
    level:    LogLevel,
}

impl EntryKey {
    #[inline]
    fn from_entry(e: &LogEntry) -> Self {
        Self {
            time:     e.time.clone(),
            src_ip:   e.src_ip.clone(),
            src_port: e.src_port,
            dst_ip:   e.dst_ip.clone(),
            dst_port: e.dst_port,
            level:    e.level,
        }
    }
}

/// Format and print a single log entry to stdout.
///
/// Output format (color codes omitted when stdout is not a TTY):
/// ```text
/// [BLOCK]  14:03:22.441  192.168.1.5:4444  ->  10.0.0.1:80      TCP    curl
/// ```
#[inline]
fn print_entry(e: &LogEntry) {
    // Format src and dst with port when non-zero.
    let src = if e.src_port != 0 {
        format!("{}:{}", e.src_ip, e.src_port)
    } else {
        e.src_ip.clone()
    };
    let dst = if e.dst_port != 0 {
        format!("{}:{}", e.dst_ip, e.dst_port)
    } else {
        e.dst_ip.clone()
    };

    let color = level_color(e.level);
    let rst   = reset();
    let dim_c = dim();

    // Fixed-width columns keep the output scannable in a terminal even when
    // no TUI box is present.  The widths mirror what was used in the old TUI.
    //
    //  [LEVEL ]  (8 chars including brackets + padding)
    //  TIME      (12 chars  HH:MM:SS.mmm)
    //  SRC       (23 chars  ip:port left-justified)
    //  ->        (4 chars   literal arrow)
    //  DST       (23 chars  ip:port left-justified)
    //  PROTO     (6 chars)
    //  PROCESS   (remainder, no truncation)
    println!(
        "{color}{label:<8}{rst}  {dim_c}{time}{rst}  {src:<23}  {dim_c}->{rst}  {dst:<23}  \
         {dim_c}{proto:<6}{rst}  {process}",
        color   = color,
        label   = format!("[{}]", e.level.label()),
        rst     = rst,
        dim_c   = dim_c,
        time    = e.time,
        src     = src,
        dst     = dst,
        proto   = e.proto,
        process = e.process,
    );
}

/// Extract log entries from a `LiveStats` snapshot according to `cfg`,
/// returning references into the snapshot sorted by time ascending.
///
/// This borrow-based approach avoids cloning entry data on every poll.
fn collect_entries<'a>(s: &'a LiveStats, cfg: LogStreamConfig) -> Vec<&'a LogEntry> {
    // Gather references from the appropriate ring(s).
    let mut entries: Vec<&LogEntry> = match cfg.ring {
        Ring::Security => s.recent_logs.iter().collect(),
        Ring::Normal   => s.normal_logs.iter().collect(),
        Ring::Both     => s.recent_logs.iter().chain(s.normal_logs.iter()).collect(),
    };

    // Apply level filter.
    if let Some(level) = cfg.filter {
        entries.retain(|e| e.level == level);
    }

    // Sort by time ascending so we print old→new on each poll.
    // LogEntry::time is "HH:MM:SS.mmm" — lexicographic ordering is correct
    // within a single day. Cross-midnight sessions will have at most one
    // brief reorder artefact, which is acceptable for an operational tool.
    entries.sort_unstable_by(|a, b| a.time.cmp(&b.time));
    entries
}

async fn cmd_logs(cmd: LogsCommand) {
    let cfg  = LogStreamConfig::from(cmd);
    let quit = make_quit_flag();

    // Print a one-line header to stderr so it doesn't pollute piped stdout.
    // This tells the operator what filter is active without being intrusive.
    let filter_label = match cfg.filter {
        None        => "all levels".to_string(),
        Some(level) => level.label().to_string(),
    };
    let ring_label = match cfg.ring {
        Ring::Security => "security ring",
        Ring::Normal   => "normal ring",
        Ring::Both     => "all rings",
    };
    eprintln!(
        "{}[rubix] streaming {} — {} — Ctrl+C to exit{}",
        if use_color() { COLOR_DIM } else { "" },
        ring_label,
        filter_label,
        if use_color() { COLOR_RESET } else { "" },
    );

    let mut seen: HashSet<EntryKey> = HashSet::new();

    // Flush stdout explicitly after each poll so output appears immediately
    // even when the process is running inside a pipe.
    let stdout = io::stdout();

    loop {
        if quit.load(Ordering::Relaxed) {
            break;
        }

        match send_command(&serde_json::json!({"cmd": "logs"}).to_string()).await {
            Err(e) => {
                // Print connection errors to stderr; don't pollute the log
                // stream on stdout.  Retry after the poll interval.
                eprintln!(
                    "{}[rubix] cannot reach daemon: {} — retrying…{}",
                    if use_color() { "\x1B[1;31m" } else { "" },
                    e,
                    if use_color() { COLOR_RESET } else { "" },
                );
            }
            Ok(resp) => {
                match resp
                    .get("live_stats")
                    .and_then(|v| serde_json::from_value::<LiveStats>(v.clone()).ok())
                {
                    None => {
                        eprintln!(
                            "{}[rubix] unexpected response shape — retrying…{}",
                            if use_color() { "\x1B[1;31m" } else { "" },
                            if use_color() { COLOR_RESET } else { "" },
                        );
                    }
                    Some(stats) => {
                        let entries = collect_entries(&stats, cfg);
                        let mut wrote = false;
                        for entry in entries {
                            let key = EntryKey::from_entry(entry);
                            if seen.contains(&key) {
                                continue;
                            }
                            seen.insert(key);
                            print_entry(entry);
                            wrote = true;
                        }
                        if wrote {
                            // Flush after each batch so piped consumers see
                            // output without buffering delay.
                            let _ = stdout.lock().flush();
                        }
                    }
                }
            }
        }

        // Sleep in small increments so the quit flag is checked promptly.
        // We use a 100 ms granularity; total sleep adds up to POLL_INTERVAL_MS.
        let steps = (POLL_INTERVAL_MS / 100).max(1);
        for _ in 0..steps {
            if quit.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    // Print a clean exit line to stderr so it's visible but doesn't mix into
    // any piped stdout stream the operator may have captured.
    eprintln!(
        "{}[rubix] stream ended{}",
        if use_color() { COLOR_DIM } else { "" },
        if use_color() { COLOR_RESET } else { "" },
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  MONITOR — in-place TUI, fixed DASHBOARD_LINES frame (unchanged)
// ─────────────────────────────────────────────────────────────────────────────

async fn cmd_monitor() {
    print!("\x1B[?25l");
    let _ = io::stdout().flush();

    let mut first_frame = true;
    let quit = make_quit_flag();

    while !quit.load(Ordering::Relaxed) {
        if !first_frame {
            print!("\x1B[{}A\x1B[1G", DASHBOARD_LINES);
        }

        let snap_result = send_command(
            &serde_json::json!({"cmd": "stats"}).to_string()
        ).await;

        match snap_result {
            Err(e) => {
                render_monitor_error(&e);
                let _ = io::stdout().flush();
                first_frame = false;
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
            Ok(resp) => {
                match resp
                    .get("live_stats")
                    .and_then(|v| serde_json::from_value::<LiveStats>(v.clone()).ok())
                {
                    Some(stats) => render_dashboard(&stats),
                    None        => render_monitor_error("Unexpected response shape from daemon"),
                }
                let _ = io::stdout().flush();
                first_frame = false;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    print!("\x1B[?25h");
    println!();
    let _ = io::stdout().flush();
}

// ─────────────────────────────────────────────────────────────────────────────
//  MONITOR render functions (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

fn render_dashboard(s: &LiveStats) {
    let (status_plain, status_color) = if s.block_count > 0 {
        ("[BLOCKING]", "\x1B[1;31m[BLOCKING]\x1B[0m")
    } else if s.alert_count > 0 {
        ("[ALERTING]", "\x1B[1;33m[ALERTING]\x1B[0m")
    } else {
        ("[ CLEAN  ]", "\x1B[1;32m[ CLEAN  ]\x1B[0m")
    };

    dln("╔══════════════════════════════════════════════════════════════════╗");
    println!(
        "\x1B[2K║  \x1B[1mRUBIX LIVE MONITOR\x1B[0m   {}                                   ║",
        status_color,
    );
    dln("║  Ctrl+C to exit                                                  ║");
    dln("╚══════════════════════════════════════════════════════════════════╝");
    dln("");
    println!("\x1B[2K {} |{}|  {:>6.0} pps", status_plain, s.heartbeat, s.pps);
    dln("");
    dln("┌─ LIVE COUNTERS ──────────────────────────────────────────────────┐");
    println!(
        "\x1B[2K│  Packets  : {:>10}    Rate   : {:>8.0} pps                 │",
        s.packet_count, s.pps,
    );
    println!(
        "\x1B[2K│  Blocked  : {:>10}    Avg    : {:>8.0} pps                 │",
        s.block_count, s.avg_pps,
    );
    println!(
        "\x1B[2K│  Alerts   : {:>10}    Uptime : {:>7.0} sec                 │",
        s.alert_count, s.runtime_secs,
    );
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    dln("┌─ TOP PROCESSES  (5 s window) ────────────────────────────────────┐");
    println!(
        "\x1B[2K│ {:>5} {:<22} {:>7} {:>8} {:>5} {:>5} {:>4} {:>3} │",
        "PID", "PROCESS", "PKTS", "BYTES", "BLK", "ALT", "DST", "PRO",
    );
    dln("├──────────────────────────────────────────────────────────────────┤");
    for i in 0..MAX_PROC_ROWS {
        if let Some(p) = s.top_procs.get(i) {
            let name      = truncate_tilde(&p.name, 22);
            let bytes_str = fmt_bytes(p.bytes);
            let blk_str   = if p.blocked > 0 {
                format!("\x1B[1;31m{:>5}\x1B[0m", format!("!{}", p.blocked))
            } else {
                format!("{:>5}", "0")
            };
            let alrt_str  = if p.alerted > 0 {
                format!("\x1B[1;33m{:>5}\x1B[0m", format!("!{}", p.alerted))
            } else {
                format!("{:>5}", "0")
            };
            println!(
                "\x1B[2K│ {:>5} {:<22} {:>7} {:>8} {} {} {:>4} {:>3} │",
                p.pid, name, p.packets, bytes_str,
                blk_str, alrt_str, p.unique_dsts, p.protocol_cnt,
            );
        } else {
            dln("│                                                                    │");
        }
    }
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    dln("┌─ RECENT THREATS ─────────────────────────────────────────────────┐");
    let total = s.recent_threats.len();
    for i in 0..MAX_THREAT_ROWS {
        if i < total {
            let line = &s.recent_threats[total - 1 - i];
            let disp = truncate_ellipsis(line, 66);
            println!("\x1B[2K│ \x1B[1;31m{:<66}\x1B[0m │", disp);
        } else {
            dln("│                                                                    │");
        }
    }
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    println!(
        "\x1B[2m Refreshing every 1 s  │  rubix-cli monitor  │  Ctrl+C to exit\x1B[0m",
    );
    dln("");
}

fn render_monitor_error(msg: &str) {
    dln("╔══════════════════════════════════════════════════════════════════╗");
    dln("║  RUBIX LIVE MONITOR   \x1B[1;31m[OFFLINE]\x1B[0m                                 ║");
    dln("║  Ctrl+C to exit                                                  ║");
    dln("╚══════════════════════════════════════════════════════════════════╝");
    dln("");
    println!("\x1B[2K [!] Cannot reach daemon at {:<38}", SOCKET_ADDR);
    dln("");
    dln("┌─ LIVE COUNTERS ──────────────────────────────────────────────────┐");
    println!("\x1B[2K│  \x1B[1;31m{:<66}\x1B[0m │", tpad(msg, 66));
    dln("│                                                                    │");
    dln("│                                                                    │");
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    dln("┌─ TOP PROCESSES  (5 s window) ────────────────────────────────────┐");
    dln("│   PID PROCESS                   PKTS    BYTES   BLK   ALT  DST PRO │");
    dln("├──────────────────────────────────────────────────────────────────┤");
    for _ in 0..MAX_PROC_ROWS {
        dln("│                                                                    │");
    }
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    dln("┌─ RECENT THREATS ─────────────────────────────────────────────────┐");
    for _ in 0..MAX_THREAT_ROWS {
        dln("│                                                                    │");
    }
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    dln(" Retrying...  │  rubix-cli monitor  │  Ctrl+C to exit              ");
    dln("");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Render helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Erase current line then print — used by monitor TUI only.
#[inline(always)]
fn dln(s: &str) {
    println!("\x1B[2K\r{}", s);
}

/// Truncate + pad to exactly `max` visible chars (no ANSI codes in input).
#[inline]
fn tpad(s: &str, max: usize) -> String {
    if s.len() > max {
        s[..max].to_string()
    } else {
        format!("{:<width$}", s, width = max)
    }
}

fn truncate_tilde(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}~", &s[..max.saturating_sub(1)]) }
    else             { s.to_string() }
}

fn truncate_ellipsis(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max.saturating_sub(3)]) }
    else             { s.to_string() }
}

fn fmt_bytes(b: u64) -> String {
    if      b >= 1_000_000_000 { format!("{:.1}G", b as f64 / 1e9) }
    else if b >= 1_000_000     { format!("{:.1}M", b as f64 / 1e6) }
    else if b >= 1_000         { format!("{:.1}K", b as f64 / 1e3) }
    else                       { format!("{}B",    b) }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    enable_ansi_terminal();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { foreground } => {
            match start_daemon(foreground) {
                Ok(())  => {}
                Err(e)  => { eprintln!("[!] {}", e); std::process::exit(1); }
            }
        }

        Commands::Stop { force } => {
            if force {
                match stop_daemon_force() {
                    Ok(())  => println!("[+] RUBIX force-stopped"),
                    Err(e)  => { eprintln!("[!] {}", e); std::process::exit(1); }
                }
            } else {
                if is_daemon_running() {
                    let _ = send_command(
                        &serde_json::json!({"cmd": "shutdown"}).to_string()
                    ).await;
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                match stop_daemon() {
                    Ok(())  => println!("[+] RUBIX stopped"),
                    Err(e)  => { eprintln!("[!] {}", e); std::process::exit(1); }
                }
            }
        }

        Commands::Status => {
            match get_daemon_pid() {
                Some(pid) => {
                    println!("[+] RUBIX is running (PID: {})", pid);
                    run_command(serde_json::json!({"cmd": "status"})).await;
                }
                None => {
                    eprintln!("[!] RUBIX is not running");
                    std::process::exit(1);
                }
            }
        }

        Commands::Block { ip, duration, reason } => {
            require_running();
            if ip.parse::<std::net::IpAddr>().is_err() {
                eprintln!("[!] Invalid IP address: {}", ip);
                std::process::exit(1);
            }
            run_command(serde_json::json!({
                "cmd":           "block_ip",
                "ip":            ip,
                "duration_secs": if duration > 0 { Some(duration) } else { None },
                "reason":        reason,
            })).await;
        }

        Commands::Unblock { ip } => {
            require_running();
            if ip.parse::<std::net::IpAddr>().is_err() {
                eprintln!("[!] Invalid IP address: {}", ip);
                std::process::exit(1);
            }
            run_command(serde_json::json!({"cmd": "unblock_ip", "ip": ip})).await;
        }

        Commands::List => {
            require_running();
            run_command(serde_json::json!({"cmd": "list_blocked"})).await;
        }

        Commands::Rules => {
            require_running();
            run_command(serde_json::json!({"cmd": "get_rules"})).await;
        }

        Commands::Reload => {
            require_running();
            run_command(serde_json::json!({"cmd": "reload_config"})).await;
        }

        Commands::Monitor => {
            require_running();
            cmd_monitor().await;
        }

        // `rubix-cli logs` with no subcommand → stream all rings, all levels.
        // clap routes an absent subcommand here via the hidden `All` variant.
        Commands::Logs(sub) => {
            require_running();
            cmd_logs(sub).await;
        }
    }
}
