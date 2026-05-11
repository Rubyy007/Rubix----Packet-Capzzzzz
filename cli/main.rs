// cli/main.rs
//! RUBIX CLI — Command line interface for RUBIX Network Blocking Engine
//!
//! ## Subcommands
//!
//! ```text
//! rubix-cli start                                     Start the daemon
//! rubix-cli start --foreground                        Start in foreground
//! rubix-cli stop                                      Graceful stop
//! rubix-cli stop --force                              Force kill
//! rubix-cli status                                    Daemon status + uptime
//! rubix-cli block <IP>                                Block IP permanently
//! rubix-cli block <IP> --duration 3600                Block IP for 1 hour
//! rubix-cli unblock <IP>                              Remove an IP block
//! rubix-cli list                                      List active IP blocks
//! rubix-cli block-pid <PID>                           Block process by PID permanently
//! rubix-cli block-pid <PID> --duration 300            Block PID for 5 minutes
//! rubix-cli block-exe <PATH>                          Block all processes from executable
//! rubix-cli block-hash <SHA256>                       Block by executable SHA-256
//! rubix-cli unblock-pid <PID>                         Remove PID block + flush kernel IPs
//! rubix-cli unblock-exe <PATH>                        Remove executable block
//! rubix-cli unblock-hash <SHA256>                     Remove hash block
//! rubix-cli list-processes                            List all process blocks
//! rubix-cli rules                                     List policy rules
//! rubix-cli reload                                    Hot-reload rules from disk
//! rubix-cli monitor                                   Live TUI dashboard (Ctrl+C to exit)
//! rubix-cli logs                                      All rings, all levels — live stream
//! rubix-cli logs alerts                               Security ring, Alert level
//! rubix-cli logs blocks                               Security ring, Block level
//! rubix-cli logs threats                              Security ring, Threat level
//! rubix-cli logs normal                               Normal ring, Normal level
//! rubix-cli logs errors                               Normal ring, Error level
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
const COLOR_BLOCK:  &str = "\x1B[1;31m";
const COLOR_ALERT:  &str = "\x1B[1;33m";
const COLOR_THREAT: &str = "\x1B[1;35m";
const COLOR_NORMAL: &str = "\x1B[0;37m";
const COLOR_ERROR:  &str = "\x1B[1;91m";
const COLOR_DIM:    &str = "\x1B[2m";
const COLOR_CYAN:   &str = "\x1B[1;36m";
const COLOR_GREEN:  &str = "\x1B[1;32m";

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "rubix-cli")]
#[command(about = "RUBIX Network Defense Engine — CLI")]
#[command(version = "1.0.0")]
#[command(long_about = "
RUBIX Network Defense Engine CLI

── IP BLOCKING ───────────────────────────────────────────────────────────────
  rubix-cli block 185.230.125.100                  Block IP permanently
  rubix-cli block 1.2.3.4 --duration 3600          Block IP for 1 hour
  rubix-cli unblock 1.2.3.4                         Remove IP block
  rubix-cli list                                    List active IP blocks

── PROCESS BLOCKING ──────────────────────────────────────────────────────────
  rubix-cli block-pid 1234                          Block PID permanently
  rubix-cli block-pid 1234 --duration 300           Block PID for 5 minutes
  rubix-cli block-exe /usr/bin/curl                 Block all curl processes
  rubix-cli block-hash aabb1122...                  Block by SHA-256 hash
  rubix-cli unblock-pid 1234                        Remove PID block
  rubix-cli unblock-exe /usr/bin/curl               Remove executable block
  rubix-cli unblock-hash aabb1122...                Remove hash block
  rubix-cli list-processes                          List all process blocks

── DAEMON ────────────────────────────────────────────────────────────────────
  rubix-cli start                                   Start the daemon
  rubix-cli start --foreground                      Start in foreground
  rubix-cli stop                                    Stop gracefully
  rubix-cli stop --force                            Force kill
  rubix-cli status                                  Show status + uptime
  rubix-cli rules                                   List policy rules
  rubix-cli reload                                  Reload rules.yaml

── MONITORING ────────────────────────────────────────────────────────────────
  rubix-cli monitor                                 Live TUI dashboard
  rubix-cli logs                                    Stream all events
  rubix-cli logs blocks                             Stream Block events only
  rubix-cli logs alerts                             Stream Alert events only
  rubix-cli logs threats                            Stream Threat events only
  rubix-cli logs normal                             Stream normal traffic
  rubix-cli logs errors                             Stream daemon errors
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

    /// Block an IP address permanently or for a timed duration
    Block {
        ip: String,
        #[arg(short, long, default_value = "0", help = "Duration in seconds (0 = permanent)")]
        duration: u64,
        #[arg(short, long, help = "Optional reason label")]
        reason: Option<String>,
    },

    /// Remove an IP block rule
    Unblock {
        ip: String,
    },

    /// List all active IP block rules
    List,

    // ── Process blocking ──────────────────────────────────────────────────────

    /// Block a specific running process by PID.
    ///
    /// The block is immediate and auto-expires when the process exits
    /// or the optional duration elapses. When a packet from this PID
    /// is seen, the remote IP is automatically kernel-blocked and tagged
    /// with this PID as the origin. unblock-pid flushes those kernel IPs.
    ///
    /// Examples:
    ///   rubix-cli block-pid 1234
    ///   rubix-cli block-pid 1234 --duration 300
    ///   rubix-cli block-pid 1234 --reason "data exfil suspect"
    BlockPid {
        pid: u32,
        #[arg(short, long, default_value = "0", help = "Duration in seconds (0 = permanent until PID exits)")]
        duration: u64,
        #[arg(short, long, help = "Optional reason label")]
        reason: Option<String>,
    },

    /// Block all processes launched from an executable path.
    ///
    /// The path is canonicalized at registration time (symlinks resolved).
    /// All currently running instances are PID-blocked immediately.
    /// Any new process launched from this path is auto-blocked on first packet.
    ///
    /// Examples:
    ///   rubix-cli block-exe /usr/bin/curl
    ///   rubix-cli block-exe "C:\Windows\System32\curl.exe"
    ///   rubix-cli block-exe /usr/bin/python3 --reason "malware dropper"
    BlockExe {
        path: String,
        #[arg(short, long, help = "Optional reason label")]
        reason: Option<String>,
    },

    /// Block any process whose executable SHA-256 matches.
    ///
    /// Hash-based blocking survives the binary being renamed or moved.
    /// The sha256 argument must be exactly 64 lowercase hex characters.
    ///
    /// Get the hash:
    ///   Windows: (Get-FileHash payload.exe -Algorithm SHA256).Hash.ToLower()
    ///   Linux:   sha256sum /path/to/binary
    ///
    /// Examples:
    ///   rubix-cli block-hash aabbcc1122...64chars
    ///   rubix-cli block-hash aabbcc1122...64chars --reason "known malware"
    BlockHash {
        sha256: String,
        #[arg(short, long, help = "Optional reason label")]
        reason: Option<String>,
    },

    /// Remove a PID block and flush all kernel IP rules installed for it.
    ///
    /// Kernel IP rules that were automatically installed because of this
    /// PID block are also removed from nftables/WFP.
    UnblockPid {
        pid: u32,
    },

    /// Remove an executable path block.
    ///
    /// Existing PID blocks derived from this exe block remain active until
    /// the process exits or you explicitly unblock-pid them.
    UnblockExe {
        path: String,
    },

    /// Remove a SHA-256 hash block.
    UnblockHash {
        /// 64-character lowercase hex SHA-256
        sha256: String,
    },

    /// List all active process blocks: PIDs, executables, and hashes.
    ListProcesses,

    /// List all loaded policy rules
    Rules,

    /// Reload rules from configs/rules.yaml (hot reload, no restart required)
    Reload,

    /// Live TUI dashboard — refreshes in place every second (Ctrl+C to exit)
    Monitor,

    /// Live log stream — raw text, one line per entry (Ctrl+C to exit)
    #[command(subcommand)]
    Logs(LogsCommand),
}

// ── Logs subcommands ──────────────────────────────────────────────────────────

#[derive(Subcommand, Debug, Clone, Copy)]
enum LogsCommand {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ring {
    Security,
    Normal,
    Both,
}

#[derive(Debug, Clone, Copy)]
struct LogStreamConfig {
    ring:   Ring,
    filter: Option<LogLevel>,
}

impl From<LogsCommand> for LogStreamConfig {
    fn from(cmd: LogsCommand) -> Self {
        match cmd {
            LogsCommand::All     => Self { ring: Ring::Both,     filter: None                   },
            LogsCommand::Alerts  => Self { ring: Ring::Security, filter: Some(LogLevel::Alert)  },
            LogsCommand::Blocks  => Self { ring: Ring::Security, filter: Some(LogLevel::Block)  },
            LogsCommand::Threats => Self { ring: Ring::Security, filter: Some(LogLevel::Threat) },
            LogsCommand::Normal  => Self { ring: Ring::Normal,   filter: Some(LogLevel::Normal) },
            LogsCommand::Errors  => Self { ring: Ring::Normal,   filter: Some(LogLevel::Error)  },
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

#[inline]
fn use_color() -> bool {
    io::stdout().is_terminal()
}

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

#[inline]
fn reset() -> &'static str {
    if use_color() { COLOR_RESET } else { "" }
}

#[inline]
fn dim() -> &'static str {
    if use_color() { COLOR_DIM } else { "" }
}

#[inline]
fn cyan() -> &'static str {
    if use_color() { COLOR_CYAN } else { "" }
}

#[inline]
fn green() -> &'static str {
    if use_color() { COLOR_GREEN } else { "" }
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
    if success {
        println!("{}[+]{} {}", green(), reset(), message);
    } else {
        eprintln!("{}[!]{} {}", COLOR_BLOCK, reset(), message);
    }

    if let Some(data) = resp.get("data") {

        // ── IP block list ─────────────────────────────────────────────────────
        if let Some(rules) = data.get("rules").and_then(|r| r.as_array()) {
            if rules.is_empty() {
                println!("    (none)");
            } else {
                println!();
                println!(
                    "{}    {:<20} {:<18} {:<12} {}{}",
                    dim(), "IP", "Duration", "Type", "Reason", reset()
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

        // ── Status uptime block ───────────────────────────────────────────────
        if let Some(uptime) = data.get("uptime_human") {
            println!("    Uptime           : {}", uptime.as_str().unwrap_or("-"));
            println!("    Active IP blocks : {}", data["active_ip_blocks"].as_u64().unwrap_or(0));
            println!("    Active PID blocks: {}", data["active_pid_blocks"].as_u64().unwrap_or(0));
            println!("    Active exe blocks: {}", data["active_exe_blocks"].as_u64().unwrap_or(0));
            println!("    Hash blocks      : {}", data["active_hash_blocks"].as_u64().unwrap_or(0));
            println!("    Policy rules     : {}", data["policy_rules"].as_u64().unwrap_or(0));
        }

        // ── PID block list ────────────────────────────────────────────────────
        if let Some(pids) = data.get("pid_blocks").and_then(|r| r.as_array()) {
            if !pids.is_empty() {
                println!();
                println!(
                    "{}  PID BLOCKS:{}",
                    cyan(), reset()
                );
                println!(
                    "{}    {:<8} {:<24} {:<12} {:<10} {}{}",
                    dim(), "PID", "NAME", "EXPIRES", "KERNEL IPs", "REASON", reset()
                );
                println!("    {}", "-".repeat(72));
                for p in pids {
                    println!(
                        "    {:<8} {:<24} {:<12} {:<10} {}",
                        p["pid"].as_u64().unwrap_or(0),
                        p["name"].as_str().unwrap_or("-"),
                        p["expires"].as_str().unwrap_or("permanent"),
                        p["kernel_ips"].as_u64().unwrap_or(0),
                        p["reason"].as_str().unwrap_or("-"),
                    );
                }
            }
        }

        // ── Executable block list ─────────────────────────────────────────────
        if let Some(exes) = data.get("exe_blocks").and_then(|r| r.as_array()) {
            if !exes.is_empty() {
                println!();
                println!(
                    "{}  EXECUTABLE BLOCKS:{}",
                    cyan(), reset()
                );
                println!(
                    "{}    {:<52} {}{}",
                    dim(), "PATH", "REASON", reset()
                );
                println!("    {}", "-".repeat(72));
                for e in exes {
                    println!(
                        "    {:<52} {}",
                        e["path"].as_str().unwrap_or("-"),
                        e["reason"].as_str().unwrap_or("-"),
                    );
                }
            }
        }

        // ── Hash block list ───────────────────────────────────────────────────
        if let Some(hashes) = data.get("hash_blocks").and_then(|r| r.as_array()) {
            if !hashes.is_empty() {
                println!();
                println!(
                    "{}  HASH BLOCKS:{}",
                    cyan(), reset()
                );
                println!(
                    "{}    {:<68} {}{}",
                    dim(), "SHA-256", "REASON", reset()
                );
                println!("    {}", "-".repeat(80));
                for h in hashes {
                    println!(
                        "    {:<68} {}",
                        h["sha256"].as_str().unwrap_or("-"),
                        h["reason"].as_str().unwrap_or("-"),
                    );
                }
            }
        }

        // ── Single block confirmation ─────────────────────────────────────────
        if let Some(ip) = data.get("ip") {
            println!("    IP      : {}", ip.as_str().unwrap_or("-"));
            if let Some(id) = data.get("rule_id") {
                println!("    Rule ID : {}", id.as_str().unwrap_or("-"));
            }
        }

        // ── Process block confirmation ────────────────────────────────────────
        if let Some(pid) = data.get("pid") {
            println!("    PID    : {}", pid.as_u64().unwrap_or(0));
            if let Some(r) = data.get("reason") {
                println!("    Reason : {}", r.as_str().unwrap_or("-"));
            }
            if let Some(n) = data.get("newly_blocked") {
                println!("    New    : {}", n.as_bool().unwrap_or(false));
            }
        }
        if let Some(path) = data.get("path") {
            println!("    Path   : {}", path.as_str().unwrap_or("-"));
            if let Some(r) = data.get("reason") {
                println!("    Reason : {}", r.as_str().unwrap_or("-"));
            }
        }
        if let Some(sha) = data.get("sha256") {
            println!("    SHA256 : {}", sha.as_str().unwrap_or("-"));
            if let Some(r) = data.get("reason") {
                println!("    Reason : {}", r.as_str().unwrap_or("-"));
            }
        }

        // ── note field (used by several process block responses) ──────────────
        if let Some(note) = data.get("note") {
            println!(
                "    {}Note   : {}{}",
                dim(),
                note.as_str().unwrap_or("-"),
                reset()
            );
        }

        // ── Kernel IPs flushed (unblock-pid) ──────────────────────────────────
        if let Some(flushed) = data.get("kernel_ips_flushed") {
            println!(
                "    Kernel IPs flushed : {}",
                flushed.as_u64().unwrap_or(0)
            );
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

// ── Log streaming ─────────────────────────────────────────────────────────────

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

#[inline]
fn print_entry(e: &LogEntry) {
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

fn collect_entries<'a>(s: &'a LiveStats, cfg: LogStreamConfig) -> Vec<&'a LogEntry> {
    let mut entries: Vec<&LogEntry> = match cfg.ring {
        Ring::Security => s.recent_logs.iter().collect(),
        Ring::Normal   => s.normal_logs.iter().collect(),
        Ring::Both     => s.recent_logs.iter().chain(s.normal_logs.iter()).collect(),
    };
    if let Some(level) = cfg.filter {
        entries.retain(|e| e.level == level);
    }
    entries.sort_unstable_by(|a, b| a.time.cmp(&b.time));
    entries
}

async fn cmd_logs(cmd: LogsCommand) {
    let cfg  = LogStreamConfig::from(cmd);
    let quit = make_quit_flag();

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
    let stdout = io::stdout();

    loop {
        if quit.load(Ordering::Relaxed) { break; }

        match send_command(&serde_json::json!({"cmd": "logs"}).to_string()).await {
            Err(e) => {
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
                            if seen.contains(&key) { continue; }
                            seen.insert(key);
                            print_entry(entry);
                            wrote = true;
                        }
                        if wrote { let _ = stdout.lock().flush(); }
                    }
                }
            }
        }

        let steps = (POLL_INTERVAL_MS / 100).max(1);
        for _ in 0..steps {
            if quit.load(Ordering::Relaxed) { break; }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    eprintln!(
        "{}[rubix] stream ended{}",
        if use_color() { COLOR_DIM } else { "" },
        if use_color() { COLOR_RESET } else { "" },
    );
}

// ── Monitor TUI ───────────────────────────────────────────────────────────────

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

// ── Monitor render ────────────────────────────────────────────────────────────

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

// ── Render helpers ────────────────────────────────────────────────────────────

#[inline(always)]
fn dln(s: &str) {
    println!("\x1B[2K\r{}", s);
}

#[inline]
fn tpad(s: &str, max: usize) -> String {
    if s.len() > max { s[..max].to_string() }
    else             { format!("{:<width$}", s, width = max) }
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

// ── SHA-256 validation ────────────────────────────────────────────────────────

fn validate_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    enable_ansi_terminal();

    let cli = Cli::parse();

    match cli.command {

        // ── Daemon lifecycle ──────────────────────────────────────────────────

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

        // ── IP blocking ───────────────────────────────────────────────────────

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

        // ── Process blocking — PID ────────────────────────────────────────────

        Commands::BlockPid { pid, duration, reason } => {
            require_running();
            run_command(serde_json::json!({
                "cmd":           "block_pid",
                "pid":           pid,
                "duration_secs": if duration > 0 { Some(duration) } else { None },
                "reason":        reason,
            })).await;
        }

        Commands::UnblockPid { pid } => {
            require_running();
            run_command(serde_json::json!({
                "cmd": "unblock_pid",
                "pid": pid,
            })).await;
        }

        // ── Process blocking — executable path ────────────────────────────────

        Commands::BlockExe { path, reason } => {
            require_running();
            if path.trim().is_empty() {
                eprintln!("[!] Executable path must not be empty");
                std::process::exit(1);
            }
            run_command(serde_json::json!({
                "cmd":    "block_executable",
                "path":   path,
                "reason": reason,
            })).await;
        }

        Commands::UnblockExe { path } => {
            require_running();
            run_command(serde_json::json!({
                "cmd":  "unblock_executable",
                "path": path,
            })).await;
        }

        // ── Process blocking — SHA-256 hash ───────────────────────────────────

        Commands::BlockHash { sha256, reason } => {
            require_running();
            let sha256 = sha256.to_lowercase();
            if !validate_sha256(&sha256) {
                eprintln!(
                    "[!] Invalid SHA-256: must be exactly 64 lowercase hex characters.\n    \
                     Got {} characters.",
                    sha256.len()
                );
                eprintln!(
                    "    Windows: (Get-FileHash binary.exe -Algorithm SHA256).Hash.ToLower()"
                );
                eprintln!(
                    "    Linux:   sha256sum /path/to/binary"
                );
                std::process::exit(1);
            }
            run_command(serde_json::json!({
                "cmd":    "block_hash",
                "sha256": sha256,
                "reason": reason,
            })).await;
        }

        Commands::UnblockHash { sha256 } => {
            require_running();
            let sha256 = sha256.to_lowercase();
            if !validate_sha256(&sha256) {
                eprintln!("[!] Invalid SHA-256: must be exactly 64 lowercase hex characters");
                std::process::exit(1);
            }
            run_command(serde_json::json!({
                "cmd":    "unblock_hash",
                "sha256": sha256,
            })).await;
        }

        // ── List all process blocks ───────────────────────────────────────────

        Commands::ListProcesses => {
            require_running();
            run_command(serde_json::json!({"cmd": "list_blocked_processes"})).await;
        }

        // ── Policy ────────────────────────────────────────────────────────────

        Commands::Rules => {
            require_running();
            run_command(serde_json::json!({"cmd": "get_rules"})).await;
        }

        Commands::Reload => {
            require_running();
            run_command(serde_json::json!({"cmd": "reload_config"})).await;
        }

        // ── Monitoring ────────────────────────────────────────────────────────

        Commands::Monitor => {
            require_running();
            cmd_monitor().await;
        }

        Commands::Logs(sub) => {
            require_running();
            cmd_logs(sub).await;
        }
    }
}