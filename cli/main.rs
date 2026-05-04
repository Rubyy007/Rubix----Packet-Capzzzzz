// cli/main.rs
//! RUBIX CLI - Command line interface for RUBIX Network Blocking Engine
//!
//! `rubix-cli monitor` renders a live in-place TUI dashboard.
//!
//! Windows note: CMD and PowerShell do NOT process ANSI/VT escape codes
//! by default. `enable_ansi_terminal()` calls SetConsoleMode with
//! ENABLE_VIRTUAL_TERMINAL_PROCESSING at startup — this is the FIRST thing
//! main() does, before any print! that contains escape codes.
//! The `Win32_System_Console` windows-crate feature must be present in
//! Cargo.toml (already added).

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command as SysCommand, Stdio};

use rubix::types::stats::LiveStats;

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
")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the RUBIX daemon
    Start {
        /// Run in foreground (don't detach)
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the RUBIX daemon
    Stop {
        /// Force kill immediately (no graceful shutdown)
        #[arg(short, long)]
        force: bool,
    },
    /// Show daemon status, uptime, and active rules
    Status,
    /// Block an IP address
    Block {
        /// IP address to block (e.g. 185.230.125.100)
        ip: String,
        /// Duration in seconds — omit or 0 for permanent
        #[arg(short, long, default_value = "0")]
        duration: u64,
        /// Reason for the block (optional, stored in rule)
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Remove a block rule
    Unblock {
        /// IP address to unblock
        ip: String,
    },
    /// List all active block rules
    List,
    /// List all loaded policy rules
    Rules,
    /// Reload rules from configs/rules.yaml (hot reload, no restart)
    Reload,
    /// Live TUI dashboard — refreshes in place every second (Ctrl+C to exit)
    Monitor,
}

// ── Platform: socket address ──────────────────────────────────────────────────

#[cfg(unix)]
const SOCKET_ADDR: &str = "/var/run/rubix.sock";
#[cfg(windows)]
const SOCKET_ADDR: &str = "127.0.0.1:9876";

// ── Dashboard dimensions ──────────────────────────────────────────────────────
//
// DASHBOARD_LINES must equal the EXACT number of lines (newlines) that
// render_dashboard() and render_error() each print.
//
// Line-by-line breakdown of render_dashboard():
//   header    4   (top border, title+status, ctrl-c hint, bottom border)
//   gap       1
//   heartbeat 1
//   gap       1
//   counters  5   (top border, 3 data rows, bottom border)
//   gap       1
//   procs    12   (top border, col header, divider, 8 data rows, bottom border)
//   gap       1
//   threats   7   (top border, 5 data rows, bottom border)
//   gap       1
//   footer    1
//   trailing  1
//   ──────────
//   TOTAL    36
//
// If you add/remove any println!/dln() in render_dashboard, update this number.

const DASHBOARD_LINES: u16 = 36;
const MAX_PROC_ROWS:   usize = 8;
const MAX_THREAT_ROWS: usize = 5;

// ─────────────────────────────────────────────────────────────────────────────
//  Windows ANSI enablement
//
//  SetConsoleMode( stdout_handle,
//      current_mode
//      | ENABLE_VIRTUAL_TERMINAL_PROCESSING   -- processes \x1B[...
//      | ENABLE_PROCESSED_OUTPUT              -- processes \n, \r, \b etc.
//  )
//
//  Must be called before the very first ANSI escape is emitted.
//  Fails silently if the handle is not a real console (e.g. redirected to
//  a file) — that is the correct behaviour.
// ─────────────────────────────────────────────────────────────────────────────

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
        // GetStdHandle returns INVALID_HANDLE_VALUE on failure; unwrap_or_default
        // gives a null handle which SetConsoleMode will harmlessly reject.
        let handle = match GetStdHandle(STD_OUTPUT_HANDLE) {
            Ok(h)  => h,
            Err(_) => return,
        };

        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_err() {
            return; // not a console (pipe/redirect) — skip silently
        }

        let new_mode = CONSOLE_MODE(
            mode.0
            | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0
            | ENABLE_PROCESSED_OUTPUT.0,
        );

        // Ignore error — worst case the user sees raw escape codes, but we
        // never crash or panic because of a console handle.
        let _ = SetConsoleMode(handle, new_mode);
    }
}

#[cfg(unix)]
#[inline(always)]
fn enable_ansi_terminal() {
    // All Unix terminals support ANSI/VT natively — nothing to do.
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

// ── Platform: start daemon ────────────────────────────────────────────────────

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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn: {}", e))?;

    #[cfg(windows)]
    let _child = SysCommand::new(binary)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
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

// ── Platform: stop daemon ─────────────────────────────────────────────────────

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

    let mut stream = UnixStream::connect(SOCKET_ADDR)
        .await
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

    let mut stream = TcpStream::connect(SOCKET_ADDR)
        .await
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
                println!("    {:<20} {:<18} {:<12} {}", "IP", "Duration", "Type", "Reason");
                println!("    {}", "-".repeat(70));
                for rule in rules {
                    println!(
                        "    {:<20} {:<18} {:<12} {}",
                        rule["ip"].as_str().unwrap_or("-"),
                        rule["remaining"].as_str().unwrap_or("-"),
                        if rule["permanent"].as_bool().unwrap_or(false) { "permanent" } else { "timed" },
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

// ── Guards ────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
//  MONITOR — in-place TUI
//
//  Strategy: cursor-up by DASHBOARD_LINES after the first frame.
//
//  Frame N:   print dashboard   (cursor is now at bottom of dashboard)
//  Frame N+1: \x1B[36A\x1B[1G  (cursor jumps back to top of dashboard)
//             overwrite every line with \x1B[2K + new content
//
//  This works on:
//    • Windows CMD / PowerShell (after enable_ansi_terminal())
//    • Windows Terminal
//    • All Unix terminals
//
//  No alternate screen buffer needed — avoids the ←[?1049h compatibility
//  issue seen in older CMD/PowerShell.
// ─────────────────────────────────────────────────────────────────────────────

async fn cmd_monitor() {
    // Hide cursor — reduces flicker during redraws
    print!("\x1B[?25l");
    let _ = io::stdout().flush();

    let mut first_frame = true;

    // Ctrl+C handler — sets flag, loop exits cleanly
    let quit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let q = quit.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut s = signal(SignalKind::interrupt()).expect("SIGINT");
                s.recv().await;
            }
            #[cfg(windows)]
            {
                tokio::signal::ctrl_c().await.ok();
            }
            q.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }

    while !quit.load(std::sync::atomic::Ordering::Relaxed) {
        // On all frames after the first, jump cursor back to the top of the
        // dashboard so we overwrite in place instead of appending.
        if !first_frame {
            // \x1B[{n}A = cursor up n lines
            // \x1B[1G   = cursor to column 1
            print!("\x1B[{}A\x1B[1G", DASHBOARD_LINES);
        }

        let snap_result = send_command(
            &serde_json::json!({"cmd": "stats"}).to_string()
        ).await;

        match snap_result {
            Err(e) => {
                render_error(&e);
                let _ = io::stdout().flush();
                first_frame = false;
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
            Ok(resp) => {
                match resp.get("live_stats")
                    .and_then(|v| serde_json::from_value::<LiveStats>(v.clone()).ok())
                {
                    Some(stats) => render_dashboard(&stats),
                    None        => render_error("Unexpected response shape from daemon"),
                }
                let _ = io::stdout().flush();
                first_frame = false;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    // Restore cursor on clean exit
    print!("\x1B[?25h");
    println!();
    let _ = io::stdout().flush();
}

// ─────────────────────────────────────────────────────────────────────────────
//  render_dashboard — prints EXACTLY DASHBOARD_LINES (36) lines.
//
//  Every line uses dln() which prepends \x1B[2K (erase to end of line)
//  before the content, clearing any leftover characters from a wider
//  previous frame.
//
//  Lines with inline ANSI colour codes use println!("\x1B[2K...") directly
//  because dln() would double-print the erase prefix.
// ─────────────────────────────────────────────────────────────────────────────

fn render_dashboard(s: &LiveStats) {
    let (status_plain, status_color) = if s.block_count > 0 {
        ("[BLOCKING]", "\x1B[1;31m[BLOCKING]\x1B[0m")  // bold red
    } else if s.alert_count > 0 {
        ("[ALERTING]", "\x1B[1;33m[ALERTING]\x1B[0m")  // bold yellow
    } else {
        ("[ CLEAN  ]", "\x1B[1;32m[ CLEAN  ]\x1B[0m")  // bold green
    };

    // ── Header (4 lines) ──────────────────────────────────────────────────────
    dln("╔══════════════════════════════════════════════════════════════════╗");
    // ANSI colour codes are zero-width — box alignment is preserved
    println!("\x1B[2K║  \x1B[1mRUBIX LIVE MONITOR\x1B[0m   {}                                   ║",
        status_color);
    dln("║  Ctrl+C to exit                                                  ║");
    dln("╚══════════════════════════════════════════════════════════════════╝");

    // ── Gap (1) ───────────────────────────────────────────────────────────────
    dln("");

    // ── Heartbeat (1) ─────────────────────────────────────────────────────────
    println!("\x1B[2K {} |{}|  {:>6.0} pps",
        status_plain, s.heartbeat, s.pps);

    // ── Gap (1) ───────────────────────────────────────────────────────────────
    dln("");

    // ── Live counters (5 lines) ───────────────────────────────────────────────
    dln("┌─ LIVE COUNTERS ──────────────────────────────────────────────────┐");
    println!("\x1B[2K│  Packets  : {:>10}    Rate   : {:>8.0} pps                 │",
        s.packet_count, s.pps);
    println!("\x1B[2K│  Blocked  : {:>10}    Avg    : {:>8.0} pps                 │",
        s.block_count, s.avg_pps);
    println!("\x1B[2K│  Alerts   : {:>10}    Uptime : {:>7.0} sec                 │",
        s.alert_count, s.runtime_secs);
    dln("└──────────────────────────────────────────────────────────────────┘");

    // ── Gap (1) ───────────────────────────────────────────────────────────────
    dln("");

    // ── Top processes (3 header + 8 data + 1 footer = 12 lines) ───────────────
    dln("┌─ TOP PROCESSES  (5 s window) ────────────────────────────────────┐");
    println!("\x1B[2K│ {:>5} {:<22} {:>7} {:>8} {:>5} {:>5} {:>4} {:>3} │",
        "PID", "PROCESS", "PKTS", "BYTES", "BLK", "ALT", "DST", "PRO");
    dln("├──────────────────────────────────────────────────────────────────┤");

    for i in 0..MAX_PROC_ROWS {
        if let Some(p) = s.top_procs.get(i) {
            let name      = truncate_tilde(&p.name, 22);
            let bytes_str = fmt_bytes(p.bytes);
            // Colour codes are zero-width — column alignment is unaffected
            let blk_str = if p.blocked > 0 {
                format!("\x1B[1;31m{:>5}\x1B[0m", format!("!{}", p.blocked))
            } else {
                format!("{:>5}", "0")
            };
            let alrt_str = if p.alerted > 0 {
                format!("\x1B[1;33m{:>5}\x1B[0m", format!("!{}", p.alerted))
            } else {
                format!("{:>5}", "0")
            };
            println!("\x1B[2K│ {:>5} {:<22} {:>7} {:>8} {} {} {:>4} {:>3} │",
                p.pid, name, p.packets, bytes_str,
                blk_str, alrt_str, p.unique_dsts, p.protocol_cnt);
        } else {
            // Blank stable row — fixed height, nothing jumps
            dln("│                                                                    │");
        }
    }
    dln("└──────────────────────────────────────────────────────────────────┘");

    // ── Gap (1) ───────────────────────────────────────────────────────────────
    dln("");

    // ── Recent threats (1 header + 5 data + 1 footer = 7 lines) ───────────────
    dln("┌─ RECENT THREATS ─────────────────────────────────────────────────┐");
    let total = s.recent_threats.len();
    for i in 0..MAX_THREAT_ROWS {
        if i < total {
            let line = &s.recent_threats[total - 1 - i]; // newest first
            let disp = truncate_ellipsis(line, 66);
            println!("\x1B[2K│ \x1B[1;31m{:<66}\x1B[0m │", disp);
        } else {
            dln("│                                                                    │");
        }
    }
    dln("└──────────────────────────────────────────────────────────────────┘");

    // ── Gap (1) ───────────────────────────────────────────────────────────────
    dln("");

    // ── Footer (1) ────────────────────────────────────────────────────────────
    println!("\x1B[2m Refreshing every 1 s  │  rubix-cli monitor  │  Ctrl+C to exit\x1B[0m");

    // ── Trailing blank (1) ────────────────────────────────────────────────────
    dln("");

    // Total: 4+1+1+1+5+1+12+1+7+1+1+1 = 36 ✓
}

// ─────────────────────────────────────────────────────────────────────────────
//  render_error — MUST print exactly DASHBOARD_LINES (36) lines.
//  Keeps the frame height stable so cursor-up math is correct even when the
//  daemon is unreachable.
// ─────────────────────────────────────────────────────────────────────────────

fn render_error(msg: &str) {
    // Header (4)
    dln("╔══════════════════════════════════════════════════════════════════╗");
    dln("║  RUBIX LIVE MONITOR   \x1B[1;31m[OFFLINE]\x1B[0m                                 ║");
    dln("║  Ctrl+C to exit                                                  ║");
    dln("╚══════════════════════════════════════════════════════════════════╝");
    // Gap (1)
    dln("");
    // Heartbeat row (1)
    println!("\x1B[2K [!] Cannot reach daemon at {:<38}", SOCKET_ADDR);
    // Gap (1)
    dln("");
    // Counters box (5)
    dln("┌─ LIVE COUNTERS ──────────────────────────────────────────────────┐");
    println!("\x1B[2K│  \x1B[1;31m{:<66}\x1B[0m │", truncate_pad(msg, 66));
    dln("│                                                                    │");
    dln("│                                                                    │");
    dln("└──────────────────────────────────────────────────────────────────┘");
    // Gap (1)
    dln("");
    // Procs box (12)
    dln("┌─ TOP PROCESSES  (5 s window) ────────────────────────────────────┐");
    dln("│   PID PROCESS                   PKTS    BYTES   BLK   ALT  DST PRO │");
    dln("├──────────────────────────────────────────────────────────────────┤");
    for _ in 0..MAX_PROC_ROWS {
        dln("│                                                                    │");
    }
    dln("└──────────────────────────────────────────────────────────────────┘");
    // Gap (1)
    dln("");
    // Threats box (7)
    dln("┌─ RECENT THREATS ─────────────────────────────────────────────────┐");
    for _ in 0..MAX_THREAT_ROWS {
        dln("│                                                                    │");
    }
    dln("└──────────────────────────────────────────────────────────────────┘");
    // Gap (1)
    dln("");
    // Footer (1)
    dln(" Retrying...  │  rubix-cli monitor  │  Ctrl+C to exit              ");
    // Trailing blank (1)
    dln("");
    // Total: 4+1+1+1+5+1+12+1+7+1+1+1 = 36 ✓
}

// ── Render helpers ────────────────────────────────────────────────────────────

/// Erase the current terminal line then print content.
/// Using \x1B[2K before each line means leftover characters from a longer
/// previous frame are cleared — no ghost characters.
#[inline(always)]
fn dln(s: &str) {
    println!("\x1B[2K{}", s);
}

fn truncate_tilde(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}~", &s[..max.saturating_sub(1)])
    } else {
        s.to_string()
    }
}

fn truncate_ellipsis(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

fn truncate_pad(s: &str, max: usize) -> String {
    if s.len() > max {
        s[..max].to_string()
    } else {
        format!("{:<width$}", s, width = max)
    }
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
    // ── Step 1: enable ANSI VT processing on Windows ─────────────────────────
    // This MUST be the very first call — before any print!/println! that
    // contains escape codes. On Unix this is a no-op.
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
                // Ask daemon to flush/cleanup, then OS-kill
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
    }
}