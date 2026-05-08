// cli/main.rs
//! RUBIX CLI - Command line interface for RUBIX Network Blocking Engine
//!
//! `rubix-cli monitor` — live in-place TUI dashboard (36-line fixed frame).
//! `rubix-cli logs`    — live in-place structured log view (29-line fixed frame).
//!
//! ── Fixed-frame rendering ─────────────────────────────────────────────────
//!
//! Both views use an in-place cursor-up redraw strategy:
//!
//!   Frame N:  print exactly FIXED lines (no more, no less).
//!   Frame N+1: `\x1B[{FIXED}A\x1B[1G` — jump cursor to start of frame N.
//!             Overwrite every line with `\x1B[2K` (erase) + new content.
//!
//! Because the frame height is a compile-time constant, the cursor-up count
//! is always exact — no drift, no scrolling, regardless of entry count.
//!
//! Empty rows in the log table body are filled with blank padded lines so
//! the box drawing stays intact and the line count stays fixed.
//!
//! ── Two log rings ─────────────────────────────────────────────────────────
//!
//! `--ring security` (default): Block + Alert + Threat events from `recent_logs`.
//! `--ring normal`             : Normal + Error events from `normal_logs`.
//! `--ring all`                : Both rings interleaved, newest-first.
//!
//! ── Windows ANSI ─────────────────────────────────────────────────────────
//!
//! `enable_ansi_terminal()` calls SetConsoleMode with
//! ENABLE_VIRTUAL_TERMINAL_PROCESSING before any escape code is printed.

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command as SysCommand, Stdio};

use rubix::types::stats::{LiveStats, LogEntry, LogLevel};

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
  rubix-cli logs                             Live log view — security events
  rubix-cli logs --ring normal               Live log view — normal traffic
  rubix-cli logs --ring all                  Live log view — everything
  rubix-cli logs --filter block              Show only blocked connections
  rubix-cli logs --filter alert              Show only alerts
  rubix-cli logs --filter threat             Show only threat-detector events
  rubix-cli logs --filter normal             Show only normal traffic entries
  rubix-cli logs --filter error              Show only daemon error entries
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
    /// Show daemon status, uptime, and active rules
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
    /// Reload rules from configs/rules.yaml (hot reload, no restart)
    Reload,
    /// Live TUI dashboard — refreshes in place every second (Ctrl+C to exit)
    Monitor,
    /// Live structured log stream — fixed in-place view (Ctrl+C to exit)
    ///
    /// Rings:
    ///   security (default) — Block, Alert, Threat events
    ///   normal             — Normal traffic and daemon errors (requires
    ///                        log_normal_traffic: true in config)
    ///   all                — Both rings interleaved newest-first
    ///
    /// Filters (applied within the selected ring):
    ///   all (default) | block | alert | threat | normal | error
    Logs {
        /// Which ring to display: security | normal | all
        #[arg(long, default_value = "security")]
        ring: String,

        /// Filter by level within the ring: all | block | alert | threat | normal | error
        #[arg(short, long, default_value = "all")]
        filter: String,
    },
}

// ── Platform: socket address ──────────────────────────────────────────────────

#[cfg(unix)]
const SOCKET_ADDR: &str = "/var/run/rubix.sock";
#[cfg(windows)]
const SOCKET_ADDR: &str = "127.0.0.1:9876";

// ── Dashboard fixed frame height ──────────────────────────────────────────────

const DASHBOARD_LINES: u16 = 36;
const MAX_PROC_ROWS:   usize = 8;
const MAX_THREAT_ROWS: usize = 5;

// ── Log view fixed frame ──────────────────────────────────────────────────────
//
// The log frame ALWAYS prints exactly LOG_FRAME_LINES lines.
// Empty body rows are filled with blank padded lines.
//
// Layout:
//   1  ╔══ title ══╗
//   2  ║ RUBIX LIVE LOGS  filter: XX  ring: XX ║
//   3  ║ Ctrl+C ...  ║
//   4  ╚══════════╝
//   5  (blank)
//   6  counter bar: PACKETS / BLOCKED / ALERTS / NORMAL / PPS
//   7  (blank)
//   8  ┌─ table top ─┐
//   9  │ TIME │ LEVEL │ SRC │ DST │ PROTO │ PROCESS │ DETAIL │
//  10  ├─ divider ─┤
//  11..25  body rows  (LOG_BODY_ROWS = 15 fixed)
//  26  └─ table bottom ─┘
//  27  (blank)
//  28  status / footer line
//  29  (trailing blank — cursor never sits on content)
//
// Total = 29 lines — compile-time constant.

const LOG_BODY_ROWS:   usize = 15;
const LOG_FRAME_LINES: usize = 10 + LOG_BODY_ROWS + 4; // = 29

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
    SysCommand::new("kill").arg(pid.to_string()).status()
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
    SysCommand::new("kill").args(["-9", &pid.to_string()]).status()
        .map_err(|e| format!("kill -9 failed: {}", e))?;
    Ok(())
}

#[cfg(windows)]
fn stop_daemon() -> Result<(), String> {
    let pid = get_daemon_pid().ok_or("Daemon not running")?;
    SysCommand::new("taskkill").args(["/PID", &pid.to_string()]).status()
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
    SysCommand::new("taskkill").args(["/F", "/PID", &pid.to_string()]).status()
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
//  MONITOR — in-place TUI, fixed DASHBOARD_LINES frame
// ─────────────────────────────────────────────────────────────────────────────

async fn cmd_monitor() {
    print!("\x1B[?25l");
    let _ = io::stdout().flush();

    let mut first_frame = true;
    let quit = make_quit_flag();

    while !quit.load(std::sync::atomic::Ordering::Relaxed) {
        if !first_frame {
            // DASHBOARD_LINES is u16 — cast to usize for the escape sequence.
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
                match resp.get("live_stats")
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
//  LOGS — live in-place log view, fixed LOG_FRAME_LINES frame
// ─────────────────────────────────────────────────────────────────────────────

/// Which ring(s) to display.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RingMode {
    /// Only `recent_logs` (Block + Alert + Threat).
    Security,
    /// Only `normal_logs` (Normal + Error).
    Normal,
    /// Both rings interleaved, sorted newest-first by `time` string.
    All,
}

async fn cmd_logs(ring_str: String, filter_str: String) {
    let ring_mode: RingMode = match ring_str.to_lowercase().as_str() {
        "normal"  => RingMode::Normal,
        "all"     => RingMode::All,
        _         => RingMode::Security,
    };

    let filter: Option<LogLevel> = match filter_str.to_lowercase().as_str() {
        "block"  => Some(LogLevel::Block),
        "alert"  => Some(LogLevel::Alert),
        "threat" => Some(LogLevel::Threat),
        "normal" => Some(LogLevel::Normal),
        "error"  => Some(LogLevel::Error),
        _        => None,
    };

    print!("\x1B[?25l");
    let _ = io::stdout().flush();

    let mut first_frame = true;
    let quit = make_quit_flag();

    while !quit.load(std::sync::atomic::Ordering::Relaxed) {
        // On every frame after the first, jump cursor back exactly
        // LOG_FRAME_LINES lines — this is a compile-time constant so it
        // is always correct regardless of entry count.
        if !first_frame {
            print!("\x1B[{}A\x1B[1G", LOG_FRAME_LINES);
        }

        let snap_result = send_command(
            &serde_json::json!({"cmd": "logs"}).to_string()
        ).await;

        match snap_result {
            Err(e) => render_logs_error(&e),
            Ok(resp) => {
                match resp.get("live_stats")
                    .and_then(|v| serde_json::from_value::<LiveStats>(v.clone()).ok())
                {
                    Some(stats) => render_logs(&stats, ring_mode, filter),
                    None        => render_logs_error("Unexpected response shape from daemon"),
                }
            }
        }

        let _ = io::stdout().flush();
        first_frame = false;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    print!("\x1B[?25h");
    println!();
    let _ = io::stdout().flush();
}

// ─────────────────────────────────────────────────────────────────────────────
//  render_logs — always prints exactly LOG_FRAME_LINES (29) lines.
//
//  Strategy:
//  1. Build the candidate entry list from the selected ring(s).
//  2. Apply the level filter.
//  3. Reverse to newest-first.
//  4. Take at most LOG_BODY_ROWS entries for display.
//  5. Print exactly LOG_BODY_ROWS body rows — pad with blank lines if fewer
//     entries than rows.
//
//  Every `println!` is preceded by `\x1B[2K` (via `dln`) to erase any
//  leftover content from a previous frame that may have been wider.
// ─────────────────────────────────────────────────────────────────────────────

fn render_logs(s: &LiveStats, ring: RingMode, filter: Option<LogLevel>) {
    // ── Build entry list ──────────────────────────────────────────────────

    // Collect references from the appropriate ring(s).
    let mut entries: Vec<&LogEntry> = match ring {
        RingMode::Security => s.recent_logs.iter().collect(),
        RingMode::Normal   => s.normal_logs.iter().collect(),
        RingMode::All      => {
            let mut v: Vec<&LogEntry> = s.recent_logs.iter()
                .chain(s.normal_logs.iter())
                .collect();
            // Sort by time string descending.
            // Time is "HH:MM:SS.mmm" — lexicographic sort is correct.
            v.sort_unstable_by(|a, b| b.time.cmp(&a.time));
            v
        }
    };

    // Apply level filter.
    if let Some(f) = filter {
        entries.retain(|e| e.level == f);
    }

    // Newest-first (for Security and Normal rings which are oldest-first).
    // All ring is already sorted above.
    if ring != RingMode::All {
        entries.reverse();
    }

    let total_in_ring = entries.len();
    // Clamp to exactly LOG_BODY_ROWS for display.
    entries.truncate(LOG_BODY_ROWS);

    // ── Per-level counts for the counter bar (from raw rings, not filtered) ──
    let n_block  = s.recent_logs.iter().filter(|e| e.level == LogLevel::Block).count();
    let n_alert  = s.recent_logs.iter().filter(|e| e.level == LogLevel::Alert).count();
    let n_threat = s.recent_logs.iter().filter(|e| e.level == LogLevel::Threat).count();
    let n_normal = s.normal_logs.iter().filter(|e| e.level == LogLevel::Normal).count();
    let n_error  = s.normal_logs.iter().filter(|e| e.level == LogLevel::Error).count();

    // ── Labels ────────────────────────────────────────────────────────────
    let ring_label = match ring {
        RingMode::Security => "ring:SECURITY",
        RingMode::Normal   => "ring:NORMAL  ",
        RingMode::All      => "ring:ALL     ",
    };
    let filter_label = match filter {
        Some(LogLevel::Block)  => "BLOCK ",
        Some(LogLevel::Alert)  => "ALERT ",
        Some(LogLevel::Threat) => "THREAT",
        Some(LogLevel::Normal) => "NORMAL",
        Some(LogLevel::Error)  => "ERROR ",
        None                   => "ALL   ",
    };

    // ── Header — 10 lines ─────────────────────────────────────────────────

    // Line 1
    dln("╔══════════════════════════════════════════════════════════════════╗");
    // Line 2
    println!(
        "\x1B[2K║  \x1B[1mRUBIX LIVE LOGS\x1B[0m  \x1B[2m{}  filter:{}\x1B[0m{:>13}║",
        ring_label, filter_label, ""
    );
    // Line 3
    dln("║  Ctrl+C to exit  │  refreshing every 1 s                        ║");
    // Line 4
    dln("╚══════════════════════════════════════════════════════════════════╝");
    // Line 5 — blank
    dln("");

    // Line 6 — counter bar sourced from LiveStats lifetime counters.
    //
    //   PACKETS  = s.packet_count  — every captured packet (non-zero immediately)
    //   BLOCKED  = s.block_count   — lifetime Block policy hits
    //   ALERTS   = s.alert_count   — lifetime Alert + Threat hits
    //   NORMAL   = normal ring entries currently buffered
    //   PPS      = current capture rate
    //
    // These counters are independent of the ring filter — they always reflect
    // real daemon activity so the user can tell the daemon is alive even when
    // no security events have been generated.
    println!(
        "\x1B[2K  \x1B[1mPKTS\x1B[0m:{pkts:<8} \
         \x1B[1;31mBLK\x1B[0m:{blk:<6} \
         \x1B[1;33mALT\x1B[0m:{alt:<6} \
         \x1B[1;35mTHR\x1B[0m:{thr:<5} \
         \x1B[0;37mNRM\x1B[0m:{nrm:<5} \
         \x1B[1;91mERR\x1B[0m:{err:<4} \
         \x1B[0;36mPPS\x1B[0m:{pps:<8.0}\x1B[0m",
        pkts = s.packet_count,
        blk  = n_block,
        alt  = n_alert,
        thr  = n_threat,
        nrm  = n_normal,
        err  = n_error,
        pps  = s.pps,
    );

    // Line 7 — blank
    dln("");
    // Line 8 — table top border
    dln("┌─────────────┬────────┬──────────────────────┬──────────────────────┬───────┬──────────────────┬──────────────────────────────┐");
    // Line 9 — column headers
    println!(
        "\x1B[2K│ {:<13} │ {:<6} │ {:<20} │ {:<20} │ {:<5} │ {:<16} │ {:<28} │",
        "TIME", "LEVEL", "SRC IP:PORT", "DST IP:PORT", "PROTO", "PROCESS", "DETAIL"
    );
    // Line 10 — divider
    dln("├─────────────┼────────┼──────────────────────┼──────────────────────┼───────┼──────────────────┼──────────────────────────────┤");

    // ── Body — exactly LOG_BODY_ROWS lines (15) ───────────────────────────

    for row in 0..LOG_BODY_ROWS {
        if let Some(e) = entries.get(row) {
            // Real entry row.
            let color = e.level.ansi_color();
            let label = e.level.label();

            let src = if e.src_port == 0 {
                tpad(&e.src_ip, 20)
            } else {
                tpad(&format!("{}:{}", e.src_ip, e.src_port), 20)
            };
            let dst = if e.dst_port == 0 {
                tpad(&e.dst_ip, 20)
            } else {
                tpad(&format!("{}:{}", e.dst_ip, e.dst_port), 20)
            };

            println!(
                "\x1B[2K│ {time:<13} │ {color}{label}\x1B[0m │ {src} │ {dst} │ {proto} │ {proc} │ {detail} │",
                time   = e.time,
                color  = color,
                label  = label,
                src    = src,
                dst    = dst,
                proto  = tpad(&e.proto,    5),
                proc   = tpad(&e.process, 16),
                detail = tpad(&e.detail,  28),
            );
        } else if row == 0 && total_in_ring == 0 {
            // First empty row — show a contextual hint.
            let hint = contextual_hint(s, ring, filter);
            println!(
                "\x1B[2K│ {:<13} │ {:<6} │ {:<20} │ {:<20} │ {:<5} │ {:<16} │ \x1B[2m{:<28}\x1B[0m │",
                "", "", "", "", "", "", tpad(hint, 28)
            );
        } else {
            // Blank padding row — keeps box drawing intact and line count fixed.
            dln("│             │        │                      │                      │       │                  │                              │");
        }
    }

    // ── Footer — 4 lines ──────────────────────────────────────────────────

    // Line 26 — table bottom
    dln("└─────────────┴────────┴──────────────────────┴──────────────────────┴───────┴──────────────────┴──────────────────────────────┘");
    // Line 27 — blank
    dln("");
    // Line 28 — status
    println!(
        "\x1B[2m Showing {shown} of {total}  │  {rl}  filter:{fl}  │  \
         sec:{nb}B {na}A {nt}T  nrm:{nn}N {ne}E  │  Ctrl+C\x1B[0m",
        shown = entries.len().min(total_in_ring),
        total = total_in_ring,
        rl    = ring_label.trim(),
        fl    = filter_label.trim(),
        nb    = n_block,
        na    = n_alert,
        nt    = n_threat,
        nn    = n_normal,
        ne    = n_error,
    );
    // Line 29 — trailing blank
    dln("");
}

/// Context-aware hint for the empty-ring first row.
fn contextual_hint(s: &LiveStats, ring: RingMode, filter: Option<LogLevel>) -> &'static str {
    match ring {
        RingMode::Security => {
            if s.packet_count == 0 {
                "Waiting for first packet..."
            } else if filter.is_some() {
                "No matching events in security ring"
            } else {
                "No security events yet — traffic is flowing"
            }
        }
        RingMode::Normal => {
            if !s.normal_logging_enabled {
                "Enable: log_normal_traffic: true in config"
            } else if s.packet_count == 0 {
                "Waiting for first packet..."
            } else {
                "Normal traffic ring — waiting for sample..."
            }
        }
        RingMode::All => {
            if s.packet_count == 0 {
                "Waiting for first packet..."
            } else {
                "No events in either ring yet"
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  render_logs_error — always prints exactly LOG_FRAME_LINES lines.
// ─────────────────────────────────────────────────────────────────────────────

fn render_logs_error(msg: &str) {
    // Header (10 lines)
    dln("╔══════════════════════════════════════════════════════════════════╗");
    dln("║  RUBIX LIVE LOGS   \x1B[1;31m[OFFLINE]\x1B[0m                                    ║");
    dln("║  Ctrl+C to exit  │  refreshing every 1 s                        ║");
    dln("╚══════════════════════════════════════════════════════════════════╝");
    dln("");
    println!(
        "\x1B[2K  \x1B[1mPKTS\x1B[0m:{:<8} \x1B[1;31mBLK\x1B[0m:{:<6} \x1B[1;33mALT\x1B[0m:{:<6} \
         \x1B[1;35mTHR\x1B[0m:{:<5} \x1B[0;37mNRM\x1B[0m:{:<5} \x1B[1;91mERR\x1B[0m:{:<4} \
         \x1B[0;36mPPS\x1B[0m:{:<8}\x1B[0m",
        "--", "--", "--", "--", "--", "--", "--"
    );
    dln("");
    dln("┌─────────────┬────────┬──────────────────────┬──────────────────────┬───────┬──────────────────┬──────────────────────────────┐");
    println!(
        "\x1B[2K│ {:<13} │ {:<6} │ {:<20} │ {:<20} │ {:<5} │ {:<16} │ {:<28} │",
        "TIME", "LEVEL", "SRC IP:PORT", "DST IP:PORT", "PROTO", "PROCESS", "DETAIL"
    );
    dln("├─────────────┼────────┼──────────────────────┼──────────────────────┼───────┼──────────────────┼──────────────────────────────┤");

    // Body — exactly LOG_BODY_ROWS lines.
    // Row 0: error message.
    println!(
        "\x1B[2K│ {:<13} │ \x1B[1;31m{:<6}\x1B[0m │ {:<20} │ {:<20} │ {:<5} │ {:<16} │ {:<28} │",
        "--:--:--.---", "ERROR", SOCKET_ADDR, "", "", "", tpad(msg, 28)
    );
    // Row 1: retry hint.
    dln("│             │        │                      │                      │       │                  │ Retrying in 1 s...           │");
    // Rows 2..LOG_BODY_ROWS-1: blank padding.
    for _ in 2..LOG_BODY_ROWS {
        dln("│             │        │                      │                      │       │                  │                              │");
    }

    // Footer (4 lines)
    dln("└─────────────┴────────┴──────────────────────┴──────────────────────┴───────┴──────────────────┴──────────────────────────────┘");
    dln("");
    println!("\x1B[2m Cannot reach daemon at {}  │  Ctrl+C to exit\x1B[0m", SOCKET_ADDR);
    dln("");
}

// ─────────────────────────────────────────────────────────────────────────────
//  render_dashboard — fixed DASHBOARD_LINES (36) frame (unchanged logic)
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
    println!("\x1B[2K║  \x1B[1mRUBIX LIVE MONITOR\x1B[0m   {}                                   ║",
        status_color);
    dln("║  Ctrl+C to exit                                                  ║");
    dln("╚══════════════════════════════════════════════════════════════════╝");
    dln("");
    println!("\x1B[2K {} |{}|  {:>6.0} pps", status_plain, s.heartbeat, s.pps);
    dln("");
    dln("┌─ LIVE COUNTERS ──────────────────────────────────────────────────┐");
    println!("\x1B[2K│  Packets  : {:>10}    Rate   : {:>8.0} pps                 │",
        s.packet_count, s.pps);
    println!("\x1B[2K│  Blocked  : {:>10}    Avg    : {:>8.0} pps                 │",
        s.block_count, s.avg_pps);
    println!("\x1B[2K│  Alerts   : {:>10}    Uptime : {:>7.0} sec                 │",
        s.alert_count, s.runtime_secs);
    dln("└──────────────────────────────────────────────────────────────────┘");
    dln("");
    dln("┌─ TOP PROCESSES  (5 s window) ────────────────────────────────────┐");
    println!("\x1B[2K│ {:>5} {:<22} {:>7} {:>8} {:>5} {:>5} {:>4} {:>3} │",
        "PID", "PROCESS", "PKTS", "BYTES", "BLK", "ALT", "DST", "PRO");
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
            println!("\x1B[2K│ {:>5} {:<22} {:>7} {:>8} {} {} {:>4} {:>3} │",
                p.pid, name, p.packets, bytes_str,
                blk_str, alrt_str, p.unique_dsts, p.protocol_cnt);
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
    println!("\x1B[2m Refreshing every 1 s  │  rubix-cli monitor  │  Ctrl+C to exit\x1B[0m");
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
//  Quit flag helper
// ─────────────────────────────────────────────────────────────────────────────

fn make_quit_flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let quit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let q    = quit.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut s = signal(SignalKind::interrupt()).expect("SIGINT");
            s.recv().await;
        }
        #[cfg(windows)]
        { tokio::signal::ctrl_c().await.ok(); }
        q.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    quit
}

// ─────────────────────────────────────────────────────────────────────────────
//  Render helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Erase current line then print.  Every output line in a fixed frame MUST
/// use this so leftover content from a wider previous frame is cleared.
#[inline(always)]
fn dln(s: &str) { println!("\x1B[2K{}", s); }

/// Truncate + pad to exactly `max` chars.
/// Used for all table columns so box-drawing alignment is preserved.
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
        Commands::Logs { ring, filter } => {
            require_running();
            cmd_logs(ring, filter).await;
        }
    }
}
