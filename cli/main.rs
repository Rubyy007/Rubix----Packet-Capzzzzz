// cli/main.rs
//! RUBIX CLI - Command line interface for RUBIX Network Blocking Engine

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::{Command as SysCommand, Stdio};

#[derive(Parser)]
#[command(name = "rubix")]
#[command(about = "RUBIX Network Defense Engine")]
#[command(version = "1.0.0")]
#[command(long_about = "
RUBIX Network Defense Engine CLI

Examples:
  rubix start                            Start the daemon
  rubix start --foreground               Start in foreground
  rubix stop                             Stop the daemon (graceful)
  rubix stop --force                     Force kill immediately
  rubix status                           Show daemon status and uptime
  rubix block 185.230.125.100            Block IP permanently
  rubix block 1.2.3.4 --duration 3600   Block IP for 1 hour
  rubix unblock 1.2.3.4                  Remove a block
  rubix list                             List all active blocks
  rubix rules                            List all policy rules
  rubix reload                           Reload rules from disk
  rubix monitor                          Live traffic monitor
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
        /// Force kill immediately (no shutdown summary)
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

        /// Reason for blocking (optional, stored in rule)
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

    /// Reload rules from configs/rules.yaml
    Reload,

    /// Stream live traffic events (Ctrl+C to stop)
    Monitor,
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
    let out = SysCommand::new("pgrep")
        .args(["-x", "rubix"])
        .output()
        .ok()?;
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
    let pid_str = line.split(',').nth(1)?.trim_matches('"');
    pid_str.parse().ok()
}

// ── Platform: stop daemon ─────────────────────────────────────────────────────

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
        PathBuf::from(r".\target\release\rubix.exe"),
    ];

    let binary = candidates.iter().find(|p| p.exists())
        .ok_or("RUBIX binary not found. Run: cargo build --release")?;

    if foreground {
        println!("[*] Starting RUBIX in foreground...");
        SysCommand::new(binary).status()
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

// ── IPC — send JSON command, receive JSON response ────────────────────────────

#[cfg(unix)]
async fn send_command(json: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect("/var/run/rubix.sock")
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

    let mut stream = TcpStream::connect("127.0.0.1:9876")
        .await
        .map_err(|e| format!(
            "Cannot connect to RUBIX (127.0.0.1:9876): {}. Is it running as Administrator?",
            e
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
        println!("[+] {}", message);
    } else {
        eprintln!("[!] {}", message);
    }

    // Pretty-print data block if present
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
        } else if let Some(policy_rules) = data.get("rules").and_then(|r| r.as_array()) {
            println!();
            println!("    {:<30} {:<12} {:<10} {}", "Name", "Action", "Enabled", "ID");
            println!("    {}", "-".repeat(70));
            for rule in policy_rules {
                println!(
                    "    {:<30} {:<12} {:<10} {}",
                    rule["name"].as_str().unwrap_or("-"),
                    rule["action"].as_str().unwrap_or("-"),
                    if rule["enabled"].as_bool().unwrap_or(false) { "yes" } else { "no" },
                    rule["id"].as_str().unwrap_or("-"),
                );
            }
            println!();
        }

        // Print status data
        if let Some(uptime) = data.get("uptime_human") {
            println!("    Uptime        : {}", uptime.as_str().unwrap_or("-"));
            println!("    Active blocks : {}", data["active_blocks"].as_u64().unwrap_or(0));
            println!("    Policy rules  : {}", data["policy_rules"].as_u64().unwrap_or(0));
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_running() {
    if !is_daemon_running() {
        eprintln!("[!] RUBIX is not running. Start it with: rubix start");
        std::process::exit(1);
    }
}

async fn run_command(cmd: serde_json::Value) {
    match send_command(&cmd.to_string()).await {
        Ok(resp)  => print_response(resp),
        Err(e)    => {
            eprintln!("[!] {}", e);
            std::process::exit(1);
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
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
                // Force kill immediately — no shutdown summary
                match stop_daemon_force() {
                    Ok(())  => println!("[+] RUBIX force-stopped"),
                    Err(e)  => { eprintln!("[!] {}", e); std::process::exit(1); }
                }
            } else {
                // Graceful shutdown — daemon prints summary
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

            let cmd = serde_json::json!({
                "cmd": "block_ip",
                "ip": ip,
                "duration_secs": if duration > 0 { Some(duration) } else { None },
                "reason": reason,
            });
            run_command(cmd).await;
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
            println!("[*] Connecting to RUBIX event stream (Ctrl+C to stop)...");
            println!();
            loop {
                match send_command(&serde_json::json!({"cmd": "status"}).to_string()).await {
                    Ok(resp) => {
                        let data = &resp["data"];
                        print!(
                            "\r[*] up:{} blocks:{} rules:{}          ",
                            data["uptime_human"].as_str().unwrap_or("-"),
                            data["active_blocks"].as_u64().unwrap_or(0),
                            data["policy_rules"].as_u64().unwrap_or(0),
                        );
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                    Err(e) => {
                        eprintln!("\n[!] Lost connection: {}", e);
                        break;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
}