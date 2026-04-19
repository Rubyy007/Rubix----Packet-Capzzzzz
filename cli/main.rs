//! RUBIX CLI - Command line interface for RUBIX Network Blocking Engine

use clap::{Parser, Subcommand};
use std::process::{Command, Stdio};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rubix-cli")]
#[command(about = "RUBIX Network Blocking Engine CLI")]
#[command(version = "1.0.0")]
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
    Stop,
    /// Check daemon status
    Status,
    /// Block an IP address
    BlockIp { 
        /// IP address to block
        ip: String,
        /// Block duration in seconds (0 = permanent)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },
    /// Unblock an IP address
    UnblockIp { 
        /// IP address to unblock
        ip: String,
    },
    /// List active blocks
    List,
    /// Reload configuration
    Reload,
}

/// Check if rubix daemon is actually running
fn is_daemon_running() -> bool {
    Command::new("pgrep")
        .args(&["-x", "rubix"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Get daemon PID if running
fn get_daemon_pid() -> Option<u32> {
    let output = Command::new("pgrep")
        .args(&["-x", "rubix"])
        .output()
        .ok()?;
    
    if output.status.success() {
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>()
            .ok()
    } else {
        None
    }
}

/// Kill the daemon process gracefully
fn stop_daemon() -> Result<(), String> {
    if let Some(pid) = get_daemon_pid() {
        // Try graceful termination first (SIGTERM)
        let result = Command::new("kill")
            .arg(pid.to_string())
            .status();
            
        match result {
            Ok(status) if status.success() => {
                // Wait up to 3 seconds for process to terminate
                for _ in 0..30 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    if !is_daemon_running() {
                        return Ok(());
                    }
                }
                // Force kill if still running
                let _ = Command::new("kill")
                    .args(&["-9", &pid.to_string()])
                    .status();
                Ok(())
            }
            Ok(_) => Err(format!("Failed to send termination signal to PID {}", pid)),
            Err(e) => Err(format!("Failed to execute kill command: {}", e)),
        }
    } else {
        Err("Daemon not running".to_string())
    }
}

/// Start the daemon
fn start_daemon(foreground: bool) -> Result<(), String> {
    if is_daemon_running() {
        return Err("RUBIX is already running".to_string());
    }

    let binary_path = PathBuf::from("/usr/local/bin/rubix");
    let fallback_path = PathBuf::from("./target/release/rubix");
    
    let rubix_binary = if binary_path.exists() {
        binary_path
    } else if fallback_path.exists() {
        fallback_path
    } else {
        return Err("RUBIX binary not found. Install to /usr/local/bin/rubix or build with cargo build --release".to_string());
    };

    if foreground {
        println!("Starting RUBIX daemon in foreground...");
        let status = Command::new(&rubix_binary)
            .status()
            .map_err(|e| format!("Failed to start daemon: {}", e))?;
            
        if status.success() {
            Ok(())
        } else {
            Err("Daemon exited with error".to_string())
        }
    } else {
        println!("Starting RUBIX daemon in background...");
        
        // Start daemon detached (double fork via nohup)
        let child = Command::new("nohup")
            .arg(&rubix_binary)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn daemon: {}", e))?;
        
        // Give it a moment to start
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        if is_daemon_running() {
            println!("✅ RUBIX daemon started successfully (PID: {:?})", get_daemon_pid());
            Ok(())
        } else {
            Err("Daemon failed to start".to_string())
        }
    }
}

/// Send command to daemon via Unix socket
async fn send_daemon_command(command: &str) -> Result<String, String> {
    use tokio::net::UnixStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let socket_path = "/var/run/rubix.sock";
    
    match UnixStream::connect(socket_path).await {
        Ok(mut stream) => {
            stream.write_all(command.as_bytes()).await
                .map_err(|e| format!("Failed to write to socket: {}", e))?;
            stream.shutdown().await
                .map_err(|e| format!("Failed to shutdown write: {}", e))?;
            
            let mut response = String::new();
            stream.read_to_string(&mut response).await
                .map_err(|e| format!("Failed to read response: {}", e))?;
            Ok(response)
        }
        Err(e) => Err(format!("Failed to connect to daemon socket: {}. Is the daemon running?", e))
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Start { foreground } => {
            match start_daemon(foreground) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Stop => {
            match stop_daemon() {
                Ok(()) => println!("✅ RUBIX stopped successfully"),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Status => {
            if let Some(pid) = get_daemon_pid() {
                println!("✅ RUBIX is running (PID: {})", pid);
                
                // Try to get detailed status from daemon
                match send_daemon_command("STATUS").await {
                    Ok(response) => println!("{}", response),
                    Err(_) => println!("(Basic status only - daemon socket unavailable)"),
                }
            } else {
                println!("❌ RUBIX is not running");
                std::process::exit(1);
            }
        }
        
        Commands::BlockIp { ip, duration } => {
            if !is_daemon_running() {
                eprintln!("Error: RUBIX is not running. Start it with 'rubix-cli start'");
                std::process::exit(1);
            }
            
            // Validate IP format
            if ip.parse::<std::net::IpAddr>().is_err() {
                eprintln!("Error: Invalid IP address format: {}", ip);
                std::process::exit(1);
            }
            
            let cmd = if duration > 0 {
                format!("BLOCK {} {}", ip, duration)
            } else {
                format!("BLOCK {}", ip)
            };
            
            match send_daemon_command(&cmd).await {
                Ok(response) => println!("✅ {}", response),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::UnblockIp { ip } => {
            if !is_daemon_running() {
                eprintln!("Error: RUBIX is not running");
                std::process::exit(1);
            }
            
            match send_daemon_command(&format!("UNBLOCK {}", ip)).await {
                Ok(response) => println!("✅ {}", response),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::List => {
            if !is_daemon_running() {
                eprintln!("Error: RUBIX is not running");
                std::process::exit(1);
            }
            
            match send_daemon_command("LIST").await {
                Ok(response) => println!("{}", response),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Reload => {
            if !is_daemon_running() {
                eprintln!("Error: RUBIX is not running");
                std::process::exit(1);
            }
            
            match send_daemon_command("RELOAD").await {
                Ok(response) => println!("✅ {}", response),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}