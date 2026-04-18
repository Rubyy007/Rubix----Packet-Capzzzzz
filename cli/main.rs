use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(name = "rubix-cli")]
#[command(about = "RUBIX Network Blocking Engine CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Stop,
    Status,
    BlockIp { ip: String },
    UnblockIp { ip: String },
    List,
}

/// Check if rubix daemon is actually running
fn is_daemon_running() -> bool {
    Command::new("pgrep")
        .args(&["-x", "rubix"])
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false)
}

/// Kill the daemon process
fn stop_daemon() {
    let _ = Command::new("pkill")
        .args(&["-x", "rubix"])
        .output();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Start => {
            if is_daemon_running() {
                println!("RUBIX is already running");
            } else {
                println!("Starting RUBIX daemon...");
                // Start daemon in background
                let _ = Command::new("sudo")
                    .args(&["./target/release/rubix"])
                    .spawn();
            }
        }
        
        Commands::Stop => {
            if is_daemon_running() {
                println!("Stopping RUBIX daemon...");
                stop_daemon();
                // Wait a moment and verify
                std::thread::sleep(std::time::Duration::from_millis(500));
                if is_daemon_running() {
                    println!("Warning: Daemon still running (may need sudo)");
                } else {
                    println!("RUBIX stopped successfully");
                }
            } else {
                println!("RUBIX is not running");
            }
        }
        
        Commands::Status => {
            if is_daemon_running() {
                println!("RUBIX status: running");
            } else {
                println!("RUBIX status: stopped");
            }
        }
        
        Commands::BlockIp { ip } => {
            println!("Blocking IP: {}", ip);
            // TODO: Send command to daemon via Unix socket
        }
        
        Commands::UnblockIp { ip } => {
            println!("Unblocking IP: {}", ip);
            // TODO: Send command to daemon via Unix socket
        }
        
        Commands::List => {
            if is_daemon_running() {
                println!("Active blocks: (fetching from daemon...)");
                // TODO: Query daemon via Unix socket
            } else {
                println!("RUBIX is not running");
            }
        }
    }
    
    Ok(())
}