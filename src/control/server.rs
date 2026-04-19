//! Control server for RUBIX

use super::{Command, CommandHandler, CommandResponse};
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, warn};
use std::sync::Arc;

pub struct ControlServer {
    socket_path: String,
    handler: Arc<CommandHandler>,
}

impl ControlServer {
    pub fn new(socket_path: String, handler: Arc<CommandHandler>) -> Self {
        Self {
            socket_path,
            handler,
        }
    }
    
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove old socket if exists
        let _ = std::fs::remove_file(&self.socket_path);
        
        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Control server listening on {}", self.socket_path);
        
        let handler = self.handler.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, handler).await {
                                error!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    handler: Arc<CommandHandler>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    
    let request = String::from_utf8_lossy(&buf[..n]);
    
    match serde_json::from_str::<Command>(&request) {
        Ok(command) => {
            let response = handler.handle(command).await;
            let response_json = serde_json::to_string(&response)?;
            stream.write_all(response_json.as_bytes()).await?;
        }
        Err(e) => {
            let error_response = CommandResponse::error(format!("Invalid command: {}", e));
            let response_json = serde_json::to_string(&error_response)?;
            stream.write_all(response_json.as_bytes()).await?;
        }
    }
    
    Ok(())
}