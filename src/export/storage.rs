//! Local storage for blocked IPs and events

use rusqlite::{Connection, Result};
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{info, error};

pub struct StorageExport {
    conn: Connection,
}

impl StorageExport {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY,
                ip TEXT NOT NULL,
                reason TEXT,
                blocked_at INTEGER NOT NULL,
                unblocked_at INTEGER
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                alert_type TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                message TEXT,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY,
                metric_name TEXT NOT NULL,
                metric_value INTEGER NOT NULL,
                recorded_at INTEGER NOT NULL
            )",
            [],
        )?;
        
        info!("Storage database initialized");
        Ok(Self { conn })
    }
    
    pub fn record_blocked_ip(&self, ip: &str, reason: Option<&str>) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        self.conn.execute(
            "INSERT INTO blocked_ips (ip, reason, blocked_at) VALUES (?1, ?2, ?3)",
            &[&ip, &reason.unwrap_or(""), &now],
        )?;
        
        info!("Recorded blocked IP: {}", ip);
        Ok(())
    }
    
    pub fn record_alert(&self, alert_type: &str, src_ip: &str, dst_ip: &str, message: &str) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        self.conn.execute(
            "INSERT INTO alerts (alert_type, src_ip, dst_ip, message, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[&alert_type, &src_ip, &dst_ip, &message, &now],
        )?;
        
        Ok(())
    }
    
    pub fn record_stat(&self, metric_name: &str, metric_value: i64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        self.conn.execute(
            "INSERT INTO stats (metric_name, metric_value, recorded_at) VALUES (?1, ?2, ?3)",
            &[&metric_name, &metric_value, &now],
        )?;
        
        Ok(())
    }
    
    pub fn get_blocked_ips(&self, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT ip FROM blocked_ips WHERE unblocked_at IS NULL ORDER BY blocked_at DESC LIMIT ?1")?;
        let ips = stmt.query_map(&[&limit], |row| row.get(0))?;
        
        let mut result = Vec::new();
        for ip in ips {
            result.push(ip?);
        }
        
        Ok(result)
    }
    
    pub fn get_stats_summary(&self) -> Result<serde_json::Value> {
        let total_blocks: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM blocked_ips WHERE unblocked_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        
        let total_alerts: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE created_at > strftime('%s', 'now') - 86400",
            [],
            |row| row.get(0),
        )?;
        
        Ok(serde_json::json!({
            "total_active_blocks": total_blocks,
            "alerts_last_24h": total_alerts,
        }))
    }
}