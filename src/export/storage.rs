// src/export/storage.rs
//! SQLite-backed persistent event storage.
//!
//! Requires the `storage` Cargo feature (`rusqlite` optional dependency).
//!
//! Architecture:
//!   rusqlite uses blocking I/O.  All database operations are dispatched
//!   via `tokio::task::spawn_blocking` so they never block the Tokio runtime.
//!   The `Connection` is wrapped in `Arc<Mutex<Connection>>` so it can be
//!   sent across the spawn_blocking boundary safely.
//!
//! Schema:
//!   events  — unified table for all export event types (threat/block/alert).
//!   stats   — periodic metric snapshots (packet_count, block_count, etc.).
//!
//! Fixes from the original implementation:
//!   • Blocking rusqlite calls were made directly inside async functions —
//!     this stalls the Tokio runtime under load.  Fixed with spawn_blocking.
//!   • `Connection` is not Send — wrapped in Arc<std::sync::Mutex<Connection>>
//!     which is Send + Sync.
//!   • `unwrap()` on SystemTime was used — replaced with saturating arithmetic.

#[cfg(feature = "storage")]
mod inner {
    use rusqlite::{params, Connection};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tracing::{error, info};

    use crate::export::ExportEvent;

    /// Persistent SQLite event store.
    ///
    /// All async methods dispatch blocking work to `spawn_blocking`.
    pub struct StorageExport {
        /// Shared connection — Mutex makes it Send + Sync for spawn_blocking.
        conn: Arc<Mutex<Connection>>,
    }

    impl StorageExport {
        /// Open (or create) the SQLite database and initialise the schema.
        pub fn new(db_path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let conn = Connection::open(&db_path)
                .map_err(|e| format!("Cannot open SQLite at {:?}: {}", db_path, e))?;

            // WAL mode: readers don't block writers and writes don't block readers.
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

            // Unified events table — one row per ExportEvent.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp  TEXT    NOT NULL,
                    kind       TEXT    NOT NULL,
                    src_ip     TEXT    NOT NULL,
                    dst_ip     TEXT    NOT NULL,
                    src_port   INTEGER NOT NULL DEFAULT 0,
                    dst_port   INTEGER NOT NULL DEFAULT 0,
                    protocol   TEXT    NOT NULL DEFAULT '',
                    process    TEXT    NOT NULL DEFAULT 'unknown',
                    detail     TEXT    NOT NULL DEFAULT '',
                    severity   TEXT    NOT NULL DEFAULT 'MEDIUM'
                );
                CREATE INDEX IF NOT EXISTS idx_events_kind      ON events(kind);
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);",
            )?;

            // Periodic stats snapshots.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS stats (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at  TEXT    NOT NULL,
                    metric_name  TEXT    NOT NULL,
                    metric_value INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_stats_name ON stats(metric_name);",
            )?;

            info!(path = %db_path.display(), "Storage export database opened");

            Ok(Self {
                conn: Arc::new(Mutex::new(conn)),
            })
        }

        /// Persist a single ExportEvent asynchronously.
        ///
        /// Dispatches to spawn_blocking so the Tokio runtime is never stalled.
        pub async fn record_event(
            &self,
            event: ExportEvent,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let conn = self.conn.clone();
            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| format!("DB mutex poisoned: {}", e))?;
                guard.execute(
                    "INSERT INTO events
                     (timestamp, kind, src_ip, dst_ip, src_port, dst_port,
                      protocol, process, detail, severity)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        event.timestamp,
                        format!("{:?}", event.kind),
                        event.src_ip,
                        event.dst_ip,
                        event.src_port,
                        event.dst_port,
                        event.protocol,
                        event.process,
                        event.detail,
                        event.severity,
                    ],
                )
                .map_err(|e| format!("INSERT events failed: {}", e))?;
                Ok::<(), String>(())
            })
            .await
            .map_err(|e| format!("spawn_blocking join error: {}", e))??;

            Ok(())
        }

        /// Persist a batch of events in a single transaction.
        ///
        /// Much faster than one-by-one for high-volume export because SQLite
        /// amortises the fsync cost across the entire batch.
        pub async fn record_events(
            &self,
            events: Vec<ExportEvent>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if events.is_empty() { return Ok(()); }

            let conn = self.conn.clone();
            tokio::task::spawn_blocking(move || {
                let mut guard = conn.lock().map_err(|e| format!("DB mutex poisoned: {}", e))?;
                let tx = guard.transaction().map_err(|e| format!("BEGIN failed: {}", e))?;

                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO events
                         (timestamp, kind, src_ip, dst_ip, src_port, dst_port,
                          protocol, process, detail, severity)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    ).map_err(|e| format!("prepare failed: {}", e))?;

                    for event in &events {
                        stmt.execute(params![
                            event.timestamp,
                            format!("{:?}", event.kind),
                            event.src_ip,
                            event.dst_ip,
                            event.src_port,
                            event.dst_port,
                            event.protocol,
                            event.process,
                            event.detail,
                            event.severity,
                        ])
                        .map_err(|e| format!("INSERT events batch failed: {}", e))?;
                    }
                }

                tx.commit().map_err(|e| format!("COMMIT failed: {}", e))?;
                Ok::<(), String>(())
            })
            .await
            .map_err(|e| format!("spawn_blocking join error: {}", e))??;

            Ok(())
        }

        /// Record a named metric snapshot (e.g. packet_count, block_count).
        pub async fn record_stat(
            &self,
            metric_name:  &str,
            metric_value: i64,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let conn        = self.conn.clone();
            let name_owned  = metric_name.to_string();
            let recorded_at = chrono::Utc::now().to_rfc3339();

            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| format!("DB mutex poisoned: {}", e))?;
                guard.execute(
                    "INSERT INTO stats (recorded_at, metric_name, metric_value)
                     VALUES (?1, ?2, ?3)",
                    params![recorded_at, name_owned, metric_value],
                )
                .map_err(|e| format!("INSERT stats failed: {}", e))?;
                Ok::<(), String>(())
            })
            .await
            .map_err(|e| format!("spawn_blocking join error: {}", e))??;

            Ok(())
        }

        /// Query recent events of a given kind.
        pub async fn recent_events(
            &self,
            kind:  &str,
            limit: usize,
        ) -> Result<Vec<ExportEvent>, Box<dyn std::error::Error + Send + Sync>> {
            let conn       = self.conn.clone();
            let kind_owned = kind.to_string();

            let rows = tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| format!("DB mutex poisoned: {}", e))?;
                let mut stmt = guard.prepare(
                    "SELECT timestamp, kind, src_ip, dst_ip, src_port, dst_port,
                            protocol, process, detail, severity
                     FROM   events
                     WHERE  kind = ?1
                     ORDER  BY id DESC
                     LIMIT  ?2",
                ).map_err(|e| format!("prepare failed: {}", e))?;

                let rows: Vec<ExportEvent> = stmt
                    .query_map(params![kind_owned, limit as i64], |row| {
                        use crate::export::ExportKind;
                        let kind_str: String = row.get(1)?;
                        let kind = match kind_str.as_str() {
                            "Threat" => ExportKind::Threat,
                            "Block"  => ExportKind::Block,
                            _        => ExportKind::Alert,
                        };
                        Ok(ExportEvent {
                            timestamp: row.get(0)?,
                            kind,
                            src_ip:    row.get(2)?,
                            dst_ip:    row.get(3)?,
                            src_port:  row.get::<_, i64>(4)? as u16,
                            dst_port:  row.get::<_, i64>(5)? as u16,
                            protocol:  row.get(6)?,
                            process:   row.get(7)?,
                            detail:    row.get(8)?,
                            severity:  row.get(9)?,
                        })
                    })
                    .map_err(|e| format!("query_map failed: {}", e))?
                    .filter_map(|r| {
                        r.map_err(|e| { error!("Row decode error: {}", e); }).ok()
                    })
                    .collect();

                Ok::<Vec<ExportEvent>, String>(rows)
            })
            .await
            .map_err(|e| format!("spawn_blocking join error: {}", e))??;

            Ok(rows)
        }

        /// Summary statistics: event counts per kind in the last N hours.
        pub async fn summary(
            &self,
            hours: u32,
        ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
            let conn = self.conn.clone();

            let result = tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| format!("DB mutex poisoned: {}", e))?;

                let threats: i64 = guard.query_row(
                    "SELECT COUNT(*) FROM events WHERE kind='Threat' \
                     AND timestamp >= datetime('now', ?1)",
                    params![format!("-{} hours", hours)],
                    |r| r.get(0),
                ).unwrap_or(0);

                let blocks: i64 = guard.query_row(
                    "SELECT COUNT(*) FROM events WHERE kind='Block' \
                     AND timestamp >= datetime('now', ?1)",
                    params![format!("-{} hours", hours)],
                    |r| r.get(0),
                ).unwrap_or(0);

                let alerts: i64 = guard.query_row(
                    "SELECT COUNT(*) FROM events WHERE kind='Alert' \
                     AND timestamp >= datetime('now', ?1)",
                    params![format!("-{} hours", hours)],
                    |r| r.get(0),
                ).unwrap_or(0);

                Ok::<serde_json::Value, String>(serde_json::json!({
                    "window_hours": hours,
                    "threats":      threats,
                    "blocks":       blocks,
                    "alerts":       alerts,
                    "total":        threats + blocks + alerts,
                }))
            })
            .await
            .map_err(|e| format!("spawn_blocking join error: {}", e))??;

            Ok(result)
        }
    }
}

// ── Public re-export (feature-gated) ─────────────────────────────────────────

#[cfg(feature = "storage")]
pub use inner::StorageExport;

/// Stub type when the `storage` feature is not enabled.
/// Allows the rest of the codebase to compile without conditional imports.
#[cfg(not(feature = "storage"))]
pub struct StorageExport;

#[cfg(not(feature = "storage"))]
impl StorageExport {
    pub fn new(_path: std::path::PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Err("Storage feature not enabled — rebuild with --features storage".into())
    }
}