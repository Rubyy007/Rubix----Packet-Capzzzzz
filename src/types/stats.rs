// src/types/stats.rs
//! Shared live-stats snapshot.
//!
//! Written by the packet loop (hot path), read by the control server on demand.
//! Uses parking_lot::RwLock — already a project dependency — for minimal
//! contention: multiple CLI readers never block each other, and a writer that
//! can't immediately acquire the lock skips the update rather than stalling
//! the capture loop.

use serde::{Deserialize, Serialize};

// ── Per-process snapshot (one 5-second window) ────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcStatSnapshot {
    pub pid:          u32,
    pub name:         String,
    /// Packets seen this window.
    pub packets:      u64,
    /// Bytes seen this window.
    pub bytes:        u64,
    /// Packets blocked this window (policy hit).
    pub blocked:      u64,
    /// Alerts raised this window.
    pub alerted:      u64,
    /// Distinct destination IPs this window.
    pub unique_dsts:  usize,
    /// Distinct protocols this window.
    pub protocol_cnt: usize,
}

// ── Full live-stats snapshot ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveStats {
    // ── Lifetime totals ───────────────────────────────────────────────────────
    /// Total packets captured since startup.
    pub packet_count:  u64,
    /// Total packets blocked since startup (policy engine).
    pub block_count:   u64,
    /// Total alerts raised since startup.
    pub alert_count:   u64,

    // ── Rate metrics ──────────────────────────────────────────────────────────
    /// Packets/sec over the last measurement interval (~500 ms).
    pub pps:           f64,
    /// Average packets/sec since startup.
    pub avg_pps:       f64,
    /// Daemon uptime in seconds.
    pub runtime_secs:  f64,

    // ── Visualisation ─────────────────────────────────────────────────────────
    /// 30-character heartbeat wave string (rendered by the daemon, sent as-is).
    pub heartbeat:     String,

    // ── Per-process table ─────────────────────────────────────────────────────
    /// Top-8 processes by blocked → alerted → packets, current 5-second window.
    pub top_procs:     Vec<ProcStatSnapshot>,

    // ── Threat log ────────────────────────────────────────────────────────────
    /// Last 20 threat lines, newest last, pre-formatted by the daemon.
    /// Format: "<icon> <kind> | src=<ip> | <detail>"
    pub recent_threats: Vec<String>,
}
