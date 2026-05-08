// src/types/stats.rs
//! Shared live-stats snapshot.
//!
//! Written by the packet loop (hot path), read by the control server on demand.
//! Uses parking_lot::RwLock — already a project dependency — for minimal
//! contention: multiple CLI readers never block each other, and a writer that
//! can't immediately acquire the lock skips the update rather than stalling
//! the capture loop.
//!
//! ── Two separate log rings ────────────────────────────────────────────────
//!
//! `recent_logs`  — security ring (Block, Alert, Threat).
//!                  Capacity: LOG_RING_CAPACITY (50).
//!                  Never populated by Allow packets.
//!                  Always meaningful; never drowned by normal traffic.
//!
//! `normal_logs`  — normal-traffic ring (Allow + app-level events).
//!                  Capacity: configurable, default 200.
//!                  Only populated when `log_normal_traffic = true` in config.
//!                  Sampled at `normal_sample_divisor` (default 1-in-100).
//!                  Separate from the security ring so high-volume normal
//!                  traffic can never evict Block/Alert/Threat entries.
//!
//! The CLI `rubix-cli logs` command receives the full LiveStats snapshot
//! (both rings) and applies its own `--ring` / `--filter` flags client-side.

use serde::{Deserialize, Serialize};

// ── Log severity / category ───────────────────────────────────────────────────

/// The event categories used by both log rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Packet explicitly blocked by a policy rule.
    Block,
    /// Packet flagged by a policy alert rule or threat detector.
    Alert,
    /// Normal traffic (allowed, no rule matched).
    /// Only written when `log_normal_traffic = true` in config.
    Normal,
    /// Threat-detector event (port scan, ping flood, etc.).
    Threat,
    /// Daemon-internal error (file I/O, resolver failure, etc.).
    /// Written to the normal ring so it is always visible even when
    /// security-ring entries are filtered out.
    Error,
}

impl LogLevel {
    /// ANSI colour prefix for CLI rendering.
    /// Reset code is always appended by the caller so column math is clean.
    #[inline]
    pub fn ansi_color(self) -> &'static str {
        match self {
            LogLevel::Block  => "\x1B[1;31m",  // bold red
            LogLevel::Alert  => "\x1B[1;33m",  // bold yellow
            LogLevel::Normal => "\x1B[0;37m",  // dim white
            LogLevel::Threat => "\x1B[1;35m",  // bold magenta
            LogLevel::Error  => "\x1B[1;91m",  // bright red
        }
    }

    /// Fixed 6-char label used in the CLI table (right-padded with spaces).
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Block  => "BLOCK ",
            LogLevel::Alert  => "ALERT ",
            LogLevel::Normal => "NORMAL",
            LogLevel::Threat => "THREAT",
            LogLevel::Error  => "ERROR ",
        }
    }

    /// True for levels that belong in the security ring.
    #[inline]
    pub fn is_security(self) -> bool {
        matches!(self, LogLevel::Block | LogLevel::Alert | LogLevel::Threat)
    }

    /// True for levels that belong in the normal/app ring.
    #[inline]
    pub fn is_normal(self) -> bool {
        matches!(self, LogLevel::Normal | LogLevel::Error)
    }
}

// ── Single structured log entry ───────────────────────────────────────────────

/// One event in either log ring buffer.
///
/// Kept flat (no nested structs) so serde_json serialises it without
/// intermediate `Value` allocations.  All strings are bounded at construction
/// time by `push_log_entry()` in main.rs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Wall-clock timestamp pre-formatted by the daemon as
    /// `HH:MM:SS.mmm` (13 chars) — no chrono work in the CLI.
    pub time:     String,

    /// Event category.
    pub level:    LogLevel,

    /// Source IP string (max 39 chars for IPv6).
    pub src_ip:   String,

    /// Destination IP string.
    pub dst_ip:   String,

    /// Source port (0 for ICMP/IGMP/Other).
    pub src_port: u16,

    /// Destination port (0 for ICMP/IGMP/Other).
    pub dst_port: u16,

    /// Protocol string: "TCP", "UDP", "ICMP", "ICMPv6", "IGMP", "PROTO(n)".
    pub proto:    String,

    /// Process name, or "unknown".  Capped at 32 chars.
    pub process:  String,

    /// Human-readable detail.  Capped at 64 chars.
    pub detail:   String,
}

// ── Per-process snapshot (one 5-second window) ────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcStatSnapshot {
    pub pid:          u32,
    pub name:         String,
    pub packets:      u64,
    pub bytes:        u64,
    pub blocked:      u64,
    pub alerted:      u64,
    pub unique_dsts:  usize,
    pub protocol_cnt: usize,
}

// ── Full live-stats snapshot ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveStats {
    // ── Lifetime totals ───────────────────────────────────────────────────────
    pub packet_count: u64,
    pub block_count:  u64,
    pub alert_count:  u64,

    // ── Rate metrics ──────────────────────────────────────────────────────────
    pub pps:          f64,
    pub avg_pps:      f64,
    pub runtime_secs: f64,

    // ── Visualisation ─────────────────────────────────────────────────────────
    pub heartbeat:    String,

    // ── Per-process table ─────────────────────────────────────────────────────
    pub top_procs:    Vec<ProcStatSnapshot>,

    // ── Threat log (monitor dashboard) ───────────────────────────────────────
    pub recent_threats: Vec<String>,

    // ── Security log ring (Block + Alert + Threat) ────────────────────────────
    //
    // Capped at LOG_RING_CAPACITY (50).  Never contains Normal/Error entries.
    // Normal traffic cannot evict security events from this ring.
    pub recent_logs: Vec<LogEntry>,

    // ── Normal / app log ring (Normal + Error) ────────────────────────────────
    //
    // Capped at NORMAL_RING_CAPACITY (200 default, config-driven).
    // Only populated when `log_normal_traffic = true` in config.
    // Entries are sampled at `normal_sample_divisor` — at 200 kpps with
    // divisor=100 this ring receives ~2 000 entries/sec but the cap keeps
    // memory bounded.  Error entries (daemon-internal) bypass sampling and
    // are always written.
    pub normal_logs: Vec<LogEntry>,

    // ── Normal-traffic logging state (read by CLI for display hints) ──────────
    /// Whether `log_normal_traffic` is enabled in the running config.
    /// The CLI uses this to show a helpful hint when the normal ring is empty.
    pub normal_logging_enabled: bool,

    /// The configured sample divisor (1 = every packet, 100 = 1%).
    pub normal_sample_divisor: u64,
}

/// Maximum entries in the security log ring (Block, Alert, Threat).
/// 50 × ~200 bytes ≈ 10 KB per snapshot clone.
pub const LOG_RING_CAPACITY: usize = 50;

/// Default maximum entries in the normal-traffic ring.
/// Overridden by `logging.normal_ring_capacity` in config.
/// 200 × ~200 bytes ≈ 40 KB per snapshot clone.
pub const DEFAULT_NORMAL_RING_CAPACITY: usize = 200;
