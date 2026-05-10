// src/main.rs
//! RUBIX - Production Network Blocking Engine with Process Attribution
//!
//! ── Production fixes applied ──────────────────────────────────────────────
//!
//! FIX #1 — overflow-checks = true  (Cargo.toml)
//!   Counters use saturating_add() in the hot path.
//!
//! FIX #2 — proc_stats hard cap (MAX_PROC_ENTRIES = 512)
//!   Bounded HashMap growth; eviction on cap breach.
//!
//! FIX #3 — VecDeque for all log rings (O(1) push/pop)
//!
//! FIX #4 — blocking write() instead of try_write() in publish_stats
//!
//! FIX #5 — Zombie PID TTL eviction (PROC_TTL_SECS = 300)
//!   last_active: Instant added to ProcStats; TTL-based retain at window reset.
//!   PROC_TTL_DURATION is a const — zero runtime cost, computed at compile time.
//!
//! FIX #6 — Unbounded HashSets in ProcStats
//!   Pre-insert cap guards.  reset_window() clears sets.
//!   Lifetime unique-count scalars (total_unique_*) added so the CLI always
//!   shows meaningful values rather than near-zero window residuals.
//!
//! FIX #7 — IPv6 misclassification in is_private_ip()
//!   ::1 via v6.is_loopback(); fe80::/10 via RFC 4291 bit check.
//!   fc00::/7 (Unique Local Addresses) added — was missing, caused internal
//!   traffic to be misclassified as public.
//!
//! FIX #8 — Capture timeout warnings
//!   One-shot warning per silence period via timeout_warned: bool.
//!   Threshold raised to TIMEOUT_WARN_THRESHOLD = 3000 (~5 min of silence).
//!
//! FIX #9 — Idle wakeup rate (sleep(100µs) → sleep(IDLE_SLEEP_MS = 10ms))
//!
//! FIX #10 — get_mut() fast path in proc_stats_insert_or_get
//!   entry() cannot be used when vacant path must mutate the map before
//!   inserting (VacantEntry holds a mutable borrow of the entire map).
//!   get_mut() on fast path (one probe); entry().or_insert_with() on cold
//!   path after eviction.
//!
//! FIX #11 — Atomic ordering: Release store + Acquire load for shutdown flag
//!   Consistent Release/Acquire pairing — correct for a stop-flag on all
//!   architectures including ARM.
//!
//! FIX #12 — FxHashMap for proc_stats (u32 keys, no HashDoS risk)
//!   2-3× faster than SipHash for integer keys.
//!
//! FIX #13 — unique_dsts / protocols always near-zero in CLI
//!   Lifetime scalar counters (total_unique_*: usize) track accumulated unique
//!   counts independently of the window-scoped sets which are cleared every 5s.
//!   publish_stats() publishes the lifetime scalars, not window set sizes.
//!
//! FIX #14 — Timeout warning too aggressive / misleading
//!   One-shot warning; threshold 3000 × 100ms = ~5 min.
//!
//! FIX #15 — FxHashSet for ProcStats inner sets
//!   unique_dsts, unique_srcs, protocols switched from std::collections::HashSet
//!   (SipHash) to rustc_hash::FxHashSet.  The outer FxHashMap was already
//!   fast; the inner sets were still paying SipHash cost on every packet's
//!   cap-check insert.  FxHashSet is safe here: sets are packet-loop-private,
//!   bounded at 256 elements, and keyed by IpAddr/String — not attacker-
//!   controlled hash inputs (cap prevents HashDoS regardless).
//!
//! FIX #16 — PROC_TTL_DURATION as compile-time const
//!   Duration::from_secs(PROC_TTL_SECS) was called on every 5-second window
//!   reset.  Duration::from_secs is a const fn since Rust 1.32; hoisting it
//!   to a const eliminates the function call entirely at zero maintenance cost.
//!
//! FIX #17 — PolicyWatcher: hot-reload of rules.yaml without restart
//!   PolicyWatcher registers a kernel-level filesystem watch (inotify on Linux,
//!   ReadDirectoryChangesW on Windows) on the configs directory.  On any
//!   Modify/Create/Remove event for rules.yaml, a debounced Tokio task calls
//!   reloader.reload() after 500ms of silence — one save = one reload.
//!   Failure is non-fatal: RUBIX continues with the previous rule set active.
//!
//! ── Config path resolution ────────────────────────────────────────────────
//!
//! Search order (stops at first hit):
//!   1. <exe_dir>/configs/
//!   2. <exe_dir>/../configs/   (target\release\ → project root)
//!   3. <exe_dir>/../../configs/
//!   4. ./configs/              (CWD fallback)

mod types;
mod capture;
mod policy;
mod config;
mod blocker;
mod logger;
mod control;
mod resolver;
mod detector;

use detector::{ScanDetector, PingDetector, ThreatTracker, ThreatEvent};
use policy::{PolicyEngine, PolicyReloader, PolicyWatcher, RuleAction};
use config::loader::ConfigLoader;
use blocker::{PlatformBlocker, Blocker};
use capture::{CaptureConfig, CaptureFactory};
use capture::filter::FilterBuilder;
use logger::AlertLogger;
use control::{CommandHandler, ControlServer};
use resolver::{ProcessResolver, FlowKey, Protocol};
use types::stats::{
    LiveStats, LogEntry, LogLevel,
    ProcStatSnapshot, LOG_RING_CAPACITY,
};

use parking_lot::RwLock;
use rustc_hash::{FxHashMap, FxHashSet};   // FIX #12 + FIX #15
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::IpAddr;
use std::path::PathBuf;
use std::collections::VecDeque;
use std::time::Instant;
use tokio::time::{Duration, timeout, sleep};
use tracing::{info, warn, error};

// ── Platform constants ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
const OS_NAME: &str = "linux";
#[cfg(target_os = "windows")]
const OS_NAME: &str = "windows";

// ── FIX #2: hard cap on per-process stat entries ──────────────────────────────
const MAX_PROC_ENTRIES: usize = 512;

// ── FIX #6: hard caps on per-process set sizes ───────────────────────────────
const MAX_UNIQUE_DSTS:      usize = 256;
const MAX_UNIQUE_SRCS:      usize = 256;
const MAX_UNIQUE_PROTOCOLS: usize = 16;

// ── FIX #5 + FIX #16: TTL for zombie PID eviction ────────────────────────────
//
// PROC_TTL_DURATION is a compile-time const — Duration::from_secs is a
// const fn since Rust 1.32.  The previous code called Duration::from_secs()
// inside the window-reset block (every 5 seconds); this eliminates that call
// entirely.  No lazy_static or once_cell needed.
const PROC_TTL_SECS:     u64      = 300;
const PROC_TTL_DURATION: Duration = Duration::from_secs(PROC_TTL_SECS);

// ── FIX #9: idle sleep duration ──────────────────────────────────────────────
const IDLE_SLEEP_MS: u64 = 10;

// ── FIX #14: capture silence warning threshold ────────────────────────────────
//
// 3000 × 100ms = 300 seconds (~5 minutes) before the one-shot warning fires.
const TIMEOUT_WARN_THRESHOLD: u32 = 3000;

// ── Per-process statistics (packet-loop-private) ──────────────────────────────

#[derive(Clone)]
struct ProcStats {
    name:    String,

    // ── Window-scoped counters (reset every 5 seconds) ────────────────────
    packets: u64,
    bytes:   u64,
    blocked: u64,
    alerted: u64,

    // ── Window-scoped bounded sets (cleared every 5 seconds — FIX #6) ─────
    //
    // FIX #15: switched from std::collections::HashSet (SipHash) to
    // FxHashSet (identity/FNV-based).  These sets are:
    //   • packet-loop-private — no concurrent access, no lock contention
    //   • bounded at MAX_UNIQUE_* — cap prevents HashDoS regardless of hasher
    //   • keyed by IpAddr (4 or 16 bytes) and short protocol strings —
    //     not attacker-controlled hash inputs in the HashDoS sense
    //
    // FxHashSet is safe here and saves SipHash mixing cost on every insert
    // and the len() cap check that precedes it.
    //
    // These sets are NOT read by publish_stats() — the CLI receives the
    // total_unique_* lifetime scalars instead (FIX #13).
    unique_dsts: FxHashSet<IpAddr>,
    unique_srcs: FxHashSet<IpAddr>,
    protocols:   FxHashSet<String>,

    // ── Lifetime totals (never reset) ────────────────────────────────────
    total_packets: u64,
    total_blocked: u64,
    total_alerted: u64,

    // FIX #13: lifetime unique-count scalars.
    //
    // Incremented once per successful insert into the corresponding window set
    // (HashSet::insert returns true only when the value was not already present).
    // Never reset.  Published to ProcStatSnapshot.unique_dsts / protocol_cnt
    // so the CLI always shows accumulated values rather than the near-zero
    // residuals left in the window sets after each 5-second reset.
    //
    // Type is usize to match ProcStatSnapshot.unique_dsts / protocol_cnt —
    // changing to u64 would require changing those fields too, which touches
    // the CLI serialisation layer.  usize::MAX on 32-bit (~4 billion unique
    // destinations per PID) is unreachable in practice.
    total_unique_dsts:      usize,
    total_unique_srcs:      usize,
    total_unique_protocols: usize,

    // FIX #5: wall-clock timestamp of the last packet that touched this entry.
    last_active: Instant,
}

impl ProcStats {
    #[inline]
    fn new(name: String) -> Self {
        Self {
            name,
            packets:  0,
            bytes:    0,
            blocked:  0,
            alerted:  0,
            // FIX #15: FxHashSet — with_capacity_and_hasher not needed;
            // FxHashSet::default() uses the Fx hasher automatically.
            unique_dsts: FxHashSet::default(),
            unique_srcs: FxHashSet::default(),
            protocols:   FxHashSet::default(),
            total_packets:          0,
            total_blocked:          0,
            total_alerted:          0,
            total_unique_dsts:      0,
            total_unique_srcs:      0,
            total_unique_protocols: 0,
            last_active: Instant::now(),
        }
    }

    // FIX #6: clears window-scoped sets — prevents unbounded accumulation.
    // FIX #13: total_unique_* scalars NOT touched — lifetime counters.
    // FIX #5:  last_active NOT reset — TTL eviction depends on real timestamp.
    #[inline]
    fn reset_window(&mut self) {
        self.packets = 0;
        self.bytes   = 0;
        self.blocked = 0;
        self.alerted = 0;
        // clear() retains allocated capacity — next window's inserts do not
        // reallocate unless they exceed the previous high-water mark.
        self.unique_dsts.clear();
        self.unique_srcs.clear();
        self.protocols.clear();
    }
}

// ── FIX #10: proc_stats insertion — get_mut() fast path ──────────────────────
//
// See FIX #10 header comment above for the full borrow-checker explanation of
// why entry() alone cannot be used here.
//
// Phase 1 (fast path — dominates at steady state):
//   contains_key() + get_mut() — 2 probes, borrow ends on return.
//
// Phase 2 (cold path — fires exactly once per PID lifetime):
//   map borrow ended; retain() and len() are freely callable.
//   entry().or_insert_with() — 1 probe for the actual insert.
#[inline]
fn proc_stats_insert_or_get<'a>(
    map:  &'a mut FxHashMap<u32, ProcStats>,
    pid:  u32,
    name: &str,
    now:  Instant,
) -> Option<&'a mut ProcStats> {
    // ── Phase 1: fast path ────────────────────────────────────────────────
    if map.contains_key(&pid) {
        return map.get_mut(&pid);
    }

    // ── Phase 2: cold path — new PID ─────────────────────────────────────

    if map.len() >= MAX_PROC_ENTRIES {
        // FIX #5: evict PIDs silent for > PROC_TTL_DURATION (const — FIX #16).
        map.retain(|_, s| now.duration_since(s.last_active) <= PROC_TTL_DURATION);
    }

    if map.len() >= MAX_PROC_ENTRIES {
        // Second pass: evict zero-lifetime-activity entries.
        map.retain(|_, s| {
            s.total_packets > 0 || s.total_blocked > 0 || s.total_alerted > 0
        });
    }

    // Hard full: drop attribution for this PID rather than exceed the cap.
    if map.len() >= MAX_PROC_ENTRIES {
        warn!(
            pid = pid,
            max = MAX_PROC_ENTRIES,
            "proc_stats map full — dropping attribution for PID"
        );
        return None;
    }

    Some(
        map.entry(pid)
            .or_insert_with(|| ProcStats::new(name.to_string()))
    )
}

// ── Heartbeat wave ────────────────────────────────────────────────────────────

struct Heartbeat {
    samples:  VecDeque<f64>,
    capacity: usize,
}

impl Heartbeat {
    fn new(capacity: usize) -> Self {
        Self { samples: VecDeque::with_capacity(capacity), capacity }
    }

    #[inline]
    fn push(&mut self, pps: f64) {
        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(pps);
    }

    fn render(&self) -> String {
        let padding = self.capacity.saturating_sub(self.samples.len());
        let pad_str = "_".repeat(padding);

        if self.samples.is_empty() {
            return pad_str;
        }

        let max  = self.samples.iter().cloned().fold(1.0_f64, f64::max);
        let bars = ['_', '.', '-', '^', '|'];

        let wave: String = self.samples.iter().map(|&v| {
            let ratio = (v / max).clamp(0.0, 1.0);
            let idx   = (ratio * (bars.len() - 1) as f64).round() as usize;
            bars[idx]
        }).collect();

        format!("{}{}", pad_str, wave)
    }
}

// ── Graceful shutdown signal ──────────────────────────────────────────────────

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint  = signal(SignalKind::interrupt()).expect("SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM");
        tokio::select! {
            _ = sigint.recv()  => println!("\n[!] Shutdown signal received (Ctrl+C / SIGINT)..."),
            _ = sigterm.recv() => println!("\n[!] Shutdown signal received (SIGTERM)..."),
        }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await.expect("Ctrl+C");
        println!("\n[!] Shutdown signal received (Ctrl+C)...");
    }
}

// ── Config directory resolution ───────────────────────────────────────────────

fn resolve_configs_dir() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let candidates = [
                exe_dir.to_path_buf(),
                exe_dir.join(".."),
                exe_dir.join("../.."),
            ];
            for base in &candidates {
                let candidate = base.join("configs");
                if let Ok(resolved) = candidate.canonicalize() {
                    if resolved.is_dir() {
                        return resolved;
                    }
                }
            }
        }
    }
    PathBuf::from("configs")
}

// ── Extract pre-block IPs from rules.yaml ─────────────────────────────────────

fn extract_malicious_ips_from_rules(configs_dir: &std::path::Path) -> Vec<String> {
    let rules_path = configs_dir.join("rules.yaml");
    let mut ips    = Vec::new();

    if let Ok(contents) = std::fs::read_to_string(&rules_path) {
        if let Ok(rules) = serde_yaml::from_str::<Vec<serde_yaml::Value>>(&contents) {
            for rule in rules {
                let enabled = rule.get("enabled")
                    .and_then(|e| e.as_bool())
                    .unwrap_or(true);
                if !enabled { continue; }

                if let Some("Block") = rule.get("action").and_then(|a| a.as_str()) {
                    if let Some(dst_ips) = rule
                        .get("conditions")
                        .and_then(|c| c.get("dst_ips"))
                        .and_then(|i| i.as_sequence())
                    {
                        for ip in dst_ips {
                            if let Some(s) = ip.as_str() {
                                if !s.contains('/') && s != "0.0.0.0" && s != "255.255.255.255" {
                                    ips.push(s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ips
}

// ── BPF filter ────────────────────────────────────────────────────────────────

fn build_bpf_filter(
    config_filter: &Option<String>,
    malicious_ips: &[String],
) -> Option<String> {
    if let Some(f) = config_filter {
        match capture::filter::validate_filter(f) {
            Ok(()) => {
                info!(filter = %f, "Using config-provided BPF filter");
                return Some(f.clone());
            }
            Err(e) => warn!("Config BPF filter invalid: {} — falling back to auto-built", e),
        }
    }

    let filter = FilterBuilder::from_block_list(malicious_ips, &[])
        .unwrap_or_else(FilterBuilder::default_filter);

    info!(filter = %filter, "Using auto-built BPF filter");
    Some(filter)
}

// ── Startup banner ────────────────────────────────────────────────────────────

pub async fn print_banner(
    config:          &config::RubixConfig,
    rules_count:     usize,
    kernel_rules:    usize,
    interface:       &str,
    interface_label: &str,
    bpf_filter:      &str,
    malicious_ips:   &[String],
    configs_dir:     &std::path::Path,
) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                                                              ║");
    println!("║   ██████  ██    ██ ██████  ██ ██   ██                        ║");
    println!("║   ██   ██ ██    ██ ██   ██ ██  ██ ██                         ║");
    println!("║   ██████  ██    ██ ██████  ██   ███                          ║");
    println!("║   ██   ██ ██    ██ ██   ██ ██  ██ ██                         ║");
    println!("║   ██   ██  ██████  ██████  ██ ██   ██                        ║");
    println!("║                                                              ║");
    println!("║              RUBIX by Uniq                                   ║");
    println!("║          Network Defense Engine v1.0.0                       ║");
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    sleep(Duration::from_millis(300)).await;

    println!("┌─ SYSTEM CONFIG ──────────────────────────────────────────────┐");
    sleep(Duration::from_millis(120)).await;
    println!("│ Mode           : {:<43} │", config.mode);
    sleep(Duration::from_millis(120)).await;
    println!("│ Interface      : {:<43} │", interface_label);
    sleep(Duration::from_millis(120)).await;
    println!("│ Promiscuous    : {:<43} │",
        if config.promiscuous { "ENABLED" } else { "DISABLED" });
    sleep(Duration::from_millis(120)).await;
    let filter_display = if bpf_filter.len() > 43 {
        format!("{}...", &bpf_filter[..40])
    } else {
        bpf_filter.to_string()
    };
    println!("│ BPF Filter     : {:<43} │", filter_display);
    sleep(Duration::from_millis(120)).await;
    println!("│ Buffer Size    : {:<43} │", format!("{} MB", config.buffer_size_mb));
    sleep(Duration::from_millis(120)).await;
    println!("│ Platform       : {:<43} │", OS_NAME.to_uppercase());
    sleep(Duration::from_millis(120)).await;
    #[cfg(unix)]
    println!("│ Control Socket : {:<43} │", "/var/run/rubix.sock");
    #[cfg(windows)]
    println!("│ Control Socket : {:<43} │", "127.0.0.1:9876");
    sleep(Duration::from_millis(120)).await;
    let configs_display = configs_dir.display().to_string();
    let configs_display = if configs_display.len() > 43 {
        format!("...{}", &configs_display[configs_display.len().saturating_sub(40)..])
    } else {
        configs_display
    };
    println!("│ Configs Dir    : {:<43} │", configs_display);
    sleep(Duration::from_millis(120)).await;
    println!("│ Normal Logging : {:<43} │",
        if config.logging.log_normal_traffic {
            format!("ENABLED (1-in-{} sampling)", config.logging.normal_sample_divisor)
        } else {
            "DISABLED (set log_normal_traffic: true to enable)".to_string()
        });
    println!("│ Hot Reload     : {:<43} │", "ENABLED (rules.yaml)");
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(250)).await;

    println!("┌─ SECURITY STATUS ────────────────────────────────────────────┐");
    sleep(Duration::from_millis(120)).await;
    println!("│ Policy Rules    : {:<41} │", rules_count);
    sleep(Duration::from_millis(120)).await;
    println!("│ Kernel Rules    : {:<41} │", kernel_rules);
    sleep(Duration::from_millis(120)).await;
    println!("│ Default Action  : {:<41} │",
        config.blocking.default_action.to_uppercase());
    sleep(Duration::from_millis(120)).await;
    println!("│ Auto Cleanup    : {:<41} │",
        if config.blocking.auto_cleanup { "ENABLED" } else { "DISABLED" });
    sleep(Duration::from_millis(120)).await;
    println!("│ Block Timeout   : {:<41} │",
        format!("{} sec", config.blocking.block_timeout_seconds));
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(250)).await;

    if !malicious_ips.is_empty() {
        println!("┌─ ACTIVE THREATS ─────────────────────────────────────────────┐");
        sleep(Duration::from_millis(150)).await;
        println!("│ [!] {} IPs pre-blocked at kernel level{:>23} │",
            malicious_ips.len(), "");
        for ip in malicious_ips.iter().take(5) {
            sleep(Duration::from_millis(80)).await;
            println!("│   + {:<57} │", ip);
        }
        if malicious_ips.len() > 5 {
            sleep(Duration::from_millis(80)).await;
            println!("│   ... and {} more{:>39} │", malicious_ips.len() - 5, "");
        }
        println!("└──────────────────────────────────────────────────────────────┘");
        println!();
    }

    sleep(Duration::from_millis(250)).await;

    println!("┌─ NETWORK INTERFACES ─────────────────────────────────────────┐");
    match CaptureFactory::list_interfaces() {
        Ok(interfaces) => {
            for iface in interfaces.iter().take(10) {
                let is_active    = iface.name == interface;
                let status       = if is_active { "(*) ACTIVE" } else { "( ) IDLE  " };
                let display_name = iface.description.as_deref().unwrap_or(&iface.name);
                let display_name = if display_name.len() > 28 {
                    format!("{}...", &display_name[..25])
                } else {
                    display_name.to_string()
                };
                sleep(Duration::from_millis(80)).await;
                println!("│ {:<10} {:<28} {:<20} │",
                    status, display_name, format!("{} addrs", iface.addresses.len()));
            }
        }
        Err(e) => println!("│ [!] {:<56} │", format!("Interface error: {}", e)),
    }
    println!("└──────────────────────────────────────────────────────────────┘");
    println!();

    sleep(Duration::from_millis(200)).await;

    println!("[*] RUBIX ACTIVE — monitoring on {} (Ctrl+C to stop)", interface_label);
    println!("[*] Run 'rubix-cli monitor' in another terminal for live stats");
    println!("[*] Run 'rubix-cli logs' in another terminal for live log stream");
    println!("[*] Run 'rubix-cli logs normal' for normal traffic log");
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline(always)]
fn is_ingress_packet(src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    dst_ip.is_loopback() || (is_private_ip(dst_ip) && !is_private_ip(src_ip))
}

// FIX #7: IPv6 private IP check — all three RFC ranges covered.
//
//   ::1          → v6.is_loopback()              (std, always correct)
//   fe80::/10    → RFC 4291 §2.5.6 link-local    (o[0]==0xfe, o[1]&0xc0==0x80)
//   fc00::/7     → RFC 4193 unique local (ULA)   (o[0]&0xfe==0xfc)
//                  Covers both fc00::/8 and fd00::/8.
//                  Was missing before — ULA addresses were misclassified as
//                  public, causing internal traffic to bypass ingress checks.
#[inline(always)]
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() { return true; }
            let o = v6.octets();
            // fe80::/10 — link-local
            let is_link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
            // fc00::/7  — unique local (ULA): fc00::/8 and fd00::/8
            let is_ula        = (o[0] & 0xfe) == 0xfc;
            is_link_local || is_ula
        }
    }
}

// ── FIX #3: Security log ring — VecDeque, O(1) push/pop ──────────────────────

#[inline]
fn push_log_entry(
    recent_logs: &mut VecDeque<LogEntry>,
    level:       LogLevel,
    src_ip:      &str,
    dst_ip:      &str,
    src_port:    u16,
    dst_port:    u16,
    proto:       &str,
    process:     &str,
    detail:      &str,
) {
    let time = chrono::Local::now().format("%H:%M:%S%.3f").to_string();

    let process: String = if process.len() > 32 {
        process.chars().take(32).collect()
    } else {
        process.to_string()
    };
    let detail: String = if detail.len() > 64 {
        detail.chars().take(64).collect()
    } else {
        detail.to_string()
    };

    let entry = LogEntry {
        time, level,
        src_ip:   src_ip.to_string(),
        dst_ip:   dst_ip.to_string(),
        src_port, dst_port,
        proto:    proto.to_string(),
        process,  detail,
    };

    if recent_logs.len() >= LOG_RING_CAPACITY {
        recent_logs.pop_front();
    }
    recent_logs.push_back(entry);
}

// ── FIX #3: Normal log ring — VecDeque, O(1) push/pop ────────────────────────

#[inline]
fn push_normal_entry(
    normal_logs:          &mut VecDeque<LogEntry>,
    normal_ring_capacity: usize,
    level:                LogLevel,
    src_ip:               &str,
    dst_ip:               &str,
    src_port:             u16,
    dst_port:             u16,
    proto:                &str,
    process:              &str,
    detail:               &str,
) {
    let time = chrono::Local::now().format("%H:%M:%S%.3f").to_string();

    let process: String = if process.len() > 32 {
        process.chars().take(32).collect()
    } else {
        process.to_string()
    };
    let detail: String = if detail.len() > 64 {
        detail.chars().take(64).collect()
    } else {
        detail.to_string()
    };

    let entry = LogEntry {
        time, level,
        src_ip:   src_ip.to_string(),
        dst_ip:   dst_ip.to_string(),
        src_port, dst_port,
        proto:    proto.to_string(),
        process,  detail,
    };

    if normal_logs.len() >= normal_ring_capacity {
        normal_logs.pop_front();
    }
    normal_logs.push_back(entry);
}

// ── FIX #4: Stats publisher — blocking write() ────────────────────────────────

#[inline]
#[allow(clippy::too_many_arguments)]
fn publish_stats(
    shared:                 &Arc<RwLock<LiveStats>>,
    packet_count:           u64,
    block_count:            u64,
    alert_count:            u64,
    pps:                    f64,
    avg_pps:                f64,
    runtime_secs:           f64,
    wave:                   String,
    proc_stats:             &FxHashMap<u32, ProcStats>,
    recent_threats:         &VecDeque<String>,
    recent_logs:            &VecDeque<LogEntry>,
    normal_logs:            &VecDeque<LogEntry>,
    normal_logging_enabled: bool,
    normal_sample_divisor:  u64,
) {
    let mut top: Vec<ProcStatSnapshot> = proc_stats
        .iter()
        .filter(|(_, s)| s.total_packets > 0 || s.total_blocked > 0 || s.total_alerted > 0)
        .map(|(&pid, s)| ProcStatSnapshot {
            pid,
            name:         s.name.clone(),
            packets:      s.packets,
            bytes:        s.bytes,
            blocked:      s.blocked,
            alerted:      s.alerted,
            // FIX #13: lifetime scalars — never near-zero after window reset.
            unique_dsts:  s.total_unique_dsts,
            protocol_cnt: s.total_unique_protocols,
        })
        .collect();

    top.sort_unstable_by(|a, b| {
        b.blocked.cmp(&a.blocked)
            .then_with(|| b.alerted.cmp(&a.alerted))
            .then_with(|| b.packets.cmp(&a.packets))
    });
    top.truncate(8);

    let threats: Vec<String>      = recent_threats.iter().cloned().collect();
    let recent_vec: Vec<LogEntry> = recent_logs.iter().cloned().collect();
    let normal_vec: Vec<LogEntry> = normal_logs.iter().cloned().collect();

    let mut guard = shared.write();
    guard.packet_count           = packet_count;
    guard.block_count            = block_count;
    guard.alert_count            = alert_count;
    guard.pps                    = pps;
    guard.avg_pps                = avg_pps;
    guard.runtime_secs           = runtime_secs;
    guard.heartbeat              = wave;
    guard.top_procs              = top;
    guard.recent_threats         = threats;
    guard.recent_logs            = recent_vec;
    guard.normal_logs            = normal_vec;
    guard.normal_logging_enabled = normal_logging_enabled;
    guard.normal_sample_divisor  = normal_sample_divisor;
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _logger = logger::Logger::init_dual()?;
    _logger.start_cleanup_task();

    let start_time = Instant::now();

    let configs_dir   = resolve_configs_dir();
    info!(path = %configs_dir.display(), "Using configs directory");

    let config_loader = ConfigLoader::load(&configs_dir, OS_NAME)?;
    let config        = config_loader.get();

    AlertLogger::init_with_config(
        config.logging.normal_channel_depth,
        config.logging.max_file_size_mb,
    )?;

    let log_normal:            bool  = config.logging.log_normal_traffic;
    let normal_sample_divisor: u64   = config.logging.normal_sample_divisor.max(1);
    let normal_ring_capacity:  usize = config.logging.normal_ring_capacity
        .max(1)
        .min(2048);

    let policy_engine = Arc::new(PolicyEngine::new());
    let rules_yaml    = configs_dir.join("rules.yaml").to_string_lossy().into_owned();
    let reloader      = Arc::new(PolicyReloader::new(policy_engine.clone(), rules_yaml));
    let _             = reloader.load_initial();
    let rules_count   = policy_engine.rule_count();

    // ── FIX #17: hot-reload watcher ──────────────────────────────────────────
    //
    // Must be started AFTER load_initial() so the first rule load is
    // synchronous and complete before the packet loop begins.  The watcher
    // runs as a detached Tokio background task for the process lifetime.
    //
    // Non-fatal: if the OS watch registration fails (e.g. inotify limit
    // reached, permission denied on configs dir), RUBIX continues normally.
    // The operator must restart to pick up rule changes in that case.
    let rules_yaml_path = configs_dir.join("rules.yaml");
    match PolicyWatcher::new(&rules_yaml_path, reloader.clone()).start() {
        Ok(()) => info!(
            path = %rules_yaml_path.display(),
            "Policy hot-reload active — edit rules.yaml to apply changes live"
        ),
        Err(e) => warn!(
            error = %e,
            path  = %rules_yaml_path.display(),
            "Policy file watcher failed to start — rule changes require restart"
        ),
    }

    let blocker       = Arc::new(PlatformBlocker::new());
    let malicious_ips = extract_malicious_ips_from_rules(&configs_dir);

    let mut kernel_rules = 0usize;
    for ip_str in &malicious_ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match blocker.block_ip(ip).await {
                Ok(_)  => { kernel_rules += 1; info!(ip = %ip_str, "Kernel block rule installed"); }
                Err(e) => error!(ip = %ip_str, error = %e, "Failed to install kernel block rule"),
            }
        } else {
            warn!(ip = %ip_str, "Skipping invalid IP in rules.yaml");
        }
    }

    let resolver = Arc::new(ProcessResolver::new());
    info!("Process resolver initialized");

    let interface_name = if config.capture_interface == "auto" {
        match CaptureFactory::auto_select_interface() {
            Some(iface) => { info!(interface = %iface, "Auto-selected network interface"); iface }
            None => {
                error!("Could not auto-detect a suitable network interface");
                error!("Set capture_interface manually in configs/rubix.{}.yaml", OS_NAME);
                std::process::exit(1);
            }
        }
    } else {
        info!(interface = %config.capture_interface, "Using manually configured interface");
        config.capture_interface.clone()
    };

    let interface_label = CaptureFactory::list_interfaces()
        .ok()
        .and_then(|ifaces| ifaces.into_iter()
            .find(|i| i.name == interface_name)
            .map(|i| i.description.unwrap_or_else(|| i.name.clone())))
        .unwrap_or_else(|| interface_name.clone());

    let bpf_filter         = build_bpf_filter(&config.bpf_filter, &malicious_ips);
    let bpf_filter_display = bpf_filter.as_deref().unwrap_or("none").to_string();

    print_banner(
        &config, rules_count, kernel_rules,
        &interface_name, &interface_label,
        &bpf_filter_display, &malicious_ips,
        &configs_dir,
    ).await;

    let shared_stats: Arc<RwLock<LiveStats>> = Arc::new(RwLock::new(LiveStats::default()));

    let capture_config = CaptureConfig {
        interface:      interface_name.clone(),
        promiscuous:    config.promiscuous,
        buffer_size_mb: config.buffer_size_mb as usize,
        timeout_ms:     config.timeout_ms as i32,
        snaplen:        config.snaplen as i32,
        bpf_filter,
    };
    let mut capture = CaptureFactory::create(capture_config)?;
    capture.start().await?;

    let ctrl_handler = Arc::new(CommandHandler::new(
        blocker.clone(),
        policy_engine.clone(),
        reloader.clone(),
        start_time,
        shared_stats.clone(),
    ));
    let ctrl_server = ControlServer::new(ctrl_handler);
    ctrl_server.start().await;
    info!("Control server started — CLI commands are active");

    // FIX #11: Release/Acquire pairing for the shutdown stop-flag.
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        tokio::spawn(async move {
            wait_for_shutdown().await;
            r.store(false, Ordering::Release);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  PACKET LOOP
    // ─────────────────────────────────────────────────────────────────────────

    let mut packet_count:      u64 = 0;
    let mut block_count:       u64 = 0;
    let mut alert_count:       u64 = 0;
    let mut last_stats_time        = start_time;
    let mut last_packet_count: u64 = 0;
    let mut last_window_reset      = start_time;
    let mut normal_sample_counter: u64 = 0;

    // FIX #14: one-shot timeout warning state.
    let mut consecutive_timeouts: u32  = 0;
    let mut timeout_warned:       bool = false;

    let mut heartbeat  = Heartbeat::new(30);
    // FIX #12: FxHashMap; FIX #15: values contain FxHashSet fields.
    let mut proc_stats: FxHashMap<u32, ProcStats> = FxHashMap::default();
    proc_stats.reserve(128);
    let mut threat_tracker = ThreatTracker::new();

    let mut recent_threats: VecDeque<String>   = VecDeque::with_capacity(20);
    let mut recent_logs:    VecDeque<LogEntry> = VecDeque::with_capacity(LOG_RING_CAPACITY);
    let mut normal_logs:    VecDeque<LogEntry> = VecDeque::with_capacity(normal_ring_capacity);

    while running.load(Ordering::Acquire) {   // FIX #11

        match timeout(Duration::from_millis(100), capture.next_packet()).await {

            Ok(Some(packet)) => {
                // FIX #14: rearm warning on traffic.
                consecutive_timeouts = 0;
                timeout_warned       = false;

                packet_count = packet_count.saturating_add(1);

                let proto = Protocol::from_str(&packet.protocol.to_string());

                let proc_info = resolver.lookup(&FlowKey {
                    local_ip:   packet.src_ip,
                    local_port: packet.src_port,
                    protocol:   proto,
                }).or_else(|| resolver.lookup(&FlowKey {
                    local_ip:   packet.dst_ip,
                    local_port: packet.dst_port,
                    protocol:   proto,
                }));

                let now_instant = Instant::now();
                if let Some(ref info) = proc_info {
                    if let Some(entry) = proc_stats_insert_or_get(
                        &mut proc_stats, info.pid, &info.name, now_instant,
                    ) {
                        if entry.name.is_empty() {
                            entry.name.clone_from(&info.name);
                        }
                        entry.packets       = entry.packets.saturating_add(1);
                        entry.bytes         = entry.bytes.saturating_add(packet.size as u64);
                        entry.total_packets = entry.total_packets.saturating_add(1);
                        entry.last_active   = now_instant;

                        // FIX #6: capped inserts.
                        // FIX #13: increment lifetime scalar on each genuinely new insert.
                        // FIX #15: FxHashSet — insert() return value semantics unchanged.
                        if entry.unique_dsts.len() < MAX_UNIQUE_DSTS {
                            if entry.unique_dsts.insert(packet.dst_ip) {
                                entry.total_unique_dsts =
                                    entry.total_unique_dsts.saturating_add(1);
                            }
                        }
                        if entry.unique_srcs.len() < MAX_UNIQUE_SRCS {
                            if entry.unique_srcs.insert(packet.src_ip) {
                                entry.total_unique_srcs =
                                    entry.total_unique_srcs.saturating_add(1);
                            }
                        }
                        if entry.protocols.len() < MAX_UNIQUE_PROTOCOLS {
                            if entry.protocols.insert(packet.protocol.to_string()) {
                                entry.total_unique_protocols =
                                    entry.total_unique_protocols.saturating_add(1);
                            }
                        }
                    }
                }

                let proc_name  = proc_info.as_ref().map(|p| p.name.as_str());
                let is_ingress = is_ingress_packet(packet.src_ip, packet.dst_ip);

                let threat: Option<ThreatEvent> = match packet.protocol {
                    crate::types::Protocol::Tcp => ScanDetector::analyze_tcp(
                        &mut threat_tracker, packet.src_ip, packet.dst_port,
                        &packet.flags, proc_name, is_ingress,
                    ),
                    crate::types::Protocol::Udp => ScanDetector::analyze_udp(
                        &mut threat_tracker, packet.src_ip, packet.dst_port,
                        proc_name, is_ingress,
                    ),
                    crate::types::Protocol::Icmp | crate::types::Protocol::Icmpv6 =>
                        PingDetector::analyze(
                            &mut threat_tracker, packet.src_ip,
                            true, proc_name, is_ingress,
                        ),
                    _ => None,
                };

                if let Some(ref threat) = threat {
                    AlertLogger::log_block(
                        &threat.src_ip.to_string(), "local", 0, 0, "DETECT",
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                    );

                    let line = format!(
                        "{} {} | src={} | {}",
                        threat.severity.icon(),
                        threat.kind.as_str(),
                        threat.src_ip,
                        threat.detail,
                    );
                    if recent_threats.len() == 20 { recent_threats.pop_front(); }
                    recent_threats.push_back(line);

                    push_log_entry(
                        &mut recent_logs,
                        LogLevel::Threat,
                        &threat.src_ip.to_string(),
                        "local", 0, 0, "DETECT",
                        proc_info.as_ref().map(|p| p.name.as_str()).unwrap_or("unknown"),
                        &format!("{}:{}", threat.kind.as_str(), threat.detail),
                    );

                    alert_count = alert_count.saturating_add(1);

                    if let Some(ref info) = proc_info {
                        if let Some(s) = proc_stats.get_mut(&info.pid) {
                            s.alerted       = s.alerted.saturating_add(1);
                            s.total_alerted = s.total_alerted.saturating_add(1);
                            s.last_active   = now_instant;
                        }
                    }
                }

                if packet_count % 1_000 == 0 {
                    threat_tracker.maybe_evict();
                }

                match policy_engine.evaluate(&packet) {
                    RuleAction::Block => {
                        block_count = block_count.saturating_add(1);

                        if let Some(ref info) = proc_info {
                            if let Some(s) = proc_stats.get_mut(&info.pid) {
                                s.blocked       = s.blocked.saturating_add(1);
                                s.total_blocked = s.total_blocked.saturating_add(1);
                                s.last_active   = now_instant;
                            }
                        }

                        let proc_label = proc_info.as_ref()
                            .map(|p| format!("{}({})", p.name, p.pid))
                            .unwrap_or_else(|| "unknown".into());

                        AlertLogger::log_block(
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port, packet.dst_port,
                            &packet.protocol.to_string(),
                            &format!("proc={}", proc_label),
                        );

                        push_log_entry(
                            &mut recent_logs, LogLevel::Block,
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port, packet.dst_port,
                            &packet.protocol.to_string(),
                            proc_info.as_ref().map(|p| p.name.as_str()).unwrap_or("unknown"),
                            &format!("proc={}", proc_label),
                        );
                    }

                    RuleAction::Alert => {
                        alert_count = alert_count.saturating_add(1);

                        if let Some(ref info) = proc_info {
                            if let Some(s) = proc_stats.get_mut(&info.pid) {
                                s.alerted       = s.alerted.saturating_add(1);
                                s.total_alerted = s.total_alerted.saturating_add(1);
                                s.last_active   = now_instant;
                            }
                        }

                        let proc_label = proc_info.as_ref()
                            .map(|p| format!("{}({})", p.name, p.pid))
                            .unwrap_or_else(|| "unknown".into());

                        AlertLogger::log_alert(
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port, packet.dst_port,
                            &packet.protocol.to_string(),
                            &format!("proc={}", proc_label),
                        );

                        push_log_entry(
                            &mut recent_logs, LogLevel::Alert,
                            &packet.src_ip.to_string(),
                            &packet.dst_ip.to_string(),
                            packet.src_port, packet.dst_port,
                            &packet.protocol.to_string(),
                            proc_info.as_ref().map(|p| p.name.as_str()).unwrap_or("unknown"),
                            &format!("proc={}", proc_label),
                        );
                    }

                    RuleAction::Allow => {
                        if log_normal {
                            normal_sample_counter =
                                normal_sample_counter.saturating_add(1);
                            if normal_sample_counter >= normal_sample_divisor {
                                normal_sample_counter = 0;

                                let pname = proc_info
                                    .as_ref()
                                    .map(|p| p.name.as_str())
                                    .unwrap_or("unknown");

                                AlertLogger::log_normal(
                                    &packet.src_ip.to_string(),
                                    &packet.dst_ip.to_string(),
                                    packet.src_port, packet.dst_port,
                                    &packet.protocol.to_string(),
                                    pname,
                                );

                                push_normal_entry(
                                    &mut normal_logs, normal_ring_capacity,
                                    LogLevel::Normal,
                                    &packet.src_ip.to_string(),
                                    &packet.dst_ip.to_string(),
                                    packet.src_port, packet.dst_port,
                                    &packet.protocol.to_string(),
                                    pname, "allow",
                                );
                            }
                        }
                    }
                }

                let check_interval = if packet_count < 1_000 { 50 } else { 500 };

                if packet_count % check_interval == 0 {
                    let now = Instant::now();

                    if now.duration_since(last_stats_time).as_secs_f64() >= 0.5 {
                        let elapsed  = now.duration_since(start_time).as_secs_f64();
                        let int_pkts = packet_count.saturating_sub(last_packet_count);
                        let int_secs = now.duration_since(last_stats_time)
                            .as_secs_f64().max(0.001);
                        let pps      = int_pkts as f64 / int_secs;
                        let avg_pps  = packet_count as f64 / elapsed.max(0.001);

                        heartbeat.push(pps);

                        publish_stats(
                            &shared_stats,
                            packet_count, block_count, alert_count,
                            pps, avg_pps, elapsed,
                            heartbeat.render(),
                            &proc_stats, &recent_threats,
                            &recent_logs, &normal_logs,
                            log_normal, normal_sample_divisor,
                        );

                        if now.duration_since(last_window_reset).as_secs() >= 5 {
                            for s in proc_stats.values_mut() {
                                s.reset_window();
                            }

                            // FIX #5 + FIX #16: PROC_TTL_DURATION is a compile-time const.
                            proc_stats.retain(|_, s| {
                                now.duration_since(s.last_active) <= PROC_TTL_DURATION
                            });

                            last_window_reset = now;
                        }

                        last_stats_time   = now;
                        last_packet_count = packet_count;
                    }
                }
            }

            Ok(None) => {
                // FIX #14: rearm warning on heartbeat.
                consecutive_timeouts = 0;
                timeout_warned       = false;

                let now = Instant::now();

                if now.duration_since(last_stats_time).as_secs() >= 2 {
                    heartbeat.push(0.0);

                    let elapsed = start_time.elapsed().as_secs_f64();
                    let avg_pps = packet_count as f64 / elapsed.max(0.001);

                    publish_stats(
                        &shared_stats,
                        packet_count, block_count, alert_count,
                        0.0, avg_pps, elapsed,
                        heartbeat.render(),
                        &proc_stats, &recent_threats,
                        &recent_logs, &normal_logs,
                        log_normal, normal_sample_divisor,
                    );

                    last_stats_time = now;
                }

                // FIX #9: 100µs → 10ms.
                sleep(Duration::from_millis(IDLE_SLEEP_MS)).await;
            }

            // FIX #14: one-shot warning per silence period.
            Err(_elapsed) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                if consecutive_timeouts >= TIMEOUT_WARN_THRESHOLD && !timeout_warned {
                    warn!(
                        silence_secs = (TIMEOUT_WARN_THRESHOLD as u64 * 100) / 1000,
                        "No packets received for ~{}s — \
                         verify interface is up and capture handle is healthy",
                        (TIMEOUT_WARN_THRESHOLD as u64 * 100) / 1000,
                    );
                    timeout_warned = true;
                }
            }
        }
    }

    // ── Graceful shutdown ─────────────────────────────────────────────────────

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     SHUTTING DOWN RUBIX                          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    info!("Cleaning up kernel rules...");
    if let Err(e) = blocker.cleanup().await {
        error!(error = %e, "Failed to clean up kernel rules — manual flush may be needed");
    }

    if timeout(Duration::from_secs(2), capture.stop()).await.is_err() {
        warn!("Capture did not stop cleanly within 2 seconds");
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let avg_pps = packet_count as f64 / elapsed.max(0.001);

    println!();
    println!("┌─ FINAL STATISTICS ──────────────────────────────────────────────┐");
    println!("│ Total Packets:  {:<48} │", packet_count);
    println!("│ Total Blocked:  {:<48} │", block_count);
    println!("│ Total Alerts:   {:<48} │", alert_count);
    println!("│ Average Rate:   {:<48} │", format!("{:.0} pps", avg_pps));
    println!("│ Runtime:        {:<48} │", format!("{:.1} seconds", elapsed));
    println!("└──────────────────────────────────────────────────────────────────┘");

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                                                                  ║");
    println!("║         GOODBYE BUDDY! RUBIX IS SIGNING OFF...                   ║");
    println!("║                                                                  ║");
    println!("║              Stay safe out there!                                ║");
    println!("║                                                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    info!("RUBIX stopped successfully - Goodbye Buddy!");
    Ok(())
}
