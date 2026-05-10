// src/policy/engine.rs
//! Rule evaluation engine.
//!
//! Matching semantics (per condition field):
//!   - None or empty vec  → condition not constrained (wildcard, always passes)
//!   - Non-empty vec      → packet field must match at least one element
//!
//! This means `src_ips: []` in YAML (which deserialises to Some(vec![]))
//! is treated identically to omitting the field entirely.  Without this
//! an empty list would make every rule a dead rule.
//!
//! ── Production fixes applied ──────────────────────────────────────────────
//!
//! FIX #E1 — std::sync::RwLock → parking_lot::RwLock
//!   parking_lot locks NEVER poison on panic.  All the Ok(guard)/Err(e)
//!   match arms on every lock acquisition are gone.  A panic while holding
//!   the lock unwinds the thread; the lock is released cleanly and the next
//!   caller gets a valid guard.  With std::sync::RwLock a panic produces a
//!   poisoned lock, every subsequent acquire returns Err, and the engine
//!   silently falls back to RuleAction::Allow — effectively disabling all
//!   security enforcement.
//!
//! FIX #E2 — EngineStats fields replaced with atomics (AtomicU64)
//!   evaluate() was acquiring a write lock on stats up to three times per
//!   packet (entry, block/alert/allow branch, default allow).  At 200k pps
//!   that is up to 600 000 exclusive lock acquisitions per second on one
//!   contended word.  Atomic fetch_add with Relaxed ordering costs a single
//!   CPU instruction on x86/ARM and requires no lock at all.  get_stats()
//!   loads each counter individually — acceptable for a monitoring/CLI path
//!   that runs at human timescales, not in the packet loop.
//!
//! FIX #E3 — HashSet<IpAddr> → FxHashSet<IpAddr> for blocked_ips
//!   Consistent with the FxHashMap/FxHashSet usage in main.rs.  IpAddr keys
//!   are 4 or 16 bytes; SipHash's DoS resistance is unnecessary here because
//!   block_ip() is called only from authenticated CLI commands, not from
//!   packet data.  FxHash is 2–3× faster for small fixed-size keys.

use super::Rule;
use crate::types::Packet;
use parking_lot::RwLock;
use rustc_hash::FxHashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, debug};

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
    Alert,
}

// ── FIX #E2: atomic stats — zero lock contention in the hot path ──────────────

pub struct EngineStats {
    pub total_evaluations: AtomicU64,
    pub cache_hits:        AtomicU64,
    pub blocks:            AtomicU64,
    pub allows:            AtomicU64,
    pub alerts:            AtomicU64,
}

impl EngineStats {
    fn new() -> Self {
        Self {
            total_evaluations: AtomicU64::new(0),
            cache_hits:        AtomicU64::new(0),
            blocks:            AtomicU64::new(0),
            allows:            AtomicU64::new(0),
            alerts:            AtomicU64::new(0),
        }
    }
}

/// Snapshot of engine stats for CLI / monitoring — loaded outside hot path.
#[derive(Debug, Default, Clone)]
pub struct EngineStatsSnapshot {
    pub total_evaluations: u64,
    pub cache_hits:        u64,
    pub blocks:            u64,
    pub allows:            u64,
    pub alerts:            u64,
}

// ── FIX #E1: parking_lot::RwLock — no poisoning, no Ok/Err match arms ─────────

pub struct PolicyEngine {
    rules:       RwLock<Vec<Rule>>,
    // FIX #E3: FxHashSet — faster for IpAddr keys, safe (CLI-only writer)
    blocked_ips: RwLock<FxHashSet<IpAddr>>,
    // FIX #E2: atomics — no lock needed for stats increments
    stats:       EngineStats,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rules:       RwLock::new(Vec::new()),
            blocked_ips: RwLock::new(FxHashSet::default()),
            stats:       EngineStats::new(),
        }
    }

    pub fn add_rule(&self, rule: Rule) {
        if rule.enabled {
            // FIX #E1: parking_lot write() returns the guard directly — no Result.
            let mut rules = self.rules.write();
            rules.push(rule);
            debug!("Added rule, total rules: {}", rules.len());
        }
    }

    pub fn load_rules(&self, rules: Vec<Rule>) {
        let enabled_rules: Vec<Rule> = rules.into_iter()
            .filter(|r| r.enabled)
            .collect();

        let mut guard = self.rules.write();
        let count = enabled_rules.len();
        *guard = enabled_rules;
        info!("Loaded {} policy rules", count);
    }

    pub fn evaluate(&self, packet: &Packet) -> RuleAction {
        // FIX #E2: single atomic increment — no lock, no contention.
        self.stats.total_evaluations.fetch_add(1, Ordering::Relaxed);

        // ── Fast-path: kernel-level blocked IPs ───────────────────────────
        //
        // FIX #E1: parking_lot read() never poisons — direct guard, no match.
        let is_blocked = {
            let guard = self.blocked_ips.read();
            guard.contains(&packet.dst_ip) || guard.contains(&packet.src_ip)
        };

        if is_blocked {
            debug!("IP {}/{} is in engine block set", packet.src_ip, packet.dst_ip);
            self.stats.blocks.fetch_add(1, Ordering::Relaxed);
            return RuleAction::Block;
        }

        // ── Rule evaluation (first match wins) ────────────────────────────
        //
        // FIX #E1: parking_lot read() — direct guard.
        let rules = self.rules.read();

        for rule in rules.iter() {
            if self.matches_rule(packet, rule) {
                debug!(
                    "Packet matched rule: {} ({}) -> {:?}",
                    rule.id, rule.name, rule.action
                );

                // FIX #E2: atomic increment per action — no write lock.
                match rule.action {
                    RuleAction::Block => self.stats.blocks.fetch_add(1, Ordering::Relaxed),
                    RuleAction::Alert => self.stats.alerts.fetch_add(1, Ordering::Relaxed),
                    RuleAction::Allow => self.stats.allows.fetch_add(1, Ordering::Relaxed),
                };

                return rule.action.clone();
            }
        }

        // ── Default: Allow ────────────────────────────────────────────────
        self.stats.allows.fetch_add(1, Ordering::Relaxed);
        RuleAction::Allow
    }

    // ── Rule matching ─────────────────────────────────────────────────────
    //
    // Each condition field is a tri-state:
    //   • None            → wildcard (field was omitted from YAML)
    //   • Some(empty)     → wildcard (field was present but empty list `[]`)
    //   • Some(non-empty) → must match at least one element
    //
    // This prevents the common YAML authoring mistake of writing `src_ips: []`
    // intending "don't care" but accidentally producing "match nothing".

    fn matches_rule(&self, packet: &Packet, rule: &Rule) -> bool {
        let cond = &rule.conditions;

        // ── src_ips ───────────────────────────────────────────────────────
        if let Some(src_ips) = &cond.src_ips {
            if !src_ips.is_empty()
                && !src_ips.iter().any(|ip| ip.matches(&packet.src_ip))
            {
                return false;
            }
        }

        // ── dst_ips ───────────────────────────────────────────────────────
        if let Some(dst_ips) = &cond.dst_ips {
            if !dst_ips.is_empty()
                && !dst_ips.iter().any(|ip| ip.matches(&packet.dst_ip))
            {
                return false;
            }
        }

        // ── src_ports ─────────────────────────────────────────────────────
        if let Some(src_ports) = &cond.src_ports {
            if !src_ports.is_empty()
                && !src_ports.contains(&packet.src_port)
            {
                return false;
            }
        }

        // ── dst_ports ─────────────────────────────────────────────────────
        if let Some(dst_ports) = &cond.dst_ports {
            if !dst_ports.is_empty()
                && !dst_ports.contains(&packet.dst_port)
            {
                return false;
            }
        }

        // ── protocols ─────────────────────────────────────────────────────
        //
        // Strings are pre-normalized to lowercase in reloader.rs (FIX #R2),
        // so eq_ignore_ascii_case is now just a safety net for any rules
        // injected programmatically via add_rule() without going through
        // the reloader.
        if let Some(protocols) = &cond.protocols {
            if !protocols.is_empty() {
                let proto_str = packet.protocol.as_str();
                if !protocols.iter().any(|p| p.eq_ignore_ascii_case(proto_str)) {
                    return false;
                }
            }
        }

        true
    }

    // ── IP block set management ───────────────────────────────────────────

    pub fn block_ip(&self, ip: IpAddr) {
        self.blocked_ips.write().insert(ip);
        info!("Added IP to engine block set: {}", ip);
    }

    pub fn unblock_ip(&self, ip: &IpAddr) -> bool {
        let removed = self.blocked_ips.write().remove(ip);
        if removed { info!("Removed IP from engine block set: {}", ip); }
        removed
    }

    pub fn get_rules(&self) -> Vec<Rule> {
        self.rules.read().clone()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    /// Returns a point-in-time snapshot of engine stats.
    /// Each counter is loaded with Relaxed ordering — acceptable for
    /// monitoring/CLI use where exact consistency across counters is not
    /// required.  Called at human timescales, never in the packet loop.
    pub fn get_stats(&self) -> EngineStatsSnapshot {
        EngineStatsSnapshot {
            total_evaluations: self.stats.total_evaluations.load(Ordering::Relaxed),
            cache_hits:        self.stats.cache_hits.load(Ordering::Relaxed),
            blocks:            self.stats.blocks.load(Ordering::Relaxed),
            allows:            self.stats.allows.load(Ordering::Relaxed),
            alerts:            self.stats.alerts.load(Ordering::Relaxed),
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self { Self::new() }
}
