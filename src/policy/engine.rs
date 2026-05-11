// src/policy/engine.rs
//! Rule evaluation engine.
//!
//! FIX #E1 — parking_lot::RwLock (no poisoning)
//! FIX #E2 — AtomicU64 stats (zero lock contention in hot path)
//! FIX #E3 — FxHashSet<IpAddr> for blocked_ips
//! FIX #E4 — evaluate() accepts proc_name: Option<&str> (process blocklist
//!            check happens upstream in main.rs; parameter kept for API
//!            consistency and future per-rule process matching)

use super::Rule;
use crate::types::Packet;
use parking_lot::RwLock;
use rustc_hash::FxHashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info};

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
    Alert,
}

// ── Atomic stats — zero lock contention in the hot path ───────────────────────

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

/// Point-in-time snapshot of engine stats for CLI / monitoring.
#[derive(Debug, Default, Clone)]
pub struct EngineStatsSnapshot {
    pub total_evaluations: u64,
    pub cache_hits:        u64,
    pub blocks:            u64,
    pub allows:            u64,
    pub alerts:            u64,
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

pub struct PolicyEngine {
    rules:       RwLock<Vec<Rule>>,
    blocked_ips: RwLock<FxHashSet<IpAddr>>,
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
            let mut rules = self.rules.write();
            rules.push(rule);
            debug!("Added rule, total rules: {}", rules.len());
        }
    }

    pub fn load_rules(&self, rules: Vec<Rule>) {
        let enabled: Vec<Rule> = rules.into_iter().filter(|r| r.enabled).collect();
        let mut guard = self.rules.write();
        let count = enabled.len();
        *guard = enabled;
        info!("Loaded {} policy rules", count);
    }

    /// Evaluate a packet against the rule set.
    ///
    /// `proc_name` is accepted for API consistency.  Process-level blocking
    /// is handled upstream in the packet loop by `ProcessBlocklist::check()`
    /// before this function is called, so proc_name is not used here.
    /// Future per-rule process-name conditions will use it via `matches_rule`.
    #[inline]
    pub fn evaluate(&self, packet: &Packet, _proc_name: Option<&str>) -> RuleAction {
        self.stats.total_evaluations.fetch_add(1, Ordering::Relaxed);

        // ── 1. IP block set — fast path ───────────────────────────────────
        {
            let guard = self.blocked_ips.read();
            if guard.contains(&packet.dst_ip) || guard.contains(&packet.src_ip) {
                debug!("IP {}/{} in engine block set", packet.src_ip, packet.dst_ip);
                self.stats.blocks.fetch_add(1, Ordering::Relaxed);
                return RuleAction::Block;
            }
        }

        // ── 2. Rule scan — first match wins ───────────────────────────────
        let rules = self.rules.read();
        for rule in rules.iter() {
            if self.matches_rule(packet, rule) {
                debug!(
                    "Packet matched rule: {} ({}) -> {:?}",
                    rule.id, rule.name, rule.action
                );
                match rule.action {
                    RuleAction::Block => self.stats.blocks.fetch_add(1, Ordering::Relaxed),
                    RuleAction::Alert => self.stats.alerts.fetch_add(1, Ordering::Relaxed),
                    RuleAction::Allow => self.stats.allows.fetch_add(1, Ordering::Relaxed),
                };
                return rule.action.clone();
            }
        }

        // ── 3. Default Allow ──────────────────────────────────────────────
        self.stats.allows.fetch_add(1, Ordering::Relaxed);
        RuleAction::Allow
    }

    // ── Rule matching ─────────────────────────────────────────────────────────
    //
    // Tri-state per condition field:
    //   None            → wildcard (omitted from YAML)
    //   Some(empty vec) → wildcard (present but empty — `src_ips: []`)
    //   Some(non-empty) → must match at least one element

    fn matches_rule(&self, packet: &Packet, rule: &Rule) -> bool {
        let cond = &rule.conditions;

        if let Some(src_ips) = &cond.src_ips {
            if !src_ips.is_empty()
                && !src_ips.iter().any(|ip| ip.matches(&packet.src_ip))
            {
                return false;
            }
        }

        if let Some(dst_ips) = &cond.dst_ips {
            if !dst_ips.is_empty()
                && !dst_ips.iter().any(|ip| ip.matches(&packet.dst_ip))
            {
                return false;
            }
        }

        if let Some(src_ports) = &cond.src_ports {
            if !src_ports.is_empty() && !src_ports.contains(&packet.src_port) {
                return false;
            }
        }

        if let Some(dst_ports) = &cond.dst_ports {
            if !dst_ports.is_empty() && !dst_ports.contains(&packet.dst_port) {
                return false;
            }
        }

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

    // ── IP block set management ───────────────────────────────────────────────

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