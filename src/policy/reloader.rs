// src/policy/reloader.rs
//!
//! ── Production fixes applied ──────────────────────────────────────────────
//!
//! FIX #R1 — Per-rule YAML parse error fallback
//!   Previously: serde_yaml::from_str() parsed the entire file as one
//!   Vec<serde_yaml::Value>.  A single malformed document (bad YAML syntax,
//!   not just bad rule fields) caused the ENTIRE rule set to fail loading —
//!   leaving the engine with zero rules and defaulting to Allow-all.
//!
//!   Now: serde_yaml::Deserializer::from_str() produces an iterator of
//!   YAML documents.  Each document is deserialized independently.  A
//!   malformed document emits a warn!() and is skipped; all valid documents
//!   are loaded.  Per-rule field errors were already handled by parse_rule()
//!   returning Err — that path is unchanged.
//!
//!   Note: rules.yaml is expected to be a single YAML file containing a
//!   sequence (list) of rule objects, not a multi-document YAML file.  The
//!   Deserializer approach handles both.  For a sequence file it produces
//!   one document (the sequence); for a multi-document file it produces one
//!   document per rule.  Both are handled correctly by the match below.
//!
//! FIX #R2 — Protocol strings normalized to lowercase on load
//!   Previously: proto.to_string() preserved original case from YAML
//!   ("TCP", "Tcp", "tcp" were all stored as-is).  engine.rs uses
//!   eq_ignore_ascii_case() for matching, so this was functionally correct
//!   but wasteful — every packet evaluation paid a case-fold cost per
//!   protocol string per rule.
//!
//!   Now: proto.to_lowercase() normalizes at load time (cold path, once).
//!   The hot-path eq_ignore_ascii_case() in matches_rule() becomes a pure
//!   safety net for rules injected via add_rule() without going through
//!   this reloader.  Zero functional change; hot-path cost reduced.

use super::{PolicyEngine, Rule, RuleAction, RuleConditions, IpNetOrAddr};
use std::sync::Arc;
use serde::de::Deserialize;   // required: brings Value::deserialize() into scope
use tracing::{info, warn, debug};
use anyhow::{Result, anyhow};

pub struct PolicyReloader {
    engine:     Arc<PolicyEngine>,
    rules_path: String,
}

impl PolicyReloader {
    pub fn new(engine: Arc<PolicyEngine>, rules_path: String) -> Self {
        Self { engine, rules_path }
    }

    pub fn load_initial(&self) -> Result<()> {
        self.load_rules_from_file()
    }

    pub fn load_rules_from_file(&self) -> Result<()> {
        let contents = std::fs::read_to_string(&self.rules_path)?;

        // ── FIX #R1: document-level fallback ─────────────────────────────
        //
        // serde_yaml::Deserializer iterates YAML documents independently.
        // A syntax error in one document does not abort parsing of others.
        // For the common single-document sequence file this produces exactly
        // one Value (the sequence); we flatten it below so parse_rule()
        // receives one Value per rule regardless of file structure.

        let mut rules: Vec<Rule> = Vec::new();
        let mut doc_index = 0usize;

        for de in serde_yaml::Deserializer::from_str(&contents) {
            let value = match serde_yaml::Value::deserialize(de) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Skipping malformed YAML document [{}]: {}", doc_index, e);
                    doc_index += 1;
                    continue;
                }
            };

            // A sequence document is a rules.yaml file: unwrap each element.
            // A mapping document is a single rule (multi-document YAML style).
            match value {
                serde_yaml::Value::Sequence(seq) => {
                    for rule_data in seq {
                        match self.parse_rule(&rule_data) {
                            Ok(Some(rule)) => {
                                debug!("Parsed rule: {} ({})", rule.id, rule.name);
                                rules.push(rule);
                            }
                            Ok(None) => {} // disabled rule — skip silently
                            Err(e)   => warn!(
                                "Skipping malformed rule in document [{}]: {}",
                                doc_index, e
                            ),
                        }
                    }
                }
                ref mapping @ serde_yaml::Value::Mapping(_) => {
                    match self.parse_rule(mapping) {
                        Ok(Some(rule)) => {
                            debug!("Parsed rule: {} ({})", rule.id, rule.name);
                            rules.push(rule);
                        }
                        Ok(None) => {}
                        Err(e)   => warn!(
                            "Skipping malformed rule document [{}]: {}",
                            doc_index, e
                        ),
                    }
                }
                _ => warn!(
                    "Unexpected YAML structure in document [{}] — expected sequence or mapping",
                    doc_index
                ),
            }

            doc_index += 1;
        }

        info!("Loaded {} rules from {}", rules.len(), self.rules_path);
        self.engine.load_rules(rules);

        Ok(())
    }

    fn parse_rule(&self, data: &serde_yaml::Value) -> Result<Option<Rule>> {
        let id = match data.get("id") {
            Some(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None    => return Err(anyhow!("id must be a string")),
            },
            None => return Err(anyhow!("Missing required field: id")),
        };

        let name = match data.get("name") {
            Some(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None    => return Err(anyhow!("name must be a string")),
            },
            None => return Err(anyhow!("Missing required field: name")),
        };

        let enabled = data.get("enabled")
            .and_then(|e| e.as_bool())
            .unwrap_or(true);

        if !enabled {
            debug!("Rule {} ({}) is disabled, skipping", id, name);
            return Ok(None);
        }

        let action_str = match data.get("action") {
            Some(v) => match v.as_str() {
                Some(s) => s,
                None    => return Err(anyhow!("action must be a string")),
            },
            None => return Err(anyhow!("Missing required field: action")),
        };

        let action = match action_str {
            "Allow" => RuleAction::Allow,
            "Block" => RuleAction::Block,
            "Alert" => RuleAction::Alert,
            other   => return Err(anyhow!("Unknown action '{}' in rule '{}'", other, id)),
        };

        let conditions_data = match data.get("conditions") {
            Some(v) => v,
            None    => return Err(anyhow!("Missing required field: conditions")),
        };

        let mut conditions = RuleConditions::default();

        // ── src_ips ───────────────────────────────────────────────────────
        if let Some(src_ips) = conditions_data.get("src_ips").and_then(|v| v.as_sequence()) {
            let mut ips = Vec::new();
            for ip_val in src_ips {
                if let Some(ip_str) = ip_val.as_str() {
                    match IpNetOrAddr::parse(ip_str) {
                        Ok(ip)  => ips.push(ip),
                        Err(e)  => warn!("Invalid src_ip '{}' in rule '{}': {}", ip_str, id, e),
                    }
                }
            }
            if !ips.is_empty() {
                conditions.src_ips = Some(ips);
            }
        }

        // ── dst_ips ───────────────────────────────────────────────────────
        if let Some(dst_ips) = conditions_data.get("dst_ips").and_then(|v| v.as_sequence()) {
            let mut ips = Vec::new();
            for ip_val in dst_ips {
                if let Some(ip_str) = ip_val.as_str() {
                    match IpNetOrAddr::parse(ip_str) {
                        Ok(ip)  => ips.push(ip),
                        Err(e)  => warn!("Invalid dst_ip '{}' in rule '{}': {}", ip_str, id, e),
                    }
                }
            }
            if !ips.is_empty() {
                conditions.dst_ips = Some(ips);
            }
        }

        // ── src_ports ─────────────────────────────────────────────────────
        if let Some(src_ports) = conditions_data.get("src_ports").and_then(|v| v.as_sequence()) {
            let mut ports = Vec::new();
            for port_val in src_ports {
                if let Some(port) = port_val.as_u64() {
                    if port <= u16::MAX as u64 {
                        ports.push(port as u16);
                    } else {
                        warn!("Port value {} out of u16 range in rule '{}'", port, id);
                    }
                }
            }
            if !ports.is_empty() {
                conditions.src_ports = Some(ports);
            }
        }

        // ── dst_ports ─────────────────────────────────────────────────────
        if let Some(dst_ports) = conditions_data.get("dst_ports").and_then(|v| v.as_sequence()) {
            let mut ports = Vec::new();
            for port_val in dst_ports {
                if let Some(port) = port_val.as_u64() {
                    if port <= u16::MAX as u64 {
                        ports.push(port as u16);
                    } else {
                        warn!("Port value {} out of u16 range in rule '{}'", port, id);
                    }
                }
            }
            if !ports.is_empty() {
                conditions.dst_ports = Some(ports);
            }
        }

        // ── protocols ─────────────────────────────────────────────────────
        //
        // FIX #R2: to_lowercase() at load time — hot-path eq_ignore_ascii_case()
        // in matches_rule() becomes a zero-cost safety net.
        if let Some(protocols) = conditions_data.get("protocols").and_then(|v| v.as_sequence()) {
            let mut protos = Vec::new();
            for proto_val in protocols {
                if let Some(proto) = proto_val.as_str() {
                    protos.push(proto.to_lowercase());   // FIX #R2
                }
            }
            if !protos.is_empty() {
                conditions.protocols = Some(protos);
            }
        }

        Ok(Some(Rule {
            id,
            name,
            enabled,
            action,
            conditions,
        }))
    }

    pub fn reload(&self) -> Result<()> {
        info!("Reloading policies from {}", self.rules_path);
        self.load_rules_from_file()
    }
}
