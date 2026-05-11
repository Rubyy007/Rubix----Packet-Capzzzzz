// src/blocker/linux.rs
//! Linux kernel-level blocker — nftables batch via `nft -f -` stdin pipe.
//!
//! Atomic netlink transaction per operation.  One fork+exec per call.
//! See mod.rs for full design notes.

use super::{Blocker, BlockOrigin, BlockRule, BlockerError};
use super::cache::BlockCache;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

const TABLE_NAME:     &str  = "rubix";
const SET_IPV4:       &str  = "blocked_ips";
const SET_IPV6:       &str  = "blocked_ips6";
const CHAIN_INPUT:    &str  = "input";
const CHAIN_OUTPUT:   &str  = "output";
const MAX_CACHE:      usize = 65_536;

#[derive(Debug, Clone)]
struct ActiveIpRule {
    block_rule: BlockRule,
    permanent:  bool,
}

pub struct LinuxBlocker {
    rules:    parking_lot::RwLock<HashMap<IpAddr, ActiveIpRule>>,
    ip_cache: BlockCache,
    nft_lock: Mutex<()>,
}

impl LinuxBlocker {
    pub fn new() -> Self {
        let b = Self {
            rules:    parking_lot::RwLock::new(HashMap::new()),
            ip_cache: BlockCache::new(MAX_CACHE),
            nft_lock: Mutex::new(()),
        };
        b.ensure_table();
        b
    }

    fn ensure_table(&self) {
        let script = format!(
            r#"add table inet {t}
add set inet {t} {s4} {{ type ipv4_addr; flags interval; }}
add set inet {t} {s6} {{ type ipv6_addr; flags interval; }}
add chain inet {t} {ci} {{ type filter hook input  priority 0; policy accept; }}
add chain inet {t} {co} {{ type filter hook output priority 0; policy accept; }}
add rule  inet {t} {ci} ip  saddr @{s4} drop
add rule  inet {t} {ci} ip  daddr @{s4} drop
add rule  inet {t} {ci} ip6 saddr @{s6} drop
add rule  inet {t} {ci} ip6 daddr @{s6} drop
add rule  inet {t} {co} ip  daddr @{s4} drop
add rule  inet {t} {co} ip6 daddr @{s6} drop
"#,
            t  = TABLE_NAME,
            s4 = SET_IPV4,
            s6 = SET_IPV6,
            ci = CHAIN_INPUT,
            co = CHAIN_OUTPUT,
        );
        match Self::nft_batch(&script) {
            Ok(())  => info!("nftables RUBIX table ready"),
            Err(e)  => warn!(error = %e, "nftables setup failed — run as root"),
        }
    }

    fn nft_batch(script: &str) -> Result<(), BlockerError> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BlockerError::NftablesError(
                format!("nft spawn failed: {}", e)
            ))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes())
                .map_err(|e| BlockerError::NftablesError(
                    format!("nft stdin write: {}", e)
                ))?;
        }

        let out = child.wait_with_output()
            .map_err(|e| BlockerError::NftablesError(
                format!("nft wait: {}", e)
            ))?;

        if out.status.success() { return Ok(()); }

        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("File exists") || stderr.contains("already exists") {
            debug!("nft: element already present (idempotent)");
            return Ok(());
        }

        Err(BlockerError::NftablesError(format!(
            "nft exit={} stderr={}",
            out.status,
            stderr.trim(),
        )))
    }

    fn nft_add_ip(&self, ip: &IpAddr) -> Result<(), BlockerError> {
        let (set, addr) = match ip {
            IpAddr::V4(v) => (SET_IPV4, v.to_string()),
            IpAddr::V6(v) => (SET_IPV6, v.to_string()),
        };
        Self::nft_batch(&format!(
            "add element inet {} {} {{ {} }}\n",
            TABLE_NAME, set, addr
        ))
    }

    fn nft_remove_ip(&self, ip: &IpAddr) -> Result<(), BlockerError> {
        let (set, addr) = match ip {
            IpAddr::V4(v) => (SET_IPV4, v.to_string()),
            IpAddr::V6(v) => (SET_IPV6, v.to_string()),
        };
        match Self::nft_batch(&format!(
            "delete element inet {} {} {{ {} }}\n",
            TABLE_NAME, set, addr
        )) {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No such file") || msg.contains("not found") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn do_block(
        &self,
        ip:       IpAddr,
        duration: Option<Duration>,
        origin:   BlockOrigin,
    ) -> Result<String, BlockerError> {
        let _g = self.nft_lock.lock();

        if self.ip_cache.contains(&ip) {
            debug!(ip = %ip, "Already blocked (cache)");
            return Ok(format!("rubix-{}", ip));
        }
        if self.rules.read().contains_key(&ip) {
            info!(ip = %ip, "Already blocked (map)");
            return Ok(format!("rubix-{}", ip));
        }

        self.nft_add_ip(&ip)?;

        let now = SystemTime::now();
        let rule_id = format!(
            "rubix-{}-{}",
            ip,
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        let expires_at = duration.map(|d| now + d);
        let permanent  = duration.is_none();

        let rule = BlockRule {
            id: rule_id.clone(),
            target: ip,
            created_at: now,
            expires_at,
            reason: match &origin {
                BlockOrigin::Manual => if permanent {
                    "permanent-block".to_string()
                } else {
                    format!("timed-block-{}s", duration.unwrap_or_default().as_secs())
                },
                BlockOrigin::ProcessBlock { pid, name, .. } =>
                    format!("process-block: {}({})", name, pid),
            },
            origin,
        };

        self.rules.write().insert(ip, ActiveIpRule { block_rule: rule, permanent });
        self.ip_cache.insert(ip);

        info!(ip = %ip, permanent = permanent, "nftables block installed");
        Ok(rule_id)
    }
}

impl Default for LinuxBlocker {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Blocker for LinuxBlocker {
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError> {
        self.do_block(ip, None, BlockOrigin::Manual)
    }

    async fn block_ip_with_origin(
        &self,
        ip:     IpAddr,
        origin: BlockOrigin,
    ) -> Result<String, BlockerError> {
        self.do_block(ip, None, origin)
    }

    async fn block_ip_timed(
        &self,
        ip:       IpAddr,
        duration: Duration,
    ) -> Result<String, BlockerError> {
        self.do_block(ip, Some(duration), BlockOrigin::Manual)
    }

    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError> {
        let _g = self.nft_lock.lock();
        if self.rules.write().remove(&ip).is_none() {
            warn!(ip = %ip, "Unblock: not tracked");
            return Ok(false);
        }
        self.ip_cache.remove(&ip);
        self.nft_remove_ip(&ip)?;
        info!(ip = %ip, "nftables block removed");
        Ok(true)
    }

    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        if self.ip_cache.contains(ip) { return Ok(true); }
        Ok(self.rules.read().contains_key(ip))
    }

    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        let rules = self.rules.read();
        let mut list: Vec<BlockRule> = rules.values().map(|a| a.block_rule.clone()).collect();
        list.sort_by(|a, b| {
            b.expires_at.is_none().cmp(&a.expires_at.is_none())
                .then(a.created_at.cmp(&b.created_at))
        });
        Ok(list)
    }

    async fn cleanup(&self) -> Result<(), BlockerError> {
        let _ = Self::nft_batch(&format!("delete table inet {}\n", TABLE_NAME));
        self.rules.write().clear();
        self.ip_cache.clear();
        info!("LinuxBlocker cleanup complete");
        Ok(())
    }
}