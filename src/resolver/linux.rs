// src/resolver/linux.rs
//! Linux process resolution via /proc.
//!
//! FIX: SnapshotResult is defined as Result<HashMap<FlowKey, ProcessInfo>>
//! using the standard RandomState hasher.  This file previously built the
//! map as FxHashMap (BuildHasherDefault<FxHasher>) and returned it directly,
//! causing a type mismatch at every return site.
//!
//! Fix: build with FxHashMap internally for performance (fast insertion
//! during the /proc walk), then convert to a standard HashMap at the single
//! return point via .into_iter().collect().  The conversion is O(n) and
//! happens once per snapshot — negligible cost compared to /proc I/O.
//!
//! inode_map remains FxHashMap throughout — it is internal and never
//! returned, so its hasher type is not constrained by SnapshotResult.

use super::{FlowKey, ProcessInfo, Protocol, SnapshotResult};
use rustc_hash::FxHashMap;
use std::collections::HashMap;

pub(crate) fn snapshot() -> SnapshotResult {
    // ── Internal maps — FxHashMap for fast insertion during /proc walk ────────

    // inode → FlowKey  (never returned; always FxHashMap)
    let mut inode_map: FxHashMap<u64, FlowKey> =
        FxHashMap::with_capacity_and_hasher(512, Default::default());

    // FlowKey → ProcessInfo  (FxHashMap internally; converted before return)
    let mut fx_map: FxHashMap<FlowKey, ProcessInfo> =
        FxHashMap::with_capacity_and_hasher(512, Default::default());

    // ── Step 1: build inode → FlowKey from /proc/net ─────────────────────────

    if let Ok(entries) = procfs::net::tcp() {
        for entry in entries {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Tcp,
            });
        }
    }

    if let Ok(entries) = procfs::net::tcp6() {
        for entry in entries {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Tcp,
            });
        }
    }

    if let Ok(entries) = procfs::net::udp() {
        for entry in entries {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Udp,
            });
        }
    }

    if let Ok(entries) = procfs::net::udp6() {
        for entry in entries {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Udp,
            });
        }
    }

    // Nothing to do if no sockets were found.
    if inode_map.is_empty() {
        // FIX: collect empty FxHashMap → HashMap to match SnapshotResult type.
        return Ok(fx_map.into_iter().collect());
    }

    // ── Step 2 + 3: walk /proc/{pid}/fd/, match inodes, read names ───────────

    let Ok(procs) = procfs::process::all_processes() else {
        return Ok(fx_map.into_iter().collect());
    };

    for proc_result in procs {
        let Ok(proc) = proc_result else { continue };
        let Ok(fds)  = proc.fd()         else { continue };

        let name: String = proc
            .stat()
            .map(|s| s.comm)
            .unwrap_or_else(|_| format!("pid:{}", proc.pid));

        let pid = proc.pid as u32;

        for fd_result in fds {
            let Ok(fd) = fd_result else { continue };

            if let procfs::process::FDTarget::Socket(inode) = fd.target {
                if let Some(flow) = inode_map.get(&inode) {
                    fx_map.insert(
                        flow.clone(),
                        ProcessInfo { pid, name: name.clone() },
                    );
                }
            }
        }
    }

    // FIX: convert FxHashMap → HashMap<_, _, RandomState> to satisfy
    // SnapshotResult = Result<HashMap<FlowKey, ProcessInfo>>.
    // into_iter().collect() re-hashes each entry once — O(n), done once
    // per snapshot.  The /proc I/O above dominates by orders of magnitude.
    Ok(fx_map.into_iter().collect())
}