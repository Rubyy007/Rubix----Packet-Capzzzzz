// src/resolver/linux.rs
//! Linux process resolution via /proc.
//!
//! Algorithm (three-step inode chase):
//!
//!   Step 1 — Read kernel socket tables from /proc/net/:
//!     /proc/net/tcp   → IPv4 TCP: { local_address: SocketAddr, inode: u64 }
//!     /proc/net/tcp6  → IPv6 TCP
//!     /proc/net/udp   → IPv4 UDP
//!     /proc/net/udp6  → IPv6 UDP
//!     Result: inode_map: HashMap<u64, FlowKey>
//!
//!   Step 2 — Walk /proc/{pid}/fd/ for every running process:
//!     Each fd entry is a symlink.  Sockets appear as "socket:[inode]".
//!     Match the inode against inode_map.
//!
//!   Step 3 — Read process name from /proc/{pid}/stat (comm field).
//!     comm is capped at 15 characters by the kernel.
//!     Fallback: "pid:{pid}" if stat() fails (process exited mid-scan).
//!
//! Error handling:
//!   Every fallible operation uses `let Ok(...) else { continue }`.
//!   A process that exits during iteration, or an fd that can't be read
//!   due to permissions, is silently skipped.  The snapshot returns whatever
//!   it successfully collected — a partial result is correct and expected.
//!
//! Performance:
//!   Typical cost: 2–10 ms depending on number of processes and open fds.
//!   Called at most once per second from a background tokio task — never
//!   from the packet-loop hot path.

use super::{FlowKey, ProcessInfo, Protocol, SnapshotResult};
use rustc_hash::FxHashMap;
use std::net::IpAddr;

pub(crate) fn snapshot() -> SnapshotResult {
    // Pre-size for a typical Linux desktop: ~200 TCP + ~100 UDP sockets.
    let mut map:       FxHashMap<FlowKey, ProcessInfo> =
        FxHashMap::with_capacity_and_hasher(512, Default::default());
    let mut inode_map: FxHashMap<u64, FlowKey> =
        FxHashMap::with_capacity_and_hasher(512, Default::default());

    // ── Step 1: build inode → FlowKey map ────────────────────────────────────

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

    // Nothing to do if no sockets were found (unlikely but safe).
    if inode_map.is_empty() {
        return Ok(map);
    }

    // ── Step 2 + 3: walk /proc/{pid}/fd/, match inodes, read names ───────────

    let Ok(procs) = procfs::process::all_processes() else {
        // /proc is unreadable — return whatever we have (empty map is fine).
        return Ok(map);
    };

    for proc_result in procs {
        // Process may have exited between all_processes() and here — skip.
        let Ok(proc) = proc_result else { continue };

        // Read fd directory.  Fails for processes owned by other users when
        // running without CAP_SYS_PTRACE, which is normal and expected.
        let Ok(fds) = proc.fd() else { continue };

        // Read comm from /proc/{pid}/stat.  Comm is limited to 15 chars by
        // the kernel (TASK_COMM_LEN - 1).  If stat() fails (process exited),
        // use "pid:{pid}" as a diagnostic fallback.
        let name: String = proc
            .stat()
            .map(|s| s.comm)
            .unwrap_or_else(|_| format!("pid:{}", proc.pid));

        let pid = proc.pid as u32;

        for fd_result in fds {
            let Ok(fd) = fd_result else { continue };

            // Only sockets have inodes in our map — pipes, files, etc. skip.
            if let procfs::process::FDTarget::Socket(inode) = fd.target {
                if let Some(flow) = inode_map.get(&inode) {
                    map.insert(
                        flow.clone(),
                        ProcessInfo {
                            pid,
                            name: name.clone(),
                        },
                    );
                }
            }
        }
    }

    Ok(map)
}