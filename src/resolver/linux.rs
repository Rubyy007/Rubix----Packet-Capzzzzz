//! Linux: /proc/net/{tcp,udp} → inode → /proc/<pid>/fd → PID.

use super::{FlowKey, ProcessInfo, Protocol, SnapshotResult};
use std::collections::HashMap;
use std::net::IpAddr;

pub(crate) fn snapshot() -> SnapshotResult {
    let mut map = HashMap::with_capacity(512);
    let mut inode_map: HashMap<u64, FlowKey> = HashMap::with_capacity(512);

    if let Ok(tcp) = procfs::net::tcp() {
        for entry in tcp {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Tcp,
            });
        }
    }

    if let Ok(tcp6) = procfs::net::tcp6() {
        for entry in tcp6 {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Tcp,
            });
        }
    }

    if let Ok(udp) = procfs::net::udp() {
        for entry in udp {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Udp,
            });
        }
    }

    if let Ok(udp6) = procfs::net::udp6() {
        for entry in udp6 {
            inode_map.insert(entry.inode, FlowKey {
                local_ip:   entry.local_address.ip(),
                local_port: entry.local_address.port(),
                protocol:   Protocol::Udp,
            });
        }
    }

    if let Ok(procs) = procfs::process::all_processes() {
        for proc_result in procs {
            let Ok(proc) = proc_result else { continue };
            let Ok(fds)  = proc.fd()    else { continue };
            
            let name = proc.stat()
                .map(|s| s.comm)
                .unwrap_or_else(|_| format!("pid:{}", proc.pid));

            for fd_result in fds {
                let Ok(fd) = fd_result else { continue };
                
                if let procfs::process::FDTarget::Socket(inode) = fd.target {
                    if let Some(flow) = inode_map.get(&inode) {
                        map.insert(
                            flow.clone(),
                            ProcessInfo {
                                pid:  proc.pid as u32,
                                name: name.clone(),
                            },
                        );
                    }
                }
            }
        }
    }

    Ok(map)
}