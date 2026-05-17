// src/resolver/windows.rs
//! Windows process resolution via IP Helper API.
//!
//! Uses GetExtendedTcpTable / GetExtendedUdpTable to enumerate all active
//! TCP and UDP sockets system-wide in a single kernel call per protocol/family.
//!
//! Four collection passes per snapshot:
//!   collect_tcp_v4  — MIB_TCPTABLE_OWNER_PID  (IPv4 TCP)
//!   collect_tcp_v6  — MIB_TCP6TABLE_OWNER_PID (IPv6 TCP)
//!   collect_udp_v4  — MIB_UDPTABLE_OWNER_PID  (IPv4 UDP)
//!   collect_udp_v6  — MIB_UDP6TABLE_OWNER_PID (IPv6 UDP)
//!
//! Each pass uses the two-call pattern:
//!   1st call with None buffer → kernel writes required byte count into `size`.
//!   2nd call with sized Vec    → kernel writes the actual table.
//!
//! Process name resolution:
//!   Each row gives a PID.  PID → name via OpenProcess + K32GetProcessImageFileNameW.
//!   A per-snapshot name_cache: HashMap<u32, String> ensures each PID is only
//!   opened once per snapshot regardless of how many sockets it owns.
//!   The cache is discarded after the snapshot — PIDs are recycled by Windows.
//!
//! Error handling:
//!   Each collect_* function is non-fatal.  If IPv6 is not installed, or a
//!   protocol table is unavailable, that pass returns Ok(()) and the others
//!   continue.  The snapshot always returns Ok(map) — a partial result is
//!   correct behaviour.
//!
//! Performance:
//!   Typical cost: 1–5 ms (4 kernel calls + OpenProcess per unique PID).
//!   Called at most once per second from a background tokio task.

use super::{FlowKey, ProcessInfo, Protocol, SnapshotResult};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable,
    MIB_TCPTABLE_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

// ── Public snapshot entry point ───────────────────────────────────────────────

/// Snapshot all TCP/UDP connections across IPv4 and IPv6.
///
/// Returns a plain `HashMap` — this matches `SnapshotResult` exactly.
/// `cache.rs` converts it to `FxHashMap` when swapping the live table via
/// `snap.into_iter().collect()`.
///
/// Always returns Ok — individual collect failures are non-fatal.
pub(crate) fn snapshot() -> SnapshotResult {
    // Plain HashMap — must match SnapshotResult = Result<HashMap<...>, ...>.
    // Pre-sized for a typical desktop: ~300 TCP + ~200 UDP sockets.
    let mut map: HashMap<FlowKey, ProcessInfo> = HashMap::with_capacity(512);

    // Per-snapshot PID → name cache: avoids repeated OpenProcess for the same
    // process.  Chrome alone can own 80+ connections.
    let mut name_cache: HashMap<u32, String> = HashMap::with_capacity(128);

    unsafe {
        if let Err(e) = collect_tcp_v4(&mut map, &mut name_cache) {
            tracing::debug!(error = %e, "resolver: TCP/IPv4 collection failed");
        }
        if let Err(e) = collect_tcp_v6(&mut map, &mut name_cache) {
            tracing::debug!(error = %e, "resolver: TCP/IPv6 collection failed");
        }
        if let Err(e) = collect_udp_v4(&mut map, &mut name_cache) {
            tracing::debug!(error = %e, "resolver: UDP/IPv4 collection failed");
        }
        if let Err(e) = collect_udp_v6(&mut map, &mut name_cache) {
            tracing::debug!(error = %e, "resolver: UDP/IPv6 collection failed");
        }
    }

    Ok(map)
}

// ── TCP IPv4 ──────────────────────────────────────────────────────────────────

unsafe fn collect_tcp_v4(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut size = 0u32;

    GetExtendedTcpTable(
        None,
        &mut size,
        false,
        AF_INET.0 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );

    if size == 0 {
        return Ok(());
    }

    let mut buf = vec![0u8; size as usize];
    let rc = GetExtendedTcpTable(
        Some(buf.as_mut_ptr() as _),
        &mut size,
        false,
        AF_INET.0 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );

    if rc != 0 {
        return Err(format!("GetExtendedTcpTable(IPv4) failed: {}", rc).into());
    }

    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let rows  = std::slice::from_raw_parts(
        table.table.as_ptr(),
        table.dwNumEntries as usize,
    );

    for row in rows {
        let ip   = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let pid  = row.dwOwningPid;

        let name = name_cache
            .entry(pid)
            .or_insert_with(|| get_process_name(pid))
            .clone();

        map.insert(
            FlowKey { local_ip: IpAddr::V4(ip), local_port: port, protocol: Protocol::Tcp },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ── TCP IPv6 ──────────────────────────────────────────────────────────────────

unsafe fn collect_tcp_v6(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut size = 0u32;

    GetExtendedTcpTable(
        None,
        &mut size,
        false,
        AF_INET6.0 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );

    if size == 0 {
        return Ok(());
    }

    let mut buf = vec![0u8; size as usize];
    let rc = GetExtendedTcpTable(
        Some(buf.as_mut_ptr() as _),
        &mut size,
        false,
        AF_INET6.0 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );

    if rc != 0 {
        return Err(format!("GetExtendedTcpTable(IPv6) failed: {}", rc).into());
    }

    let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
    let rows  = std::slice::from_raw_parts(
        table.table.as_ptr(),
        table.dwNumEntries as usize,
    );

    for row in rows {
        let ip   = Ipv6Addr::from(row.ucLocalAddr);
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let pid  = row.dwOwningPid;

        let name = name_cache
            .entry(pid)
            .or_insert_with(|| get_process_name(pid))
            .clone();

        map.insert(
            FlowKey { local_ip: IpAddr::V6(ip), local_port: port, protocol: Protocol::Tcp },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ── UDP IPv4 ──────────────────────────────────────────────────────────────────

unsafe fn collect_udp_v4(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut size = 0u32;

    GetExtendedUdpTable(
        None,
        &mut size,
        false,
        AF_INET.0 as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );

    if size == 0 {
        return Ok(());
    }

    let mut buf = vec![0u8; size as usize];
    let rc = GetExtendedUdpTable(
        Some(buf.as_mut_ptr() as _),
        &mut size,
        false,
        AF_INET.0 as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );

    if rc != 0 {
        return Err(format!("GetExtendedUdpTable(IPv4) failed: {}", rc).into());
    }

    let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
    let rows  = std::slice::from_raw_parts(
        table.table.as_ptr(),
        table.dwNumEntries as usize,
    );

    for row in rows {
        let ip   = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let pid  = row.dwOwningPid;

        let name = name_cache
            .entry(pid)
            .or_insert_with(|| get_process_name(pid))
            .clone();

        map.insert(
            FlowKey { local_ip: IpAddr::V4(ip), local_port: port, protocol: Protocol::Udp },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ── UDP IPv6 ──────────────────────────────────────────────────────────────────

unsafe fn collect_udp_v6(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut size = 0u32;

    GetExtendedUdpTable(
        None,
        &mut size,
        false,
        AF_INET6.0 as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );

    if size == 0 {
        return Ok(());
    }

    let mut buf = vec![0u8; size as usize];
    let rc = GetExtendedUdpTable(
        Some(buf.as_mut_ptr() as _),
        &mut size,
        false,
        AF_INET6.0 as u32,
        UDP_TABLE_OWNER_PID,
        0,
    );

    if rc != 0 {
        return Err(format!("GetExtendedUdpTable(IPv6) failed: {}", rc).into());
    }

    let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
    let rows  = std::slice::from_raw_parts(
        table.table.as_ptr(),
        table.dwNumEntries as usize,
    );

    for row in rows {
        let ip   = Ipv6Addr::from(row.ucLocalAddr);
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let pid  = row.dwOwningPid;

        let name = name_cache
            .entry(pid)
            .or_insert_with(|| get_process_name(pid))
            .clone();

        map.insert(
            FlowKey { local_ip: IpAddr::V6(ip), local_port: port, protocol: Protocol::Udp },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ── Process name resolution ───────────────────────────────────────────────────

/// Resolve PID → process image filename (e.g. "chrome.exe").
///
/// Fast path for the two well-known kernel pseudo-processes.
/// Falls back to "pid:{pid}" when OpenProcess fails or the name cannot be read.
#[inline]
fn get_process_name(pid: u32) -> String {
    match pid {
        0 => return "System Idle".into(),
        4 => return "System".into(),
        _ => {}
    }

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) if !h.is_invalid() => h,
            _ => return format!("pid:{}", pid),
        };

        let mut buf = [0u16; 260];
        let len = K32GetProcessImageFileNameW(handle, &mut buf);
        let _ = CloseHandle(handle);

        if len == 0 {
            return format!("pid:{}", pid);
        }

        let path = String::from_utf16_lossy(&buf[..len as usize]);
        path.rsplit('\\').next().unwrap_or(&path).to_string()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_succeeds() {
        let result = snapshot();
        assert!(result.is_ok(), "snapshot() must not return Err");
        assert!(!result.unwrap().is_empty(), "expected at least one active socket");
    }

    #[test]
    fn test_kernel_process_names() {
        assert_eq!(get_process_name(0), "System Idle");
        assert_eq!(get_process_name(4), "System");
    }

    #[test]
    fn test_current_process_resolves() {
        let pid  = std::process::id();
        let name = get_process_name(pid);
        assert!(!name.starts_with("pid:"), "got: {}", name);
        assert!(name.ends_with(".exe"),    "got: {}", name);
    }

    #[test]
    fn test_invalid_pid_fallback() {
        let name = get_process_name(0xFFFF_FFFE);
        assert!(name.starts_with("pid:"), "got: {}", name);
    }
}