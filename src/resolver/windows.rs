//! Windows process resolution via IP Helper API
//!
//! Uses GetExtendedTcpTable/GetExtendedUdpTable for batch socket enumeration.
//! Supports IPv4 + IPv6 for both TCP and UDP protocols.
//!
//! Performance:
//! - Single syscall per protocol/family (4 total per refresh)
//! - Process name caching to avoid duplicate OpenProcess calls
//! - Pre-sized allocations for typical workloads

use super::{FlowKey, ProcessInfo, Protocol, SnapshotResult};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Snapshot all TCP/UDP connections across IPv4 and IPv6.
/// Returns a map of (local_ip, local_port, protocol) → (pid, process_name).
pub(crate) fn snapshot() -> SnapshotResult {
    // Pre-size for typical desktop workload: ~300 TCP + ~200 UDP
    let mut map = HashMap::with_capacity(512);
    
    // Process name cache: avoid repeated OpenProcess for same PID
    let mut name_cache: HashMap<u32, String> = HashMap::with_capacity(128);

    unsafe {
        // Non-fatal errors: if one protocol fails, continue with others
        let _ = collect_tcp_v4(&mut map, &mut name_cache);
        let _ = collect_tcp_v6(&mut map, &mut name_cache);
        let _ = collect_udp_v4(&mut map, &mut name_cache);
        let _ = collect_udp_v6(&mut map, &mut name_cache);
    }

    Ok(map)
}

// ══════════════════════════════════════════════════════════════════════════════
// ── TCP IPv4 ──────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

unsafe fn collect_tcp_v4(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut size = 0u32;
    
    // First call: get required buffer size
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

    // Second call: retrieve actual data
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
        return Ok(());  // Non-fatal: IPv4 TCP may not be available
    }

    // Parse connection table
    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(
        table.table.as_ptr(),
        table.dwNumEntries as usize,
    );

    for row in rows {
        // Windows stores IPs in network byte order (big-endian)
        let ip   = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let pid  = row.dwOwningPid;

        // Cache hit: reuse process name; cache miss: query and store
        let name = name_cache
            .entry(pid)
            .or_insert_with(|| get_process_name(pid))
            .clone();

        map.insert(
            FlowKey {
                local_ip:   IpAddr::V4(ip),
                local_port: port,
                protocol:   Protocol::Tcp,
            },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// ── TCP IPv6 ──────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

unsafe fn collect_tcp_v6(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        return Ok(());
    }

    let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(
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
            FlowKey {
                local_ip:   IpAddr::V6(ip),
                local_port: port,
                protocol:   Protocol::Tcp,
            },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// ── UDP IPv4 ──────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

unsafe fn collect_udp_v4(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        return Ok(());
    }

    let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(
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
            FlowKey {
                local_ip:   IpAddr::V4(ip),
                local_port: port,
                protocol:   Protocol::Udp,
            },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// ── UDP IPv6 ──────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

unsafe fn collect_udp_v6(
    map:        &mut HashMap<FlowKey, ProcessInfo>,
    name_cache: &mut HashMap<u32, String>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        return Ok(());
    }

    let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
    let rows = std::slice::from_raw_parts(
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
            FlowKey {
                local_ip:   IpAddr::V6(ip),
                local_port: port,
                protocol:   Protocol::Udp,
            },
            ProcessInfo { pid, name },
        );
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Process name resolution ───────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/// Resolve PID → process image name (e.g., "chrome.exe").
///
/// Fast path for well-known kernel PIDs (0, 4).
/// Uses K32GetProcessImageFileNameW for user processes.
/// Falls back to "pid:N" if access is denied.
#[inline]
fn get_process_name(pid: u32) -> String {
    // Fast path: kernel processes
    match pid {
        0 => return "System Idle".into(),
        4 => return "System".into(),
        _ => {}
    }

    unsafe {
        // Request minimal access: PROCESS_QUERY_LIMITED_INFORMATION
        // Works even for protected processes when running as non-admin
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) if !h.is_invalid() => h,
            _ => return format!("pid:{}", pid),
        };

        // Stack-allocated buffer (MAX_PATH = 260 UTF-16 chars)
        let mut buf = [0u16; 260];
        let len = K32GetProcessImageFileNameW(handle, &mut buf);
        
        // Always close handle (even if K32GetProcessImageFileNameW fails)
        let _ = CloseHandle(handle);

        if len == 0 {
            return format!("pid:{}", pid);
        }

        // Convert UTF-16 path to UTF-8 string
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        
        // Extract filename only (last component after backslash)
        // e.g., "C:\Windows\System32\svchost.exe" → "svchost.exe"
        path.rsplit('\\')
            .next()
            .unwrap_or(&path)
            .to_string()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Tests ─────────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_runs() {
        // Should not panic and return at least some connections
        let result = snapshot();
        assert!(result.is_ok());
        
        let map = result.unwrap();
        // Typical Windows system has 50+ active connections
        assert!(map.len() > 0, "Expected at least 1 connection");
    }

    #[test]
    fn test_kernel_process_names() {
        assert_eq!(get_process_name(0), "System Idle");
        assert_eq!(get_process_name(4), "System");
    }

    #[test]
    fn test_current_process_name() {
        let pid = std::process::id();
        let name = get_process_name(pid);
        
        // Should resolve to something like "rubix.exe" or "cargo.exe"
        assert!(!name.starts_with("pid:"));
        assert!(name.ends_with(".exe"));
    }
}