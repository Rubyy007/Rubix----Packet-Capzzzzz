// src/blocker/process.rs
//! Production process blocklist — PID, executable path, and SHA-256 blocking.
//!
//! Three primitives:
//!   block_pid(pid, duration, reason)     — immediate, TTL-expiring
//!   block_executable(path, reason)       — persistent, survives restart
//!   block_hash(sha256, reason)           — permanent, anti-evasion
//!
//! Exe path resolved only at check time for PIDs not already in pid_blocks.
//! Cached 30s per PID. Zero cost when no exe/hash blocks are active.

use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, info};

// ── Platform exe resolver ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod exe_resolver {
    use std::path::PathBuf;

    /// Read /proc/<pid>/exe symlink.
    pub fn resolve(pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{}/exe", pid)).ok()
    }

    /// Check liveness via /proc/<pid> directory existence.
    #[inline]
    pub fn is_alive(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
}

#[cfg(target_os = "windows")]
mod exe_resolver {
    use std::path::PathBuf;

    /// Resolve PID → full executable path via QueryFullProcessImageNameW.
    pub fn resolve(pid: u32) -> Option<PathBuf> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW,
            PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == 0 {
                return None;
            }

            let mut buf  = [0u16; 32768];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &mut size,
            );
            CloseHandle(handle);

            if ok == 0 || size == 0 { return None; }
            Some(PathBuf::from(String::from_utf16_lossy(&buf[..size as usize])))
        }
    }

    /// Check liveness via GetExitCodeProcess.
    /// STILL_ACTIVE = 259 (STATUS_PENDING) — same value on all Windows versions.
    #[inline]
    pub fn is_alive(pid: u32) -> bool {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        const STILL_ACTIVE: u32 = 259;

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == 0 { return false; }
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(handle, &mut code);
            CloseHandle(handle);
            ok != 0 && code == STILL_ACTIVE
        }
    }
}

// ── SHA-256 helper ────────────────────────────────────────────────────────────

/// Compute SHA-256 of a file. Returns None on I/O error.
/// Called once per unique exe path; result is cached in ExeLookupResult.
fn sha256_file(path: &Path) -> Option<[u8; 32]> {
    use sha2::Digest;
    use std::io::Read;

    let mut file   = std::fs::File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut buf    = [0u8; 65536];

    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }

    Some(hasher.finalize().into())
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Cached exe path + hash for a single PID (30s TTL).
#[derive(Debug, Clone)]
struct ExeLookupResult {
    pub exe_path:  Option<PathBuf>,
    pub sha256:    Option<[u8; 32]>,
    pub cached_at: Instant,
}

const EXE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Active PID block entry.
#[derive(Debug, Clone)]
pub struct PidBlock {
    pub pid:        u32,
    pub name:       String,
    pub reason:     String,
    pub blocked_at: Instant,
    /// None = permanent until PID dies or manually removed.
    pub expires_at: Option<Instant>,
    /// Kernel IP rules installed because of this PID block.
    /// Flushed when the PID block is removed.
    pub kernel_ips: HashSet<IpAddr>,
}

impl PidBlock {
    #[inline]
    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Instant::now() >= exp)
            .unwrap_or(false)
    }
}

/// Active executable path block entry.
#[derive(Debug, Clone)]
pub struct ExeBlock {
    pub path:       PathBuf,
    pub reason:     String,
    pub blocked_at: SystemTime,
}

/// Active SHA-256 hash block entry.
#[derive(Debug, Clone)]
pub struct HashBlock {
    pub sha256:     [u8; 32],
    pub reason:     String,
    pub blocked_at: SystemTime,
}

/// Reason a packet was blocked by the process blocklist.
#[derive(Debug, Clone)]
pub enum BlockReason {
    Pid  { pid: u32, name: String },
    Exe  { path: PathBuf },
    Hash { hex: String },
}

// ── ProcessBlocklist ──────────────────────────────────────────────────────────

pub struct ProcessBlocklist {
    pid_blocks:     DashMap<u32, PidBlock>,
    exe_blocks:     DashMap<PathBuf, ExeBlock>,
    hash_blocks:    DashMap<[u8; 32], HashBlock>,
    /// Per-PID exe path + hash cache (cold path only, TTL 30s).
    exe_path_cache: DashMap<u32, ExeLookupResult>,
}

impl ProcessBlocklist {
    pub fn new() -> Arc<Self> {
        let bl = Arc::new(Self {
            pid_blocks:     DashMap::new(),
            exe_blocks:     DashMap::new(),
            hash_blocks:    DashMap::new(),
            exe_path_cache: DashMap::new(),
        });
        bl.start_reaper();
        bl
    }

    // ── Block API ─────────────────────────────────────────────────────────────

    /// Block a specific PID. Returns true if newly added.
    pub fn block_pid(
        &self,
        pid:      u32,
        name:     &str,
        duration: Option<Duration>,
        reason:   &str,
    ) -> bool {
        if self.pid_blocks.contains_key(&pid) {
            return false;
        }
        self.pid_blocks.insert(pid, PidBlock {
            pid,
            name:       name.to_string(),
            reason:     reason.to_string(),
            blocked_at: Instant::now(),
            expires_at: duration.map(|d| Instant::now() + d),
            kernel_ips: HashSet::new(),
        });
        info!(pid, name, reason, ttl = ?duration, "PID block registered");
        true
    }

    /// Block an executable path. Eagerly PID-blocks all currently running
    /// instances. Returns canonicalized path.
    pub fn block_executable(&self, path: &Path, reason: &str) -> Result<PathBuf, String> {
        let canonical = path.canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());

        if self.exe_blocks.contains_key(&canonical) {
            info!(path = %canonical.display(), "Executable already blocked");
            return Ok(canonical);
        }

        let live = self.find_pids_for_exe(&canonical);
        let count = live.len();
        for (pid, name) in live {
            self.block_pid(pid, &name, None, reason);
        }

        self.exe_blocks.insert(canonical.clone(), ExeBlock {
            path:       canonical.clone(),
            reason:     reason.to_string(),
            blocked_at: SystemTime::now(),
        });
        info!(path = %canonical.display(), reason, live_pids = count,
              "Executable block registered");
        Ok(canonical)
    }

    /// Block by SHA-256. Eagerly PID-blocks all matching running processes.
    /// Returns true if newly added.
    pub fn block_hash(&self, sha256: [u8; 32], reason: &str) -> bool {
        if self.hash_blocks.contains_key(&sha256) {
            return false;
        }

        let live  = self.find_pids_for_hash(&sha256);
        let count = live.len();
        for (pid, name) in live {
            self.block_pid(pid, &name, None, reason);
        }

        self.hash_blocks.insert(sha256, HashBlock {
            sha256,
            reason:     reason.to_string(),
            blocked_at: SystemTime::now(),
        });
        info!(sha256 = %hex::encode(sha256), reason, live_pids = count,
              "Hash block registered");
        true
    }

    // ── Unblock API ───────────────────────────────────────────────────────────

    /// Remove a PID block. Returns kernel IPs installed for this PID so the
    /// caller can flush them from nftables/WFP.
    pub fn unblock_pid(&self, pid: u32) -> Option<HashSet<IpAddr>> {
        let (_, block) = self.pid_blocks.remove(&pid)?;
        self.exe_path_cache.remove(&pid);
        info!(pid, name = %block.name, "PID block removed");
        Some(block.kernel_ips)
    }

    /// Remove an executable block. Existing derived PID blocks are not
    /// removed — they expire naturally.
    pub fn unblock_executable(&self, path: &Path) -> bool {
        let canonical = path.canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());
        let removed = self.exe_blocks.remove(&canonical).is_some();
        if removed { info!(path = %canonical.display(), "Executable block removed"); }
        removed
    }

    /// Remove a hash block.
    pub fn unblock_hash(&self, sha256: &[u8; 32]) -> bool {
        let removed = self.hash_blocks.remove(sha256).is_some();
        if removed { info!(sha256 = %hex::encode(sha256), "Hash block removed"); }
        removed
    }

    // ── Hot-path check ────────────────────────────────────────────────────────

    /// Called in the packet loop for every packet with a resolved process.
    ///
    /// Fast path  — DashMap pid_blocks lookup, O(1), no allocation.
    /// Cold path  — exe path resolved once per PID, cached 30s.
    ///              Only entered when exe_blocks or hash_blocks are non-empty.
    #[inline]
    pub fn check(&self, pid: u32, name: &str) -> Option<BlockReason> {
        // ── 1. PID fast path ──────────────────────────────────────────────
        if let Some(entry) = self.pid_blocks.get(&pid) {
            // Lazy expiry / dead-process check.
            if entry.is_expired() || !exe_resolver::is_alive(pid) {
                drop(entry);
                let _ = self.unblock_pid(pid);
                debug!(pid, "PID block removed (expired or process exited)");
                return None;
            }
            return Some(BlockReason::Pid { pid, name: entry.name.clone() });
        }

        // ── 2. Skip cold path when no exe/hash blocks are active ──────────
        if self.exe_blocks.is_empty() && self.hash_blocks.is_empty() {
            return None;
        }

        // ── 3. Resolve exe path (cached 30s per PID) ──────────────────────
        let lookup = self.get_or_resolve_exe(pid);

        // ── 4. Exe block check ────────────────────────────────────────────
        if let Some(ref exe_path) = lookup.exe_path {
            if let Some(entry) = self.exe_blocks.get(exe_path) {
                let reason = entry.reason.clone();
                drop(entry);
                self.block_pid(pid, name, None, &reason);
                info!(pid, name, exe = %exe_path.display(),
                      "Process auto-blocked via exe rule");
                return Some(BlockReason::Exe { path: exe_path.clone() });
            }
        }

        // ── 5. Hash block check ───────────────────────────────────────────
        if !self.hash_blocks.is_empty() {
            if let Some(ref hash) = lookup.sha256 {
                if let Some(entry) = self.hash_blocks.get(hash) {
                    let reason = entry.reason.clone();
                    drop(entry);
                    self.block_pid(pid, name, None, &reason);
                    info!(pid, name, sha256 = %hex::encode(hash),
                          "Process auto-blocked via hash rule");
                    return Some(BlockReason::Hash { hex: hex::encode(hash) });
                }
            }
        }

        None
    }

    /// Record a kernel IP block installed because of a PID block.
    /// Used so unblock_pid() can flush associated kernel rules.
    pub fn record_kernel_ip(&self, pid: u32, ip: IpAddr) {
        if let Some(mut entry) = self.pid_blocks.get_mut(&pid) {
            entry.kernel_ips.insert(ip);
        }
    }

    // ── Snapshot accessors ────────────────────────────────────────────────────

    pub fn list_pid_blocks(&self) -> Vec<PidBlock> {
        let mut list: Vec<PidBlock> = self.pid_blocks.iter()
            .map(|e| e.value().clone()).collect();
        list.sort_by_key(|b| b.pid);
        list
    }

    pub fn list_exe_blocks(&self) -> Vec<ExeBlock> {
        let mut list: Vec<ExeBlock> = self.exe_blocks.iter()
            .map(|e| e.value().clone()).collect();
        list.sort_by(|a, b| a.path.cmp(&b.path));
        list
    }

    pub fn list_hash_blocks(&self) -> Vec<HashBlock> {
        self.hash_blocks.iter().map(|e| e.value().clone()).collect()
    }

    pub fn is_pid_blocked(&self, pid: u32) -> bool {
        self.pid_blocks.contains_key(&pid)
    }

    pub fn is_exe_blocked(&self, path: &Path) -> bool {
        let canonical = path.canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());
        self.exe_blocks.contains_key(&canonical)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn get_or_resolve_exe(&self, pid: u32) -> ExeLookupResult {
        if let Some(cached) = self.exe_path_cache.get(&pid) {
            if cached.cached_at.elapsed() < EXE_CACHE_TTL {
                return cached.clone();
            }
        }

        let exe_path = exe_resolver::resolve(pid);
        let sha256   = if !self.hash_blocks.is_empty() {
            exe_path.as_ref().and_then(|p| sha256_file(p))
        } else {
            None
        };

        let result = ExeLookupResult { exe_path, sha256, cached_at: Instant::now() };
        self.exe_path_cache.insert(pid, result.clone());
        result
    }

    /// Enumerate running PIDs whose exe path matches `canonical`.
    /// Called only at block-registration time — not in hot path.
    fn find_pids_for_exe(&self, canonical: &Path) -> Vec<(u32, String)> {
        #[cfg(target_os = "linux")]
        {
            use procfs::process::all_processes;
            let mut found = Vec::new();
            if let Ok(procs) = all_processes() {
                for proc in procs.flatten() {
                    if let Ok(exe) = proc.exe() {
                        if exe == canonical {
                            let name = proc.stat()
                                .map(|s| s.comm)
                                .unwrap_or_else(|_| format!("pid:{}", proc.pid));
                            found.push((proc.pid as u32, name));
                        }
                    }
                }
            }
            found
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                PROCESSENTRY32W, TH32CS_SNAPPROCESS,
            };

            let mut found = Vec::new();
            unsafe {
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                    return found;
                }
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        let pid = entry.th32ProcessID;
                        if let Some(exe) = exe_resolver::resolve(pid) {
                            if exe == canonical {
                                let nu16 = &entry.szExeFile;
                                let len  = nu16.iter().position(|&c| c == 0)
                                    .unwrap_or(nu16.len());
                                found.push((pid, String::from_utf16_lossy(&nu16[..len]).into()));
                            }
                        }
                        if Process32NextW(snap, &mut entry) == 0 { break; }
                    }
                }
                CloseHandle(snap);
            }
            found
        }
    }

    /// Enumerate running PIDs whose exe SHA-256 matches `target`.
    /// Called only at block-registration time — not in hot path.
    fn find_pids_for_hash(&self, target: &[u8; 32]) -> Vec<(u32, String)> {
        #[cfg(target_os = "linux")]
        {
            use procfs::process::all_processes;
            let mut found = Vec::new();
            if let Ok(procs) = all_processes() {
                for proc in procs.flatten() {
                    if let Ok(exe) = proc.exe() {
                        if let Some(hash) = sha256_file(&exe) {
                            if &hash == target {
                                let name = proc.stat()
                                    .map(|s| s.comm)
                                    .unwrap_or_else(|_| format!("pid:{}", proc.pid));
                                found.push((proc.pid as u32, name));
                            }
                        }
                    }
                }
            }
            found
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                PROCESSENTRY32W, TH32CS_SNAPPROCESS,
            };

            let mut found = Vec::new();
            unsafe {
                let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                    return found;
                }
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        let pid = entry.th32ProcessID;
                        if let Some(exe) = exe_resolver::resolve(pid) {
                            if let Some(hash) = sha256_file(&exe) {
                                if &hash == target {
                                    let nu16 = &entry.szExeFile;
                                    let len  = nu16.iter().position(|&c| c == 0)
                                        .unwrap_or(nu16.len());
                                    found.push((pid, String::from_utf16_lossy(&nu16[..len]).into()));
                                }
                            }
                        }
                        if Process32NextW(snap, &mut entry) == 0 { break; }
                    }
                }
                CloseHandle(snap);
            }
            found
        }
    }

    // ── Background reaper ─────────────────────────────────────────────────────

    /// Tokio task — every 10s removes expired/dead PID blocks and
    /// evicts stale exe_path_cache entries.
    fn start_reaper(self: &Arc<Self>) {
        let bl = Arc::downgrade(self);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;
                let Some(bl) = bl.upgrade() else { break };

                let mut to_remove: Vec<u32> = Vec::new();
                for entry in bl.pid_blocks.iter() {
                    let pid = *entry.key();
                    if entry.value().is_expired() || !exe_resolver::is_alive(pid) {
                        to_remove.push(pid);
                    }
                }

                for pid in to_remove {
                    if let Some(ips) = bl.unblock_pid(pid) {
                        if !ips.is_empty() {
                            debug!(pid, kernel_ips = ips.len(),
                                   "Reaper: PID gone, associated kernel IPs remain");
                        }
                    }
                }

                bl.exe_path_cache.retain(|_, v| v.cached_at.elapsed() < EXE_CACHE_TTL);
            }
        });
    }
}

impl Default for ProcessBlocklist {
    fn default() -> Self {
        panic!("Use ProcessBlocklist::new() — returns Arc<ProcessBlocklist>");
    }
}