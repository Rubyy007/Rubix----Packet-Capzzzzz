// src/blocker/windows.rs
//! Windows kernel-level blocker — WFP FwpmFilterAdd0 direct API.
//!
//! DEFINITIVE FIX: Use a unique sublayer per RUBIX run.  WFP enforces
//! uniqueness at the (layer + sublayer + conditions) level, not by GUID.
//! By creating a unique sublayer GUID per run, filters can never collide
//! with orphaned filters from previous runs, even if BFE enumeration fails.
//!
//! The sublayer is created in the session, and since the session is
//! DYNAMIC, the sublayer + all its filters are auto-deleted on exit.

use super::{Blocker, BlockOrigin, BlockRule, BlockerError};
use super::cache::BlockCache;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineOpen0, FwpmEngineClose0,
    FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
    FwpmFreeMemory0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FwpmTransactionAbort0,
    FWPM_SESSION0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_SUBLAYER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,     FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWP_ACTION_BLOCK, FWP_CONDITION_VALUE0, FWP_BYTE_ARRAY16,
    FWP_MATCH_EQUAL, FWP_UINT32, FWP_BYTE_ARRAY16_TYPE,
    FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_SESSION_FLAG_DYNAMIC,
};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};

const MAX_CACHE: usize = 65_536;
const FILTER_PREFIX_OUT: &str = "RUBIX-OUT-";
const FILTER_PREFIX_IN:  &str = "RUBIX-IN-";

#[cfg(target_os = "windows")]
const ENUM_BATCH_SIZE: u32 = 256;
#[cfg(target_os = "windows")]
const NULL_HANDLE: isize = 0isize;

/// Generate a random-ish GUID from current time + counter.
#[cfg(target_os = "windows")]
fn make_guid() -> windows::core::GUID {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let n = base.wrapping_add(COUNTER.fetch_add(1, Ordering::SeqCst));
    
    windows::core::GUID {
        data1: n as u32,
        data2: (n >> 32) as u16,
        data3: ((n >> 48) as u16 & 0x0FFF) | 0x4000,
        data4: [
            ((n >> 56) as u8 & 0x3F) | 0x80,
            (n >> 48) as u8,
            (n >> 40) as u8,
            (n >> 32) as u8,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ],
    }
}

#[derive(Debug, Clone)]
struct WfpPair {
    connect_id: u64,
    recv_id:    u64,
}

#[derive(Debug, Clone)]
struct ActiveIpRule {
    block_rule: BlockRule,
    pair:       WfpPair,
    permanent:  bool,
}

pub struct WindowsBlocker {
    #[cfg(target_os = "windows")]
    engine:     parking_lot::Mutex<isize>,
    /// Unique sublayer GUID for this run — prevents filter collisions.
    #[cfg(target_os = "windows")]
    sublayer:   windows::core::GUID,
    rules:      RwLock<HashMap<IpAddr, ActiveIpRule>>,
    ip_cache:   BlockCache,
}

#[cfg(target_os = "windows")]
unsafe impl Send for WindowsBlocker {}
#[cfg(target_os = "windows")]
unsafe impl Sync for WindowsBlocker {}

impl WindowsBlocker {
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            let (raw, sublayer_key) = match Self::open_engine_and_create_sublayer() {
                Ok((h, sk)) => {
                    info!("WFP engine session opened (dynamic — auto-cleanup on exit)");
                    (h.0 as isize, sk)
                }
                Err(e) => {
                    warn!(error = %e, "WFP engine open failed — run as Administrator");
                    (NULL_HANDLE, make_guid())
                }
            };

            let blocker = Self {
                engine:   parking_lot::Mutex::new(raw),
                sublayer: sublayer_key,
                rules:    RwLock::new(HashMap::new()),
                ip_cache: BlockCache::new(MAX_CACHE),
            };

            // Best-effort sweep of orphaned RUBIX filters from previous runs.
            // If BFE rejects enumeration (session aborted), we log and continue.
            // The unique sublayer ensures new filters won't collide anyway.
            if raw != NULL_HANDLE {
                let engine = HANDLE(raw as *mut _);
                let swept = blocker.sweep_stale_filters(engine);
                if swept > 0 {
                    info!(count = swept, "Swept stale RUBIX filters from previous session");
                }
            }

            blocker
        }

        #[cfg(not(target_os = "windows"))]
        Self {
            rules:    RwLock::new(HashMap::new()),
            ip_cache: BlockCache::new(MAX_CACHE),
        }
    }

    // ── Engine + Sublayer setup ───────────────────────────────────────────────

    /// Open a dynamic WFP engine session and create a unique sublayer.
    /// The sublayer ensures filters from different runs never collide.
    #[cfg(target_os = "windows")]
    fn open_engine_and_create_sublayer() -> Result<(HANDLE, windows::core::GUID), BlockerError> {
        use std::mem;
        use windows::core::PWSTR;

        let mut session: FWPM_SESSION0 = unsafe { mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut h = HANDLE::default();
        let r = unsafe {
            FwpmEngineOpen0(
                None,
                10, // RPC_C_AUTHN_WINNT
                None,
                Some(&session),
                &mut h,
            )
        };
        if r != ERROR_SUCCESS.0 {
            return Err(BlockerError::WfpError(
                format!("FwpmEngineOpen0: 0x{:08X}", r)
            ));
        }

        let sublayer_key = make_guid();
        let name_wide: Vec<u16> = "RUBIX-Sublayer".encode_utf16().chain(Some(0)).collect();
        let desc_wide: Vec<u16> = "RUBIX per-run sublayer".encode_utf16().chain(Some(0)).collect();

        let mut sublayer: FWPM_SUBLAYER0 = unsafe { mem::zeroed() };
        sublayer.subLayerKey = sublayer_key;
        sublayer.displayData.name = PWSTR(name_wide.as_ptr() as *mut u16);
        sublayer.displayData.description = PWSTR(desc_wide.as_ptr() as *mut u16);
        sublayer.weight = 0xFFFF;

        let r = unsafe { FwpmSubLayerAdd0(h, &sublayer, None) };
        // Ignore ALREADY_EXISTS for sublayer — means a previous run left it
        const FWP_E_ALREADY_EXISTS: u32 = 0x80320025;
        if r != ERROR_SUCCESS.0 && r != FWP_E_ALREADY_EXISTS {
            unsafe { FwpmEngineClose0(h) };
            return Err(BlockerError::WfpError(
                format!("FwpmSubLayerAdd0: 0x{:08X}", r)
            ));
        }

        Ok((h, sublayer_key))
    }

    // ── Stale filter sweep (best-effort) ─────────────────────────────────────

    #[cfg(target_os = "windows")]
    fn sweep_stale_filters(&self, engine: HANDLE) -> usize {
        use std::mem;

        let template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { mem::zeroed() };
        let mut enum_handle = HANDLE::default();

        let r = unsafe {
            FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle)
        };
        if r != ERROR_SUCCESS.0 {
            warn!(
                error = format!("0x{:08X}", r),
                "sweep_stale_filters: FwpmFilterCreateEnumHandle0 failed — \
                 stale filters may remain (harmless with unique sublayer)"
            );
            return 0;
        }

        let mut deleted = 0usize;

        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;

            let r = unsafe {
                FwpmFilterEnum0(engine, enum_handle, ENUM_BATCH_SIZE, &mut entries, &mut returned)
            };
            if r != ERROR_SUCCESS.0 { break; }
            if returned == 0 || entries.is_null() { break; }

            for i in 0..returned as usize {
                let filter_ptr: *mut FWPM_FILTER0 = unsafe { *entries.add(i) };
                if filter_ptr.is_null() { continue; }
                let filter: &FWPM_FILTER0 = unsafe { &*filter_ptr };

                let name_pwstr = filter.displayData.name;
                if name_pwstr.is_null() { continue; }

                let wide_slice = unsafe {
                    let mut len = 0usize;
                    let mut p = name_pwstr.0;
                    while !p.is_null() && *p != 0 { p = p.add(1); len += 1; }
                    std::slice::from_raw_parts(name_pwstr.0, len)
                };
                let name = String::from_utf16_lossy(wide_slice);

                if name.starts_with(FILTER_PREFIX_OUT) || name.starts_with(FILTER_PREFIX_IN) {
                    let filter_id = filter.filterId;
                    let r = unsafe { FwpmFilterDeleteById0(engine, filter_id) };
                    if r == ERROR_SUCCESS.0 { deleted += 1; }
                }
            }

            let mut entries_ptr: *mut std::ffi::c_void = entries as *mut _;
            unsafe { FwpmFreeMemory0(&mut entries_ptr) };
            if returned < ENUM_BATCH_SIZE { break; }
        }

        unsafe { FwpmFilterDestroyEnumHandle0(engine, enum_handle) };
        deleted
    }

    // ── Filter installation ───────────────────────────────────────────────────

    #[cfg(target_os = "windows")]
    fn add_filters(&self, ip: &IpAddr) -> Result<WfpPair, BlockerError> {
        let raw = *self.engine.lock();
        if raw == NULL_HANDLE {
            return Err(BlockerError::WfpError(
                "WFP engine not open — run as Administrator".into()
            ));
        }
        let engine = HANDLE(raw as *mut _);

        let r = unsafe { FwpmTransactionBegin0(engine, 0) };
        if r != ERROR_SUCCESS.0 {
            return Err(BlockerError::WfpError(
                format!("FwpmTransactionBegin0: 0x{:08X}", r)
            ));
        }

        let result = Self::add_filters_inner(engine, self.sublayer, ip);
        match &result {
            Ok(_)  => { unsafe { FwpmTransactionCommit0(engine); } }
            Err(_) => { unsafe { FwpmTransactionAbort0(engine); } }
        }
        result
    }

    #[cfg(target_os = "windows")]
    fn add_filters_inner(
        engine: HANDLE,
        sublayer_key: windows::core::GUID,
        ip: &IpAddr,
    ) -> Result<WfpPair, BlockerError> {
        use std::mem;

        let (connect_layer, recv_layer, mut cond_value) = match ip {
            IpAddr::V4(v4) => {
                let mut cv: FWP_CONDITION_VALUE0 = unsafe { mem::zeroed() };
                cv.r#type = FWP_UINT32;
                unsafe { cv.Anonymous.uint32 = u32::from_be_bytes(v4.octets()); }
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, cv)
            }
            IpAddr::V6(v6) => {
                let arr = Box::new(FWP_BYTE_ARRAY16 { byteArray16: v6.octets() });
                let ptr = Box::into_raw(arr);
                let mut cv: FWP_CONDITION_VALUE0 = unsafe { mem::zeroed() };
                cv.r#type = FWP_BYTE_ARRAY16_TYPE;
                unsafe { cv.Anonymous.byteArray16 = ptr; }
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, cv)
            }
        };

        let connect_name = format!("RUBIX-OUT-{}", ip);
        let recv_name    = format!("RUBIX-IN-{}", ip);

        let connect_id = Self::install_one(
            engine, connect_layer, &cond_value, &connect_name, sublayer_key,
        );
        let recv_id = Self::install_one(
            engine, recv_layer, &cond_value, &recv_name, sublayer_key,
        );

        if let IpAddr::V6(_) = ip {
            unsafe {
                let ptr = cond_value.Anonymous.byteArray16;
                if !ptr.is_null() { drop(Box::from_raw(ptr)); }
            }
        }

        Ok(WfpPair { connect_id: connect_id?, recv_id: recv_id? })
    }

    #[cfg(target_os = "windows")]
    fn install_one(
        engine:       HANDLE,
        layer_key:    windows::core::GUID,
        cond_value:   &FWP_CONDITION_VALUE0,
        display_name: &str,
        sublayer_key: windows::core::GUID,
    ) -> Result<u64, BlockerError> {
        use std::mem;

        let wide: Vec<u16> = display_name.encode_utf16().chain(Some(0)).collect();

        let mut cond = FWPM_FILTER_CONDITION0 {
            fieldKey:       FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType:      FWP_MATCH_EQUAL,
            conditionValue: *cond_value,
        };

        let mut f: FWPM_FILTER0 = unsafe { mem::zeroed() };
        f.displayData.name    = windows::core::PWSTR(wide.as_ptr() as *mut u16);
        f.layerKey            = layer_key;
        f.subLayerKey         = sublayer_key;  // ← KEY: unique sublayer prevents collisions
        f.action.r#type       = FWP_ACTION_BLOCK;
        f.numFilterConditions = 1;
        f.filterCondition     = &mut cond;
        f.weight.r#type       = FWP_UINT32;
        unsafe { f.weight.Anonymous.uint32 = 0xFFFF; }

        let mut filter_id: u64 = 0;
        let r = unsafe {
            FwpmFilterAdd0(engine, &f, None, Some(&mut filter_id))
        };

        drop(wide);

        // DEFINITIVE FIX: Treat ALREADY_EXISTS as success.  This can happen
        // if a previous run crashed and left a filter with the same IP in
        // the same sublayer.  The filter is already blocking the IP — mission accomplished.
        const FWP_E_ALREADY_EXISTS: u32 = 0x80320025;
        if r == FWP_E_ALREADY_EXISTS {
            info!(ip = %display_name, "WFP filter already exists — IP is already blocked");
            return Ok(0); // Dummy ID — cleanup skips 0
        }

        if r != ERROR_SUCCESS.0 {
            return Err(BlockerError::WfpError(
                format!("FwpmFilterAdd0 ({}): 0x{:08X}", display_name, r)
            ));
        }
        Ok(filter_id)
    }

    // ── Filter removal ────────────────────────────────────────────────────────

    #[cfg(target_os = "windows")]
    fn remove_filters(&self, pair: &WfpPair) {
        let raw = *self.engine.lock();
        if raw == NULL_HANDLE { return; }
        let engine = HANDLE(raw as *mut _);
        for &id in &[pair.connect_id, pair.recv_id] {
            if id == 0 { continue; } // Skip dummy IDs from ALREADY_EXISTS
            let r = unsafe { FwpmFilterDeleteById0(engine, id) };
            if r != ERROR_SUCCESS.0 {
                warn!(filter_id = id, error = format!("0x{:08X}", r), "FwpmFilterDeleteById0 failed");
            }
        }
    }

    // ── Non-Windows stubs ─────────────────────────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    fn add_filters(&self, _ip: &IpAddr) -> Result<WfpPair, BlockerError> {
        Err(BlockerError::WfpError("Not Windows".into()))
    }
    #[cfg(not(target_os = "windows"))]
    fn remove_filters(&self, _pair: &WfpPair) {}

    // ── Core block logic ──────────────────────────────────────────────────────

    fn do_block(
        &self,
        ip:       IpAddr,
        duration: Option<Duration>,
        origin:   BlockOrigin,
    ) -> Result<String, BlockerError> {
        if self.ip_cache.contains(&ip) {
            return Ok(format!("rubix-{}", ip));
        }
        if self.rules.read().contains_key(&ip) {
            info!(ip = %ip, "Already blocked — skipping duplicate");
            return Ok(format!("rubix-{}", ip));
        }

        let pair = self.add_filters(&ip)?;

        let now     = SystemTime::now();
        let rule_id = format!(
            "rubix-{}-{}",
            ip,
            now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
        );
        let expires_at = duration.map(|d| now + d);
        let permanent  = duration.is_none();

        let rule = BlockRule {
            id: rule_id.clone(),
            target: ip,
            created_at: now,
            expires_at,
            reason: match &origin {
                BlockOrigin::Manual =>
                    if permanent { "permanent-block".into() }
                    else { format!("timed-block-{}s", duration.unwrap_or_default().as_secs()) },
                BlockOrigin::ProcessBlock { pid, name, .. } =>
                    format!("process-block: {}({})", name, pid),
            },
            origin,
        };

        self.rules.write().insert(ip, ActiveIpRule { block_rule: rule, pair, permanent });
        self.ip_cache.insert(ip);
        info!(ip = %ip, permanent, "WFP block installed");
        Ok(rule_id)
    }
}

impl Default for WindowsBlocker {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Blocker for WindowsBlocker {
    async fn block_ip(&self, ip: IpAddr) -> Result<String, BlockerError> {
        self.do_block(ip, None, BlockOrigin::Manual)
    }
    async fn block_ip_with_origin(&self, ip: IpAddr, origin: BlockOrigin) -> Result<String, BlockerError> {
        self.do_block(ip, None, origin)
    }
    async fn block_ip_timed(&self, ip: IpAddr, duration: Duration) -> Result<String, BlockerError> {
        self.do_block(ip, Some(duration), BlockOrigin::Manual)
    }
    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError> {
        match self.rules.write().remove(&ip) {
            None => { warn!(ip = %ip, "Unblock: IP not tracked"); Ok(false) }
            Some(r) => {
                self.ip_cache.remove(&ip);
                self.remove_filters(&r.pair);
                info!(ip = %ip, "WFP block removed");
                Ok(true)
            }
        }
    }
    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        if self.ip_cache.contains(ip) { return Ok(true); }
        Ok(self.rules.read().contains_key(ip))
    }
    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        let mut list: Vec<BlockRule> = self.rules.read().values().map(|a| a.block_rule.clone()).collect();
        list.sort_by(|a, b| {
            b.expires_at.is_none().cmp(&a.expires_at.is_none())
                .then(a.created_at.cmp(&b.created_at))
        });
        Ok(list)
    }
    async fn cleanup(&self) -> Result<(), BlockerError> {
        let rules: Vec<ActiveIpRule> = self.rules.write().drain().map(|(_, v)| v).collect();
        for r in &rules { self.remove_filters(&r.pair); }
        self.ip_cache.clear();

        #[cfg(target_os = "windows")]
        {
            let mut guard = self.engine.lock();
            if *guard != NULL_HANDLE {
                let engine = HANDLE(*guard as *mut _);
                *guard = NULL_HANDLE;
                let r = unsafe { FwpmEngineClose0(engine) };
                if r != ERROR_SUCCESS.0 {
                    warn!(error = format!("0x{:08X}", r), "FwpmEngineClose0 failed");
                } else {
                    info!("WFP engine session closed");
                }
            }
        }
        info!("WindowsBlocker cleanup complete");
        Ok(())
    }
}