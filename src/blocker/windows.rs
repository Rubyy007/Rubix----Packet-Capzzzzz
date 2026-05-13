// src/blocker/windows.rs
//! Windows kernel-level blocker — WFP FwpmFilterAdd0 direct API.
//!
//! Uses the `windows` crate for all WFP calls.
//!
//! ── HANDLE threading fix ─────────────────────────────────────────────────
//!
//! windows::Win32::Foundation::HANDLE wraps *mut c_void which is !Send+!Sync.
//! We store the engine handle as a raw isize (the pointer value) inside a
//! parking_lot::Mutex.  parking_lot::Mutex<isize> is Send+Sync.
//! We cast back to HANDLE only inside #[cfg(target_os="windows")] fn bodies
//! that are never exposed across thread boundaries.
//!
//! ── FIX-1: FWPM_SESSION_FLAG_DYNAMIC ────────────────────────────────────
//!
//! The original session was opened with a zeroed FWPM_SESSION0, meaning the
//! `flags` field was 0.  Without FWPM_SESSION_FLAG_DYNAMIC (0x00000001), WFP
//! writes filters into the persistent (boot-time) store.  Those filters
//! survive process death, so a hard-killed RUBIX leaves orphaned filters that
//! cause FWP_E_ALREADY_EXISTS (0x80320025) on the next startup.
//!
//! Fix: set flags = FWPM_SESSION_FLAG_DYNAMIC on FwpmEngineOpen0.  WFP then
//! automatically removes every filter added through this session when the
//! engine handle is closed OR when the process dies unexpectedly.
//!
//! ── FIX-2: Startup stale-filter sweep ───────────────────────────────────
//!
//! As a belt-and-suspenders measure, WindowsBlocker::new() calls
//! sweep_stale_filters() immediately after opening the engine.  This
//! enumerates all current WFP filters, finds any whose display name begins
//! with "RUBIX-OUT-" or "RUBIX-IN-" (i.e., left by a previous non-dynamic
//! session or a crash before FIX-1 was deployed), and deletes them.
//!
//! After the sweep, add_filters() will never hit FWP_E_ALREADY_EXISTS for
//! RUBIX-owned filters regardless of how the previous run ended.
//!
//! ── FIX-3: FWPM_FILTER_ENUM_TEMPLATE0.actionMask ───────────────────────
//!
//! FwpmFilterCreateEnumHandle0 fails with FWP_E_NEVER_MATCH (0x80320033)
//! when actionMask is 0.  actionMask=0 means "match no action bits", so no
//! filter can ever match.  Fix: set actionMask = 0xFFFFFFFF to ignore
//! action type during enumeration.
//!
//! ── FIX-4: Filter weight type ───────────────────────────────────────────
//!
//! FwpmFilterAdd0 fails with FWP_E_INVALID_WEIGHT (0x80320025) when
//! weight.type = FWP_UINT32.  Per Microsoft docs, valid weight types are
//! FWP_UINT64, FWP_EMPTY (auto), or FWP_UINT8 (range).  Fix: use FWP_EMPTY
//! for automatic weight assignment.
//!
//! ── Required Cargo features ───────────────────────────────────────────────
//!   Win32_NetworkManagement_WindowsFilteringPlatform
//!   Win32_Foundation
//!   Win32_Security          ← FWPM_SESSION0 / FWPM_FILTER0
//!   Win32_System_Rpc        ← FwpmEngineOpen0 (RPC auth constants)

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
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
    FwpmFreeMemory0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FwpmTransactionAbort0,
    FWPM_SESSION0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,     FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWP_ACTION_BLOCK, FWP_CONDITION_VALUE0, FWP_BYTE_ARRAY16,
    FWP_EMPTY, FWP_MATCH_EQUAL, FWP_UINT32, FWP_BYTE_ARRAY16_TYPE,
    FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_SESSION_FLAG_DYNAMIC,
};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};

const MAX_CACHE: usize = 65_536;

/// Prefix used for outbound WFP filter display names.
const FILTER_PREFIX_OUT: &str = "RUBIX-OUT-";
/// Prefix used for inbound WFP filter display names.
const FILTER_PREFIX_IN:  &str = "RUBIX-IN-";

/// Maximum filters returned per FwpmFilterEnum0 call.
#[cfg(target_os = "windows")]
const ENUM_BATCH_SIZE: u32 = 256;

/// Null sentinel for a WFP engine handle stored as isize.
#[cfg(target_os = "windows")]
const NULL_HANDLE: isize = 0isize;

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
    engine:   parking_lot::Mutex<isize>,
    rules:    RwLock<HashMap<IpAddr, ActiveIpRule>>,
    ip_cache: BlockCache,
}

#[cfg(target_os = "windows")]
unsafe impl Send for WindowsBlocker {}
#[cfg(target_os = "windows")]
unsafe impl Sync for WindowsBlocker {}

impl WindowsBlocker {
    pub fn new() -> Self {
        #[cfg(target_os = "windows")]
        {
            let raw = match Self::open_engine() {
                Ok(h) => {
                    info!("WFP engine session opened (dynamic — auto-cleanup on exit)");
                    h.0 as isize
                }
                Err(e) => {
                    warn!(error = %e, "WFP engine open failed — run as Administrator");
                    NULL_HANDLE
                }
            };

            let blocker = Self {
                engine:   parking_lot::Mutex::new(raw),
                rules:    RwLock::new(HashMap::new()),
                ip_cache: BlockCache::new(MAX_CACHE),
            };

            if raw != NULL_HANDLE {
                let engine = HANDLE(raw as *mut _);
                let swept = blocker.sweep_stale_filters(engine);
                if swept > 0 {
                    info!(
                        count = swept,
                        "Swept stale RUBIX filters from previous session"
                    );
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

    // ── Engine session ────────────────────────────────────────────────────────

    #[cfg(target_os = "windows")]
    fn open_engine() -> Result<HANDLE, BlockerError> {
        use std::mem;
        let mut session: FWPM_SESSION0 = unsafe { mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut h = HANDLE::default();
        let r = unsafe {
            FwpmEngineOpen0(
                None,
                10,             // RPC_C_AUTHN_WINNT
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
        Ok(h)
    }

    // ── FIX-2 + FIX-3: Stale filter sweep ───────────────────────────────────
    //
    // FIX-3: actionMask must be 0xFFFFFFFF (ignore action type), not 0.
    // actionMask=0 means "match no action bits" → FWP_E_NEVER_MATCH.
    #[cfg(target_os = "windows")]
    fn sweep_stale_filters(&self, engine: HANDLE) -> usize {
        use std::mem;

        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { mem::zeroed() };
        // FIX-3: 0xFFFFFFFF = ignore action type during enumeration.
        template.actionMask = 0xFFFFFFFF;

        let mut enum_handle = HANDLE::default();

        let r = unsafe {
            FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle)
        };
        if r != ERROR_SUCCESS.0 {
            warn!(
                error = format!("0x{:08X}", r),
                "sweep_stale_filters: FwpmFilterCreateEnumHandle0 failed — \
                 stale filters may cause ALREADY_EXISTS on first run"
            );
            return 0;
        }

        let mut deleted = 0usize;

        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;

            let r = unsafe {
                FwpmFilterEnum0(
                    engine,
                    enum_handle,
                    ENUM_BATCH_SIZE,
                    &mut entries,
                    &mut returned,
                )
            };

            if r != ERROR_SUCCESS.0 {
                warn!(
                    error = format!("0x{:08X}", r),
                    "sweep_stale_filters: FwpmFilterEnum0 failed"
                );
                break;
            }

            if returned == 0 || entries.is_null() {
                break;
            }

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
                    if r != ERROR_SUCCESS.0 {
                        warn!(
                            filter_id,
                            name  = %name,
                            error = format!("0x{:08X}", r),
                            "sweep_stale_filters: FwpmFilterDeleteById0 failed"
                        );
                    } else {
                        deleted += 1;
                    }
                }
            }

            unsafe { FwpmFreeMemory0(&mut (entries as *mut _)) };

            if returned < ENUM_BATCH_SIZE {
                break;
            }
        }

        let r = unsafe { FwpmFilterDestroyEnumHandle0(engine, enum_handle) };
        if r != ERROR_SUCCESS.0 {
            warn!(
                error = format!("0x{:08X}", r),
                "sweep_stale_filters: FwpmFilterDestroyEnumHandle0 failed"
            );
        }

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

        let result = Self::add_filters_inner(engine, ip);
        match &result {
            Ok(_)  => unsafe { FwpmTransactionCommit0(engine); },
            Err(_) => unsafe { FwpmTransactionAbort0(engine); },
        }
        result
    }

    #[cfg(target_os = "windows")]
    fn add_filters_inner(engine: HANDLE, ip: &IpAddr) -> Result<WfpPair, BlockerError> {
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
                let ptr  = Box::into_raw(arr);
                let mut cv: FWP_CONDITION_VALUE0 = unsafe { mem::zeroed() };
                cv.r#type = FWP_BYTE_ARRAY16_TYPE;
                unsafe { cv.Anonymous.byteArray16 = ptr; }
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, cv)
            }
        };

        let connect_id = Self::install_one(
            engine, connect_layer, &cond_value,
            &format!("RUBIX-OUT-{}\0", ip),
        );
        let recv_id = Self::install_one(
            engine, recv_layer, &cond_value,
            &format!("RUBIX-IN-{}\0",  ip),
        );

        if let IpAddr::V6(_) = ip {
            unsafe {
                let ptr = cond_value.Anonymous.byteArray16;
                if !ptr.is_null() { drop(Box::from_raw(ptr)); }
            }
        }

        Ok(WfpPair { connect_id: connect_id?, recv_id: recv_id? })
    }

    // ── FIX-4: Filter weight ────────────────────────────────────────────────
    //
    // FWP_UINT32 is NOT a valid weight type.  Valid types: FWP_UINT64,
    // FWP_EMPTY (auto), or FWP_UINT8 (range).  We use FWP_EMPTY — WFP
    // auto-generates a weight in [0, 2^60), which is simpler and avoids
    // weight collision issues entirely.
    #[cfg(target_os = "windows")]
    fn install_one(
        engine:       HANDLE,
        layer_key:    windows::core::GUID,
        cond_value:   &FWP_CONDITION_VALUE0,
        display_name: &str,
    ) -> Result<u64, BlockerError> {
        use std::mem;

        let wide: Vec<u16> = display_name
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();

        let mut cond = FWPM_FILTER_CONDITION0 {
            fieldKey:       FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType:      FWP_MATCH_EQUAL,
            conditionValue: *cond_value,
        };

        let mut f: FWPM_FILTER0 = unsafe { mem::zeroed() };
        f.displayData.name    = windows::core::PWSTR(wide.as_ptr() as *mut u16);
        f.layerKey            = layer_key;
        f.action.r#type       = FWP_ACTION_BLOCK;
        f.numFilterConditions = 1;
        f.filterCondition     = &mut cond;
        // FIX-4: FWP_EMPTY = auto-weight.  WFP picks a unique weight.
        f.weight.r#type       = FWP_EMPTY;

        let mut filter_id: u64 = 0;
        let r = unsafe {
            FwpmFilterAdd0(engine, &f, None, Some(&mut filter_id))
        };

        if r != ERROR_SUCCESS.0 {
            return Err(BlockerError::WfpError(
                format!(
                    "FwpmFilterAdd0 ({}): 0x{:08X}",
                    display_name.trim_end_matches('\0'),
                    r
                )
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
            let r = unsafe { FwpmFilterDeleteById0(engine, id) };
            if r != ERROR_SUCCESS.0 {
                warn!(
                    filter_id = id,
                    error     = format!("0x{:08X}", r),
                    "FwpmFilterDeleteById0 failed"
                );
            }
        }
    }

    // ── Force removal by IP (targeted sweep) ────────────────────────────────

    #[cfg(target_os = "windows")]
    fn force_remove_by_ip(&self, engine: HANDLE, ip: &IpAddr) -> usize {
        use std::mem;

        let out_name = format!("RUBIX-OUT-{}", ip);
        let in_name  = format!("RUBIX-IN-{}",  ip);

        // FIX-3: actionMask = 0xFFFFFFFF to ignore action type.
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { mem::zeroed() };
        template.actionMask = 0xFFFFFFFF;

        let mut enum_handle = HANDLE::default();

        let r = unsafe {
            FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle)
        };
        if r != ERROR_SUCCESS.0 {
            warn!(
                error = format!("0x{:08X}", r),
                "force_remove_by_ip: FwpmFilterCreateEnumHandle0 failed"
            );
            return 0;
        }

        let mut deleted = 0usize;

        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;

            let r = unsafe {
                FwpmFilterEnum0(
                    engine,
                    enum_handle,
                    ENUM_BATCH_SIZE,
                    &mut entries,
                    &mut returned,
                )
            };

            if r != ERROR_SUCCESS.0 {
                warn!(
                    error = format!("0x{:08X}", r),
                    "force_remove_by_ip: FwpmFilterEnum0 failed"
                );
                break;
            }

            if returned == 0 || entries.is_null() {
                break;
            }

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

                if name == out_name || name == in_name {
                    let r = unsafe { FwpmFilterDeleteById0(engine, filter.filterId) };
                    if r == ERROR_SUCCESS.0 {
                        deleted += 1;
                    } else {
                        warn!(
                            filter_id = filter.filterId,
                            name      = %name,
                            error     = format!("0x{:08X}", r),
                            "force_remove_by_ip: FwpmFilterDeleteById0 failed"
                        );
                    }
                }
            }

            unsafe { FwpmFreeMemory0(&mut (entries as *mut _)) };

            if returned < ENUM_BATCH_SIZE {
                break;
            }
        }

        let r = unsafe { FwpmFilterDestroyEnumHandle0(engine, enum_handle) };
        if r != ERROR_SUCCESS.0 {
            warn!(
                error = format!("0x{:08X}", r),
                "force_remove_by_ip: FwpmFilterDestroyEnumHandle0 failed"
            );
        }

        deleted
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
                BlockOrigin::Manual =>
                    if permanent { "permanent-block".into() }
                    else {
                        format!(
                            "timed-block-{}s",
                            duration.unwrap_or_default().as_secs()
                        )
                    },
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

    async fn block_ip_with_origin(
        &self, ip: IpAddr, origin: BlockOrigin,
    ) -> Result<String, BlockerError> {
        self.do_block(ip, None, origin)
    }

    async fn block_ip_timed(
        &self, ip: IpAddr, duration: Duration,
    ) -> Result<String, BlockerError> {
        self.do_block(ip, Some(duration), BlockOrigin::Manual)
    }

    async fn unblock_ip(&self, ip: IpAddr) -> Result<bool, BlockerError> {
        match self.rules.write().remove(&ip) {
            None => {
                warn!(ip = %ip, "Unblock: IP not tracked");
                Ok(false)
            }
            Some(r) => {
                self.ip_cache.remove(&ip);
                self.remove_filters(&r.pair);
                info!(ip = %ip, "WFP block removed");
                Ok(true)
            }
        }
    }

    async fn force_unblock_ip(&self, ip: IpAddr) -> Result<(), BlockerError> {
        if self.unblock_ip(ip).await? {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            let raw = *self.engine.lock();
            if raw != NULL_HANDLE {
                let engine = HANDLE(raw as *mut _);
                let deleted = self.force_remove_by_ip(engine, &ip);
                if deleted > 0 {
                    info!(ip = %ip, count = deleted, "Force-removed orphaned WFP filters");
                }
            }
        }

        self.ip_cache.remove(&ip);
        Ok(())
    }

    async fn is_blocked(&self, ip: &IpAddr) -> Result<bool, BlockerError> {
        if self.ip_cache.contains(ip) { return Ok(true); }
        Ok(self.rules.read().contains_key(ip))
    }

    async fn list_rules(&self) -> Result<Vec<BlockRule>, BlockerError> {
        let mut list: Vec<BlockRule> = self.rules.read()
            .values()
            .map(|a| a.block_rule.clone())
            .collect();
        list.sort_by(|a, b| {
            b.expires_at.is_none().cmp(&a.expires_at.is_none())
                .then(a.created_at.cmp(&b.created_at))
        });
        Ok(list)
    }

    async fn cleanup(&self) -> Result<(), BlockerError> {
        let rules: Vec<ActiveIpRule> = self.rules.write()
            .drain()
            .map(|(_, v)| v)
            .collect();

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