// src/detector/tracker.rs
//! Per-IP state tracker — lock-free, fixed-capacity, zero-allocation hot path.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;

use crate::detector::{AlertKey, ALERT_KEY_COUNT};

// ── Detection thresholds ──────────────────────────────────────────────────────

pub const TRACK_WINDOW_SECS:         u64   = 10;
pub const SCAN_PORT_THRESHOLD:       u32   = 20;
pub const PING_THRESHOLD:            u32   = 8;
pub const SYN_FLOOD_THRESHOLD:       u32   = 200;
pub const SEQUENTIAL_PORT_THRESHOLD: u32   = 12;
pub const MAX_PORTS_TRACKED:         usize = 64;
pub const MAX_HISTORY_LEN:           usize = 64;
pub const MAX_SYN_TRACKED:           usize = 256;
pub const MAX_ICMP_TRACKED:          usize = 128;
pub const ACK_SCAN_PORT_THRESHOLD:   u32   = 8;

// ── Whitelist ─────────────────────────────────────────────────────────────────

static WHITELIST_NETWORKS: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    let nets: &[&str] = &[
        // Google DNS / services
        "8.8.8.0/24", "8.8.4.0/24", "142.250.0.0/15", "172.217.0.0/16",
        "216.58.0.0/16", "74.125.0.0/16", "108.177.0.0/17", "209.85.0.0/16",
        // Cloudflare DNS / CDN
        "1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/13", "172.64.0.0/13",
        "162.158.0.0/15", "108.162.0.0/16", "131.0.72.0/22",
        "162.159.0.0/16",
        // GitHub
        "140.82.112.0/20", "192.30.252.0/22", "185.199.108.0/22",
        // Microsoft / Azure
        "13.64.0.0/11", "13.104.0.0/14", "20.0.0.0/8", "40.0.0.0/8",
        "52.0.0.0/8", "104.40.0.0/13", "131.253.0.0/16", "150.171.0.0/16",
        "168.61.0.0/16", "191.232.0.0/13", "204.79.197.0/24",
        // Apple
        "17.0.0.0/8", "63.92.0.0/16",
        // Facebook / Meta
        "31.13.0.0/16", "157.240.0.0/16", "173.252.0.0/16",
        // Fastly / Akamai
        "151.101.0.0/16", "146.75.0.0/16", "104.28.0.0/16",
        // Amazon AWS
        "3.0.0.0/8", "52.94.0.0/16", "54.0.0.0/8", "99.0.0.0/8",
        // Akamai / Limelight
        "23.0.0.0/8", "104.0.0.0/8", "184.0.0.0/8",
        // Twitter
        "104.244.0.0/16", "192.133.0.0/16",
        // Netflix
        "23.246.0.0/16", "37.77.0.0/16", "45.57.0.0/16", "108.175.0.0/16",
        "78.31.0.0/16", "193.182.0.0/16",
        // Zoom
        "66.22.0.0/16",
        // Steam
        "108.174.0.0/16", "144.2.0.0/16",
        // RFC-1918 private + loopback + link-local + multicast
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    ];
    nets.iter().filter_map(|s| s.parse().ok()).collect()
});

#[inline(always)]
pub fn is_whitelisted(ip: IpAddr) -> bool {
    if let IpAddr::V4(v4) = ip {
        let o = v4.octets();
        if o[0] == 127
            || o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
        {
            return true;
        }
    }
    WHITELIST_NETWORKS.iter().any(|net| net.contains(ip))
}

// ── Process trust — exact name matching ───────────────────────────────────────

static HIGHLY_TRUSTED_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // Browsers
        "chrome.exe", "chrome", "firefox.exe", "firefox",
        "msedge.exe", "msedge", "brave.exe", "brave",
        "opera.exe", "opera", "vivaldi.exe", "vivaldi",
        "safari", "arc.exe", "arc",
        // Windows system
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
        "csrss.exe", "smss.exe", "winlogon.exe", "explorer.exe",
        "dwm.exe", "taskhostw.exe", "RuntimeBroker.exe",
        "MicrosoftEdgeUpdate.exe", "WUDFHost.exe", "spoolsv.exe",
        "SecurityHealthService.exe", "MpDefenderCoreService.exe",
        "MsMpEng.exe", "NisSrv.exe", "SgrmBroker.exe",
        "OfficeClickToRun.exe",
        // Linux system
        "systemd", "NetworkManager", "dhclient", "dhcpcd",
        "chronyd", "ntpd", "resolved", "avahi-daemon",
        // Communication / productivity
        "teams.exe", "teams", "slack.exe", "slack",
        "discord.exe", "discord", "zoom.exe", "zoom",
        "outlook.exe", "outlook", "onedrive.exe", "onedrive",
        // Dev tools
        "code.exe", "code", "cursor.exe", "cursor",
        "devenv.exe", "devenv", "idea64.exe", "idea",
        "rider64.exe", "clion64.exe", "pycharm64.exe",
        "goland64.exe", "webstorm64.exe",
        "steam.exe", "steam",
        "rubix.exe", "rubix",
        "dropbox.exe", "dropbox",
        // Claude
        "claude.exe", "claude",
    ]
    .iter().copied().collect()
});

static MEDIUM_TRUST_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // Background/update processes
        "SearchApp.exe", "SearchIndexer.exe",
        "backgroundTaskHost.exe", "backgroundTransferHost.exe",
        "AppVShNotify.exe", "WmiPrvSE.exe", "dllhost.exe",
        "conhost.exe", "fontdrvhost.exe",
        "PerfWatson2.exe", "DiagTrack",
        // Dev runtimes
        "node.exe", "node", "python.exe", "python", "python3",
        "ruby.exe", "ruby", "java.exe", "java",
        "cargo.exe", "cargo", "rustc.exe",
        "git.exe", "git",
        "ssh.exe", "ssh", "sshd",
        "curl.exe", "curl", "wget",
        // Shell
        "powershell.exe", "powershell", "pwsh.exe", "pwsh",
        "cmd.exe", "bash", "zsh", "sh",
        // Terminal
        "WindowsTerminal.exe", "wt.exe",
        "wezterm.exe", "alacritty.exe",
        // System utilities
        "msedgewebview2.exe", "msedge.exe",
        "System", "Registry",
    ]
    .iter().copied().collect()
});

#[inline(always)]
pub fn is_highly_trusted_process(name: &str) -> bool {
    HIGHLY_TRUSTED_NAMES.contains(name)
}

#[inline(always)]
pub fn is_medium_trust_process(name: &str) -> bool {
    MEDIUM_TRUST_NAMES.contains(name)
}

// ── IpState ───────────────────────────────────────────────────────────────────

pub struct IpState {
    pub ports_hit:      HashSet<u16>,
    pub port_history:   Vec<u16>,
    pub syn_times:      Vec<Instant>,
    pub icmp_times:     Vec<Instant>,
    pub tcp_flags_raw:  [u8; 16],
    pub tcp_flags_cnt:  u8,
    pub icmp_count:     u64,
    pub total_packets:  u64,
    pub first_seen:     Instant,
    pub last_seen:      Instant,
    alert_times:        [Option<Instant>; ALERT_KEY_COUNT],
}

impl IpState {
    #[inline(always)]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            ports_hit:     HashSet::with_capacity(16),
            port_history:  Vec::with_capacity(32),
            syn_times:     Vec::with_capacity(32),
            icmp_times:    Vec::with_capacity(16),
            tcp_flags_raw: [0u8; 16],
            tcp_flags_cnt: 0,
            icmp_count:    0,
            total_packets: 0,
            first_seen:    now,
            last_seen:     now,
            alert_times:   [None; ALERT_KEY_COUNT],
        }
    }

    #[inline(always)]
    pub fn touch(&mut self) {
        self.last_seen     = Instant::now();
        self.total_packets += 1;
    }

    #[inline(always)]
    pub fn record_flags(&mut self, flag_byte: u8) {
        for i in 0..self.tcp_flags_cnt as usize {
            if self.tcp_flags_raw[i] == flag_byte {
                return;
            }
        }
        if (self.tcp_flags_cnt as usize) < self.tcp_flags_raw.len() {
            self.tcp_flags_raw[self.tcp_flags_cnt as usize] = flag_byte;
            self.tcp_flags_cnt += 1;
        }
    }

    /// Returns true if this alert kind is in cooldown (suppressed).
    /// Records the alert time when NOT suppressed.
    #[inline(always)]
    pub fn is_suppressed(&mut self, key: AlertKey, cooldown_secs: u64) -> bool {
        let idx = key as usize;
        let now = Instant::now();
        let cooldown = Duration::from_secs(cooldown_secs);

        if let Some(last) = self.alert_times[idx] {
            if now.saturating_duration_since(last) < cooldown {
                return true;
            }
        }
        self.alert_times[idx] = Some(now);
        false
    }

    #[inline]
    pub fn evict_old(&mut self, window: Duration) {
        let cutoff = Instant::now()
            .checked_sub(window)
            .unwrap_or_else(Instant::now);

        let keep = self.syn_times.partition_point(|&t| t < cutoff);
        if keep > 0 { self.syn_times.drain(0..keep); }

        let keep = self.icmp_times.partition_point(|&t| t < cutoff);
        if keep > 0 { self.icmp_times.drain(0..keep); }
    }

    #[inline]
    pub fn has_sequential_ports(&self) -> bool {
        let hist = &self.port_history;
        if hist.len() < SEQUENTIAL_PORT_THRESHOLD as usize {
            return false;
        }

        let mut scratch = [0u16; 64];
        let mut scratch_len = 0usize;

        'outer: for &port in hist.iter().rev() {
            for i in 0..scratch_len {
                if scratch[i] == port { continue 'outer; }
            }
            if scratch_len < 64 {
                scratch[scratch_len] = port;
                scratch_len += 1;
            }
        }

        if scratch_len < SEQUENTIAL_PORT_THRESHOLD as usize {
            return false;
        }

        let mut max_run: u32 = 1;
        let mut cur_run: u32 = 1;

        for i in 1..scratch_len {
            if scratch[i - 1].abs_diff(scratch[i]) == 1 {
                cur_run += 1;
                if cur_run > max_run { max_run = cur_run; }
            } else {
                cur_run = 1;
            }
        }

        max_run >= SEQUENTIAL_PORT_THRESHOLD
    }

    #[inline(always)]
    pub fn weird_flag_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.tcp_flags_cnt as usize {
            let f = self.tcp_flags_raw[i];
            count += matches!(f, 0x00 | 0x01 | 0x29 | 0x3F) as u32;
        }
        count
    }

    #[inline(always)]
    pub fn cap_growth(&mut self) {
        if self.ports_hit.len() > MAX_PORTS_TRACKED {
            self.ports_hit.clear();
            self.port_history.clear();
        } else if self.port_history.len() > MAX_HISTORY_LEN {
            let drain = self.port_history.len() - MAX_HISTORY_LEN;
            self.port_history.drain(0..drain);
        }
        if self.syn_times.len() > MAX_SYN_TRACKED {
            let drain = self.syn_times.len() - MAX_SYN_TRACKED;
            self.syn_times.drain(0..drain);
        }
        if self.icmp_times.len() > MAX_ICMP_TRACKED {
            let drain = self.icmp_times.len() - MAX_ICMP_TRACKED;
            self.icmp_times.drain(0..drain);
        }
    }
}

// ── ThreatTracker ─────────────────────────────────────────────────────────────

pub struct ThreatTracker {
    states:           std::collections::HashMap<IpAddr, IpState>,
    window:           Duration,
    last_eviction:    Instant,
    eviction_counter: u64,
}

impl ThreatTracker {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            states:           std::collections::HashMap::with_capacity(256),
            window:           Duration::from_secs(TRACK_WINDOW_SECS),
            last_eviction:    Instant::now(),
            eviction_counter: 0,
        }
    }

    #[inline(always)]
    pub fn get_or_create(&mut self, ip: IpAddr) -> &mut IpState {
        self.states.entry(ip).or_insert_with(IpState::new)
    }

    #[inline]
    pub fn maybe_evict(&mut self) {
        self.eviction_counter += 1;
        if self.eviction_counter & 0x3FF != 0 { return; }
        if self.last_eviction.elapsed().as_secs() < 60 { return; }

        let cutoff = Instant::now()
            .checked_sub(self.window * 3)
            .unwrap_or_else(Instant::now);

        self.states.retain(|_, s| s.last_seen > cutoff);

        let window = self.window;
        for state in self.states.values_mut() {
            state.evict_old(window);
            state.cap_growth();
        }

        self.last_eviction = Instant::now();
    }

    #[inline(always)]
    pub fn active_ips(&self) -> usize {
        self.states.len()
    }
}