//! Per-IP state tracker — lock-free, fixed-capacity, zero-allocation hot path

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;

// ── Thresholds ────────────────────────────────────────────────────────────────

pub const TRACK_WINDOW_SECS: u64         = 10;
pub const SCAN_PORT_THRESHOLD: u32        = 20;
pub const PING_THRESHOLD: u32            = 8;
pub const SYN_FLOOD_THRESHOLD: u32      = 200;
pub const SEQUENTIAL_PORT_THRESHOLD: u32 = 12;
pub const ALERT_COOLDOWN_SECS: u64      = 300;
pub const MAX_PORTS_TRACKED: usize       = 64;
pub const MAX_HISTORY_LEN: usize         = 64;
pub const MAX_SYN_TRACKED: usize         = 256;
pub const MAX_ICMP_TRACKED: usize        = 128;

// ── Whitelist ─────────────────────────────────────────────────────────────────

static WHITELIST_NETWORKS: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    let nets: &[&str] = &[
        "8.8.8.0/24", "8.8.4.0/24", "142.250.0.0/15", "172.217.0.0/16",
        "216.58.0.0/16", "74.125.0.0/16", "108.177.0.0/17", "209.85.0.0/16",
        "1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/13", "172.64.0.0/13",
        "162.158.0.0/15", "108.162.0.0/16", "131.0.72.0/22",
        "140.82.112.0/20", "192.30.252.0/22", "185.199.108.0/22",
        "13.64.0.0/11", "13.104.0.0/14", "20.0.0.0/8", "40.0.0.0/8",
        "52.0.0.0/8", "104.40.0.0/13", "131.253.0.0/16", "150.171.0.0/16",
        "168.61.0.0/16", "191.232.0.0/13", "204.79.197.0/24",
        "17.0.0.0/8", "63.92.0.0/16", "104.28.0.0/16",
        "31.13.0.0/16", "157.240.0.0/16", "173.252.0.0/16",
        "151.101.0.0/16", "146.75.0.0/16",
        "3.0.0.0/8", "52.94.0.0/16", "54.0.0.0/8", "99.0.0.0/8",
        "23.0.0.0/8", "104.0.0.0/8", "184.0.0.0/8",
        "104.244.0.0/16", "192.133.0.0/16",
        "23.246.0.0/16", "37.77.0.0/16", "45.57.0.0/16", "108.175.0.0/16",
        "78.31.0.0/16", "193.182.0.0/16",
        "162.159.0.0/16", "66.22.0.0/16",
        "108.174.0.0/16", "144.2.0.0/16",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    ];
    nets.iter().filter_map(|s| s.parse().ok()).collect()
});

#[inline(always)]
pub fn is_whitelisted(ip: IpAddr) -> bool {
    WHITELIST_NETWORKS.iter().any(|net| net.contains(ip))
}

// ── Process trust ─────────────────────────────────────────────────────────────

#[inline(always)]
pub fn is_highly_trusted_process(name: &str) -> bool {
    let name = name.as_bytes();
    match name.get(0..3) {
        Some(b"chr" | b"Chr") => true,
        Some(b"fir" | b"Fir") => true,
        Some(b"edg" | b"Edg") => true,
        Some(b"bra" | b"Bra") => true,
        Some(b"ope" | b"Ope") => true,
        Some(b"viv" | b"Viv") => true,
        Some(b"sve" | b"Sve") => true,
        Some(b"dll" | b"Dll") => true,
        Some(b"ser" | b"Ser") => true,
        Some(b"lsa" | b"Lsa") => true,
        Some(b"one" | b"One") => true,
        Some(b"tea" | b"Tea") => true,
        Some(b"sla" | b"Sla") => true,
        Some(b"dis" | b"Dis") => true,
        Some(b"zoo" | b"Zoo") => true,
        Some(b"ste" | b"Ste") => true,
        Some(b"cod" | b"Cod") => true,
        Some(b"cur" | b"Cur") => true,
        Some(b"cla" | b"Cla") => true,
        Some(b"dev" | b"Dev") => true,
        Some(b"jet" | b"Jet") => true,
        Some(b"pyt" | b"Pyt") => true,
        Some(b"ide" | b"Ide") => true,
        Some(b"rub" | b"Rub") => true,
        Some(b"msw" | b"Msw") => true,
        Some(b"goo" | b"Goo") => true,
        Some(b"dro" | b"Dro") => true,
        Some(b"epi" | b"Epi") => true,
        Some(b"web" | b"Web") => true,
        Some(b"tru" | b"Tru") => true,
        Some(b"tiw" | b"Tiw") => true,
        Some(b"uso" | b"Uso") => true,
        Some(b"win" | b"Win") => true,
        _ => false,
    }
}

#[inline(always)]
pub fn is_medium_trust_process(name: &str) -> bool {
    let name = name.as_bytes();
    match name.get(0..3) {
        Some(b"sea" | b"Sea") => true,
        Some(b"run" | b"Run") => true,
        Some(b"bac" | b"Bac") => true,
        Some(b"app" | b"App") => true,
        Some(b"she" | b"She") => true,
        Some(b"sta" | b"Sta") => true,
        Some(b"tex" | b"Tex") => true,
        Some(b"wid" | b"Wid") => true,
        Some(b"exp" | b"Exp") => true,
        Some(b"tas" | b"Tas") => true,
        Some(b"per" | b"Per") => true,
        Some(b"ser" | b"Ser") => true,
        Some(b"dot" | b"Dot") => true,
        Some(b"nod" | b"Nod") => true,
        Some(b"pyt" | b"Pyt") => true,
        Some(b"py." | b"Py.") => true,
        Some(b"car" | b"Car") => true,
        Some(b"rus" | b"Rus") => true,
        Some(b"go." | b"Go.") => true,
        Some(b"git" | b"Git") => true,
        Some(b"ssh" | b"Ssh") => true,
        Some(b"cur" | b"Cur") => true,
        Some(b"wge" | b"Wge") => true,
        _ => false,
    }
}

// ── IpState ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct IpState {
    pub ports_hit:        HashSet<u16>,
    pub syn_times:        Vec<Instant>,
    pub port_history:     Vec<u16>,
    pub tcp_flags_seen:   HashSet<u8>,
    pub icmp_times:       Vec<Instant>,
    pub icmp_count:       u64,
    pub first_seen:       Instant,
    pub last_seen:        Instant,
    pub total_packets:    u64,
    pub alerted:          HashSet<&'static str>,
    pub alerted_times:    HashMap<&'static str, Instant>,
}

impl IpState {
    #[inline(always)]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            ports_hit:      HashSet::with_capacity(16),
            syn_times:      Vec::with_capacity(32),
            port_history:   Vec::with_capacity(32),
            tcp_flags_seen: HashSet::with_capacity(4),
            icmp_times:     Vec::with_capacity(16),
            icmp_count:     0,
            first_seen:     now,
            last_seen:      now,
            total_packets:  0,
            alerted:        HashSet::with_capacity(4),
            alerted_times:  HashMap::with_capacity(4),
        }
    }

    #[inline(always)]
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.total_packets += 1;
    }

    /// Evict old entries — amortized, call every N packets
    #[inline]
    pub fn evict_old(&mut self, window: Duration) {
        let cutoff = Instant::now().checked_sub(window).unwrap_or(Instant::now());
        
        // Remove old SYN times
        let syn_len = self.syn_times.len();
        let syn_keep = self.syn_times.iter().rposition(|&t| t > cutoff);
        if let Some(keep) = syn_keep {
            let remove = syn_len - keep - 1;
            if remove > 0 {
                self.syn_times.drain(0..remove);
            }
        } else if syn_len > 0 {
            self.syn_times.clear();
        }

        // Remove old ICMP times
        let icmp_len = self.icmp_times.len();
        let icmp_keep = self.icmp_times.iter().rposition(|&t| t > cutoff);
        if let Some(keep) = icmp_keep {
            let remove = icmp_len - keep - 1;
            if remove > 0 {
                self.icmp_times.drain(0..remove);
            }
        } else if icmp_len > 0 {
            self.icmp_times.clear();
        }
    }

    #[inline(always)]
    pub fn syn_rate(&self) -> u32 {
        self.syn_times.len() as u32
    }

    /// Alert with cooldown — returns true if suppressed
    #[inline(always)]
    pub fn already_alerted(&mut self, key: &'static str) -> bool {
        let now = Instant::now();
        let cooldown = Duration::from_secs(ALERT_COOLDOWN_SECS);

        if let Some(&last) = self.alerted_times.get(key) {
            if now.saturating_duration_since(last) < cooldown {
                return true;
            }
        }

        self.alerted.insert(key);
        self.alerted_times.insert(key, now);
        false
    }

    /// Strict sequential: requires diff==1
    #[inline]
    pub fn has_sequential_ports(&self) -> bool {
        if self.port_history.len() < SEQUENTIAL_PORT_THRESHOLD as usize {
            return false;
        }

        let mut seen = HashSet::with_capacity(32);
        let mut unique: Vec<u16> = Vec::with_capacity(32);

        for &port in self.port_history.iter().rev() {
            if seen.insert(port) {
                unique.push(port);
                if unique.len() >= 32 {
                    break;
                }
            }
        }

        if unique.len() < SEQUENTIAL_PORT_THRESHOLD as usize {
            return false;
        }

        let mut max_run = 1u32;
        let mut current = 1u32;

        for i in 1..unique.len() {
            let a = unique[i - 1];
            let b = unique[i];
            if a.abs_diff(b) == 1 {
                current += 1;
                if current > max_run {
                    max_run = current;
                }
            } else {
                current = 1;
            }
        }

        max_run >= SEQUENTIAL_PORT_THRESHOLD
    }

    /// Count weird flag patterns
    #[inline(always)]
    pub fn weird_flag_count(&self) -> u32 {
        let mut count = 0u32;
        for &f in &self.tcp_flags_seen {
            count += ((f == 0x00) || (f == 0x01) || (f == 0x29) || (f == 0x3F)) as u32;
        }
        count
    }

    /// Cap growth to prevent memory bloat
    #[inline(always)]
    pub fn cap_growth(&mut self) {
        if self.ports_hit.len() > MAX_PORTS_TRACKED {
            self.ports_hit.clear();
            self.port_history.clear();
        }
        if self.syn_times.len() > MAX_SYN_TRACKED {
            self.syn_times.drain(0..self.syn_times.len() - MAX_SYN_TRACKED);
        }
        if self.icmp_times.len() > MAX_ICMP_TRACKED {
            self.icmp_times.drain(0..self.icmp_times.len() - MAX_ICMP_TRACKED);
        }
    }
}

// ── ThreatTracker ─────────────────────────────────────────────────────────────

pub struct ThreatTracker {
    states:           HashMap<IpAddr, IpState>,
    window:           Duration,
    last_eviction:    Instant,
    eviction_counter: u64,
}

impl ThreatTracker {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            states:           HashMap::with_capacity(256),
            window:           Duration::from_secs(TRACK_WINDOW_SECS),
            last_eviction:    Instant::now(),
            eviction_counter: 0,
        }
    }

    #[inline(always)]
    pub fn get_or_create(&mut self, ip: IpAddr) -> &mut IpState {
        // Use entry API to avoid double-borrow
        self.states.entry(ip).or_insert_with(IpState::new)
    }

    /// Amortized eviction — every 1024 calls or 60s
    #[inline]
    pub fn maybe_evict(&mut self) {
        self.eviction_counter += 1;
        if self.eviction_counter & 0x3FF != 0 {
            return;
        }
        if self.last_eviction.elapsed().as_secs() < 60 {
            return;
        }

        let cutoff = Instant::now() - self.window * 3;
        self.states.retain(|_, s| s.last_seen > cutoff);
        
        for state in self.states.values_mut() {
            state.evict_old(self.window);
            state.cap_growth();
        }

        self.last_eviction = Instant::now();
    }

    #[inline(always)]
    pub fn active_ips(&self) -> usize {
        self.states.len()
    }
}