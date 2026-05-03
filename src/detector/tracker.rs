//! Per-IP state tracker for scan/ping detection
//! Tracks packet history per source IP with sliding time windows

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

// ── Thresholds ────────────────────────────────────────────────────────────────

/// How long to track state per IP
pub const TRACK_WINDOW_SECS: u64 = 10;

/// Unique ports hit within window to trigger scan alert
pub const SCAN_PORT_THRESHOLD: usize = 15;

/// ICMP packets within window to trigger ping sweep alert  
pub const PING_THRESHOLD: usize = 5;

/// SYN packets per second to trigger flood alert
pub const SYN_FLOOD_THRESHOLD: u64 = 100;

/// Sequential ports to detect sequential scan
pub const SEQUENTIAL_PORT_THRESHOLD: usize = 10;

// ── Per-IP state ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct IpState {
    // Port scan tracking
    pub ports_hit:        HashSet<u16>,        // Unique ports contacted
    pub syn_times:        VecDeque<Instant>,   // Timestamps of SYN packets
    pub port_history:     VecDeque<u16>,       // Recent port sequence
    pub tcp_flags_seen:   HashSet<u8>,         // Flag combinations seen

    // ICMP tracking
    pub icmp_times:       VecDeque<Instant>,   // Timestamps of ICMP packets
    pub icmp_count:       u64,

    // General
    pub first_seen:       Instant,
    pub last_seen:        Instant,
    pub total_packets:    u64,
    pub alerted:          HashSet<String>,     // Alerts already fired (dedup)
}

impl IpState {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            ports_hit:      HashSet::with_capacity(64),
            syn_times:      VecDeque::with_capacity(128),
            port_history:   VecDeque::with_capacity(64),
            tcp_flags_seen: HashSet::with_capacity(8),
            icmp_times:     VecDeque::with_capacity(32),
            icmp_count:     0,
            first_seen:     now,
            last_seen:      now,
            total_packets:  0,
            alerted:        HashSet::with_capacity(8),
        }
    }

    /// Remove entries older than the tracking window
    pub fn evict_old(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        while self.syn_times.front().map(|t| *t < cutoff).unwrap_or(false) {
            self.syn_times.pop_front();
        }
        while self.icmp_times.front().map(|t| *t < cutoff).unwrap_or(false) {
            self.icmp_times.pop_front();
        }
    }

    /// SYN rate in the current window
    pub fn syn_rate(&self) -> u64 {
        self.syn_times.len() as u64
    }

    /// Check if a specific alert has already been fired
    pub fn already_alerted(&mut self, key: &str) -> bool {
        if self.alerted.contains(key) {
            true
        } else {
            self.alerted.insert(key.to_string());
            false
        }
    }

    /// Check if port sequence is sequential (nmap default behavior)
    pub fn has_sequential_ports(&self) -> bool {
        if self.port_history.len() < SEQUENTIAL_PORT_THRESHOLD {
            return false;
        }

        let ports: Vec<u16> = self.port_history
            .iter()
            .rev()
            .take(SEQUENTIAL_PORT_THRESHOLD)
            .cloned()
            .collect();

        let mut sequential = 0;
        for i in 1..ports.len() {
            if ports[i].wrapping_sub(ports[i - 1]) <= 2 {
                sequential += 1;
            }
        }

        sequential >= SEQUENTIAL_PORT_THRESHOLD - 2
    }
}

// ── Threat tracker ────────────────────────────────────────────────────────────

pub struct ThreatTracker {
    states:        HashMap<IpAddr, IpState>,
    window:        Duration,
    last_eviction: Instant,
}

impl ThreatTracker {
    pub fn new() -> Self {
        Self {
            states:        HashMap::with_capacity(256),
            window:        Duration::from_secs(TRACK_WINDOW_SECS),
            last_eviction: Instant::now(),
        }
    }

    /// Get or create state for an IP
    #[inline]
    pub fn get_or_create(&mut self, ip: IpAddr) -> &mut IpState {
        self.states.entry(ip).or_insert_with(IpState::new)
    }

    /// Periodically evict stale IPs (call every ~1000 packets)
    pub fn maybe_evict(&mut self) {
        if self.last_eviction.elapsed().as_secs() < 30 {
            return;
        }

        let window    = self.window;
        let cutoff    = Instant::now() - window * 3; // Keep 3x window for history
        self.states.retain(|_, state| state.last_seen > cutoff);

        // Evict old entries within kept states
        for state in self.states.values_mut() {
            state.evict_old(window);
        }

        self.last_eviction = Instant::now();
    }

    pub fn active_ips(&self) -> usize {
        self.states.len()
    }
}