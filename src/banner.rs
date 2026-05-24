// src/banner.rs
//! RUBIX banner — professional, theme‑aware, with your centered logo.
//! Supports 7 colour themes. Only ANSI colour codes change between them.

use crate::capture::CaptureFactory;
use crate::config::RubixConfig;
use tokio::time::{Duration, sleep};
use std::process::Command;

// ─────────────────────────────────────────────────────────────────────────────
//  TERMINAL CAPABILITY DETECTION (unchanged)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TermCaps {
    FullVt,      // Linux / macOS / Windows Terminal — full colour + Unicode
    VtNoBlocks,  // ConHost / legacy PowerShell — colour yes, ██ blocks no
    Plain,       // CMD without VT, pipes, CI — no colour, no Unicode
}

pub fn detect_and_init_terminal() -> TermCaps {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, SetConsoleOutputCP,
            STD_OUTPUT_HANDLE,
        };
        unsafe { SetConsoleOutputCP(65001) };
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let mut mode: u32 = 0;
        let vt_enabled = unsafe {
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | 0x0004) != 0
            } else {
                false
            }
        };
        if !vt_enabled { return TermCaps::Plain; }
        if std::env::var("WT_SESSION").is_ok() { TermCaps::FullVt }
        else { TermCaps::VtNoBlocks }
    }
    #[cfg(not(windows))]
    {
        match std::env::var("TERM").as_deref() {
            Ok("dumb") | Err(_) => TermCaps::Plain,
            _ => TermCaps::FullVt,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  THEME ENGINE — only colour codes differ
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub enum BannerStyle {
    CyanBlue         = 1,
    GreenOps         = 2,
    AmberAlert       = 3,
    MidnightAmethyst = 4,
    CrimsonDawn      = 5,
    CyberpunkNeon    = 6,
    ArcticFrost      = 7,
}

struct Theme {
    border:     &'static str,  // outer frame, logo lines
    accent:     &'static str,  // subtitles, status boxes, labels
    highlight:  &'static str,  // important values, gauge fill
    dim:        &'static str,  // secondary text
    threat_lvl: &'static str,  // displayed threat level string
}

impl Theme {
    fn for_style(style: BannerStyle) -> Self {
        match style {
            BannerStyle::CyanBlue => Theme {
                border:     "\x1b[96m",
                accent:     "\x1b[94m",
                highlight:  "\x1b[97m",
                dim:        "\x1b[90m",
                threat_lvl: "● MODERATE",
            },
            BannerStyle::GreenOps => Theme {
                border:     "\x1b[92m",
                accent:     "\x1b[97m",
                highlight:  "\x1b[92m",
                dim:        "\x1b[90m",
                threat_lvl: "● LOW",
            },
            BannerStyle::AmberAlert => Theme {
                border:     "\x1b[93m",
                accent:     "\x1b[91m",
                highlight:  "\x1b[93m",
                dim:        "\x1b[90m",
                threat_lvl: "● HIGH",
            },
            BannerStyle::MidnightAmethyst => Theme {
                border:     "\x1b[38;5;147m",
                accent:     "\x1b[38;5;55m",
                highlight:  "\x1b[38;5;207m",
                dim:        "\x1b[38;5;240m",
                threat_lvl: "✦ STEALTH",
            },
            BannerStyle::CrimsonDawn => Theme {
                border:     "\x1b[38;5;203m",
                accent:     "\x1b[38;5;160m",
                highlight:  "\x1b[38;5;196m",
                dim:        "\x1b[38;5;236m",
                threat_lvl: "⚠️  CRITICAL",
            },
            BannerStyle::CyberpunkNeon => Theme {
                border:     "\x1b[38;5;51m",
                accent:     "\x1b[38;5;165m",
                highlight:  "\x1b[38;5;226m",
                dim:        "\x1b[38;5;244m",
                threat_lvl: "⚡ ACTIVE",
            },
            BannerStyle::ArcticFrost => Theme {
                border:     "\x1b[38;5;255m",
                accent:     "\x1b[38;5;75m",
                highlight:  "\x1b[38;5;123m",
                dim:        "\x1b[38;5;250m",
                threat_lvl: "❄️  LOW",
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CENTERED LOGO (exactly as provided)
// ─────────────────────────────────────────────────────────────────────────────

async fn print_logo(theme: &Theme) {
    println!("{}", theme.border);
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                              ║");
    println!("║                ██████╗ ██╗   ██╗██████╗ ██╗██╗  ██╗                         ║");
    println!("║                ██╔══██╗██║   ██║██╔══██╗██║╚██╗██╔╝                         ║");
    println!("║                ██████╔╝██║   ██║██████╔╝██║ ╚███╔╝                          ║");
    println!("║                ██╔══██╗██║   ██║██╔══██╗██║ ██╔██╗                          ║");
    println!("║                ██║  ██║╚██████╔╝██████╔╝██║██╔╝ ██╗                         ║");
    println!("║                ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝                         ║");
    println!("║                                                                              ║");
    println!("{}", theme.accent);
    println!("║                      ╔════════════════════════════╗                          ║");
    println!("║                      ║   NETWORK DEFENCE SYSTEM   ║                          ║");
    println!("║                      ╚════════════════════════════╝                          ║");
    println!("{}", theme.dim);
    println!("║                                                                              ║");
    println!("║                 ◉ AI-Powered Threat Intelligence                            ║");
    println!("║                 ◉ Real-Time Packet Inspection                               ║");
    println!("║                 ◉ Zero-Trust Infrastructure Protection                      ║");
    println!("║                 ◉ SIEM / XDR Security Analytics                             ║");
    println!("║                 ◉ Adaptive Network Defense Engine                           ║");
    println!("║                                                                              ║");
    println!("{}", theme.accent);
    println!("║                    ┌──────────────────────────────┐                          ║");
    println!("║                    │  STATUS : ACTIVE             │                          ║");
    println!("║                    │  ENGINE : ONLINE             │                          ║");
    println!("║                    │  THREATS: MONITORING         │                          ║");
    println!("║                    └──────────────────────────────┘                          ║");
    println!("{}", theme.dim);
    println!("║                                                                              ║");
    println!("║                     [ ENCRYPT • DETECT • DEFEND ]                           ║");
    println!("║                                                                              ║");
    println!("{}", theme.highlight);
    println!("║                        RUBIX Sentinel SOC v1.0.0                             ║");
    println!("{}", theme.border);
    println!("║                                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!("\x1b[0m");
    sleep(Duration::from_millis(300)).await;
}

// ─────────────────────────────────────────────────────────────────────────────
//  SYSTEM INFO HELPERS
//
//  `hostname` crate deliberately NOT used — stdlib + one Command call only.
//  Zero new Cargo.toml dependency.
//
//  Hostname resolution order:
//    Linux   → /proc/sys/kernel/hostname (canonical, always present)
//              → $HOSTNAME (fallback)
//    Windows → %COMPUTERNAME% (always set by OS)
//              → %HOSTNAME%   (fallback)
//    other   → $HOSTNAME → `uname -n`
//
//  Kernel version:
//    Linux/macOS → `uname -r`
//    Windows     → %OS% env var
// ─────────────────────────────────────────────────────────────────────────────

fn get_system_info() -> (String, String) {
    // ── Hostname ──────────────────────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());

    #[cfg(target_os = "windows")]
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            Command::new("uname")
                .arg("-n")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // ── Kernel version ────────────────────────────────────────────────────────
    let kernel = if cfg!(target_os = "linux") {
        Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Linux".to_string())
    } else if cfg!(target_os = "macos") {
        Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Darwin".to_string())
    } else if cfg!(target_os = "windows") {
        std::env::var("OS").unwrap_or_else(|_| "Windows".to_string())
    } else {
        "Unknown".to_string()
    };

    (hostname, kernel)
}

fn security_gauge(rules_count: usize, kernel_rules: usize) -> String {
    let total  = (rules_count + kernel_rules).min(100);
    let filled = total / 10;
    let empty  = 10 - filled;
    format!("[{}>{}] {:3}%", "█".repeat(filled), "░".repeat(empty), total)
}

// ─────────────────────────────────────────────────────────────────────────────
//  THEME SELECTION MENU (7 options — unchanged)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn select_banner_style(caps: TermCaps) -> BannerStyle {
    use std::io::{self, Write};
    if caps == TermCaps::Plain {
        return BannerStyle::CyanBlue;
    }
    println!("\x1b[97m");
    println!("  +--------------------------------------------------+");
    println!("  |       RUBIX  --  Select Color Theme            |");
    println!("  +--------------------------------------------------+");
    println!("  |  \x1b[96m[1] Cyan / Blue   -- Classic (default)\x1b[97m        |");
    println!("  |  \x1b[92m[2] Green / White -- Matrix Ops       \x1b[97m        |");
    println!("  |  \x1b[93m[3] Amber / Red   -- Threat Alert     \x1b[97m        |");
    println!("  |  \x1b[38;5;147m[4] Midnight Amethyst -- Stealth Forensics\x1b[97m |");
    println!("  |  \x1b[38;5;203m[5] Crimson Dawn     -- Critical Incident\x1b[97m |");
    println!("  |  \x1b[38;5;51m[6] Cyberpunk Neon    -- Active Response\x1b[97m |");
    println!("  |  \x1b[38;5;255m[7] Arctic Frost      -- Compliance Audit\x1b[97m |");
    println!("  +--------------------------------------------------+");
    println!("\x1b[0m");
    print!("  Enter theme [1-7] (default 1, auto in 5s): ");
    let _ = io::stdout().flush();
    let choice = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).ok();
            buf.trim().to_string()
        }),
    ).await.ok().and_then(|r| r.ok()).unwrap_or_default();
    match choice.as_str() {
        "2" => { println!("  -> Green/White selected\n");       BannerStyle::GreenOps         }
        "3" => { println!("  -> Amber/Red selected\n");         BannerStyle::AmberAlert       }
        "4" => { println!("  -> Midnight Amethyst selected\n"); BannerStyle::MidnightAmethyst }
        "5" => { println!("  -> Crimson Dawn selected\n");      BannerStyle::CrimsonDawn      }
        "6" => { println!("  -> Cyberpunk Neon selected\n");    BannerStyle::CyberpunkNeon    }
        "7" => { println!("  -> Arctic Frost selected\n");      BannerStyle::ArcticFrost      }
        _   => { println!("  -> Cyan/Blue selected\n");         BannerStyle::CyanBlue         }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SHUTDOWN / OFFLINE BANNERS (unchanged)
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_shutdown_banner(caps: TermCaps) {
    match caps {
        TermCaps::FullVt | TermCaps::VtNoBlocks => {
            println!("\x1b[91m");
            println!("╔══════════════════════════════════════════════════════════════════════════════╗");
            println!("║                                                                              ║");
            println!("║                        RUBIX SENTINEL SOC SHUTDOWN                           ║");
            println!("║                                                                              ║");
            println!("╚══════════════════════════════════════════════════════════════════════════════╝");
            println!("\x1b[0m");
        }
        TermCaps::Plain => {
            println!();
            println!("================================================================================");
            println!("                       RUBIX SENTINEL SOC  --  SHUTDOWN");
            println!("================================================================================");
            println!();
        }
    }
}

pub fn print_offline_banner(caps: TermCaps) {
    match caps {
        TermCaps::FullVt | TermCaps::VtNoBlocks => {
            println!("\x1b[95m");
            println!("╔══════════════════════════════════════════════════════════════════════════════╗");
            println!("║                                                                              ║");
            println!("║                         RUBIX SENTINEL OFFLINE                              ║");
            println!("║                                                                              ║");
            println!("║                  All monitoring pipelines terminated                        ║");
            println!("║                  Kernel telemetry streams disconnected                      ║");
            println!("║                  Security services safely shut down                         ║");
            println!("║                                                                              ║");
            println!("║                     Stay safe out there, operator.                          ║");
            println!("║                                                                              ║");
            println!("╚══════════════════════════════════════════════════════════════════════════════╝");
            println!("\x1b[0m");
        }
        TermCaps::Plain => {
            println!("================================================================================");
            println!("  All monitoring pipelines terminated");
            println!("  Kernel telemetry streams disconnected");
            println!("  Security services safely shut down");
            println!("  Stay safe out there, operator.");
            println!("================================================================================");
            println!("                        RUBIX SENTINEL  --  OFFLINE");
            println!("================================================================================");
            println!();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN STARTUP BANNER
//
//  `dashboard_url` — `Some("http://127.0.0.1:7878")` when the HTTP dashboard
//  bound successfully; `None` when disabled or bind failed.
//
//  All existing panels and layout are pixel-identical to the design you
//  provided. Two additions only:
//    1. Dashboard row at the bottom of SYSTEM CONFIG
//    2. Dashboard URL hint line in the final startup messages block
// ─────────────────────────────────────────────────────────────────────────────

pub async fn print_banner(
    config:          &RubixConfig,
    rules_count:     usize,
    kernel_rules:    usize,
    interface:       &str,
    interface_label: &str,
    bpf_filter:      &str,
    malicious_ips:   &[String],
    configs_dir:     &std::path::Path,
    export_active:   bool,
    style:           BannerStyle,
    caps:            TermCaps,
    // Dashboard URL and session token — token printed ONCE, terminal only.
    dashboard_url:   Option<&str>,
    dashboard_token: Option<&str>,   // None when dashboard is disabled
) {
    let theme = Theme::for_style(style);

    // ── Logo (only on capable terminals) ──────────────────────────────────────
    match caps {
        TermCaps::Plain => {
            println!("================================================================================");
            println!("                          R U B I X   SENTINEL SOC  v1.0.0");
            println!("================================================================================");
            println!("  STATUS: ACTIVE  |  ENGINE: ONLINE  |  THREATS: MONITORING");
            println!("================================================================================");
            println!();
            sleep(Duration::from_millis(300)).await;
        }
        _ => print_logo(&theme).await,
    }

    // ── SYSTEM CONTEXT ────────────────────────────────────────────────────────
    let (hostname, kernel_ver) = get_system_info();
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    println!("{}┌─ SYSTEM CONTEXT ──────────────────────────────────────────────┐", theme.border);
    sleep(Duration::from_millis(80)).await;
    println!("{}│ Hostname       : {}{:<43} {}│", theme.accent, theme.highlight, hostname,   theme.accent);
    sleep(Duration::from_millis(80)).await;
    println!("{}│ Kernel         : {}{:<43} {}│", theme.accent, theme.highlight, kernel_ver, theme.accent);
    sleep(Duration::from_millis(80)).await;
    println!("{}│ Timestamp      : {}{:<43} {}│", theme.accent, theme.highlight, now,        theme.accent);
    sleep(Duration::from_millis(80)).await;
    println!("{}└──────────────────────────────────────────────────────────────┘", theme.border);
    println!();
    sleep(Duration::from_millis(200)).await;

    // ── SYSTEM CONFIG ─────────────────────────────────────────────────────────
    println!("{}┌─ SYSTEM CONFIG ──────────────────────────────────────────────┐", theme.border);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Mode           : {}{:<43} {}│", theme.accent, theme.highlight,
        config.mode.to_string(), theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Interface      : {}{:<43} {}│", theme.accent, theme.highlight,
        interface_label, theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Promiscuous    : {}{:<43} {}│", theme.accent, theme.highlight,
        if config.promiscuous { "ENABLED" } else { "DISABLED" }, theme.accent);
    sleep(Duration::from_millis(120)).await;
    let filter_display = if bpf_filter.len() > 43 {
        format!("{}...", &bpf_filter[..40])
    } else {
        bpf_filter.to_string()
    };
    println!("{}│ BPF Filter     : {}{:<43} {}│", theme.accent, theme.highlight,
        filter_display, theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Buffer Size    : {}{:<43} {}│", theme.accent, theme.highlight,
        format!("{} MB", config.buffer_size_mb), theme.accent);
    sleep(Duration::from_millis(120)).await;
    #[cfg(target_os = "linux")]
    println!("{}│ Platform       : {}{:<43} {}│", theme.accent, theme.highlight, "LINUX",   theme.accent);
    #[cfg(target_os = "windows")]
    println!("{}│ Platform       : {}{:<43} {}│", theme.accent, theme.highlight, "WINDOWS", theme.accent);
    sleep(Duration::from_millis(120)).await;
    #[cfg(unix)]
    println!("{}│ Control Socket : {}{:<43} {}│", theme.accent, theme.highlight,
        "/var/run/rubix.sock", theme.accent);
    #[cfg(windows)]
    println!("{}│ Control Socket : {}{:<43} {}│", theme.accent, theme.highlight,
        "127.0.0.1:9876", theme.accent);
    sleep(Duration::from_millis(120)).await;
    let configs_display = {
        let s = configs_dir.display().to_string();
        if s.len() > 43 { format!("...{}", &s[s.len().saturating_sub(40)..]) } else { s }
    };
    println!("{}│ Configs Dir    : {}{:<43} {}│", theme.accent, theme.highlight,
        configs_display, theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Normal Logging : {}{:<43} {}│", theme.accent, theme.highlight,
        if config.logging.log_normal_traffic {
            format!("ENABLED (1-in-{} sampling)", config.logging.normal_sample_divisor)
        } else {
            "DISABLED (set log_normal_traffic: true)".to_string()
        }, theme.accent);
    sleep(Duration::from_millis(80)).await;
    println!("{}│ Hot Reload     : {}{:<43} {}│", theme.accent, theme.highlight,
        "ENABLED (rules.yaml)", theme.accent);
    sleep(Duration::from_millis(80)).await;
    println!("{}│ Export         : {}{:<43} {}│", theme.accent, theme.highlight,
        if export_active { "ENABLED" } else { "DISABLED" }, theme.accent);
    sleep(Duration::from_millis(80)).await;
    // ── Dashboard row ─────────────────────────────────────────────────────────
    let dashboard_display = match dashboard_url {
        Some(url) => if url.len() > 43 { format!("{}...", &url[..40]) } else { url.to_string() },
        None      => "DISABLED".to_string(),
    };
    println!("{}│ Dashboard      : {}{:<43} {}│", theme.accent, theme.highlight,
        dashboard_display, theme.accent);
    // Token row — only shown when dashboard is active.
    // Token is printed in PLAIN TEXT here so the operator can copy it.
    // It is NOT sent to tracing, file logs, or any persistent store.
    if let Some(tok) = dashboard_token {
        // Show first 8 chars + "..." for the config row (full token in hints below).
        let tok_preview = format!("{}...", &tok[..8]);
        println!("{}│ Session Token  : {}{:<43} {}│", theme.accent, theme.highlight,
            tok_preview, theme.accent);
    }
    println!("{}└──────────────────────────────────────────────────────────────┘", theme.border);
    println!();
    sleep(Duration::from_millis(250)).await;

    // ── SECURITY STATUS (with posture gauge & threat level) ───────────────────
    let gauge = security_gauge(rules_count, kernel_rules);
    println!("{}┌─ SECURITY STATUS ────────────────────────────────────────────┐", theme.border);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Policy Rules    : {}{:<41} {}│", theme.accent, theme.highlight, rules_count,      theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Kernel Rules    : {}{:<41} {}│", theme.accent, theme.highlight, kernel_rules,     theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Posture Gauge   : {}{:<41} {}│", theme.accent, theme.highlight, gauge,            theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Threat Level    : {}{:<41} {}│", theme.accent, theme.highlight, theme.threat_lvl, theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Default Action  : {}{:<41} {}│", theme.accent, theme.highlight,
        config.blocking.default_action.to_uppercase(), theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Auto Cleanup    : {}{:<41} {}│", theme.accent, theme.highlight,
        if config.blocking.auto_cleanup { "ENABLED" } else { "DISABLED" }, theme.accent);
    sleep(Duration::from_millis(120)).await;
    println!("{}│ Block Timeout   : {}{:<41} {}│", theme.accent, theme.highlight,
        format!("{} sec", config.blocking.block_timeout_seconds), theme.accent);
    println!("{}└──────────────────────────────────────────────────────────────┘", theme.border);
    println!();
    sleep(Duration::from_millis(250)).await;

    // ── ACTIVE THREATS (if any) ───────────────────────────────────────────────
    if !malicious_ips.is_empty() {
        println!("{}┌─ ACTIVE THREATS ─────────────────────────────────────────────┐", theme.accent);
        sleep(Duration::from_millis(150)).await;
        println!("{}│ [!] {} IPs pre-blocked at kernel level{:>23} │",
            theme.highlight, malicious_ips.len(), "");
        for ip in malicious_ips.iter().take(5) {
            sleep(Duration::from_millis(80)).await;
            println!("{}│   + {}{:<57} │", theme.highlight, theme.dim, ip);
        }
        if malicious_ips.len() > 5 {
            sleep(Duration::from_millis(80)).await;
            println!("{}│   ... and {} more{:>39} │", theme.dim, malicious_ips.len() - 5, "");
        }
        println!("{}└──────────────────────────────────────────────────────────────┘", theme.accent);
        println!();
    }
    sleep(Duration::from_millis(250)).await;

    // ── NETWORK INTERFACES ────────────────────────────────────────────────────
    println!("{}┌─ NETWORK INTERFACES ─────────────────────────────────────────┐", theme.border);
    match CaptureFactory::list_interfaces() {
        Ok(interfaces) => {
            for iface in interfaces.iter().take(10) {
                let is_active    = iface.name == interface;
                let status       = if is_active { "(*) ACTIVE" } else { "( ) IDLE  " };
                let display_name = iface.description.as_deref().unwrap_or(&iface.name);
                let display_name = if display_name.len() > 28 {
                    format!("{}...", &display_name[..25])
                } else {
                    display_name.to_string()
                };
                sleep(Duration::from_millis(80)).await;
                println!("{}│ {:<10} {:<28} {:<20} │",
                    theme.dim, status, display_name,
                    format!("{} addrs", iface.addresses.len()));
            }
        }
        Err(e) => println!("{}│ [!] {:<56} │",
            theme.accent, format!("Interface error: {}", e)),
    }
    println!("{}└──────────────────────────────────────────────────────────────┘", theme.border);
    println!();
    sleep(Duration::from_millis(200)).await;

    // ── FINAL STARTUP MESSAGES ────────────────────────────────────────────────
    println!("{}[*] RUBIX ACTIVE — monitoring on {} (Ctrl+C to stop)",
        theme.highlight, interface_label);
    println!("{}[*] Run 'rubix-cli monitor' in another terminal for live stats",
        theme.dim);
    println!("{}[*] Run 'rubix-cli logs' for live log stream",
        theme.dim);
    println!("{}[*] Run 'rubix-cli logs normal' for normal traffic log",
        theme.dim);
    if export_active {
        println!("{}[*] Export pipeline active — events flowing to configured backends",
            theme.accent);
    }
    // ── Dashboard security block — printed last, most visible ──────────────────
    if let Some(url) = dashboard_url {
        match caps {
            TermCaps::Plain => {
                println!("[*] Dashboard  : {}  (open in browser)", url);
                if let Some(tok) = dashboard_token {
                    println!();
                    println!("╔══════════════════════════════════════════════════════════════╗");
                    println!("║  SESSION TOKEN (copy this — rotates on every restart)        ║");
                    println!("║                                                              ║");
                    println!("║  {}  ║", tok);
                    println!("║                                                              ║");
                    println!("╚══════════════════════════════════════════════════════════════╝");
                }
            }
            _ => {
                println!("{}[*] Dashboard  : {}{}{} — open in browser",
                    theme.highlight, theme.accent, url, theme.highlight);
                if let Some(tok) = dashboard_token {
                    println!();
                    println!("{}╔══════════════════════════════════════════════════════════════════╗", theme.border);
                    println!("{}║                                                                  ║", theme.border);
                    println!("{}║  {}SESSION TOKEN{}  (copy — rotates on every restart){}              ║",
                        theme.border, theme.highlight, theme.dim, theme.border);
                    println!("{}║                                                                  ║", theme.border);
                    println!("{}║  {}{}{:<64}{}  ║",
                        theme.border, "[1m", theme.highlight, tok, theme.border);
                    println!("{}║                                                                  ║", theme.border);
                    println!("{}╚══════════════════════════════════════════════════════════════════╝", theme.border);
                    println!("[0m");
                }
            }
        }
    }
    println!("\x1b[0m");
}