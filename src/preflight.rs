// src/preflight.rs
//! Pre-flight checks — runs synchronously before ANY other subsystem starts.
//!
//! Called as the very first statement in main() before tokio, logger, config,
//! or any other initialisation.  If any check fails the process prints a clear
//! human-readable error and exits with code 1.  No panics, no tracing output,
//! no JSON — just plain terminal text the operator can read immediately.
//!
//! Checks performed (in order):
//!   1. Administrator / root privilege
//!   2. Packet-capture library present (Npcap on Windows, libpcap on Linux)
//!
//! Both checks are synchronous and allocation-minimal — they complete in < 5 ms
//! and impose zero overhead on the normal fast path.

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all pre-flight checks.
///
/// If every check passes this function returns normally and the daemon
/// continues to start.  If any check fails it prints a diagnostic message
/// and calls `std::process::exit(1)` — it never panics or returns an error.
///
/// Call this as the absolute first line of `main()` before any other code.
pub fn run() {
    check_privilege();
    check_capture_library();
}

// ═════════════════════════════════════════════════════════════════════════════
//  CHECK 1 — Administrator / root privilege
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn check_privilege() {
    if is_admin_windows() {
        return;
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║               RUBIX  —  ADMINISTRATOR REQUIRED                      ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                      ║");
    eprintln!("║  RUBIX needs Administrator privileges to:                            ║");
    eprintln!("║    • Open raw network sockets via Npcap                              ║");
    eprintln!("║    • Install and remove Windows Filtering Platform (WFP) rules       ║");
    eprintln!("║    • Read process network tables (GetExtendedTcpTable)               ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  HOW TO FIX:                                                         ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Option 1 — Right-click the terminal icon and choose                 ║");
    eprintln!("║             \"Run as Administrator\", then run RUBIX again.            ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Option 2 — From an elevated PowerShell or CMD:                      ║");
    eprintln!("║             .\\rubix.exe                                               ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Option 3 — Right-click rubix.exe → Properties → Compatibility       ║");
    eprintln!("║             → tick \"Run this program as an administrator\".           ║");
    eprintln!("║                                                                      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn is_admin_windows() -> bool {
    // IsUserAnAdmin() — simplest correct UAC elevation check.
    // Returns non-zero only when the current token has the Administrators
    // group active (i.e. UAC elevation has been granted).
    //
    // windows-sys 0.52 exposes this under Win32_UI_Shell.
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(target_os = "linux")]
fn check_privilege() {
    if is_root_linux() || has_required_capabilities() {
        return;
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                 RUBIX  —  ROOT / CAP_NET_RAW REQUIRED               ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                      ║");
    eprintln!("║  RUBIX needs elevated privileges to:                                 ║");
    eprintln!("║    • Open raw packet sockets (AF_PACKET / libpcap)                  ║");
    eprintln!("║    • Install and remove nftables / iptables firewall rules           ║");
    eprintln!("║    • Read /proc/net/tcp for process-socket attribution               ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  HOW TO FIX — choose ONE of these options:                           ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Option 1 — Run with sudo (simplest):                                ║");
    eprintln!("║             sudo ./rubix                                              ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Option 2 — Grant capabilities (no full root, recommended):          ║");
    eprintln!("║             sudo setcap cap_net_raw,cap_net_admin=eip ./rubix        ║");
    eprintln!("║             ./rubix                                                   ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Option 3 — Install system-wide then grant capabilities:             ║");
    eprintln!("║             sudo install -m 755 ./rubix /usr/local/bin/              ║");
    eprintln!("║             sudo setcap cap_net_raw,cap_net_admin=eip \\              ║");
    eprintln!("║                          /usr/local/bin/rubix                        ║");
    eprintln!("║                                                                      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn is_root_linux() -> bool {
    // SAFETY: getuid() is always safe — no preconditions, no failure mode.
    unsafe { libc::getuid() == 0 }
}

#[cfg(target_os = "linux")]
fn has_required_capabilities() -> bool {
    // capget(2) — read effective capability set of the current thread.
    // We need CAP_NET_RAW (13) for raw packet capture and
    // CAP_NET_ADMIN (12) for firewall rule installation.
    use libc::{capget, __user_cap_header_struct, __user_cap_data_struct};

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW:   u32 = 13;

    let mut header = __user_cap_header_struct {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [__user_cap_data_struct {
        effective: 0, permitted: 0, inheritable: 0,
    }; 2];

    // SAFETY: capget is a well-defined Linux syscall with valid pointers.
    let rc = unsafe { capget(&mut header, data.as_mut_ptr()) };
    if rc != 0 { return false; }

    let eff_low       = data[0].effective;
    let has_net_raw   = (eff_low >> CAP_NET_RAW)   & 1 == 1;
    let has_net_admin = (eff_low >> CAP_NET_ADMIN)  & 1 == 1;
    has_net_raw && has_net_admin
}

// ═════════════════════════════════════════════════════════════════════════════
//  CHECK 2 — Packet capture library present
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn check_capture_library() {
    if npcap_installed() {
        return;
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║               RUBIX  —  NPCAP NOT FOUND                             ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                      ║");
    eprintln!("║  RUBIX requires Npcap to capture network packets on Windows.         ║");
    eprintln!("║  Do NOT install WinPcap — it is unmaintained and broken on          ║");
    eprintln!("║  Windows 10 and 11.                                                  ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  HOW TO INSTALL NPCAP:                                               ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  1. Open your browser and go to:                                     ║");
    eprintln!("║       https://npcap.com/#download                                    ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  2. Download the Npcap installer  (npcap-X.XX.exe)                   ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  3. Run the installer as Administrator.                               ║");
    eprintln!("║     IMPORTANT — tick this checkbox during install:                   ║");
    eprintln!("║       [✓] Install Npcap in WinPcap API-compatible Mode               ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  4. Restart your terminal / PowerShell session.                      ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  5. Run RUBIX again as Administrator.                                 ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Expected DLL location after install:                                ║");
    eprintln!("║    C:\\Windows\\System32\\Npcap\\wpcap.dll                             ║");
    eprintln!("║    C:\\Windows\\System32\\wpcap.dll  (WinPcap-compat mode)            ║");
    eprintln!("║                                                                      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn npcap_installed() -> bool {
    // Probe for wpcap.dll using LoadLibraryW.
    //
    // FIX: In windows-sys 0.52, LoadLibraryW returns isize (the raw HMODULE),
    // not a pointer type — so .is_null() does not exist.  The null sentinel
    // for HMODULE in this crate version is 0isize.
    //
    // FIX: FreeLibrary in windows-sys 0.52 is in Win32::Foundation, not in
    // Win32::System::LibraryLoader.  Import from the correct module.
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    use windows_sys::Win32::Foundation::FreeLibrary;

    let candidates: &[&str] = &[
        // Npcap default install location
        "C:\\Windows\\System32\\Npcap\\wpcap.dll",
        // WinPcap-compatible install location
        "C:\\Windows\\System32\\wpcap.dll",
    ];

    for path in candidates {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: LoadLibraryW is a standard Win32 API.  wide is a valid
        // null-terminated UTF-16 string.  We immediately free the handle.
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };

        // In windows-sys 0.52 HMODULE is isize.  Null = 0.
        if handle != 0 {
            unsafe { FreeLibrary(handle) };
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn check_capture_library() {
    if libpcap_present() {
        return;
    }

    let install_cmd = detect_package_manager_install_cmd();

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║               RUBIX  —  LIBPCAP NOT FOUND                           ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                      ║");
    eprintln!("║  RUBIX requires libpcap to capture network packets on Linux.         ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  HOW TO INSTALL LIBPCAP:                                             ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  Detected package manager command:                                   ║");
    eprintln!("║    {:<68}║", format!("  {}", install_cmd));
    eprintln!("║                                                                      ║");
    eprintln!("║  Manual options by distribution:                                     ║");
    eprintln!("║    Debian / Ubuntu : sudo apt-get install -y libpcap-dev             ║");
    eprintln!("║    Fedora / RHEL   : sudo dnf install -y libpcap-devel               ║");
    eprintln!("║    Arch Linux      : sudo pacman -S libpcap                          ║");
    eprintln!("║    Alpine          : sudo apk add libpcap-dev                        ║");
    eprintln!("║    openSUSE        : sudo zypper install libpcap-devel               ║");
    eprintln!("║                                                                      ║");
    eprintln!("║  After installing, run RUBIX again.                                  ║");
    eprintln!("║                                                                      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn libpcap_present() -> bool {
    const RTLD_LAZY:  libc::c_int = 0x0001;
    const RTLD_LOCAL: libc::c_int = 0x0000;

    let candidates: &[&[u8]] = &[
        b"libpcap.so.1\0",
        b"libpcap.so\0",
        b"libpcap.so.0.8\0",
    ];

    for name in candidates {
        // SAFETY: dlopen is a standard POSIX API.  name is a valid
        // null-terminated C string.  We immediately call dlclose.
        let handle = unsafe {
            libc::dlopen(
                name.as_ptr() as *const libc::c_char,
                RTLD_LAZY | RTLD_LOCAL,
            )
        };
        if !handle.is_null() {
            unsafe { libc::dlclose(handle) };
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn detect_package_manager_install_cmd() -> &'static str {
    let managers: &[(&str, &str)] = &[
        ("apt-get", "sudo apt-get install -y libpcap-dev"),
        ("apt",     "sudo apt install -y libpcap-dev"),
        ("dnf",     "sudo dnf install -y libpcap-devel"),
        ("yum",     "sudo yum install -y libpcap-devel"),
        ("pacman",  "sudo pacman -S libpcap"),
        ("apk",     "sudo apk add libpcap-dev"),
        ("zypper",  "sudo zypper install libpcap-devel"),
        ("emerge",  "sudo emerge net-libs/libpcap"),
    ];

    for (binary, cmd) in managers {
        let paths = [
            format!("/usr/bin/{}", binary),
            format!("/usr/local/bin/{}", binary),
            format!("/bin/{}", binary),
        ];
        for path in &paths {
            // SAFETY: access(2) is a standard POSIX API.  F_OK = 0.
            let c_path = std::ffi::CString::new(path.as_str()).unwrap();
            if unsafe { libc::access(c_path.as_ptr(), libc::F_OK) } == 0 {
                return cmd;
            }
        }
    }

    "sudo apt-get install -y libpcap-dev  (adjust for your distribution)"
}