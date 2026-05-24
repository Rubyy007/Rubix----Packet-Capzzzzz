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
//! FIX: has_required_capabilities() no longer uses libc::capget /
//! libc::__user_cap_header_struct / libc::__user_cap_data_struct — those
//! types are not exposed by the libc crate.  Instead we define the structs
//! manually (matching linux/capability.h exactly) and invoke capget(2) via
//! libc::syscall with SYS_capget.  This is the standard approach used by
//! the `caps` crate and other Linux capability libraries.

pub fn run() {
    check_privilege();
    check_capture_library();
}

// ═════════════════════════════════════════════════════════════════════════════
//  CHECK 1 — Administrator / root privilege
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn check_privilege() {
    if is_admin_windows() { return; }

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
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(target_os = "linux")]
fn check_privilege() {
    if is_root_linux() || has_required_capabilities() { return; }

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
    // SAFETY: getuid() is always safe.
    unsafe { libc::getuid() == 0 }
}

#[cfg(target_os = "linux")]
fn has_required_capabilities() -> bool {
    // The libc crate does NOT expose capget(2) structs directly.
    // We define them manually from linux/capability.h and call
    // capget via libc::syscall(SYS_capget, ...).
    //
    // This matches the approach used by the `caps` crate internally.
    //
    // Struct layout (from linux/capability.h, unchanged since Linux 2.6.26):
    //   __user_cap_header_struct { __u32 version; int pid; }
    //   __user_cap_data_struct   { __u32 effective; __u32 permitted; __u32 inheritable; }
    //
    // Version _LINUX_CAPABILITY_VERSION_3 = 0x20080522 covers all 64 caps
    // in two consecutive __user_cap_data_struct elements.

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid:     i32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective:   u32,
        permitted:   u32,
        inheritable: u32,
    }

    const VERSION_3:   u32 = 0x20080522;
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW:   u32 = 13;
    // SYS_capget on x86_64 = 125, on aarch64 = 90, on i686 = 184.
    // libc::SYS_capget is the correct portable constant — use it directly.

    let mut header = CapHeader { version: VERSION_3, pid: 0 };
    // Two elements: [0] = caps 0-31, [1] = caps 32-63.
    // CAP_NET_ADMIN=12 and CAP_NET_RAW=13 are both in element [0].
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];

    // SAFETY: SYS_capget is a well-defined Linux syscall.
    //   arg1: pointer to CapHeader (matches kernel ABI for version 3)
    //   arg2: pointer to CapData[2] (two elements for the 64-bit cap set)
    // Both pointers are valid stack references for the duration of the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };

    if rc != 0 {
        // syscall failed — assume no capabilities rather than panicking.
        return false;
    }

    let eff           = data[0].effective;
    let has_net_raw   = (eff >> CAP_NET_RAW)   & 1 == 1;
    let has_net_admin = (eff >> CAP_NET_ADMIN)  & 1 == 1;
    has_net_raw && has_net_admin
}

// ═════════════════════════════════════════════════════════════════════════════
//  CHECK 2 — Packet capture library present
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn check_capture_library() {
    if npcap_installed() { return; }

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
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    let candidates: &[&str] = &[
        "C:\\Windows\\System32\\Npcap\\wpcap.dll",
        "C:\\Windows\\System32\\wpcap.dll",
    ];

    for path in candidates {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: LoadLibraryW is a standard Win32 API.
        // HMODULE in windows-sys 0.52 is isize; null sentinel = 0.
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        if handle != 0 {
            unsafe { FreeLibrary(handle) };
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn check_capture_library() {
    if libpcap_present() { return; }

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
        // SAFETY: dlopen is a standard POSIX API.
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
            let c_path = std::ffi::CString::new(path.as_str()).unwrap();
            // SAFETY: access(2) is a standard POSIX API.  F_OK = 0.
            if unsafe { libc::access(c_path.as_ptr(), libc::F_OK) } == 0 {
                return cmd;
            }
        }
    }

    "sudo apt-get install -y libpcap-dev  (adjust for your distribution)"
}