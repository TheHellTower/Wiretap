//! Win32 queries. Read-only: nothing here changes system state (only options of the
//! caller's own sockets).
#![allow(
    unsafe_code,
    reason = "read-only Win32 queries with locally owned out-parameters"
)]

use std::io;
use std::mem::zeroed;
use std::ptr::null_mut;

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemCodeIntegrityInformation,
};
use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SIO_KEEPALIVE_VALS, SOCKET, WSAIoctl, tcp_keepalive,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFOW, WTSEnumerateProcessesExW, WTSFreeMemoryExW,
    WTSTypeProcessInfoLevel0,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, OSVERSIONINFOEXW, OSVERSIONINFOW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, IsWow64Process2, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_CODEINTEGRITY_INFORMATION;

use crate::{OsInfo, Posture};

const VER_NT_WORKSTATION: u8 = 1;
const CODEINTEGRITY_OPTION_TESTSIGN: u32 = 0x2;
const CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED: u32 = 0x400;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn size_u32<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

/// Reads the real OS version (`RtlGetVersion` is not subject to manifest-based version lies)
/// and the native machine architecture.
///
/// # Errors
/// Returns the OS error if either query fails.
pub fn detect() -> io::Result<OsInfo> {
    // SAFETY: OSVERSIONINFOEXW consists only of integers and integer arrays; all-zero is valid.
    let mut v: OSVERSIONINFOEXW = unsafe { zeroed() };
    v.dwOSVersionInfoSize = size_u32::<OSVERSIONINFOEXW>();
    // SAFETY: `v` is writable and its size field identifies the extended structure, which
    // RtlGetVersion accepts in place of OSVERSIONINFOW.
    let status = unsafe { RtlGetVersion((&raw mut v).cast::<OSVERSIONINFOW>()) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "RtlGetVersion failed: NTSTATUS {status:#010x}"
        )));
    }
    let (mut process, mut native) = (0u16, 0u16);
    // SAFETY: GetCurrentProcess returns an always-valid pseudo-handle; both out-pointers
    // reference live locals.
    if unsafe { IsWow64Process2(GetCurrentProcess(), &raw mut process, &raw mut native) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OsInfo {
        major: v.dwMajorVersion,
        minor: v.dwMinorVersion,
        build: v.dwBuildNumber,
        workstation: v.wProductType == VER_NT_WORKSTATION,
        native_x64: native == IMAGE_FILE_MACHINE_AMD64,
    })
}

/// Reports elevation, test signing, Memory Integrity and Secure Boot. Unknown facts read as
/// `false` (or `None` for Secure Boot) rather than failing.
#[must_use]
pub fn posture() -> Posture {
    let options = code_integrity_options().unwrap_or(0);
    Posture {
        elevated: elevated(),
        test_signing: options & CODEINTEGRITY_OPTION_TESTSIGN != 0,
        memory_integrity: options & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED != 0,
        secure_boot: secure_boot(),
    }
}

fn code_integrity_options() -> Option<u32> {
    let mut info = SYSTEM_CODEINTEGRITY_INFORMATION {
        Length: size_u32::<SYSTEM_CODEINTEGRITY_INFORMATION>(),
        CodeIntegrityOptions: 0,
    };
    // SAFETY: `info` is a correctly sized, writable buffer for this information class.
    let status = unsafe {
        NtQuerySystemInformation(
            SystemCodeIntegrityInformation,
            (&raw mut info).cast(),
            size_u32::<SYSTEM_CODEINTEGRITY_INFORMATION>(),
            null_mut(),
        )
    };
    (status >= 0).then_some(info.CodeIntegrityOptions)
}

fn elevated() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: pseudo-handle for the current process; `token` receives a new handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: `elevation` is a writable TOKEN_ELEVATION of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_u32::<TOKEN_ELEVATION>(),
            &mut len,
        )
    };
    // SAFETY: `token` was opened above.
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}

fn secure_boot() -> Option<bool> {
    let key = wide(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
    let value = wide("UEFISecureBootEnabled");
    let mut data = 0u32;
    let mut size = size_u32::<u32>();
    // SAFETY: NUL-terminated names; `data` is a writable DWORD of `size` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&raw mut data).cast(),
            &mut size,
        )
    };
    (status == 0).then_some(data != 0)
}

/// Maps NT device names to drive letters, e.g. `(\Device\HarddiskVolume3, C:)`.
#[must_use]
pub fn dos_devices() -> Vec<(String, String)> {
    (b'A'..=b'Z')
        .filter_map(|letter| {
            let drive = format!("{}:", char::from(letter));
            let name = wide(&drive);
            let mut buf = [0u16; 1024];
            // SAFETY: NUL-terminated device name; `buf` is writable for its full length.
            let n = unsafe {
                QueryDosDeviceW(
                    name.as_ptr(),
                    buf.as_mut_ptr(),
                    size_u32::<[u16; 1024]>() / 2,
                )
            };
            let len = usize::try_from(n).ok()?;
            let target = buf
                .get(..len)?
                .split(|&c| c == 0)
                .next()
                .filter(|t| !t.is_empty())?;
            Some((String::from_utf16_lossy(target), drive))
        })
        .collect()
}

/// Fills `buf` with cryptographically secure random bytes from the system RNG.
///
/// # Errors
/// The NTSTATUS of a failed `BCryptGenRandom` call.
pub fn random(buf: &mut [u8]) -> io::Result<()> {
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        // SAFETY: `chunk` is writable for `len` bytes; no algorithm handle with the
        // system-preferred RNG flag.
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                chunk.as_mut_ptr(),
                len,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(io::Error::other(format!(
                "BCryptGenRandom failed: NTSTATUS {status:#010x}"
            )));
        }
    }
    Ok(())
}

/// Reads the system TCP table for one address family as rows of `R`.
fn tcp_table<R: Copy>(family: u16) -> Option<Vec<R>> {
    let mut size = 0u32;
    for _ in 0..4 {
        // Vec<u32> keeps the buffer 4-byte aligned for the table header and rows.
        let mut buf = vec![0u32; usize::try_from(size).ok()?.div_ceil(4).max(1)];
        let mut len = u32::try_from(buf.len() * 4).ok()?;
        // SAFETY: `buf` is writable for `len` bytes; the API writes at most `len` bytes or
        // reports the required size.
        let status = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if status == 0 {
            let count = usize::try_from(*buf.first()?).ok()?;
            let available = (usize::try_from(len).ok()?.saturating_sub(4)) / size_of::<R>();
            let rows = count.min(available);
            // SAFETY: the table header is one u32 followed by `count` rows of `R`, which
            // are 4-byte aligned plain data; `rows` never exceeds what the API wrote.
            let slice =
                unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<R>(), rows) };
            return Some(slice.to_vec());
        }
        size = len.max(size.saturating_add(4096));
    }
    None
}

/// Port fields hold a network-order u16 in their low bytes.
fn port(field: u32) -> u16 {
    u16::from_be(u16::try_from(field & 0xFFFF).unwrap_or(0))
}

/// PID owning the TCP connection whose local and remote endpoints are `local` and `remote`
/// (as seen by that process). Used to attribute proxy clients to applications.
#[must_use]
pub fn tcp_owner(local: std::net::SocketAddr, remote: std::net::SocketAddr) -> Option<u32> {
    use std::net::SocketAddr::{V4, V6};
    match (local, remote) {
        (V4(l), V4(r)) => tcp_table::<MIB_TCPROW_OWNER_PID>(AF_INET)?
            .into_iter()
            .find(|row| {
                row.dwLocalAddr == u32::from_ne_bytes(l.ip().octets())
                    && port(row.dwLocalPort) == l.port()
                    && row.dwRemoteAddr == u32::from_ne_bytes(r.ip().octets())
                    && port(row.dwRemotePort) == r.port()
            })
            .map(|row| row.dwOwningPid),
        (V6(l), V6(r)) => tcp_table::<MIB_TCP6ROW_OWNER_PID>(AF_INET6)?
            .into_iter()
            .find(|row| {
                row.ucLocalAddr == l.ip().octets()
                    && port(row.dwLocalPort) == l.port()
                    && row.ucRemoteAddr == r.ip().octets()
                    && port(row.dwRemotePort) == r.port()
            })
            .map(|row| row.dwOwningPid),
        _ => None,
    }
}

/// Turns TCP keepalive on for `socket`: a probe after `idle` without traffic, then one every
/// `interval` (Windows gives up after 10), so a connection whose peer vanished fails instead of
/// waiting forever.
///
/// # Errors
/// Returns the OS error if the socket refuses the setting.
pub fn keepalive(
    socket: &std::net::TcpStream,
    idle: std::time::Duration,
    interval: std::time::Duration,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    let ms = |d: std::time::Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
    let values = tcp_keepalive {
        onoff: 1,
        keepalivetime: ms(idle),
        keepaliveinterval: ms(interval),
    };
    let raw = SOCKET::try_from(socket.as_raw_socket()).map_err(io::Error::other)?;
    let mut returned = 0u32;
    // SAFETY: a synchronous call (no OVERLAPPED) on a socket the borrow keeps open; `values` and
    // `returned` outlive it.
    let status = unsafe {
        WSAIoctl(
            raw,
            SIO_KEEPALIVE_VALS,
            (&raw const values).cast(),
            size_u32::<tcp_keepalive>(),
            null_mut(),
            0,
            &raw mut returned,
            null_mut(),
            None,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `WTS_ANY_SESSION` of `wtsapi32.h`: every session.
const WTS_ANY_SESSION: u32 = 0xFFFF_FFFE;

/// Windows session of process `pid` (services run in session 0), if it is running. Read from
/// the Remote Desktop Services process list, which covers elevated and protected processes
/// without opening them.
#[must_use]
pub fn process_session(pid: u32) -> Option<u32> {
    let (mut level, mut list, mut count) = (0u32, null_mut::<WTS_PROCESS_INFOW>(), 0u32);
    // SAFETY: valid out pointers; on success the list is freed below.
    let ok = unsafe {
        WTSEnumerateProcessesExW(
            WTS_CURRENT_SERVER_HANDLE,
            &mut level,
            WTS_ANY_SESSION,
            (&raw mut list).cast(),
            &mut count,
        )
    };
    if ok == 0 || list.is_null() {
        return None;
    }
    // SAFETY: Remote Desktop Services returned `count` level-0 entries at `list`.
    let entries = unsafe { std::slice::from_raw_parts(list, usize::try_from(count).unwrap_or(0)) };
    let session = entries
        .iter()
        .find(|p| p.ProcessId == pid)
        .map(|p| p.SessionId);
    // SAFETY: frees the list returned above, with its type and entry count.
    unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel0, list.cast(), count) };
    session
}

/// Full image path of process `pid`, if it can be queried.
#[must_use]
pub fn process_image(pid: u32) -> Option<String> {
    // SAFETY: requests the least privileged query right; the handle is checked and closed.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` holds `len` UTF-16 units; `handle` is valid until closed below.
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    // SAFETY: `handle` was opened above.
    unsafe { CloseHandle(handle) };
    let len = usize::try_from(len).ok()?;
    (ok != 0).then(|| String::from_utf16_lossy(buf.get(..len).unwrap_or_default()))
}
