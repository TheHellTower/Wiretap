//! Windows platform facts: version and support policy, driver-loading posture (elevation,
//! test signing, Memory Integrity, Secure Boot) and NT device to drive-letter mapping.
//!
//! The support matrix lives in `docs/compatibility/windows.md`; keep both in sync.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    detect, dos_devices, keepalive, posture, process_image, process_session, random, tcp_owner,
};

/// Facts that decide whether and how a kernel driver can be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Posture {
    /// The process runs with an elevated (Administrator) token.
    pub elevated: bool,
    /// Test signing is enabled (`bcdedit /set testsigning on`).
    pub test_signing: bool,
    /// Memory Integrity (HVCI) enforces kernel code integrity.
    pub memory_integrity: bool,
    /// UEFI Secure Boot state; `None` on legacy BIOS systems.
    pub secure_boot: Option<bool>,
}

/// Facts about the running operating system that decide support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsInfo {
    /// Major version (10 for both Windows 10 and Windows 11).
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Build number (Windows 11 starts at 22000).
    pub build: u32,
    /// `true` for client editions, `false` for Windows Server.
    pub workstation: bool,
    /// `true` when the native machine architecture is x64 (not ARM64 emulating x64).
    pub native_x64: bool,
}

/// Windows client release family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Windows {
    /// Windows 10.
    Ten,
    /// Windows 11.
    Eleven,
}

/// Outcome of the support policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// A validated build on the support matrix.
    Supported(Windows),
    /// Newer than the newest validated build: expected to work, not yet verified.
    Untested(Windows),
    /// Outside the support matrix, with the reason.
    Unsupported(&'static str),
}

/// Oldest supported Windows 10 build (21H2, Enterprise LTSC 2021).
pub const MIN_WINDOWS_10: u32 = 19044;
/// Final Windows 10 build (22H2).
pub const LAST_WINDOWS_10: u32 = 19045;
/// Oldest supported Windows 11 build (24H2).
pub const MIN_WINDOWS_11: u32 = 26100;
/// Newest validated Windows 11 build (25H2).
pub const LAST_VALIDATED_WINDOWS_11: u32 = 26200;

/// Applies the support policy. Never reports an unvalidated build as supported.
#[must_use]
pub const fn classify(os: &OsInfo) -> Support {
    if !os.native_x64 {
        return Support::Unsupported("only x64 Windows is supported");
    }
    if !os.workstation {
        return Support::Unsupported("Windows Server editions are not supported");
    }
    if os.major != 10 || os.minor != 0 {
        return Support::Unsupported("only Windows 10 and Windows 11 are supported");
    }
    match os.build {
        MIN_WINDOWS_10..=LAST_WINDOWS_10 => Support::Supported(Windows::Ten),
        MIN_WINDOWS_11..=LAST_VALIDATED_WINDOWS_11 => Support::Supported(Windows::Eleven),
        b if b > LAST_VALIDATED_WINDOWS_11 => Support::Untested(Windows::Eleven),
        _ => Support::Unsupported("this Windows build is not on the support matrix"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(build: u32) -> OsInfo {
        OsInfo {
            major: 10,
            minor: 0,
            build,
            workstation: true,
            native_x64: true,
        }
    }

    #[test]
    fn support_matrix() {
        use Support::*;
        use Windows::*;
        // 1809/LTSC 2019, 2004, 21H1, Windows 11 21H2/22H2/23H2, pre-24H2 Insider.
        for build in [17763, 19041, 19043, 22000, 22621, 22631, 26099] {
            assert!(
                matches!(classify(&os(build)), Unsupported(_)),
                "build {build}"
            );
        }
        assert_eq!(classify(&os(19044)), Supported(Ten));
        assert_eq!(classify(&os(19045)), Supported(Ten));
        assert_eq!(classify(&os(26100)), Supported(Eleven));
        assert_eq!(classify(&os(26200)), Supported(Eleven));
        assert_eq!(classify(&os(26201)), Untested(Eleven));
        assert_eq!(classify(&os(28000)), Untested(Eleven));
        assert_eq!(classify(&os(u32::MAX)), Untested(Eleven));
    }

    #[test]
    fn rejects_non_client_or_non_x64() {
        let server = OsInfo {
            workstation: false,
            ..os(26100)
        };
        let arm = OsInfo {
            native_x64: false,
            ..os(26100)
        };
        let vista = OsInfo {
            major: 6,
            minor: 0,
            ..os(6002)
        };
        for o in [server, arm, vista] {
            assert!(matches!(classify(&o), Support::Unsupported(_)), "{o:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn attributes_tcp_connections_to_this_process() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (local, remote) = (client.local_addr().unwrap(), client.peer_addr().unwrap());
        assert_eq!(super::tcp_owner(local, remote), Some(std::process::id()));
        let image = super::process_image(std::process::id()).unwrap();
        assert!(image.to_ascii_lowercase().ends_with(".exe"), "{image}");
        assert_eq!(
            super::tcp_owner(remote, local),
            Some(std::process::id()),
            "server side too"
        );
    }

    #[cfg(windows)]
    #[test]
    fn finds_process_sessions() {
        assert_eq!(
            super::process_session(4),
            Some(0),
            "the System process, session 0"
        );
        assert!(super::process_session(std::process::id()).is_some());
        assert_eq!(
            super::process_session(u32::MAX - 3),
            None,
            "no such process"
        );
    }

    #[cfg(windows)]
    #[test]
    fn turns_keepalive_on() {
        use std::time::Duration;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        super::keepalive(&client, Duration::from_secs(30), Duration::from_secs(5)).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn system_random_bytes_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        super::random(&mut a).unwrap();
        super::random(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }

    #[cfg(windows)]
    #[test]
    fn reads_posture_and_drive_mapping() {
        let _ = super::posture(); // must not fail or panic, elevated or not
        let devices = super::dos_devices();
        assert!(
            devices
                .iter()
                .any(|(nt, drive)| drive == "C:" && nt.starts_with(r"\Device\")),
            "{devices:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn detects_running_os() {
        let o = super::windows::detect().expect("version query");
        assert_eq!((o.major, o.minor), (10, 0), "{o:?}");
        assert!(o.build >= 10240, "{o:?}");
    }
}
