# Windows compatibility

## Support matrix

Encoded in `crates/wiretap-platform/src/lib.rs` (`classify`). Keep the two in sync.

| Windows | Build | Status | Microsoft servicing (as of November 2026) |
| --- | --- | --- | --- |
| Windows 10 Enterprise LTSC 2021 / IoT LTSC 2021 | 19044 | Supported | LTSC 2021 until January 2027 (IoT until 2032) |
| Windows 10 22H2 | 19045 | Supported | Extended Security Updates until October 2027 |
| Windows 11 24H2 | 26100 | Supported | Enterprise/Education until October 2027 |
| Windows 11 25H2 | 26200 | Supported | Until October 2027 (Home/Pro), October 2028 (Enterprise) |
| Newer Windows 11 builds | > 26200 | Untested | Expected to work; not yet validated |
| Windows 11 21H2–23H2, Windows 10 ≤ 21H1 | — | Unsupported | Out of servicing or ending |
| Windows Server, ARM64, 32-bit | — | Unsupported | — |

`wiretap check` reports the classification. Unsupported systems aren't blocked, but Wiretap never claims they work.

## Requirements by feature

| Feature | Requirement |
| --- | --- |
| Driver allocation API (`ExAllocatePool2`) | Windows 10 2004 (19041) or newer; covered by the matrix |
| Driver catalog | `Inf2Cat` targets 10_VB (2004+), 10_CO, 10_NI, 10_GE |
| Driver loading | Microsoft-signed driver (release), or test signing with Secure Boot off (lab) |
| Memory Integrity (HVCI) | Supported: NX pool only, no writable-executable sections |
| `wiretap.exe` | Any supported build; static C runtime, no Visual C++ Redistributable needed |

## Verification status

| Environment | Result |
| --- | --- |
| Windows 11 25H2 (26200) host | User-mode tests, platform detection, CLI; driver not loaded (Secure Boot on, by design) |
| Windows 11 build 22621 Hyper-V VM (test signing, Driver Verifier) | Install, capture, stress, crash recovery and unload: passed (build outside the matrix) |
| Windows Sandbox (26100) | Package installs; driver not loadable (no boot configuration store for test signing). Found the static-CRT requirement |
| Windows 10 22H2 / LTSC 2021 | Not yet tested |
| Windows 11 24H2 / 25H2 VM with the driver | Not yet tested |
