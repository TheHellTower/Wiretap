# WiretapDriver

## Why a driver

Windows doesn't let user-mode code see which process owns each new connection as it happens, or observe TCP stream bytes without being a proxy. The Windows Filtering Platform (WFP) exposes both through *callouts*, and callouts can only be registered by a kernel driver. Everything else (parsing, policy, storage, UI) stays in user mode.

## What it does

| Callout | Layer | Records |
| --- | --- | --- |
| flow v4/v6 | `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6` | 5-tuple, direction, PID, process image path (TCP, UDP, ICMP) |
| stream v4/v6 | `FWPM_LAYER_STREAM_V4/V6` | Up to 16 KiB of each TCP segment, at most 64 KiB per flow and direction |
| redirect v4/v6 | `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` | Nothing: while enabled, sends outbound TCP 80/443 to Wiretap's local proxy (transparent HTTPS decryption) |

The four capture callouts are **inspection** callouts:
- they always return `FWP_ACTION_CONTINUE`;
- they never block, modify, inject, redirect or reorder traffic;
- if a callout is missing, WFP simply skips its filter.

The two redirect callouts change only the destination of new outbound TCP connections to ports
80 and 443, and only while `IOCTL_SET_REDIRECT` has enabled them for one capture. They skip the
proxy's own connections, loopback and connections already redirected by anyone, and they fail
open: on any error the connection proceeds unchanged. Filters are permitted if the callout is
unregistered. QUIC (UDP 443) is blocked by a plain filter during such a capture, so browsers use
TCP.

Filters are added by `wiretap.exe` in a dynamic BFE session, never by the driver.

## Interface

| | |
| --- | --- |
| Device | `\Device\WiretapDriver` (`\\.\WiretapDriver`), exclusive (one open handle), `FILE_DEVICE_SECURE_OPEN` |
| ACL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)`: SYSTEM and Administrators only, applied by `IoCreateDeviceSecure` |
| `IOCTL_GET_VERSION` (`0x8A716000`) | Writes `{protocol version, driver version}` (8 bytes) |
| `IOCTL_READ_EVENTS` (`0x8A716004`) | Writes the dropped count plus whole records (buffer between `MIN_READ` and 256 KiB). Waits at most 100 ms |
| `IOCTL_SET_REDIRECT` (`0x8A71A008`, write access) | Reads exactly 8 bytes: proxy PID, IPv4 and IPv6 proxy ports (all zero: stop). Validated by `wiretap-driver-proto`, fuzzed (`redirect_records`) |
| Input buffers | Read only by `IOCTL_SET_REDIRECT` |
| Open | Clears the record queue |

The record format, IOCTL codes and limits are defined once in `crates/wiretap-driver-proto`. That's the same `no_std`, `unsafe`-free code the driver runs, and it is unit-tested and fuzzed in user mode.

## Resource limits

- **Memory:** one non-paged allocation of about 4.1 MiB at load (ring, flow-budget table, staging buffer). Nothing is allocated per packet.
- **Ring full:** records are dropped and counted, and classification never waits.
- **Flow budget:** a fixed table of 4096 slots. When two flows collide, the older one is evicted and restarts its budget, so memory stays constant without any per-flow lifetime tracking.

## Security properties

- It provides no memory, process, file, registry, token or command operations.
- Every unsafe block carries a safety comment. Large kernel structures are accessed through prefix views whose layouts are asserted in Rust and in `layout_check.c` against the WDK headers.
- It is compatible with Memory Integrity (HVCI): only NX pool (`ExAllocatePool2`) is used, and no section is both writable and executable.
- **No panic path, checked at build time.** In a release build the panic handler calls a symbol that does not exist, so the driver links only if the optimizer removed every possible panic (index, slice, arithmetic overflow, unwrap). The check found three overflow-checked additions in `classify_flow`, `classify_stream` and `dispatch_device_control` (ring indices, flow budget, read length), now explicit wrapping or saturating arithmetic. Debug builds keep the checks and bug-check with 0x57540001. The shared logic is unit-tested and fuzzed.
- **Crash report:** while a capture runs, `%LOCALAPPDATA%\Wiretap\capture.running` exists. If Windows restarts meanwhile, the next start shows the bug check Windows recorded (System log event 1001: code, parameters, dump file) so it can be reported.

## Install, permissions, restart, uninstall

- **Install:** `pnputil /add-driver WiretapDriver.inf /install` from an elevated prompt. This creates the demand-start service `WiretapDriver`. No reboot is needed.
- **Permissions:** Administrator rights to install and to capture (loading a driver and managing WFP filters both require them).
- **Uninstall:** `pnputil /delete-driver oemNN.inf /uninstall /force` (see SETUP.md); a driver still loaded after captures with redirection is removed at the next restart.

## Testing

| Test | Where |
| --- | --- |
| Layout check vs WDK headers | `tools/build-driver.ps1` (`layout_check.c`) |
| INF validation, catalog signability | `infverif /w`, `Inf2Cat` |
| Ring, record codec, flow budget | unit tests and `driver_ring`/`driver_records` fuzz targets |
| Load, capture, stress, crash, unload under Driver Verifier | `tools/vm-test.ps1` (Hyper-V) |

### Connect redirection and unloading

While a capture redirects connections, each redirected connection carries a small context the
driver allocates (its original destination and process). Windows takes ownership of it and frees
it only when that connection's socket is gone: through TIME_WAIT, and for as long as the app
keeps a socket whose connection was reset (it then has no row in the TCP table at all).
Unloading before leaks it: harmless without Driver Verifier (Windows frees it later), but
Verifier stops Windows (bug check 0xC4, 0x62).

Nothing Windows exposes proves that no such socket is left, so the rule is simple and sound:

- Stop: redirection off, filters removed, the app stops its per-capture listeners: new
  connections go straight to their servers, open ones (WebSockets, event streams, long polls)
  go on until their app or server ends them; HTTP/2 connections are asked to move (graceful
  GOAWAY). Nothing is ever reset.
- The driver unloads only if it redirected nothing since it was loaded (a capture without
  redirection). Otherwise it stays loaded with no filters and no redirection, seeing and
  changing no traffic, until Windows restarts; the next capture uses it, and
  `wiretap --headless driver stop` reports it.

History: a drain that waited for the TCP table to clear unloaded under contexts twice
(2026-11-10, Driver Verifier): connections it had reset with `SetTcpEntry` left their sockets,
and their contexts, behind, invisible to the table; a held socket after a reset reproduced it.
Not yet done:
- driver fuzzing of the IOCTL surface in a VM (only `IOCTL_SET_REDIRECT` reads input: 8 bytes decoded by the fuzzed `wiretap-driver-proto`; otherwise the surface is the IOCTL code and the output length);
- static analysis with the WDK's CodeQL suites;
- the Windows 10 VM run.
