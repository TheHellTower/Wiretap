# Architecture

## Process and privilege model

| Component | Runs as | Trust |
| --- | --- | --- |
| `WiretapDriver.sys` | Kernel, demand-start service, loaded only during a capture | Minimal and inspection-only; parses nothing it receives from user mode |
| `wiretap.exe capture` | Elevated user (Administrator) | Starts and stops the driver, owns the dynamic WFP session, parses all traffic |
| `wiretap.exe` other commands | Normal user | Read the local database |

Future components (service, dashboard, SDKs, addons) will keep this direction of trust: parsing and policy stay in user mode, and Python and other addons run in separate unprivileged processes.

## Data flow

```text
TCP/UDP flow established ──► ALE_FLOW_ESTABLISHED callout ──┐
TCP stream segment ────────► STREAM callout (budget 64 KiB/dir)┤
                                                             ▼
                          4 MiB ring of length-prefixed records (drop + count when full)
                                                             │ IOCTL_READ_EVENTS (≤256 KiB, waits ≤100 ms)
                                                             ▼
             wiretap-driver-proto::records ── decode, validate every length
                                                             ▼
             wiretap-capture::Tracker ── connections, TLS hellos, HTTP/1 heads (bounded buffers)
                                                             ▼
             NetworkEvent / Flow (validated) ──► wiretap-storage (SQLite) and console
```

## Crates

| Crate | Role | Dependencies |
| --- | --- | --- |
| `wiretap-core` | Unified event model (`NetworkEvent`, `Flow`, `Session`), IDs (UUIDv7), validation and limits | serde |
| `wiretap-storage` | SQLite persistence: migrations, quota, retention, integrity, paged reads | rusqlite (bundled), serde_json |
| `wiretap-platform` | Windows version and support policy, driver-loading posture, drive mapping | windows-sys |
| `wiretap-protocol` | HTTP/1 heads and framing; TLS ClientHello and ServerHello metadata | — |
| `wiretap-capture` | Tracker: driver records to events and flows | — |
| `wiretap-driver-proto` | `no_std` protocol shared with the driver: IOCTLs, record codec, ring, flow budget | — |
| `wiretap-driver-client` | Service lifecycle, device channel, dynamic WFP filters | windows-sys |
| `wiretap-cli` | `wiretap.exe`; argument parsing and rendering are pure and fuzzed | serde_json |
| `driver/` | `WiretapDriver.sys`, a separate kernel workspace | wiretap-driver-proto only |

The spec's layout lists further crates (proxy, TLS, HAR, OpenAPI, API, service, MCP, and so on). They are added when their milestones are built, not as empty placeholders.

## Language-neutral contract

All model types serialize to one stable JSON shape:
- snake_case field names;
- string enums;
- UUID strings;
- integer microsecond UTC timestamps;
- strict unknown-field rejection on input.

`crates/wiretap-core/tests/fixtures/*.json` pin that shape. This is the contract future SDKs (Python first, then .NET, C++, Rust, Go) and addon IPC will build on. Nothing in it is Rust- or Python-specific.

## Driver lifetime

1. `wiretap capture` starts the `WiretapDriver` service (demand start; never at boot).
2. It checks `PROTOCOL_VERSION` over `IOCTL_GET_VERSION`.
3. It opens BFE with `FWPM_SESSION_FLAG_DYNAMIC` and adds the sublayer, the 4 callouts and the 4 inspection filters in one transaction.
4. On stop (Ctrl+C, window close, logoff, shutdown or `--duration`), objects drop in order: filters (engine closed), then the device handle, then the service stop, which unloads the driver.
5. On a crash, Windows deletes the dynamic session's objects with the process, verified in the VM test. The loaded driver then sees no traffic; it stays loaded until Windows restarts (docs/driver/README.md) and the next capture uses it. The driver clears its queue on every open, so a new session never receives an earlier session's records.
