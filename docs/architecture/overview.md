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
| `wiretap-core` | Unified event model (`NetworkEvent`, `Flow`, `Session`), IDs (UUIDv7), validation and limits | serde, serde_json |
| `wiretap-storage` | SQLite persistence: migrations, quota, retention, integrity, paged reads | rusqlite (bundled), serde, serde_json |
| `wiretap-platform` | Windows version and support policy, driver-loading posture, drive mapping, TCP keepalive | windows-sys |
| `wiretap-protocol` | Bounded, panic-free decoders: HTTP/1 heads and framing, chunked, HTTP/2 frames and HPACK, WebSocket, Server-Sent Events, gRPC and protobuf, TLS ClientHello/ServerHello metadata | — |
| `wiretap-codec` | gzip, deflate, Brotli and Zstandard decoders | — |
| `wiretap-capture` | Tracker: driver records to events and flows | — |
| `wiretap-driver-proto` | `no_std` protocol shared with the driver: IOCTLs, record codec, ring, flow budget, redirect setting | — |
| `wiretap-driver-client` | Service lifecycle, device channel, dynamic WFP filters, crash reports | windows-sys |
| `wiretap-tls` | HTTPS interception on Windows' own TLS (SChannel) and keys (CNG) | windows-sys |
| `wiretap-autoreply` | Rules: matching, auto-replies, redirects, safe response templates | serde, serde_json |
| `wiretap-proxy` | The proxy: explicit and transparent, HTTP/1.x and HTTP/2, WebSocket, SSE, gRPC, rules | — |
| `wiretap-ui` | The app: window, loopback UI server, live feed, sessions, HAR | serde, serde_json, windows-sys |
| `wiretap-cli` | `wiretap.exe`; argument parsing and rendering are pure and fuzzed | serde, serde_json, windows-sys |
| `driver/` | `WiretapDriver.sys`, a separate kernel workspace | wiretap-driver-proto only |

Further crates (OpenAPI, local API, service, MCP and so on) are added when their milestones are built, not as empty placeholders.
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
3. It opens BFE with `FWPM_SESSION_FLAG_DYNAMIC` and adds the sublayer, the callouts and the filters in one transaction: inspection (connections and stream data), and for app captures the connect redirection of TCP 80/443 to the proxy and the QUIC block.
4. On stop (Ctrl+C, window close, logoff, shutdown or `--duration`), objects drop in order: filters (engine closed), then the device handle. The driver unloads only if nothing was redirected since it was loaded; otherwise it stays loaded, with no filters, until Windows restarts ([driver notes](../driver/README.md)).
5. On a crash, Windows deletes the dynamic session's objects with the process, verified in the VM test. The loaded driver then sees no traffic; it stays loaded until Windows restarts (docs/driver/README.md) and the next capture uses it. The driver clears its queue on every open, so a new session never receives an earlier session's records.
