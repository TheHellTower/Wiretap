# [Wiretap](https://thehelltower.github.io/Wiretap/)

> **See everything. Understand everything. Debug anything.**

Wiretap is a security-first network monitoring and debugging tool for **Windows 10 and Windows 11 (x64)**, written in Rust. Wiretap is its own desktop app: a native window with no browser around it. A small kernel driver attributes every connection to the process that owns it and, while a capture runs, sends HTTP and HTTPS through Wiretap's local proxy. There every request and response is recorded in full, bodies included; HTTPS is decrypted once you allow it. Rules can answer requests locally or redirect them to another server.

The long-term goal is one tool that combines HTTP Debugger Pro, mitmproxy, mitmproxy2swagger and Wireshark. Every feature rests on a small, tested, auditable core.

## Preview

<p align="center">
  <video controls muted loop playsinline width="100%">
    <source src="./docs/media/wiretap-preview.mp4" type="video/mp4">
  </video>
  <em>
    Video preview unavailable?
    <a href="https://www.youtube-nocookie.com/embed/224w0e_bRAY?controls=1&disablekb=1&fs=0&modestbranding=1&rel=0&iv_load_policy=3">Watch the Wiretap preview</a>.
  </em>
</p>

: one continuous, unedited recording on Windows 11 (Hyper-V lab VM, Driver Verifier on). It shows, in order:
- starting a capture;
- Edge on httpbin.org, decrypted as HTTP/2;
- the filter with auto-complete (`host:` values from the captured traffic);
- a request's headers and body;
- an auto-reply rule created from that request, with a template body, then the mocked page in Edge;
- a WebSocket conversation in the Messages tab;
- live Server-Sent Events;
- gRPC calls (protobuf messages, a failed call shown as `gRPC 5`);
- developer mode off, then on (the Connections view and connection-level rows);
- stopping the capture.

## About this project

Wiretap is a vibecoded, human-guided experiment: how far can AI help build a Windows network debugger, kernel driver included, when a person sets the direction and reviews the work? It is intentionally kept simple for learning and experimentation and is not designed to become a product.

Development is published in gradual research checkpoints. Each release adds a limited set of capabilities: so far, the WFP capture driver, the transparent HTTPS proxy, and HTTP/1.1, HTTP/2, WebSocket, Server-Sent Events and gRPC decoding. Each also documents what was tested, on real Windows under Driver Verifier, and what remains open, so readers can follow and assess the progress over time. The current checkpoint is v0.2 (below); [PROGRESS.md](PROGRESS.md) shows what is done and what comes next, and its open items are the "Not yet" row and the [threat model](docs/security/threat-model.md)'s known limitations.

Some AI-generated filler ("AI slop") may remain for a while, mostly because the human maintainer may be lazy about low-priority cleanup during review. Whatever remains will be removed in the final milestone. How the AI's work is kept in check is described under [Slop](#slop).

## Status: v0.2 (in development)

| Area | Status |
| --- | --- |
| App | Native window (WebView2, every browser feature off, InPrivate, no browser profile). `wiretap.exe` opens it; `--headless` is the command line |
| Capture | Start capture loads the driver (after UAC); every app's connections appear live with their process. Stop, close the app or crash: the driver's filters are gone (it stays loaded, inert, until Windows restarts if it redirected anything) |
| Driver safety | The release driver contains no panic path (enforced at link time), never unloads under connections it redirected: after a capture that redirected any, it stays loaded with no filters until Windows restarts (Driver Verifier clean), and if Windows ever stops during a capture, the next start reports the bug check code, parameters and dump file |
| HTTP(S) of every app | While capturing, outbound TCP 80/443 is redirected to the local proxy and recorded in full: method, URL, headers, bodies, timing, over HTTP/1.x (keep-alive and pipelining: every request its own row, client and server connections reused as the app and server allow) and HTTP/2 (every stream its own row; HPACK, trailers, server push, cleartext h2c). QUIC (UDP 443) is blocked so browsers use TCP |
| HTTPS decryption | Opt-in: Windows asks you before it trusts the per-user Wiretap root (non-exportable CNG key). TLS by Windows' own SChannel, TLS 1.0 to 1.3 as Windows enables them. Servers are verified like a browser would; one Wiretap cannot verify is relayed untouched. ALPN is mirrored: the server gets the client's offer, the client gets the server's choice, and HTTP/2 is relayed frame for frame (never re-encoded) while decoded |
| Never breaks traffic | Relayed untouched from the first connection: apps known to pin their certificates (Microsoft Defender), and Windows services and other users' apps (the Wiretap root is trusted for your account only). Apps that refuse the Wiretap certificate (a TLS alert, or hanging up twice right after the handshake before any request) are remembered and relayed untouched; a client that merely goes away mid-handshake is not mistaken for one; anything that is not HTTP or TLS is relayed; the driver fails open. No idle limit: WebSockets, event streams and long polls stay open until the app or server ends them (TCP keepalive notices vanished servers), even after the capture stops |
| Compressed bodies | gzip, deflate, Brotli and Zstandard bodies are shown decoded (Wiretap's own decoders, no dependencies) and exported decoded to HAR |
| Rules | Auto-replies (Wiretap answers, the server is never contacted) and redirects (send to another server, path and query kept), over HTTP/1.x and HTTP/2. One outcome per request, redirects first. Groups shared as `.wtrr` files. On hosts a rule targets, HTTP/2 is terminated (Wiretap is the server of the app and a client of the real server) so each stream can be answered; open connections move to it when a rule is added |
| WebSocket | `ws://` and `wss://` messages decoded live (RFC 6455 and drafts 7/8, fragmentation, `permessage-deflate`), shown in the connection's Messages tab like browser developer tools, exported in HAR (`_webSocketMessages`). Also over HTTP/2 (RFC 8441). Hixie-76 WebSockets are relayed untouched |
| gRPC | Calls over HTTP/2 and gRPC-Web (HTTP/1.x, binary and base64 text) decoded message by message as the specifications define them (grpc/grpc PROTOCOL-HTTP2 and PROTOCOL-WEB): request and response messages in the Messages tab as Protocol Buffers text without the schema (or JSON for `+json`), gzip/deflate messages decompressed, the call status from trailers (failed calls show `gRPC <code>` in the list) |
| Server-Sent Events | `text/event-stream` responses decoded live (event type, id, data), over HTTP/1.x and HTTP/2, in the Messages tab |
| Without HTTPS decryption | Every relayed connection is still a row (PINNED, REFUSED, ...) with what travels in clear text: SNI, versions, ALPN, cipher suite, the server certificate and issuer (before TLS 1.3), bytes each way, and why it was not decrypted. Encrypted traffic is never presented as decrypted |
| Search | Field filters (`app:`, `host:`, `method:`, `status:4xx`, `type:`, `url:`, `header:`, `source:`, `-` to exclude, wildcards) with autocomplete from the logged requests |
| Sessions | SQLite (WAL, quota, tamper detection); HAR 1.2 import and export |
| Not yet | HTTP/3 and QUIC decoding, gRPC schemas (.proto import), rules for WebSocket messages and events, breakpoints and edit-and-resend, packet capture and PCAPNG, OpenAPI generation, TUI, SDKs, MCP |

## Install and use

- **Users:** [SETUP.md](SETUP.md) covers requirements, installation, usage and uninstallation.
- **Maintainers:** [RELEASE.md](RELEASE.md) covers the formal release: quality gates, production driver signing (Microsoft attestation), packaging and the release checklist.

```powershell
wiretap                                  # the app
wiretap --headless check                 # Windows support, privileges, driver state
wiretap --headless capture               # elevated: capture in the terminal until Ctrl+C
wiretap --headless flows <session-id>    # HTTP flows as JSON lines (language-neutral)
```

## Architecture

```text
 wiretap.exe (app, unelevated)                  wiretap.exe --headless capture (elevated, via UAC)
 ┌──────────────────────────────────────┐ feed  ┌──────────────────────────────┐ IOCTL ┌─────────────────────────┐
 │ window   WebView2 host, no browser UI │◄──────│ driver-client  service, WFP  │◄─────►│ WiretapDriver (WFP)     │
 │ ui       loopback API + live stream   │       │   dynamic filters, redirect  │       │ flow + stream inspection│
 │ proxy    HTTP/1.1, TLS, rules, relay  │◄───┐  │ capture  records → events    │       │ connect redirect v4/v6  │
 │ tls      SChannel + CNG root CA       │    │  └──────────────────────────────┘       └─────────────────────────┘
 │ autoreply  redirects, auto-replies    │    └── apps' TCP 80/443, redirected by the driver while capturing
 │ storage  SQLite · har  HAR 1.2        │
 └──────────────────────────────────────┘
```

Design rules:
- **Minimal dependencies:** `serde`, `serde_json`, `rusqlite` (bundled SQLite) and `windows-sys`, all on their latest versions. TLS, certificates, the window and the app shell use Windows itself (SChannel, CNG, CryptoAPI, WebView2): no TLS, ASN.1 or GUI crates. The WebView2 loader is Microsoft's static library, linked in (no DLL). The driver depends on nothing but our own `no_std` protocol crate.
- **Every untrusted input is bounded and fuzzed:** 20 libFuzzer targets, replayed on every test run.
- **Driver bindings checked twice:** the driver's FFI layouts are asserted in Rust and, independently, against the official WDK headers. That check already caught a real `windows-sys` layout bug.

Details: [docs/architecture/overview.md](docs/architecture/overview.md), [docs/driver/README.md](docs/driver/README.md), [docs/security/threat-model.md](docs/security/threat-model.md), [docs/compatibility/windows.md](docs/compatibility/windows.md).
## Repository layout

```text
crates/   user-mode workspace (core, storage, platform, protocol, capture, driver-proto, driver-client,
          autoreply, proxy, tls, codec, ui, cli)
driver/   WiretapDriver (separate kernel workspace), INF, WDK layout check
fuzz/     libFuzzer targets, seed corpus, stable-Rust replay test
tools/    build-driver.ps1, fetch-webview2.ps1, vm-test.ps1, package-release.ps1, check-latest.ps1
docs/     architecture, driver, security, compatibility
```

## Security

Please report vulnerabilities privately: see [SECURITY.md](SECURITY.md). The driver deliberately has no arbitrary-memory, process, file or privileged-command capabilities. Its whole interface is three IOCTLs on an exclusive device only SYSTEM and Administrators can open: read the version, read events, and point outbound HTTP(S) at Wiretap's own proxy (off whenever the device is closed).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: minimal code, minimal and up-to-date dependencies, tests and fuzz targets with every parser, and all quality gates green.

## Slop

This project is built with AI assistance under human supervision. Most of the code, tests and documentation were written by an AI coding assistant (Claude, by Anthropic), working from requirements set by the human maintainer. The maintainer directs the work, reviews it, decides what ships and runs the tests on real Windows machines.

AI-written code can be confidently wrong. Wiretap counters that with machinery, not trust:
- strict lints;
- tests for every rule;
- fuzzing of every parser;
- layout checks of every kernel binding against Microsoft's headers;
- supply-chain checks (cargo-deny, cargo-audit, a latest-version check);
- no claim of support without a test.

If you find something that looks wrong, it may well be. Please open an issue.
