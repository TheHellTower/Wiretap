# Threat model (v0.2)

## Assets

- Integrity and availability of the Windows kernel. The driver must never become a privilege-escalation or crash primitive.
- The user's network: traffic must always reach its server unless a rule the user wrote says otherwise. Wiretap must never block, break or noticeably slow it.
- The Wiretap root CA: whoever can sign with it can impersonate any site to this user.
- Captured data: URLs, headers, cookies, bodies (decrypted HTTPS included) and process paths.
- Release integrity: signed binaries, locked and pinned dependencies.

## Trust boundaries

```text
remote hosts / network ──► [driver callouts] ──► [ring] ──IOCTL──► [capture process] ──feed──► [app]
                                 kernel                          elevated (UAC)                unelevated
apps' TCP 80/443 ──(driver redirect, while capturing)──► [proxy: TLS, rules, relay] ──► real servers
local users ──► device ACL (SYSTEM, Administrators, exclusive) ──► driver
app window (WebView2, loopback origin only) ──token cookie + Host + Origin checks──► UI server
.wtrr / HAR files, captured traffic ──► validated parsers ──► SQLite (user profile)
```

## Threats and mitigations

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| Malformed or hostile traffic crashes a parser | All parsing in user-mode Rust; bounded, panic-free decoders; strict HTTP (no folding, no bare LF, smuggling-prone framing rejected) | 21 fuzz targets (content decoders differential-tested against reference implementations), RFC test vectors, unit tests |
| The driver stops Windows (bug check) | Release driver has no panic path (link-time check: the panic handler references an undefined symbol); explicit wrapping/saturating arithmetic; never unloads once it has redirected (WFP-owned contexts can outlive anything visible), it stays loaded with no filters until Windows restarts; nothing is ever reset; a bug check during a capture is reported on the next start (System log event 1001) | Driver Verifier VM runs, linker map |
| Traffic floods exhaust memory | Fixed 4 MiB kernel ring with drop counting; per-flow budgets; tracker caps; proxy caps (512 connections, kept-alive clients idle at most 120 s with at most 64 KiB read ahead, 8 MiB request bodies, 4 MiB stored per body, 64 KiB ClientHello, 4096 remembered refusals; HTTP/2: 1024 recorded streams per connection, non-DATA frames and header blocks up to 1 MiB, HPACK table up to 64 KiB, header lists up to 512 fields and 256 KiB; gRPC: 4 MiB stored per message, protobuf views 16 KiB and 32 levels deep) | unit tests, `http2` fuzz target, VM stress test |
| Local unprivileged user abuses the driver | Device ACL SYSTEM/Administrators, exclusive open; three IOCTLs: version, events, and a fixed-size, strictly validated redirect setting | code review, `redirect_records` fuzz target |
| Driver used as an escalation primitive | No memory, process, file, registry, token or command operations. The redirect callout can only point outbound TCP 80/443 at loopback, to the process that asked; it never touches the proxy's own connections, loopback destinations or connections redirected by anyone else | code review |
| Redirection outlives Wiretap | Redirect filters live in the dynamic BFE session (deleted with the process); the setting is cleared whenever the device is opened or closed; the callout fails open on any error; filters permit if the callout is unregistered. Connections already redirected when a capture stops finish through the proxy (never cut); the driver then stays loaded, inert, until Windows restarts | VM crash test, `stopped_captures_*` proxy tests |
| Kernel memory corruption from wrong FFI layouts | Every offset asserted in Rust and against the WDK headers (`layout_check.c`, now including `FWPS_CONNECT_REQUEST0` and the redirect metadata) | build |
| Root CA key stolen or misused | Per-user, created on first use, persisted as a **non-exportable** CNG key; never in the database, logs, exports or APIs; not trusted until the user confirms Windows' own dialog; removed and deleted when decryption is turned off | code review, `wiretap-tls` tests (throwaway keys, never trusted) |
| Wiretap vouches for a server it could not verify | Upstream TLS is verified against the Windows trust store (chain, validity, server-auth usage, name) before the client is answered; unverifiable servers are relayed untouched, so the client sees the real certificate | `servers_that_cannot_be_verified_are_reached_untouched` |
| Decryption breaks apps | HTTP/2 is relayed frame for frame (never re-encoded) except on hosts a rule targets, where Wiretap terminates it with its own flow control (1 MiB windows per side) and state-free HPACK literals; known pinning apps (Defender) and processes outside the user's session (services, other users: they do not trust the per-user root) are relayed untouched from the first connection; apps refusing the Wiretap certificate are remembered per (application, host) and relayed untouched; non-TLS, non-HTTP traffic is relayed; rule-targeted hosts work without the server | proxy tests, VM |
| A rule silently changes traffic the user did not target | One outcome per request (redirects first, then auto-replies, else the real server); rules list what they match and count their hits | `wiretap-autoreply` tests, `rules` fuzz target |
| Malicious `.wtrr` or HAR file | Parsed into the same validated models as captured data, bounded (1000 rules, 100,000 HAR entries, 128 MiB), rule templates cannot run code or reach files or the network; nothing imported is executed | `rules` fuzz target, HAR round-trip test |
| Local web page or process drives the UI server | Loopback only; per-run random token exchanged for an `HttpOnly`, `SameSite=Strict` cookie; exact `Host` (DNS rebinding) and `Origin` (CSRF) checks; strict CSP; captured data inserted as text only | `ui_router` fuzz target, UI tests |
| Browser surface in the app window | WebView2 with context menus, script dialogs, DevTools, accelerators, autofill, popups, downloads UI and permissions off; navigation pinned to the Wiretap origin; InPrivate, data folder deleted on exit | code review |
| Wiretap's own secrets captured | The capture excludes the UI server and the proxy's own connections | unit tests |
| Encrypted traffic presented as decrypted | `can_carry_decrypted` invariant in `NetworkEvent` and `Flow` validation | unit tests |
| Tampered database injects bad data | Rows re-validated on read; defensive SQLite; untrusted DB files never opened | storage tests |
| Disk exhaustion | 8 GiB quota (`max_page_count`) plus retention; graceful `Full` error | storage tests |
| Dependency compromise | 4 runtime crates on their latest versions; the WebView2 SDK pinned by version and SHA-512; `cargo deny`, `cargo audit`, locked builds | CI gates |
| Test-signing weakens user machines | Test certificates are lab-only; release drivers are Microsoft attestation-signed | RELEASE.md process |

## Residual risks and known limitations

- **Privacy:** captured requests, decrypted ones included, are stored unredacted in the user's profile. Redaction is planned.
- **Same-user processes:** any process running as the user can ask CNG to sign with the root CA's key (non-exportable keys stop copying, not use). That is the same trust level as the user's own browser profile; turning decryption off removes the key.
- **QUIC is blocked while capturing**, so HTTP/3 is not observed (browsers fall back to TCP).
- **Redirected ports:** only TCP 80 and 443 are redirected; HTTPS on other ports shows metadata only.
- **Driver stays loaded:** after a capture with redirection (or a crash) the driver stays loaded, with no filters, until Windows restarts; updating it needs a restart.
- **Kernel hardening:** Control Flow Guard is not yet enabled for the driver, and the IOCTL surface has not yet been fuzzed in a VM.
