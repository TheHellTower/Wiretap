# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**, not in public issues. Use the repository's private vulnerability reporting ("Report a vulnerability" under the Security tab). Include affected versions, reproduction steps and impact. You will get an acknowledgement within 7 days.

Every confirmed vulnerability gets:
1. a root-cause analysis;
2. a severity assessment;
3. a fix;
4. a regression test;
5. new fuzz coverage where applicable;
6. a review of related code paths.

## Supported versions

Only the latest release receives security fixes.

## Security design (summary)

Full threat model: [docs/security/threat-model.md](docs/security/threat-model.md).

- **The kernel driver is deliberately small.** It observes connections, and while a capture runs it does exactly two things to traffic: it redirects outbound TCP 80/443 to Wiretap's own proxy on loopback (never the proxy's own connections, loopback destinations or connections another product redirected), and it blocks QUIC (UDP 443) so browsers use TCP. It never modifies or injects data, and it fails open on any error. It exposes one exclusive device, which only SYSTEM and Administrators can open, with three IOCTLs: version, events, and a fixed-size, strictly validated redirect setting. It provides no memory, process, file, registry, token or command operations of any kind. Memory use is constant: one 4 MiB ring allocated once, records dropped and counted when it is full.
- **The driver is active only during a capture.** It is a demand-start service, never loaded at boot. Capture filters live in a dynamic WFP session that Windows deletes when Wiretap exits or crashes. After a capture that redirected connections the driver stays loaded with no filters (it sees and changes nothing) until Windows restarts, because unloading under connections it redirected could stop Windows.
- **All parsing happens in user mode,** in memory-safe Rust. Each parser is bounded, panic-free and fuzzed. The shared driver protocol code is the same `no_std` crate in kernel and user mode, and it is fuzzed in user mode.
- **Honest inspection:** encrypted traffic is never labelled as decrypted. The event model rejects such records.
- **Untrusted data can't inject into output:** model validation rejects control characters, so captured values can't inject CR/LF into HTTP or escape sequences into terminals.
- **Storage:** a SQLite database in the user's profile, with defensive mode and an untrusted schema. Writes are bounded by a quota, and rows are re-validated when read back. Untrusted database files are never opened.
- **Supply chain:** four runtime dependencies, all on their latest versions and checked by `cargo deny`, `cargo audit` and `tools/check-latest.ps1`. Builds use locked dependencies.
