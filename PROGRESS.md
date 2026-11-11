# Progress

Where Wiretap stands, checkpoint by checkpoint. Last updated: 2026-11-10.

**Current checkpoint: v0.2 (in development).** Everything marked done below is covered by automated tests and was checked by hand on Windows 11 in a Hyper-V lab VM with Driver Verifier on.

Legend: ✅ done · 🔨 in progress · 📋 planned

## Done

### Capture and driver
- ✅ WFP kernel driver: every TCP/UDP connection attributed to its process, live
- ✅ Transparent capture: while capturing, every app's outbound HTTP and HTTPS (TCP 80/443) goes through Wiretap's local proxy, with no proxy settings needed
- ✅ Driver safety: no panic path in the release driver (checked at link time); it fails open and never cuts a connection; it never unloads under connections it redirected (it stays loaded, inert, until Windows restarts); a bug check during a capture is reported on the next start
- ✅ Stopping a capture never breaks open WebSockets, event streams or long polls: they finish through Wiretap

### HTTPS and the proxy
- ✅ Opt-in HTTPS decryption with Windows' own TLS stack and a per-user root that Windows asks you to trust
- ✅ Servers verified like a browser would; anything Wiretap cannot verify is relayed untouched
- ✅ Apps that pin certificates, Windows services and apps refusing the Wiretap certificate are relayed untouched, with their clear-text TLS details shown
- ✅ No idle limits; TCP keepalive notices vanished servers

### Protocols
- ✅ HTTP/1.0 and 1.1, keep-alive and pipelining
- ✅ HTTP/2 (HPACK, streams, trailers, server push, cleartext h2c), relayed frame for frame
- ✅ WebSocket (RFC 6455, drafts 7/8, `permessage-deflate`, over HTTP/2 too), live Messages tab
- ✅ Server-Sent Events, live
- ✅ gRPC and gRPC-Web: messages shown as protobuf without the schema, call status from trailers
- ✅ TLS metadata for everything not decrypted: server name, versions, ALPN, cipher suite, certificate
- ✅ Bodies decoded: gzip, deflate, Brotli, Zstandard (Wiretap's own decoders)

### Rules
- ✅ Auto-replies and redirects, over HTTP/1.x and HTTP/2, created from a captured request, with templates
- ✅ Rule groups shared as `.wtrr` files

### App
- ✅ Native window; live Traffic and Connections lists; Messages tab; search with auto-complete
- ✅ Developer mode for connection-level detail
- ✅ Sessions in SQLite; HAR 1.2 import and export

### Quality
- ✅ Every parser has unit tests (official test vectors where they exist) and a fuzz target (21 targets), replayed on every build
- ✅ CI on Windows Server 2022 and 2025: format, lint, tests, fuzz replay, a 60-second fuzz run per target, supply-chain checks, and the driver build with its layout checks

## Next

1. 🔨 **QUIC and HTTP/3.** Today QUIC is blocked while capturing, so browsers fall back to TCP. Plan, following RFC 9000/9001/9114/9204 and Microsoft's MsQuic:
   - show the QUIC handshake (server name, version, ALPN), which uses publicly known keys and needs no decryption setup;
   - then full HTTP/3 decoding (QPACK) through Wiretap's own QUIC endpoint.
2. 📋 Rules on messages: replace or inject WebSocket messages, SSE events and gRPC messages.
3. 📋 gRPC schemas: import `.proto` files to show field names.
4. 📋 Breakpoints and edit-and-resend.
5. 📋 Content views: JSON and XML trees, forms, multipart, images, MessagePack.

## Later

- 📋 DNS (with DoH, DoT and HTTPS/SVCB records), raw TCP/UDP stream views, TLS fingerprints (JA3/JA4)
- 📋 Reverse, upstream and SOCKS5 proxy modes
- 📋 Packet capture and PCAPNG export/import (no Npcap), TLS key log import
- 📋 Windows-network protocols (SMB, Kerberos, NTLM, LDAP, RDP metadata), mail and messaging protocols (SMTP, IMAP, MQTT, AMQP)
- 📋 OpenAPI generation from captured traffic
- 📋 A local API with SDKs (Python first, in separate repositories), a TUI, MCP
- 📋 Production: Microsoft-signed driver, installer, a Windows 10 and Windows 11 test matrix

## Known limitations

- Only TCP ports 80 and 443 are decrypted; HTTPS on other ports shows metadata only.
- After a capture that redirected connections, the driver stays loaded (with no filters, so it sees and changes nothing) until Windows restarts.
- The test VM is Windows 11 build 22621; Windows 10 and newer Windows 11 builds are not yet tested by hand.

The full list, with the reasoning behind each, is in the [threat model](docs/security/threat-model.md).
