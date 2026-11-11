# Building and releasing Wiretap

This document takes a maintainer from a clean Windows machine to a signed release: toolchain, build, quality gates, driver signing certificates, VM testing, packaging and the release checklist.

## 1. Toolchain

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | 1.99.1, pinned in `rust-toolchain.toml` | `rustup` installs it automatically on first build |
| Visual Studio 2022 | 17.14 or newer, "Desktop development with C++" (MSVC v143) | Linker, and `cl.exe` for the WDK layout check. The bundled SQLite is compiled with it |
| Windows SDK | 10.0.26100 | Installed with Visual Studio |
| Windows Driver Kit | 10.0.26100.6584 | `winget install --id Microsoft.WindowsWDK.10.0.26100 --exact`. Provides kernel headers and libraries, `signtool`, `stampinf`, `infverif` and `Inf2Cat` |
| Rust nightly + cargo-fuzz | latest | `rustup toolchain install nightly` and `cargo +nightly install cargo-fuzz --locked` (fuzzing only) |
| cargo-deny, cargo-audit | latest | `cargo install --locked cargo-deny cargo-audit` |
| WebView2 SDK | pinned in `tools/webview2-sdk.txt` | `.\tools\fetch-webview2.ps1` downloads Microsoft's `Microsoft.Web.WebView2` package from nuget.org, rejects it unless its SHA-512 matches the pin, and extracts the static loader the app links (no DLL ships). Its BSD-3-Clause `LICENSE.txt`/`NOTICE.txt` ship with releases |

**No LLVM/Clang is needed.** Microsoft's `windows-drivers-rs` needs libclang only to run bindgen over the WDK headers at build time. WiretapDriver avoids that:
- It declares the roughly twenty kernel and WFP functions it uses by hand, transcribed from the official WDK headers.
- `driver/layout_check.c` compiles 60 `C_ASSERT`s against those headers. Every size and offset is asserted on the Rust side too, so a mismatch fails one of the two builds.
- This check found that `windows-sys` gets the x64 layout of the IRP stack location's IOCTL parameters wrong (it drops `POINTER_ALIGNMENT`). That's why the driver doesn't use `windows-sys`.

## 2. Quality gates

All gates must pass before a release:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --manifest-path fuzz/Cargo.toml --no-default-features --locked     # replays the fuzz corpus
cargo deny check; cargo deny --manifest-path fuzz/Cargo.toml check
cargo audit
.\tools\check-latest.ps1 Cargo.lock fuzz\Cargo.lock driver\Cargo.lock  # every crate on its newest release
cd driver; cargo fmt -- --check; cargo clippy --release --locked -- -D warnings; cd ..
```

Fuzzing campaigns use nightly and AddressSanitizer. Put the MSVC ASan runtime on `PATH` first:

```powershell
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\<edition>\VC\Tools\MSVC\<version>\bin\Hostx64\x64;$env:PATH"
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run tracker -- -max_total_time=3600 -rss_limit_mb=2048
```

There are 19 targets: event and flow JSON, UUIDs, storage, OS classification, driver records and ring, HTTP heads, TLS hellos, the capture tracker, CLI arguments, rule files (`.wtrr`), driver/proxy redirect records, certificate host names, chunked bodies, the UI's auth router, WebSocket frames (round trips of generated streams, split invariance), and content codings (round trips against reference encoders, and decoding checked against libzstd, Google's Brotli decoder and miniz_oxide). Run every target for at least 10 minutes per release, and longer for parsers that changed. A crash input in `fuzz/artifacts/<target>/` must be fixed and its input copied to `fuzz/regressions/<target>/`. From then on, `cargo test` replays it forever.

## 3. Build

**User mode:**

```powershell
.\tools\fetch-webview2.ps1                       # once per SDK version (verified download)
cargo build --release --locked -p wiretap-cli    # target\release\wiretap.exe
```

`.cargo/config.toml` links the C runtime statically, so `wiretap.exe` runs on clean Windows installations. The Windows Sandbox test caught `vcruntime140.dll` missing otherwise.

**Driver package.** One script builds, checks and signs the whole package:

```powershell
.\tools\build-driver.ps1 -CertThumbprint <thumbprint> [-TimestampUrl http://timestamp.digicert.com]
```

It runs these steps:
1. Checks the FFI layouts against the installed WDK headers.
2. Builds `WiretapDriver.sys` (release, `panic=abort`, overflow checks, native subsystem, NX-compatible, no writable-executable sections).
3. Stamps the INF version and validates it with `infverif /w`.
4. Signs the `.sys`, generates the catalog with `Inf2Cat` (Windows 10 2004+ through Windows 11 24H2/25H2) and signs the catalog.

The output lands in `target\driver-package\`.

## 4. Certificates

Three different certificates matter. Keep them apart.

### 4a. Lab test-signing certificate (development and VM tests only)

```powershell
.\tools\build-driver.ps1 -NewTestCert
```

- **What it does:** creates a self-signed code-signing certificate, `CN=Wiretap Test Driver Signing (lab only)` (RSA 3072, SHA-256, valid 1 year), in `Cert:\CurrentUser\My`. It signs the package with it and exports the public part to `target\WiretapTestSigning.cer`.
- **Where it works:** Windows loads drivers signed with it only when test signing is on (`bcdedit /set testsigning on`, which requires Secure Boot off) and the `.cer` is in `LocalMachine\Root` and `LocalMachine\TrustedPublisher`.
- **Rules:**
  - Only in lab VMs. Never ask users to enable test signing.
  - Never ship the private key, and never trust the `.cer` on a production machine.
  - Revoke the lab trust after testing, as in SETUP.md section 7.

### 4b. Production driver signing (Microsoft attestation)

Since Windows 10 1607, kernel drivers load on Secure Boot machines only when Microsoft signed them.

1. **EV code-signing certificate:** obtain one (stored on a hardware token or HSM) from a CA accepted by the Microsoft Partner Center, and register it with your Hardware Dev Center account.
2. **Build:** sign the package with the EV certificate: `.\tools\build-driver.ps1 -CertThumbprint <EV thumbprint> -TimestampUrl <RFC 3161 URL>`.
3. **Create a CAB** for submission:

   ```powershell
   $d = 'target\driver-package'
   @(".OPTION EXPLICIT", ".Set MaxDiskSize=0", ".Set CabinetNameTemplate=WiretapDriver.cab", ".Set DiskDirectory1=target",
     ".Set DestinationDir=WiretapDriver", "$d\WiretapDriver.inf", "$d\WiretapDriver.sys", "$d\WiretapDriver.pdb") |
       Set-Content target\WiretapDriver.ddf
   makecab /f target\WiretapDriver.ddf
   signtool sign /fd SHA256 /sha1 <EV thumbprint> /tr <RFC 3161 URL> /td SHA256 target\WiretapDriver.cab
   ```

4. **Submit:** in Partner Center, go to Hardware, then Submit new hardware, and upload the CAB with *attestation signing*, choosing the Windows 10 and Windows 11 x64 targets. Microsoft returns the package re-signed with a Microsoft certificate. Attestation-signed drivers are valid on Windows 10 and 11 client editions.
5. **Requirements:** the driver must also pass Microsoft's HVCI (Memory Integrity) compatibility requirements. It allocates only NX pool (`ExAllocatePool2`) and has no writable-executable sections; check before each submission with `verifier /flags 0x02000000 /driver WiretapDriver.sys` (code integrity checks).
6. **Use the returned files:** release the Microsoft-signed `.sys`, `.cat` and `.inf` exactly as returned, without re-signing them.

### 4c. Wiretap Root CA (HTTPS decryption)

The root CA is **not** a release artifact. Nothing about it is built, signed or shipped:
- It is created on each user's machine, per Windows user, the first time they turn HTTPS decryption on (`wiretap-tls`, `Authority::open`).
- Its private key (RSA 3072) and the key of the server certificates it issues (RSA 2048) are persisted, **non-exportable** CNG keys in the user's Microsoft Software Key Storage Provider. They are never written to the database, logs, exports or any API.
- The root certificate itself is rebuilt from the key at every start (its subject derives from the key), so it can always be exported again (System view, `wiretap-root.cer`) but no copy needs to be stored.
- It is trusted only after explicit consent: Wiretap asks Windows to add it to the current user's Trusted Root store, and Windows shows its own confirmation dialog.
- Turning decryption off removes it from the store (Windows confirms again) and deletes both keys.
- Upstream servers are verified against the Windows trust store (chain, validity, server-auth usage, host name); Wiretap never vouches for a server it could not verify.

A release that contained a CA private key would let anyone intercept its users' TLS traffic; the design makes that impossible by construction. Tests use throwaway keys (`Wiretap Test <uuid>`) that are deleted afterwards and are never added to any trust store.
### 4d. Signing `wiretap.exe`

Sign the user-mode binary with an OV or EV code-signing certificate, with an RFC 3161 timestamp (see section 6).

## 5. Runtime test in a Hyper-V VM

Requirements:
- a Generation 2 Windows 10 or 11 VM with Secure Boot **off** (needed for test signing);
- a password-protected Administrator account (PowerShell Direct rejects blank passwords);
- a checkpoint to restore before each run.

```powershell
.\tools\build-driver.ps1 -NewTestCert     # or -CertThumbprint of the existing lab certificate
cargo build --release --locked -p wiretap-cli
.\tools\vm-test.ps1 -VMName '<vm>' -Credential (Get-Credential) -Checkpoint '<clean checkpoint>'
```

The script works headless over PowerShell Direct:
1. Restores the checkpoint and enables test signing and Driver Verifier (standard checks) for `WiretapDriver.sys`, then reboots.
2. Installs the package with `pnputil`.
3. Captures while generating HTTP and HTTPS traffic.
4. Runs a stress phase: 300 parallel requests, then 20 MB over HTTP and 50 MB over HTTPS.
5. Runs a crash phase: kills `wiretap.exe` mid-capture and verifies through `netsh wfp show state` that all 10 Wiretap WFP objects disappear. The next capture must reuse and then unload the driver.
6. Checks Driver Verifier statistics, bugcheck events and minidumps.

Results go to `target\vm-test\`. A release needs this test to pass on Windows 10 22H2 and Windows 11 24H2 or 25H2 VMs.

## 6. Package

```powershell
.\tools\package-release.ps1 -CertThumbprint <code-signing thumbprint> -TimestampUrl <RFC 3161 URL>
# lab build with a test-signed driver:
.\tools\package-release.ps1 -IncludeTestCertificate
```

It produces `target\release-package\wiretap-<version>-x64.zip`, containing `wiretap.exe`, `driver\WiretapDriver.{sys,inf,cat}`, README, SETUP and SECURITY. It also writes `SHA256SUMS.txt`. Publish the checksums next to the archive.

### Draft releases from CI

`.github/workflows/release.yml` builds the same package on GitHub Actions and puts it in a **draft** release, ready for review. It runs when a version tag is pushed (`git tag v0.2.0; git push origin v0.2.0`, which must match the workspace version) or by hand (Actions, *release*, Run workflow). Re-running it updates the draft; it never changes a published release.

CI holds no signing keys, so the draft's archive is `wiretap-<version>-x64-unsigned.zip`: the driver and `wiretap.exe` are unsigned (the catalog is generated, not signed). Before publishing, build the signed package as above, replace the draft's archive and `SHA256SUMS.txt` with it, and go through the checklist (section 8).
## 7. Versioning

| What changes | Update |
| --- | --- |
| Any release | `version` in `Cargo.toml` (workspace) and `driver/Cargo.toml`; `-Version` of `build-driver.ps1` (INF `DriverVer`) |
| Driver code | `DRIVER_VERSION` in `driver/src/lib.rs` |
| Record format or IOCTL semantics | `PROTOCOL_VERSION` in `wiretap-driver-proto`. Old clients then refuse new drivers instead of misreading them |
| Database schema | Add a new file to `crates/wiretap-storage/migrations/` (never edit an applied one). Older builds refuse newer databases |

## 8. Release checklist

- [ ] All quality gates green (section 2), including `check-latest.ps1`
- [ ] Every fuzz target ran at least 10 minutes on nightly with ASan, with no new artifacts
- [ ] VM test green on Windows 10 22H2 and Windows 11 24H2/25H2 with Driver Verifier (section 5)
- [ ] Driver attestation-signed by Microsoft (4b); `wiretap.exe` signed and timestamped (4d)
- [ ] Package built (section 6) and checksums published
- [ ] SETUP.md matches the release; known limitations documented
