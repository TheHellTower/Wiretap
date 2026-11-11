# Wiretap setup

This guide covers installing, using and removing Wiretap v0.1.

## 1. Requirements

| | Requirement |
| --- | --- |
| Windows | Windows 10 22H2 (19045) or Enterprise LTSC 2021 (19044), or Windows 11 24H2 (26100) or 25H2 (26200), all x64 client editions. Run `wiretap check` to see how your system is classified. |
| Rights | An Administrator account. Capturing needs an elevated terminal. |
| Disk | Up to 8 GiB for the capture database (fixed quota). |
| Not supported | Windows Server, ARM64, Windows 11 23H2 and older, Windows 10 2004/20H2/21H1 and older |

## 2. Choose the right package

The driver must be signed for Windows to load it:

- **Release package (Microsoft-signed driver):** installs on normal machines with Secure Boot and Memory Integrity on. No security setting changes. This is what end users should use.
- **Test package (test-signed driver, lab only):** loads only on a machine in *test-signing mode*, which requires Secure Boot to be off. Use it only in a virtual machine or a dedicated test machine, never on a machine you rely on.

v0.1 is currently built as a test package; a Microsoft-signed release package is part of the release process in [RELEASE.md](RELEASE.md).

## 3. Install

Unzip the package to a folder of your choice, for example `C:\Program Files\Wiretap`. It contains `wiretap.exe` and a `driver\` folder with `WiretapDriver.sys`, `WiretapDriver.inf` and `wiretapdriver.cat`; test packages also include `WiretapTestSigning.cer`. Then open **Terminal (Admin)** in that folder.

### 3a. Release package

```powershell
pnputil /add-driver .\driver\WiretapDriver.inf /install
.\wiretap.exe check
```

### 3b. Test package (lab machine or VM only)

```powershell
bcdedit /set testsigning on                                  # needs Secure Boot off; takes effect after reboot
certutil -addstore Root .\WiretapTestSigning.cer
certutil -f -addstore TrustedPublisher .\WiretapTestSigning.cer
Restart-Computer
# after the reboot, in an elevated terminal:
pnputil /add-driver .\driver\WiretapDriver.inf /install
.\wiretap.exe check                                          # "Test signing  yes", "Driver  Stopped"
```

Installing creates the `WiretapDriver` service with *manual* start: the driver is **not** loaded at boot and stays unloaded until you start a capture. No reboot is needed for the driver itself.

## 4. Use

Start **Wiretap** (`wiretap.exe`). It opens its own window; nothing needs administrator rights until you capture.

1. **Start capture.** Approve the administrator prompt: it loads the driver. From now on every app's connections appear with the application that made them, and every HTTP and HTTPS request is recorded in full (headers, bodies, timing). **Stop capture**, or closing Wiretap, removes every filter. Connections still open then (a WebSocket, an event stream) go on until they end. The driver itself stays loaded, without filters (it sees and changes nothing), until Windows restarts: connections it redirected keep a little of its memory that Windows frees only when they are fully gone, and unloading under them could crash Windows.
2. **HTTPS decryption** (optional, once). Windows shows its own dialog asking whether to trust the *Wiretap root certificate*; choose **Yes**. HTTPS then shows real requests (`GET https://…`) with bodies. Without it, HTTPS rows show only the server name, TLS version and application. Turning it off removes the certificate from Windows and deletes its keys.
3. Click a request to see its headers, body and timing. Right-click for copy (URL, cURL, headers, body), show-only and filter-out, highlight, **Create auto-reply**, **Redirect this host…** and saving the response body.

Notes:
- Apps that refuse the Wiretap certificate (some pin their own certificates or keep their own trust store, like Firefox unless you import the root there) keep working: after one refusal Wiretap relays that app's connections to that server without decrypting them. Apps known to pin (Microsoft Defender) and Windows services (which do not trust a root you trusted for your account) are relayed untouched from their first connection. Relayed connections still show their server name, TLS version, cipher, server certificate (before TLS 1.3), size and the reason.
- A server Wiretap cannot verify (expired or self-signed certificate) is relayed untouched, so the app sees it exactly as without Wiretap.
- While capturing, QUIC (HTTP/3 over UDP 443) is blocked so browsers fall back to TCP, which Wiretap can decode.
- **Open browser** opens a private browser window that sends everything through Wiretap even without a capture.

**Rules** (rail: Rules). Each request gets one outcome:
- **Redirect:** send matching requests to another server, e.g. `https://api.example.com/v1/users?id=7` → `http://localhost:3000/v1/users?id=7`. The original server is never contacted.
- **Auto-reply:** Wiretap answers with the status, headers and body you set; no server is needed. A rule created from a request starts as its original response.

Redirects are checked before auto-replies; anything else goes to its real server. Rules work over HTTP/1.x and HTTP/2; a rule added while an app keeps a connection open applies within a second (the app is asked to reconnect). Match on URL, host, path, query, headers, cookies, body, content type, application, IPs or port. Put rules in **groups**: a group is enabled, exported and imported together as a `<domain>.wtrr` file you can share. Importing a group again replaces it.

**Search** (Ctrl+F): free text or fields like `app:msedge host:*.example.com method:post status:4xx type:json -host:ads`. Suggestions come from what you captured.

**Sessions**: every run of Wiretap is one session. Open older ones, delete them, or **Export HAR** / **Import HAR** to exchange captures with browsers and other tools.

**Developer mode** (System view) shows diagnostics normal use does not need: connection-level rows (refused certificates, relayed tunnels), the Connections view and system internals.

Command-line mode (`--headless`) for scripts:

```powershell
wiretap --headless check                         # Windows support, privileges, driver state
wiretap --headless capture --duration 60         # elevated: capture in the terminal
wiretap --headless sessions                      # id, start time, name
wiretap --headless flows  <session-id>           # HTTP flows, one JSON object per line
wiretap --headless events <session-id>           # connection and TLS events, one JSON object per line
```

The JSON output is a stable, language-neutral format: snake_case fields, string enums, UUID strings and integer microsecond UTC timestamps.

## 5. Your data

Captures are stored in `%LOCALAPPDATA%\Wiretap\wiretap.db`, which only your account can read. They contain whatever the captured apps sent, including cookies, tokens and passwords in decrypted HTTPS. Delete sessions you do not need, or the whole file. The Wiretap root certificate's private key is a non-exportable key in your Windows key store; it never leaves it and is never written to the database. Wiretap's window keeps no browser data (it runs InPrivate in a temporary folder deleted on exit).
## 6. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `capture requires an elevated ... terminal` | Open Terminal with **Run as administrator**. |
| `driver not installed` | Install the package (section 3). |
| `cannot start the driver: ... 577` (signature) | A test package on a machine without test signing: see 3b, or use a release package. |
| `driver speaks protocol N` | `wiretap.exe` and the driver are from different releases; reinstall both from the same package. |
| Wiretap crashed or was killed | Nothing to do: capture filters, redirection and QUIC blocking are already gone (Windows removes them with the process). The driver stays loaded, inert, until Windows restarts. |
| A site shows a certificate warning while capturing | That app does not trust the Wiretap root (e.g. Firefox): import `wiretap-root.cer` (System view) into it, or ignore it: the next connections are relayed untouched. |
| The window does not open | Install the Microsoft Edge WebView2 Runtime (part of Windows 11 and current Windows 10). |

## 7. Uninstall

```powershell
pnputil /enum-drivers | Select-String -Context 1,5 WiretapDriver   # note the "Published Name", e.g. oem42.inf
pnputil /delete-driver oem42.inf /uninstall /force
Remove-Item -Recurse "$env:LOCALAPPDATA\Wiretap"                    # captures (optional)
```

If you turned HTTPS decryption on, turn it off in Wiretap first (it removes the root certificate and deletes its keys), or remove the certificate named *Wiretap Root CA …* with `certmgr.msc` (Trusted Root Certification Authorities).

On a test machine, also undo the lab settings:

```powershell
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher |
    Where-Object Subject -like '*Wiretap Test Driver Signing*' | Remove-Item
bcdedit /set testsigning off
Restart-Computer
```
