//! Links Microsoft's WebView2 static loader (no DLL ships with Wiretap).
//! `tools/fetch-webview2.ps1` downloads and verifies it; set WIRETAP_WEBVIEW2_LIB to the
//! directory containing `WebView2LoaderStatic.lib` to override.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=WIRETAP_WEBVIEW2_LIB");
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    let root =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default()).join("../..");
    let pinned = root.join("tools/webview2-sdk.txt");
    println!("cargo:rerun-if-changed={}", pinned.display());
    let version = std::fs::read_to_string(&pinned)
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_owned()))
        .unwrap_or_default();
    let dir = std::env::var_os("WIRETAP_WEBVIEW2_LIB").map_or_else(
        || root.join("target/webview2").join(&version).join("x64"),
        PathBuf::from,
    );
    let lib = dir.join("WebView2LoaderStatic.lib");
    if !lib.is_file() {
        println!(
            "cargo:warning=WebView2 SDK {version} not found; run tools/fetch-webview2.ps1 (or set WIRETAP_WEBVIEW2_LIB)"
        );
        std::process::exit(1);
    }
    println!("cargo:rerun-if-changed={}", lib.display());
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=WebView2LoaderStatic");
    // The loader's event tracing (EventRegister, EventWriteTransfer, ...).
    println!("cargo:rustc-link-lib=advapi32");
}
