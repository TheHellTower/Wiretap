//! Links against the WDK kernel libraries and applies the kernel-driver linker settings.
//! Set WIRETAP_WDK_LIB to the WDK `Lib\<version>\km\x64` directory to override discovery.

use std::path::{Path, PathBuf};

fn wdk_lib_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("WIRETAP_WDK_LIB") {
        return Some(PathBuf::from(dir));
    }
    let root = Path::new(r"C:\Program Files (x86)\Windows Kits\10\Lib");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path().join(r"km\x64")))
        .filter(|p| p.join("fwpkclnt.lib").is_file())
        .collect();
    candidates.sort();
    candidates.pop()
}

fn main() {
    println!("cargo:rerun-if-env-changed=WIRETAP_WDK_LIB");
    let Some(lib) = wdk_lib_dir() else {
        println!(
            "cargo:warning=WDK kernel libraries not found; install the WDK or set WIRETAP_WDK_LIB"
        );
        std::process::exit(1);
    };
    println!("cargo:rustc-link-search=native={}", lib.display());
    for name in ["ntoskrnl", "fwpkclnt", "wdmsec", "BufferOverflowFastFailK"] {
        println!("cargo:rustc-link-lib={name}");
    }
    for arg in [
        "/DRIVER",
        "/SUBSYSTEM:NATIVE,10.00",
        "/ENTRY:DriverEntry",
        "/NODEFAULTLIB",
        "/MANIFEST:NO",
        "/RELEASE",
        "/NXCOMPAT",
        "/DYNAMICBASE",
        "/OPT:REF,ICF",
        "/MERGE:.edata=.rdata",
        "/SECTION:INIT,d",
        "/IGNORE:4216", // DriverEntry is exported by Rust cdylibs; harmless
    ] {
        println!("cargo:rustc-cdylib-link-arg={arg}");
    }
}
