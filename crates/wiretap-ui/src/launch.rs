//! Windows process launching: the elevated capture process (via UAC) and the optional
//! proxied browser window.
#![allow(
    unsafe_code,
    reason = "ShellExecuteEx and process-handle FFI; every block carries a SAFETY comment"
)]

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A process handle owned by the UI server.
pub(crate) struct Child(HANDLE);

// SAFETY: a process handle is a kernel object reference usable from any thread.
unsafe impl Send for Child {}
// SAFETY: the only operations (wait, query exit code) are thread-safe kernel calls.
unsafe impl Sync for Child {}

impl Child {
    /// Blocks until the process exits and returns its exit code.
    pub(crate) fn wait(&self) -> Option<u32> {
        // SAFETY: `self.0` is a valid process handle with SYNCHRONIZE and query rights.
        unsafe {
            WaitForSingleObject(self.0, INFINITE);
            let mut code = 0u32;
            (GetExitCodeProcess(self.0, &mut code) != 0).then_some(code)
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by ShellExecuteExW and is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Starts `exe args` elevated (UAC prompt), hidden. Fails with `ERROR_CANCELLED` (1223) when
/// the user declines.
pub(crate) fn spawn_elevated(exe: &Path, args: &str) -> io::Result<Child> {
    let (verb, file, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(args));
    // SAFETY: plain data; all-zero is a valid empty request.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` and the strings it points to outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.hProcess.is_null() {
        return Err(io::Error::other("elevated process handle unavailable"));
    }
    Ok(Child(info.hProcess))
}

fn edge() -> Option<PathBuf> {
    ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(|base| PathBuf::from(base).join(r"Microsoft\Edge\Application\msedge.exe"))
        .find(|p| p.is_file())
}

/// Edge switches that keep browser prompts (first run, default browser, crash restore, sync,
/// translate, permissions) out of Wiretap's windows.
const QUIET: [&str; 7] = [
    "--no-first-run",
    "--no-default-browser-check",
    "--hide-crash-restore-bubble",
    "--disable-sync",
    "--deny-permission-prompts",
    "--disable-notifications",
    "--disable-features=Translate,msEdgeTranslate",
];

/// Deep-merges `patch` into `into`.
fn merge(into: &mut serde_json::Value, patch: serde_json::Value) {
    match (into, patch) {
        (serde_json::Value::Object(into), serde_json::Value::Object(patch)) => {
            for (key, value) in patch {
                merge(into.entry(key).or_insert(serde_json::Value::Null), value);
            }
        }
        (into, patch) => *into = patch,
    }
}

/// Marks one of Wiretap's own Edge profiles as set up and cleanly closed, so Edge shows no
/// welcome, data-consent ("customize your experience"), password, translate or "restore
/// pages" prompt. Only that profile directory is touched; best effort.
fn prepare_profile(profile: &Path) {
    let prefs = profile.join("Default").join("Preferences");
    let mut root = std::fs::read(&prefs)
        .ok()
        .filter(|bytes| bytes.len() < 16 << 20)
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    merge(
        &mut root,
        serde_json::json!({
            "browser": { "has_seen_welcome_page": true },
            "personalization_data_consent": {
                "personalization_in_context_consent_can_prompt": false,
                "personalization_in_context_count": 1
            },
            "profile": { "exit_type": "Normal", "exited_cleanly": true },
            "credentials_enable_service": false,
            "autofill": { "profile_enabled": false, "credit_card_enabled": false },
            "translate": { "enabled": false }
        }),
    );
    if let (Some(dir), Ok(bytes)) = (prefs.parent(), serde_json::to_vec(&root)) {
        let _ = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&prefs, bytes));
    }
}

/// Opens an InPrivate Edge window that sends all traffic through the proxy on `127.0.0.1:port`.
/// `profile` is a throwaway folder (nothing is kept InPrivate; Wiretap deletes it on exit).
pub(crate) fn open_browser(port: u16, profile: &Path) -> io::Result<()> {
    let edge = edge().ok_or_else(|| io::Error::other("Microsoft Edge was not found"))?;
    prepare_profile(profile);
    Command::new(edge)
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--proxy-server=127.0.0.1:{port}"))
        .args(QUIET)
        .args(["--inprivate", "about:blank"])
        .spawn()
        .map(drop)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    #[test]
    fn profiles_are_prepared_without_losing_settings() {
        let dir =
            std::env::temp_dir().join(format!("wiretap-profile-{}", wiretap_core::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("Default")).unwrap();
        std::fs::write(
            dir.join("Default").join("Preferences"),
            br#"{"profile":{"exit_type":"Crashed","name":"x"},"keep":1}"#,
        )
        .unwrap();
        super::prepare_profile(&dir);
        let prefs: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.join("Default").join("Preferences")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            (
                prefs["profile"]["exit_type"].as_str(),
                prefs["profile"]["name"].as_str()
            ),
            (Some("Normal"), Some("x"))
        );
        assert_eq!(prefs["keep"], 1);
        assert_eq!(
            prefs["personalization_data_consent"]["personalization_in_context_consent_can_prompt"],
            false
        );
        std::fs::remove_dir_all(&dir).unwrap();
        // A fresh profile is created with the same settings.
        super::prepare_profile(&dir);
        assert!(dir.join("Default").join("Preferences").is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
