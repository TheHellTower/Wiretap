//! Reports a Windows stop (bug check) that happened while a capture ran. The capture keeps a
//! marker file for its lifetime; a marker older than the last boot means Windows restarted
//! during that capture, and the System log says how (event 1001 of
//! `Microsoft-Windows-WER-SystemErrorReporting`: bug check code, parameters and dump file).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::{Duration, SystemTime};

use windows_sys::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtRender, EvtRenderEventXml,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

use crate::wide;

const MARKER: &str = "capture.running";

/// Exists while a capture runs (removed when dropped, also on errors). Windows stopping
/// meanwhile leaves it behind for [`crash_report`].
pub struct CaptureMarker(PathBuf);

impl CaptureMarker {
    /// Creates the marker in `dir` (the app's data directory).
    ///
    /// # Errors
    /// The file cannot be written.
    pub fn create(dir: &Path) -> io::Result<Self> {
        let path = dir.join(MARKER);
        fs::write(&path, b"")?;
        Ok(Self(path))
    }
}

impl Drop for CaptureMarker {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// If Windows restarted during the last capture recorded in `dir`, what happened, for the user
/// (once: the marker is removed). `None` when the last capture ended normally, or ended without
/// Windows restarting (the capture process itself was stopped).
#[must_use]
pub fn crash_report(dir: &Path) -> Option<String> {
    let path = dir.join(MARKER);
    let started = fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let _ = fs::remove_file(&path);
    // SAFETY: no arguments; milliseconds since Windows started.
    let up = Duration::from_millis(unsafe { GetTickCount64() });
    let boot = SystemTime::now().checked_sub(up)?;
    let age = SystemTime::now()
        .duration_since(started)
        .unwrap_or_default();
    report(started < boot, bugcheck_within(age))
}

/// The message for a capture that `restarted` Windows, given the recorded bug check.
fn report(restarted: bool, bugcheck: Option<(String, String)>) -> Option<String> {
    if !restarted {
        return None;
    }
    Some(match bugcheck {
        Some((code, dump)) => format!(
            "Windows stopped while Wiretap was capturing: bug check {code}. Windows saved a dump at {dump}. Please report it with the dump (see SECURITY.md) so it can be fixed."
        ),
        None => "Windows restarted while Wiretap was capturing, without recording a bug check (power loss, a forced restart, or a stop Windows could not record).".into(),
    })
}

/// The newest bug check of the last `age`: its code with parameters, and the dump path.
fn bugcheck_within(age: Duration) -> Option<(String, String)> {
    let ms = age.as_millis().saturating_add(60_000); // the event is written after the reboot
    let query = wide(&format!(
        "*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001 and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    ));
    let channel = wide("System");
    // SAFETY: NUL-terminated strings; local session (null). Closed below.
    let results = unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            query.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if results == 0 {
        return None;
    }
    let mut event: EVT_HANDLE = 0;
    let mut returned = 0u32;
    // SAFETY: valid query handle; room for one event handle.
    let found = unsafe { EvtNext(results, 1, &mut event, 1000, 0, &mut returned) } != 0;
    let xml = (found && returned == 1).then(|| render(event)).flatten();
    // SAFETY: handles from EvtQuery/EvtNext, closed once.
    unsafe {
        if event != 0 {
            EvtClose(event);
        }
        EvtClose(results);
    }
    let xml = xml?;
    Some((
        event_data(&xml, "param1")?.to_owned(),
        event_data(&xml, "param2")
            .unwrap_or("an unknown path")
            .to_owned(),
    ))
}

/// The event as XML.
fn render(event: EVT_HANDLE) -> Option<String> {
    let (mut used, mut properties) = (0u32, 0u32);
    let mut buf: Vec<u16> = Vec::new();
    for _ in 0..2 {
        let bytes = u32::try_from(buf.len().saturating_mul(2)).ok()?;
        // SAFETY: `buf` holds `bytes` writable bytes (or none on the sizing call).
        let ok = unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                bytes,
                if buf.is_empty() {
                    null_mut()
                } else {
                    buf.as_mut_ptr().cast()
                },
                &mut used,
                &mut properties,
            )
        };
        if ok != 0 {
            let chars = usize::try_from(used / 2).ok()?;
            let text = buf.get(..chars)?;
            return Some(
                String::from_utf16_lossy(text)
                    .trim_end_matches('\0')
                    .to_owned(),
            );
        }
        buf.resize(usize::try_from(used.div_ceil(2)).ok()?, 0);
    }
    None
}

/// The text of `<Data Name='name'>…</Data>` in an event's XML.
fn event_data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<Data Name='{name}'>");
    let start = xml.find(&open)?.saturating_add(open.len());
    let rest = xml.get(start..)?;
    rest.get(..rest.find("</Data>")?).map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_bugcheck_event() {
        let xml = "<Event><EventData><Data Name='param1'>0x000000c4 (0x0000000000000062, 0xffffba06da8d0870, 0xffffba06d689ed50, 0x0000000000000001)</Data><Data Name='param2'>C:\\Windows\\MEMORY.DMP</Data><Data Name='param3'>a187d0a2</Data></EventData></Event>";
        assert_eq!(
            event_data(xml, "param1"),
            Some(
                "0x000000c4 (0x0000000000000062, 0xffffba06da8d0870, 0xffffba06d689ed50, 0x0000000000000001)"
            )
        );
        assert_eq!(event_data(xml, "param2"), Some("C:\\Windows\\MEMORY.DMP"));
        assert_eq!(event_data(xml, "param9"), None);
    }

    #[test]
    fn reports_only_restarts_during_a_capture() {
        assert_eq!(
            report(false, None),
            None,
            "the capture process ended, Windows did not"
        );
        let stop = report(
            true,
            Some((
                "0x000000c4 (0x62, 0, 0, 1)".into(),
                "C:\\Windows\\MEMORY.DMP".into(),
            )),
        )
        .unwrap();
        assert!(
            stop.contains("bug check 0x000000c4 (0x62, 0, 0, 1)")
                && stop.contains("C:\\Windows\\MEMORY.DMP"),
            "{stop}"
        );
        assert!(
            report(true, None)
                .unwrap()
                .contains("without recording a bug check")
        );
    }

    #[test]
    fn markers_last_as_long_as_the_capture() {
        let dir = std::env::temp_dir().join(format!("wiretap-marker-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let marker = CaptureMarker::create(&dir).unwrap();
        assert!(dir.join(MARKER).exists());
        drop(marker);
        assert!(!dir.join(MARKER).exists());
        // A marker from this boot (the capture process ended, Windows did not): no report, and
        // it is cleaned up.
        std::mem::forget(CaptureMarker::create(&dir).unwrap());
        assert_eq!(crash_report(&dir), None);
        assert!(!dir.join(MARKER).exists());
        let _ = bugcheck_within(Duration::from_secs(3600)); // queries the real System log
        fs::remove_dir_all(&dir).unwrap();
    }
}
