//! User-mode side of `WiretapDriver`.
//!
//! [`Capture`] ties the driver's lifetime to Wiretap's: starting a capture starts the driver
//! service, opens its device and installs WFP filters in a *dynamic* session; dropping it
//! removes the filters and closes the device. The driver unloads then only if it redirected no
//! connection since it was loaded (see [`Stopped`]); otherwise it stays loaded with no filters,
//! seeing and changing no traffic, until Windows restarts. If the process dies instead, Windows
//! deletes the dynamic filters and the driver likewise sees no traffic.
#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "Win32 FFI boundary; every block carries a SAFETY comment"
)]

use std::io;
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::thread::sleep;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_NOT_ACTIVE, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_CALLOUT_INSPECTION, FWP_ACTION_CALLOUT_UNKNOWN, FWP_MATCH_EQUAL,
    FWP_UINT8, FWP_UINT16, FWPM_CALLOUT0, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
    FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, FWPM_LAYER_STREAM_V4, FWPM_LAYER_STREAM_V6,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0, FwpmCalloutAdd0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};
use windows_sys::core::GUID;
use wiretap_driver_proto as proto;

mod crash;
pub use crash::{CaptureMarker, crash_report};

/// Name of the driver's Windows service (created by `WiretapDriver.inf`).
pub const SERVICE_NAME: &str = "WiretapDriver";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn last_error(context: &str) -> io::Error {
    // SAFETY: reads the calling thread's last-error value.
    let code = unsafe { GetLastError() };
    os_error(context, code)
}

fn os_error(context: &str, code: u32) -> io::Error {
    let hint = match code {
        ERROR_ACCESS_DENIED => " (run Wiretap as Administrator)",
        ERROR_SERVICE_DOES_NOT_EXIST => " (driver not installed: see SETUP.md)",
        _ => "",
    };
    let source = io::Error::from_raw_os_error(i32::from_ne_bytes(code.to_ne_bytes()));
    io::Error::new(
        source.kind(),
        format!("{context}: {source} [0x{code:08x}]{hint}"),
    )
}

/// An open service-control handle pair; closed on drop.
struct ServiceHandle {
    manager: SC_HANDLE,
    service: SC_HANDLE,
}

impl ServiceHandle {
    /// Opens the driver service; errors carry the raw Win32 code.
    fn open_raw(access: u32) -> Result<Self, u32> {
        // SAFETY: null machine/database names select the local SCM; handles are checked.
        let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            // SAFETY: reads the thread's last-error value.
            return Err(unsafe { GetLastError() });
        }
        let name = wide(SERVICE_NAME);
        // SAFETY: `manager` is valid and `name` is NUL-terminated.
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), access) };
        let handle = Self { manager, service };
        if service.is_null() {
            // SAFETY: reads the thread's last-error value.
            return Err(unsafe { GetLastError() });
        }
        Ok(handle)
    }

    fn open(access: u32) -> io::Result<Self> {
        Self::open_raw(access)
            .map_err(|code| os_error("cannot open the WiretapDriver service", code))
    }

    fn state(&self) -> io::Result<u32> {
        // SAFETY: SERVICE_STATUS is plain data; `service` is valid.
        let mut status: SERVICE_STATUS = unsafe { zeroed() };
        // SAFETY: valid handle and out-pointer.
        if unsafe { QueryServiceStatus(self.service, &mut status) } == 0 {
            return Err(last_error("cannot query the WiretapDriver service"));
        }
        Ok(status.dwCurrentState)
    }

    fn stop(&self) -> io::Result<()> {
        // SAFETY: SERVICE_STATUS is plain data.
        let mut status: SERVICE_STATUS = unsafe { zeroed() };
        // SAFETY: valid handle and out-pointer.
        if unsafe { ControlService(self.service, SERVICE_CONTROL_STOP, &mut status) } == 0 {
            // SAFETY: reads the thread's last-error value.
            let code = unsafe { GetLastError() };
            return if code == ERROR_SERVICE_NOT_ACTIVE {
                Ok(())
            } else {
                Err(os_error("cannot stop the driver", code))
            };
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.state()? != SERVICE_STOPPED {
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "driver did not stop within 10 s",
                ));
            }
            sleep(Duration::from_millis(50));
        }
        Ok(())
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: handles were opened by `open`; null handles are skipped.
        unsafe {
            if !self.service.is_null() {
                CloseServiceHandle(self.service);
            }
            CloseServiceHandle(self.manager);
        }
    }
}

/// Driver service state, for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverState {
    /// The service does not exist (driver package not installed).
    NotInstalled,
    /// Installed and not loaded.
    Stopped,
    /// Loaded.
    Running,
    /// Starting, stopping or paused.
    Transitioning,
}

/// Queries the driver service without changing it.
///
/// # Errors
/// Service-manager failures other than "not installed".
pub fn driver_state() -> io::Result<DriverState> {
    match ServiceHandle::open_raw(SERVICE_QUERY_STATUS) {
        Err(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(DriverState::NotInstalled),
        Err(code) => Err(os_error("cannot open the WiretapDriver service", code)),
        Ok(service) => Ok(match service.state()? {
            SERVICE_RUNNING => DriverState::Running,
            SERVICE_STOPPED => DriverState::Stopped,
            _ => DriverState::Transitioning,
        }),
    }
}

/// Unloads the driver if it is loaded but cannot hold anything of a connection: never, once it
/// may have redirected connections (see [`Stopped`]), which is unknowable here, so a loaded
/// driver is only reported.
///
/// # Errors
/// The driver is loaded (it stays so, with no filters, until Windows restarts), or
/// service-manager failures, including insufficient rights.
pub fn stop_driver() -> io::Result<()> {
    let service = ServiceHandle::open(SERVICE_QUERY_STATUS)?;
    if service.state()? == SERVICE_STOPPED {
        return Ok(());
    }
    Err(io::Error::other(
        "WiretapDriver stays loaded until Windows restarts: connections it may have redirected keep memory Windows frees only when they are gone, and unloading under them could crash Windows. Without filters it sees and changes no traffic; the next capture uses it",
    ))
}

/// The driver's device channel.
struct Device(HANDLE);

impl Device {
    fn open() -> io::Result<Self> {
        let path = wide(proto::CLIENT_PATH);
        // SAFETY: NUL-terminated path; no sharing (the device is exclusive anyway).
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("cannot open the WiretapDriver device"));
        }
        Ok(Self(handle))
    }

    fn ioctl(&self, code: u32, input: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let mut returned = 0u32;
        let len = u32::try_from(out.len()).unwrap_or(u32::MAX);
        let input_len = u32::try_from(input.len()).unwrap_or(u32::MAX);
        // SAFETY: `input` is readable and `out` writable for their lengths; synchronous handle.
        let ok = unsafe {
            DeviceIoControl(
                self.0,
                code,
                input.as_ptr().cast(),
                input_len,
                out.as_mut_ptr().cast(),
                len,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("driver request failed"));
        }
        Ok(usize::try_from(returned).unwrap_or(0).min(out.len()))
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `Device::open`.
        unsafe { CloseHandle(self.0) };
    }
}

/// A dynamic BFE session holding Wiretap's sublayer, callouts and filters.
struct Filters(HANDLE);

fn check(code: u32, context: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(os_error(context, code))
    }
}

/// (callout key, WFP layer) for every callout the driver registers.
const CALLOUTS: [(u128, GUID); 4] = [
    (proto::CALLOUT_FLOW_V4, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4),
    (proto::CALLOUT_FLOW_V6, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6),
    (proto::CALLOUT_STREAM_V4, FWPM_LAYER_STREAM_V4),
    (proto::CALLOUT_STREAM_V6, FWPM_LAYER_STREAM_V6),
];

impl Filters {
    fn install(redirect: bool) -> io::Result<Self> {
        let mut name = wide("Wiretap capture");
        // SAFETY: plain data, all-zero is a valid empty session.
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = name.as_mut_ptr();
        let mut engine: HANDLE = null_mut();
        // SAFETY: local engine; `session` and `name` outlive the call.
        let status =
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) };
        check(status, "cannot open the filter engine")?;
        let filters = Self(engine);
        // SAFETY: valid engine handle.
        let status = unsafe { FwpmTransactionBegin0(engine, 0) };
        check(status, "cannot begin a filter transaction")?;
        if let Err(e) = add_objects(engine, &mut name, redirect) {
            // SAFETY: valid engine handle with an open transaction.
            unsafe { FwpmTransactionAbort0(engine) };
            return Err(e);
        }
        // SAFETY: valid engine handle with an open transaction.
        let status = unsafe { FwpmTransactionCommit0(engine) };
        check(status, "cannot commit the capture filters")?;
        Ok(filters)
    }
}

fn add_objects(engine: HANDLE, name: &mut [u16], redirect: bool) -> io::Result<()> {
    let sublayer_key = GUID::from_u128(proto::SUBLAYER_KEY);
    // SAFETY: plain data, all-zero is valid.
    let mut sublayer: FWPM_SUBLAYER0 = unsafe { zeroed() };
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData.name = name.as_mut_ptr();
    // SAFETY: valid engine; `sublayer` is fully initialized.
    let status = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    check(status, "cannot add the Wiretap sublayer")?;
    for (key, layer) in CALLOUTS {
        let callout_key = GUID::from_u128(key);
        // SAFETY: plain data, all-zero is valid.
        let mut callout: FWPM_CALLOUT0 = unsafe { zeroed() };
        callout.calloutKey = callout_key;
        callout.displayData.name = name.as_mut_ptr();
        callout.applicableLayer = layer;
        // SAFETY: valid engine; the callout is registered by the loaded driver.
        let status = unsafe { FwpmCalloutAdd0(engine, &callout, null_mut(), null_mut()) };
        check(status, "cannot add a Wiretap callout")?;
        // SAFETY: plain data, all-zero is valid (weight FWP_EMPTY = automatic).
        let mut filter: FWPM_FILTER0 = unsafe { zeroed() };
        filter.displayData.name = name.as_mut_ptr();
        filter.layerKey = layer;
        filter.subLayerKey = sublayer_key;
        // Inspection callouts can never block: if the callout is missing, WFP skips the filter.
        filter.action.r#type = FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.Anonymous.calloutKey = callout_key;
        // SAFETY: valid engine; `filter` is fully initialized.
        let status = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) };
        check(status, "cannot add a Wiretap filter")?;
    }
    if redirect {
        add_redirect_objects(engine, name, sublayer_key)?;
    }
    Ok(())
}

/// Condition `field == value` (`FWP_UINT8` when `byte`, else `FWP_UINT16`).
fn equals(field: GUID, value: u16, byte: bool) -> FWPM_FILTER_CONDITION0 {
    // SAFETY: plain data, all-zero is valid.
    let mut c: FWPM_FILTER_CONDITION0 = unsafe { zeroed() };
    c.fieldKey = field;
    c.matchType = FWP_MATCH_EQUAL;
    if byte {
        c.conditionValue.r#type = FWP_UINT8;
        c.conditionValue.Anonymous.uint8 = u8::try_from(value).unwrap_or(0);
    } else {
        c.conditionValue.r#type = FWP_UINT16;
        c.conditionValue.Anonymous.uint16 = value;
    }
    c
}

/// Transparent interception: outbound TCP to ports 80 and 443 goes through the redirect
/// callouts (conditions on the same field are ORed by WFP), and QUIC (UDP 443) is blocked so
/// browsers fall back to TCP, which can be decrypted. If the callouts are not registered the
/// redirect filters permit instead of blocking.
fn add_redirect_objects(engine: HANDLE, name: &mut [u16], sublayer_key: GUID) -> io::Result<()> {
    let redirect = [
        (
            proto::CALLOUT_REDIRECT_V4,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        ),
        (
            proto::CALLOUT_REDIRECT_V6,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        ),
    ];
    for (key, layer) in redirect {
        let callout_key = GUID::from_u128(key);
        // SAFETY: plain data, all-zero is valid.
        let mut callout: FWPM_CALLOUT0 = unsafe { zeroed() };
        callout.calloutKey = callout_key;
        callout.displayData.name = name.as_mut_ptr();
        callout.applicableLayer = layer;
        // SAFETY: valid engine; the callout is registered by the loaded driver.
        let status = unsafe { FwpmCalloutAdd0(engine, &callout, null_mut(), null_mut()) };
        check(status, "cannot add the Wiretap redirect callout")?;
        let mut conditions = [
            equals(FWPM_CONDITION_IP_PROTOCOL, 6, true),
            equals(FWPM_CONDITION_IP_REMOTE_PORT, 80, false),
            equals(FWPM_CONDITION_IP_REMOTE_PORT, 443, false),
        ];
        add_filter(
            engine,
            name,
            layer,
            sublayer_key,
            FWP_ACTION_CALLOUT_UNKNOWN,
            Some(callout_key),
            &mut conditions,
        )?;
    }
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ] {
        let mut conditions = [
            equals(FWPM_CONDITION_IP_PROTOCOL, 17, true),
            equals(FWPM_CONDITION_IP_REMOTE_PORT, 443, false),
        ];
        add_filter(
            engine,
            name,
            layer,
            sublayer_key,
            FWP_ACTION_BLOCK,
            None,
            &mut conditions,
        )?;
    }
    Ok(())
}

fn add_filter(
    engine: HANDLE,
    name: &mut [u16],
    layer: GUID,
    sublayer: GUID,
    action: u32,
    callout: Option<GUID>,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> io::Result<()> {
    // SAFETY: plain data, all-zero is valid (weight FWP_EMPTY = automatic).
    let mut filter: FWPM_FILTER0 = unsafe { zeroed() };
    filter.displayData.name = name.as_mut_ptr();
    filter.layerKey = layer;
    filter.subLayerKey = sublayer;
    filter.action.r#type = action;
    if let Some(key) = callout {
        filter.action.Anonymous.calloutKey = key;
        filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    }
    filter.numFilterConditions = u32::try_from(conditions.len()).unwrap_or(0);
    filter.filterCondition = conditions.as_mut_ptr();
    // SAFETY: valid engine; `filter` and `conditions` outlive the call.
    let status = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) };
    check(status, "cannot add a Wiretap filter")
}

impl Drop for Filters {
    fn drop(&mut self) {
        // SAFETY: closing the engine ends the dynamic session and deletes all its objects.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// The loaded driver. Dropping it ends the capture's use of it ([`Running::release`]) on any
/// exit path.
struct Running {
    service: ServiceHandle,
    /// This capture loaded the driver and nothing was redirected: it may unload.
    unloadable: bool,
    released: bool,
}

impl Running {
    /// Unloads the driver if it may (see [`Stopped`]).
    fn release(&mut self) -> io::Result<Stopped> {
        self.released = true;
        if self.unloadable {
            self.service.stop()?;
        }
        Ok(Stopped {
            unloaded: self.unloadable,
        })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.release();
        }
    }
}

/// An active capture. Field order is drop order: filters, then device, then driver.
pub struct Capture {
    filters: Filters,
    device: Device,
    driver: Running,
    buffer: Vec<u8>,
    redirect: Option<proto::Redirect>,
}

/// How [`Capture::stop`] went.
///
/// The driver unloads only if it redirected no connection since it was loaded. WFP keeps the
/// redirect context the driver attaches to each redirected connection until that connection's
/// socket is gone, which can be long after the connection itself: through TIME_WAIT, and for as
/// long as the app keeps a socket whose connection was reset. Windows exposes nothing that
/// proves none is left, and unloading under one is a pool leak (bug check 0xC4/0x62 under
/// Driver Verifier, reproduced 2026-11-10 with a socket kept after a reset). So once it has
/// redirected, the driver stays loaded with no filters and no redirection, seeing and changing
/// no traffic, until Windows restarts; the next capture uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stopped {
    /// Whether the driver was unloaded.
    pub unloaded: bool,
}

impl Capture {
    /// Loads the driver, verifies its protocol version and installs the capture filters.
    /// With `redirect`, outbound TCP 80/443 is also sent to that proxy (transparent HTTPS
    /// decryption) and QUIC is blocked for the capture's lifetime. Requires Administrator rights.
    ///
    /// # Errors
    /// Missing driver package, insufficient rights, version mismatch or WFP failures. On any
    /// error the driver is unloaded again.
    pub fn start(redirect: Option<proto::Redirect>) -> io::Result<Self> {
        let service = ServiceHandle::open(SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        // SAFETY: valid service handle; no arguments.
        let loaded_here = unsafe { StartServiceW(service.service, 0, null()) } != 0;
        if !loaded_here {
            // SAFETY: reads the thread's last-error value.
            let code = unsafe { GetLastError() };
            if code != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(os_error("cannot start the driver", code));
            }
            // Already loaded: it may have redirected before, so it stays loaded (see `Stopped`).
        }
        // On any error below, locals drop in reverse order (filters, device, then `driver`,
        // which unloads the driver if it may).
        let mut driver = Running {
            service,
            unloadable: loaded_here,
            released: false,
        };
        let device = Device::open()?;
        let mut reply = [0u8; 8];
        device.ioctl(proto::IOCTL_GET_VERSION, &[], &mut reply)?;
        let [a, b, c, d, ..] = reply;
        let protocol = u32::from_le_bytes([a, b, c, d]);
        if protocol != proto::PROTOCOL_VERSION {
            return Err(io::Error::other(format!(
                "driver speaks protocol {protocol}, Wiretap needs {}; reinstall matching versions",
                proto::PROTOCOL_VERSION
            )));
        }
        let filters = Filters::install(redirect.is_some())?;
        if let Some(r) = redirect {
            driver.unloadable = false; // from here on, connections may be redirected
            device.ioctl(proto::IOCTL_SET_REDIRECT, &r.encode(), &mut [])?;
        }
        Ok(Self {
            filters,
            device,
            driver,
            buffer: vec![0; proto::MAX_READ],
            redirect,
        })
    }

    /// Waits up to `proto::READ_WAIT_MS` for records. Returns the number of records the
    /// driver dropped since the last read and the record bytes (see `proto::records`).
    ///
    /// # Errors
    /// Device I/O failures or a malformed reply.
    pub fn read(&mut self) -> io::Result<(u64, &[u8])> {
        let n = self
            .device
            .ioctl(proto::IOCTL_READ_EVENTS, &[], &mut self.buffer)?;
        let (dropped, records) = self
            .buffer
            .get(..n)
            .and_then(|b| b.split_first_chunk::<8>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short reply from driver"))?;
        Ok((u64::from_le_bytes(*dropped), records))
    }

    /// Stops capturing: ends redirection, removes the filters, closes the device, then unloads
    /// the driver if it redirected nothing since it was loaded (see [`Stopped`]).
    ///
    /// # Errors
    /// The driver could not be stopped (it then stays loaded but receives no traffic).
    pub fn stop(self) -> io::Result<Stopped> {
        let Self {
            filters,
            device,
            mut driver,
            redirect,
            ..
        } = self;
        if redirect.is_some() {
            // All zero: stop redirecting new connections (open ones go on through the proxy).
            let _ = device.ioctl(
                proto::IOCTL_SET_REDIRECT,
                &[0; proto::Redirect::SIZE],
                &mut [],
            );
        }
        drop(filters);
        drop(device);
        driver.release()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use super::*;

    /// Values measured from the Windows SDK headers (`fwpmu.h`) with MSVC; guards against
    /// binding-layout drift like the one found in kernel structures.
    #[test]
    fn wfp_struct_layouts_match_the_sdk() {
        assert_eq!(size_of::<FWPM_SESSION0>(), 72);
        assert_eq!(offset_of!(FWPM_SESSION0, flags), 32);
        assert_eq!(size_of::<FWPM_SUBLAYER0>(), 72);
        assert_eq!(offset_of!(FWPM_SUBLAYER0, weight), 64);
        assert_eq!(size_of::<FWPM_CALLOUT0>(), 88);
        assert_eq!(offset_of!(FWPM_CALLOUT0, applicableLayer), 64);
        assert_eq!(size_of::<FWPM_FILTER0>(), 200);
        assert_eq!(offset_of!(FWPM_FILTER0, layerKey), 64);
        assert_eq!(offset_of!(FWPM_FILTER0, subLayerKey), 80);
        assert_eq!(offset_of!(FWPM_FILTER0, action), 128);
        assert_eq!(offset_of!(FWPM_FILTER0, filterId), 176);
    }

    #[test]
    fn errors_carry_actionable_hints() {
        assert!(
            os_error("x", ERROR_ACCESS_DENIED)
                .to_string()
                .contains("Administrator")
        );
        assert!(
            os_error("x", ERROR_SERVICE_DOES_NOT_EXIST)
                .to_string()
                .contains("SETUP.md")
        );
    }

    #[test]
    fn driver_state_query_does_not_require_admin() {
        // Works unelevated: either reports the installed state or "not installed".
        assert!(driver_state().is_ok());
    }
}
