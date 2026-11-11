//! WiretapDriver: a minimal WFP callout driver.
//!
//! What it does, and nothing more:
//! * registers four inspection callouts: `ALE_FLOW_ESTABLISHED` (v4/v6) to record connections
//!   with their owning process, and `STREAM` (v4/v6) to record a bounded prefix of TCP stream
//!   data; they never block, modify or inject traffic;
//! * registers two `ALE_CONNECT_REDIRECT` (v4/v6) callouts that, only while the client has
//!   enabled it (`IOCTL_SET_REDIRECT`), send outbound TCP connections matched by the client's
//!   filters (ports 80/443) to Wiretap's own proxy on loopback, attaching the original
//!   destination for it. The proxy's own connections, loopback destinations and connections
//!   already redirected by anyone are never touched. Closing the device disables it;
//! * queues records in a fixed 4 MiB ring and drops (and counts) records when it is full, so
//!   memory is constant and classification never waits;
//! * exposes one exclusive device, accessible to SYSTEM and Administrators only, with two
//!   read-only IOCTLs whose input buffers are never read.
//!
//! The user-mode client adds the WFP filters that invoke these callouts inside a *dynamic* BFE
//! session: if the client exits or crashes, the filters vanish and capture stops.
#![no_std]
#![allow(
    unsafe_code,
    reason = "kernel FFI boundary; every block carries a SAFETY comment"
)]

mod ffi;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use ffi::*;
use wiretap_driver_proto as proto;

const POOL_TAG: u32 = u32::from_le_bytes(*b"WtAp");
const RING_BYTES: usize = 4 << 20;
const BUDGET_SLOTS: usize = 4096;
/// Bug check of a panic in a debug build (release builds contain no panic path).
#[cfg(debug_assertions)]
const BUGCHECK_RUST_PANIC: u32 = 0x5754_0001;
const DRIVER_VERSION: u32 = 0x0002_0000;

/// State touched by classify callbacks on any CPU; `inner` is guarded by `lock`.
struct Shared {
    lock: UnsafeCell<usize>,
    readable: UnsafeCell<KEVENT>,
    inner: UnsafeCell<Inner>,
}

struct Inner {
    ring: proto::Ring<RING_BYTES>,
    budget: proto::FlowBudget<BUDGET_SLOTS>,
    staging: [u8; proto::SEGMENT_CAP],
}

impl Shared {
    /// Runs `f` with exclusive access to `inner` at DISPATCH_LEVEL.
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        // SAFETY: the spin lock serializes every access to `inner`; `f` cannot re-enter
        // (it calls no code that takes this lock) and runs at DISPATCH_LEVEL, as required.
        unsafe {
            let old = KeAcquireSpinLockRaiseToDpc(self.lock.get());
            let result = f(&mut *self.inner.get());
            KeReleaseSpinLock(self.lock.get(), old);
            result
        }
    }

    fn signal(&self) {
        // SAFETY: `readable` was initialized by KeInitializeEvent; KeSetEvent with Wait=FALSE
        // is callable at <= DISPATCH_LEVEL.
        unsafe { KeSetEvent(self.readable.get(), 0, 0) };
    }
}

static STATE: AtomicPtr<Shared> = AtomicPtr::new(null_mut());
static DEVICE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(null_mut());
static LINKED: AtomicBool = AtomicBool::new(false);
/// Registered callout IDs plus one (zero means not registered).
static CALLOUTS: [AtomicU32; 6] = [const { AtomicU32::new(0) }; 6];
/// Active redirect configuration (`proto::Redirect` packed as pid << 32 | v4 << 16 | v6); zero:
/// off.
static REDIRECT: AtomicU64 = AtomicU64::new(0);
/// WFP redirect handle identifying Wiretap's redirections.
static REDIRECT_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

#[allow(
    clippy::indexing_slicing,
    reason = "compile-time only: an out-of-range index fails the build"
)]
const fn ascii_utf16<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    assert!(bytes.len() == N);
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        assert!(bytes[i].is_ascii());
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

static DEVICE_NAME: [u16; proto::DEVICE_NAME.len()] = ascii_utf16(proto::DEVICE_NAME);
static SYMLINK_NAME: [u16; proto::SYMLINK_NAME.len()] = ascii_utf16(proto::SYMLINK_NAME);
static DEVICE_SDDL: [u16; proto::DEVICE_SDDL.len()] = ascii_utf16(proto::DEVICE_SDDL);

fn unicode(s: &'static [u16]) -> UNICODE_STRING {
    let bytes = u16::try_from(s.len().saturating_mul(2)).unwrap_or(u16::MAX);
    UNICODE_STRING {
        length: bytes,
        maximum_length: bytes,
        buffer: s.as_ptr(),
    }
}

const CALLOUT_TABLE: [(u128, CLASSIFY_FN0); 4] = [
    (proto::CALLOUT_FLOW_V4, classify_flow),
    (proto::CALLOUT_FLOW_V6, classify_flow),
    (proto::CALLOUT_STREAM_V4, classify_stream),
    (proto::CALLOUT_STREAM_V6, classify_stream),
];

const REDIRECT_CALLOUTS: [u128; 2] = [proto::CALLOUT_REDIRECT_V4, proto::CALLOUT_REDIRECT_V6];

/// Driver entry point.
///
/// # Safety
/// Called once by the I/O manager with a valid driver object.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DriverEntry(
    driver: *mut DRIVER_OBJECT,
    _registry: *const UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: forwarded from the I/O manager's guarantees.
    let status = unsafe { initialize(driver) };
    if status < 0 {
        // SAFETY: tears down exactly what `initialize` created; no callouts are left registered.
        unsafe { teardown() };
    }
    status
}

/// # Safety
/// `driver` must be the driver object passed to `DriverEntry`.
unsafe fn initialize(driver: *mut DRIVER_OBJECT) -> NTSTATUS {
    // SAFETY: the I/O manager passes a valid, exclusively owned driver object.
    let drv = unsafe { &mut *driver };
    drv.driver_unload = Some(unload);
    drv.major_function[IRP_MJ_CREATE] = Some(dispatch_create);
    drv.major_function[IRP_MJ_CLOSE] = Some(dispatch_close);
    drv.major_function[IRP_MJ_DEVICE_CONTROL] = Some(dispatch_device_control);

    // SAFETY: plain non-paged, zero-initialized allocation; all-zero is a valid `Shared`
    // (unlocked spin lock, empty ring and budget) except the event, initialized right after.
    let shared = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, size_of::<Shared>(), POOL_TAG) }
        .cast::<Shared>();
    if shared.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: `shared` is a valid allocation not yet visible to any other code.
    unsafe { KeInitializeEvent((*shared).readable.get(), SYNCHRONIZATION_EVENT, 0) };
    STATE.store(shared, Ordering::Release);

    let mut device = null_mut();
    let class = GUID::from_u128(proto::DEVICE_CLASS);
    // SAFETY: all pointers reference valid, live values; the device is exclusive and its ACL
    // admits only SYSTEM and Administrators.
    let status = unsafe {
        WdmlibIoCreateDeviceSecure(
            driver,
            0,
            &unicode(&DEVICE_NAME),
            proto::DEVICE_TYPE,
            FILE_DEVICE_SECURE_OPEN,
            1,
            &unicode(&DEVICE_SDDL),
            &class,
            &mut device,
        )
    };
    if status < 0 {
        return status;
    }
    DEVICE.store(device, Ordering::Release);

    // SAFETY: both strings are valid static UNICODE_STRINGs.
    let status = unsafe { IoCreateSymbolicLink(&unicode(&SYMLINK_NAME), &unicode(&DEVICE_NAME)) };
    if status < 0 {
        return status;
    }
    LINKED.store(true, Ordering::Release);

    for ((key, classify), slot) in CALLOUT_TABLE.iter().zip(&CALLOUTS) {
        let callout = FWPS_CALLOUT0 {
            callout_key: GUID::from_u128(*key),
            flags: 0,
            classify_fn: Some(*classify),
            notify_fn: Some(notify),
            flow_delete_fn: None,
        };
        let mut id = 0;
        // SAFETY: `device` is our device object; `callout` is fully initialized.
        let status = unsafe { FwpsCalloutRegister0(device.cast(), &callout, &mut id) };
        if status < 0 {
            return status;
        }
        slot.store(id.wrapping_add(1), Ordering::Release);
    }

    let mut handle = null_mut();
    let provider = GUID::from_u128(proto::PROVIDER_KEY);
    // SAFETY: valid provider GUID and out pointer.
    let status = unsafe { FwpsRedirectHandleCreate0(&provider, 0, &mut handle) };
    if status < 0 {
        return status;
    }
    REDIRECT_HANDLE.store(handle, Ordering::Release);
    for (key, slot) in REDIRECT_CALLOUTS
        .iter()
        .zip(CALLOUTS.iter().skip(CALLOUT_TABLE.len()))
    {
        let callout = FWPS_CALLOUT1 {
            callout_key: GUID::from_u128(*key),
            flags: 0,
            classify_fn: Some(classify_redirect),
            notify_fn: Some(notify),
            flow_delete_fn: None,
        };
        let mut id = 0;
        // SAFETY: device is our device object; callout is fully initialized.
        let status = unsafe { FwpsCalloutRegister1(device.cast(), &callout, &mut id) };
        if status < 0 {
            return status;
        }
        slot.store(id.wrapping_add(1), Ordering::Release);
    }
    STATUS_SUCCESS
}

/// Unregisters callouts first (so no classify can run), then frees everything else.
///
/// # Safety
/// Only called from `DriverEntry` failure or `unload`, never concurrently.
unsafe fn teardown() {
    let mut callouts_gone = true;
    for slot in &CALLOUTS {
        let id = slot.swap(0, Ordering::AcqRel);
        if id != 0 {
            // SAFETY: `id - 1` was returned by FwpsCalloutRegister0. Without flow contexts
            // unregistration cannot report STATUS_DEVICE_BUSY.
            callouts_gone &= unsafe { FwpsCalloutUnregisterById0(id - 1) } >= 0;
        }
    }
    REDIRECT.store(0, Ordering::Release);
    let handle = REDIRECT_HANDLE.swap(null_mut(), Ordering::AcqRel);
    if !handle.is_null() && callouts_gone {
        // SAFETY: created by initialize; no callout can use it any more.
        unsafe { FwpsRedirectHandleDestroy0(handle) };
    }
    if LINKED.swap(false, Ordering::AcqRel) {
        // SAFETY: the link was created by `initialize`.
        unsafe { IoDeleteSymbolicLink(&unicode(&SYMLINK_NAME)) };
    }
    let device = DEVICE.swap(null_mut(), Ordering::AcqRel);
    if !device.is_null() {
        // SAFETY: the device was created by `initialize` and has no open handles at unload.
        unsafe { IoDeleteDevice(device) };
    }
    let shared = STATE.swap(null_mut(), Ordering::AcqRel);
    if !shared.is_null() && callouts_gone {
        // SAFETY: no callout can reach `shared` any more; it was allocated with POOL_TAG.
        // If a callout failed to unregister, the memory is deliberately leaked instead.
        unsafe { ExFreePoolWithTag(shared.cast(), POOL_TAG) };
    }
}

unsafe extern "system" fn unload(_driver: *mut DRIVER_OBJECT) {
    // SAFETY: the I/O manager calls unload once, after all handles are closed.
    unsafe { teardown() };
}

fn shared() -> Option<&'static Shared> {
    // SAFETY: STATE is either null or points to a live `Shared` that outlives every callout
    // and dispatch routine (it is freed only after they are unregistered/closed).
    unsafe { STATE.load(Ordering::Acquire).as_ref() }
}

fn now() -> u64 {
    let mut t = 0i64;
    // SAFETY: writes one i64.
    unsafe { KeQuerySystemTimePrecise(&mut t) };
    u64::try_from(t).unwrap_or(0)
}

fn complete(irp: *mut IRP, status: NTSTATUS, information: usize) -> NTSTATUS {
    // SAFETY: the I/O manager passed a valid IRP that we own until completion.
    unsafe {
        (*irp).status = status;
        (*irp).information = information;
        IofCompleteRequest(irp, 0);
    }
    status
}

/// A new (exclusive) client starts with an empty queue, so a session never receives records
/// left over from a previous client that exited abnormally.
unsafe extern "system" fn dispatch_create(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    REDIRECT.store(0, Ordering::Release);
    if let Some(shared) = shared() {
        shared.with(|inner| inner.ring.clear());
    }
    complete(irp, STATUS_SUCCESS, 0)
}

/// The client is gone: stop redirecting at once (its filters disappear with its session too).
unsafe extern "system" fn dispatch_close(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    REDIRECT.store(0, Ordering::Release);
    complete(irp, STATUS_SUCCESS, 0)
}

unsafe extern "system" fn dispatch_device_control(
    _device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    // SAFETY: valid IRP and current stack location supplied by the I/O manager.
    let (code, in_len, out_len, buffer) = unsafe {
        let stack = &*(*irp).current_stack_location;
        (
            stack.io_control_code,
            stack.input_buffer_length,
            stack.output_buffer_length,
            (*irp).system_buffer,
        )
    };
    let (in_len, out_len) = (
        usize::try_from(in_len).unwrap_or(0),
        usize::try_from(out_len).unwrap_or(0),
    );
    if buffer.is_null() {
        return complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    if code == proto::IOCTL_SET_REDIRECT {
        // SAFETY: METHOD_BUFFERED: `system_buffer` holds `in_len` input bytes for this IRP.
        let input = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), in_len) };
        return complete(irp, set_redirect(input), 0);
    }
    // SAFETY: METHOD_BUFFERED: `system_buffer` is a non-paged buffer of at least the output
    // length, owned by this IRP until completion. Only output is written; input is ignored.
    let out = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), out_len) };
    let (status, written) = match code {
        proto::IOCTL_GET_VERSION => version(out),
        proto::IOCTL_READ_EVENTS => read_events(out),
        _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
    };
    complete(irp, status, written)
}

/// Turns redirection on (a validated `proto::Redirect`) or off (all zero).
fn set_redirect(input: &[u8]) -> NTSTATUS {
    match proto::Redirect::decode(input) {
        Some(Some(r)) => {
            let packed =
                (u64::from(r.pid) << 32) | (u64::from(r.port_v4) << 16) | u64::from(r.port_v6);
            REDIRECT.store(packed, Ordering::Release);
            STATUS_SUCCESS
        }
        Some(None) => {
            REDIRECT.store(0, Ordering::Release);
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_PARAMETER,
    }
}

fn version(out: &mut [u8]) -> (NTSTATUS, usize) {
    let Some((dst, _)) = out.split_first_chunk_mut::<8>() else {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    };
    // Little-endian: protocol version first, then driver version.
    *dst = ((u64::from(DRIVER_VERSION) << 32) | u64::from(proto::PROTOCOL_VERSION)).to_le_bytes();
    (STATUS_SUCCESS, 8)
}

fn read_events(out: &mut [u8]) -> (NTSTATUS, usize) {
    if out.len() < proto::MIN_READ {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    let Some(shared) = shared() else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let out = out
        .get_mut(..proto::MAX_READ.min(out.len()))
        .unwrap_or_default();
    if shared.with(|inner| inner.ring.is_empty()) {
        let timeout = -proto::READ_WAIT_MS * 10_000;
        // SAFETY: PASSIVE_LEVEL dispatch; the event lives in non-paged pool for the driver's
        // lifetime. A timeout simply returns an empty batch.
        unsafe { KeWaitForSingleObject(shared.readable.get().cast(), 0, 0, 0, &timeout) };
    }
    let (dropped, records) = out.split_at_mut(8);
    let (count, n) = shared.with(|inner| (inner.ring.take_dropped(), inner.ring.pop_into(records)));
    dropped.copy_from_slice(&count.to_le_bytes());
    (STATUS_SUCCESS, n.saturating_add(8))
}

unsafe extern "system" fn notify(
    _kind: i32,
    _filter_key: *const GUID,
    _filter: *const c_void,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// Lets classification continue unchanged (inspection only).
fn pass(out: *mut FWPS_CLASSIFY_OUT0) {
    // SAFETY: WFP passes a valid classify-out structure.
    if let Some(out) = unsafe { out.as_mut() }
        && out.rights & FWPS_RIGHT_ACTION_WRITE != 0
    {
        out.action_type = FWP_ACTION_CONTINUE;
    }
}

/// Reads incoming value `index`, bounds-checked against the layer's value count.
fn value(values: &FWPS_INCOMING_VALUES0, index: usize) -> Option<&FWP_VALUE0> {
    let count = usize::try_from(values.value_count).ok()?;
    if index >= count || values.incoming_value.is_null() {
        return None;
    }
    // SAFETY: WFP guarantees `incoming_value` holds `value_count` entries for this call.
    unsafe { values.incoming_value.add(index).as_ref() }
}

fn uint(v: Option<&FWP_VALUE0>) -> u32 {
    // SAFETY: the union member read matches the tag WFP set.
    v.map_or(0, |v| unsafe {
        match v.kind {
            FWP_UINT8 => u32::from(v.data.uint8),
            FWP_UINT16 => u32::from(v.data.uint16),
            FWP_UINT32 => v.data.uint32,
            _ => 0,
        }
    })
}

fn address(v: Option<&FWP_VALUE0>) -> [u8; 16] {
    let mut out = [0u8; 16];
    let Some(v) = v else { return out };
    match v.kind {
        // IPv4 arrives as a host-order UINT32.
        FWP_UINT32 => {
            // SAFETY: tag says the union holds `uint32`.
            let host = unsafe { v.data.uint32 };
            if let Some((v4, _)) = out.split_first_chunk_mut::<4>() {
                *v4 = host.to_be_bytes();
            }
        }
        FWP_BYTE_ARRAY16_TYPE => {
            // SAFETY: tag says the union holds a pointer to 16 bytes valid for this call.
            if let Some(bytes) = unsafe { v.data.byte_array16.as_ref() } {
                out = *bytes;
            }
        }
        _ => {}
    }
    out
}

/// Bounded view of a WFP byte blob (UTF-16LE path), without its terminating NUL.
fn blob<'a>(b: *const FWP_BYTE_BLOB) -> &'a [u8] {
    // SAFETY: WFP blobs are valid for the duration of the classify call; the slice is only
    // used inside that call (the returned lifetime never escapes `classify_flow`).
    let Some(b) = (unsafe { b.as_ref() }) else {
        return &[];
    };
    if b.data.is_null() {
        return &[];
    }
    let len = usize::try_from(b.size)
        .unwrap_or(0)
        .min(proto::MAX_PATH_BYTES)
        & !1;
    // SAFETY: `data` points to `size` readable bytes; `len <= size`.
    let bytes = unsafe { core::slice::from_raw_parts(b.data, len) };
    bytes.strip_suffix(&[0, 0]).unwrap_or(bytes)
}

unsafe extern "system" fn classify_flow(
    values: *const FWPS_INCOMING_VALUES0,
    meta: *const FWPS_INCOMING_METADATA_VALUES0,
    _layer_data: *mut c_void,
    _filter: *const c_void,
    _flow_context: u64,
    out: *mut FWPS_CLASSIFY_OUT0,
) {
    pass(out);
    // SAFETY: WFP passes valid values and metadata for the duration of the call.
    let (Some(values), Some(meta), Some(shared)) = (
        unsafe { values.as_ref() },
        unsafe { meta.as_ref() },
        shared(),
    ) else {
        return;
    };
    let present = |field| meta.current_metadata_values & field != 0;
    if !present(FWPS_METADATA_FIELD_FLOW_HANDLE) {
        return;
    }
    let path = if present(FWPS_METADATA_FIELD_PROCESS_PATH) {
        blob(meta.process_path)
    } else {
        match value(values, field::APP_ID) {
            // SAFETY: the tag says the union holds a byte-blob pointer.
            Some(v) if v.kind == FWP_BYTE_BLOB_TYPE => blob(unsafe { v.data.byte_blob }),
            _ => &[],
        }
    };
    let local = value(values, field::LOCAL_ADDRESS);
    let record = proto::FlowRecord {
        timestamp: now(),
        flow: meta.flow_handle,
        inbound: uint(value(values, field::DIRECTION)) == FWP_DIRECTION_INBOUND,
        ipv6: local.is_some_and(|v| v.kind == FWP_BYTE_ARRAY16_TYPE),
        pid: if present(FWPS_METADATA_FIELD_PROCESS_ID) {
            meta.process_id
        } else {
            0
        },
        protocol: u8::try_from(uint(value(values, field::PROTOCOL))).unwrap_or(0),
        local_port: u16::try_from(uint(value(values, field::LOCAL_PORT))).unwrap_or(0),
        remote_port: u16::try_from(uint(value(values, field::REMOTE_PORT))).unwrap_or(0),
        local_addr: address(local),
        remote_addr: address(value(values, field::REMOTE_ADDRESS)),
        path,
    };
    let header = proto::flow_header(&record);
    let wake = shared.with(|inner| {
        inner.budget.reset(record.flow);
        let was_empty = inner.ring.is_empty();
        inner.ring.push(&[&header, record.path]) && was_empty
    });
    if wake {
        shared.signal();
    }
}

unsafe extern "system" fn classify_stream(
    _values: *const FWPS_INCOMING_VALUES0,
    meta: *const FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    _filter: *const c_void,
    _flow_context: u64,
    out: *mut FWPS_CLASSIFY_OUT0,
) {
    pass(out);
    // SAFETY: at the stream layer `layer_data` is an FWPS_STREAM_CALLOUT_IO_PACKET0 owned by
    // WFP for the duration of the call.
    let Some(packet) = (unsafe { layer_data.cast::<FWPS_STREAM_CALLOUT_IO_PACKET0>().as_mut() })
    else {
        return;
    };
    packet.stream_action = FWPS_STREAM_ACTION_NONE;
    packet.count_bytes_required = 0;
    packet.count_bytes_enforced = 0;
    // SAFETY: valid for the duration of the call when non-null.
    let (Some(stream), Some(meta), Some(shared)) = (
        unsafe { packet.stream_data.as_ref() },
        unsafe { meta.as_ref() },
        shared(),
    ) else {
        return;
    };
    if meta.current_metadata_values & FWPS_METADATA_FIELD_FLOW_HANDLE == 0
        || stream.data_length == 0
    {
        return;
    }
    let (flow, inbound) = (
        meta.flow_handle,
        stream.flags & FWPS_STREAM_FLAG_RECEIVE != 0,
    );
    let wire_len = u32::try_from(stream.data_length).unwrap_or(u32::MAX);
    let timestamp = now();
    let wake = shared.with(|inner| {
        let want = stream.data_length.min(proto::SEGMENT_CAP);
        let granted = inner.budget.grant(flow, inbound, want, proto::FLOW_BUDGET);
        if granted == 0 {
            return false;
        }
        let mut copied = 0usize;
        // SAFETY: `staging` holds SEGMENT_CAP >= `granted` bytes; WFP writes at most `granted`.
        unsafe {
            FwpsCopyStreamDataToBuffer0(
                stream,
                inner.staging.as_mut_ptr().cast(),
                granted,
                &mut copied,
            )
        };
        let data = inner.staging.get(..copied.min(granted)).unwrap_or_default();
        let header = proto::data_header(timestamp, flow, inbound, wire_len, data.len());
        let was_empty = inner.ring.is_empty();
        inner.ring.push(&[&header, data]) && was_empty
    });
    if wake {
        shared.signal();
    }
}

const IPV6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// `SOCKADDR_IN` / `SOCKADDR_IN6` for the proxy on `127.0.0.1` / `[::1]`, in a
/// `SOCKADDR_STORAGE`.
fn loopback(ipv6: bool, port: u16) -> [u8; 128] {
    let mut s = [0u8; 128];
    let (family, rest) = s.split_at_mut(2);
    family.copy_from_slice(&(if ipv6 { AF_INET6 } else { AF_INET }).to_le_bytes());
    let (p, rest) = rest.split_at_mut(2);
    p.copy_from_slice(&port.to_be_bytes());
    if ipv6 {
        if let Some(last) = rest.get_mut(4 + 15) {
            *last = 1; // after the 4-byte flow info: ::1
        }
    } else if let Some(a) = rest.get_mut(..4) {
        a.copy_from_slice(&[127, 0, 0, 1]);
    }
    s
}

/// Sends an outbound TCP connection to Wiretap's proxy while redirection is enabled (see the
/// crate docs). Fails open: on any error the connection proceeds unchanged.
unsafe extern "system" fn classify_redirect(
    values: *const FWPS_INCOMING_VALUES0,
    meta: *const FWPS_INCOMING_METADATA_VALUES0,
    _layer_data: *mut c_void,
    classify_context: *const c_void,
    filter: *const FWPS_FILTER1,
    _flow_context: u64,
    out: *mut FWPS_CLASSIFY_OUT0,
) {
    pass(out);
    let packed = REDIRECT.load(Ordering::Acquire);
    let handle = REDIRECT_HANDLE.load(Ordering::Acquire);
    // SAFETY: WFP passes valid pointers for the duration of the call.
    let (Some(values), Some(meta), Some(filter), true) = (
        unsafe { values.as_ref() },
        unsafe { meta.as_ref() },
        unsafe { filter.as_ref() },
        unsafe { out.as_ref() }.is_some_and(|o| o.rights & FWPS_RIGHT_ACTION_WRITE != 0),
    ) else {
        return;
    };
    if packed == 0 || handle.is_null() {
        return;
    }
    let proxy_pid = u32::try_from(packed >> 32).unwrap_or(0);
    let port_v4 = u16::try_from((packed >> 16) & 0xFFFF).unwrap_or(0);
    let port_v6 = u16::try_from(packed & 0xFFFF).unwrap_or(0);
    let present = |field| meta.current_metadata_values & field != 0;
    if !present(FWPS_METADATA_FIELD_PROCESS_ID) || meta.process_id == u64::from(proxy_pid) {
        return; // the proxy's own connections go out directly
    }
    if uint(value(values, redirect_field::PROTOCOL)) != 6 {
        return;
    }
    let remote = value(values, redirect_field::REMOTE_ADDRESS);
    let ipv6 = remote.is_some_and(|v| v.kind == FWP_BYTE_ARRAY16_TYPE);
    let addr = address(remote);
    let port = u16::try_from(uint(value(values, redirect_field::REMOTE_PORT))).unwrap_or(0);
    let proxy_port = if ipv6 { port_v6 } else { port_v4 };
    let is_loopback = if ipv6 {
        addr == IPV6_LOOPBACK
    } else {
        addr.first() == Some(&127)
    };
    if proxy_port == 0 || port == 0 || is_loopback {
        return;
    }
    if present(FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) {
        let mut previous = null_mut();
        // SAFETY: this classify's redirect records and our redirect handle.
        let state = unsafe {
            FwpsQueryConnectionRedirectState0(meta.redirect_records, handle, &mut previous)
        };
        if state != FWPS_CONNECTION_NOT_REDIRECTED {
            return; // already redirected (by us or another product): never loop or fight
        }
    }
    let original = proto::Original {
        pid: u32::try_from(meta.process_id).unwrap_or(0),
        ipv6,
        port,
        addr,
    }
    .encode();
    // SAFETY: non-paged allocation; once attached, WFP owns and frees it with the connection.
    let context = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, original.len(), POOL_TAG) };
    if context.is_null() {
        return;
    }
    // SAFETY: `context` is a fresh allocation of `original.len()` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(original.as_ptr(), context.cast::<u8>(), original.len())
    };
    let mut classify_handle = 0u64;
    // SAFETY: the classify context of this very call.
    if unsafe { FwpsAcquireClassifyHandle0(classify_context, 0, &mut classify_handle) } < 0 {
        // SAFETY: not attached to anything yet.
        unsafe { ExFreePoolWithTag(context, POOL_TAG) };
        return;
    }
    let mut data = null_mut();
    // SAFETY: valid classify handle, this call's filter ID and classify-out structure.
    let status = unsafe {
        FwpsAcquireWritableLayerDataPointer0(classify_handle, filter.filter_id, 0, &mut data, out)
    };
    if status < 0 || data.is_null() {
        // SAFETY: not attached; the classify handle is released exactly once.
        unsafe {
            ExFreePoolWithTag(context, POOL_TAG);
            FwpsReleaseClassifyHandle0(classify_handle);
        }
        return;
    }
    // SAFETY: at the connect-redirect layers the writable layer data is a
    // FWPS_CONNECT_REQUEST0 owned by WFP until it is applied.
    unsafe {
        let request = &mut *data.cast::<FWPS_CONNECT_REQUEST0>();
        request.remote_address_and_port = loopback(ipv6, proxy_port);
        request.local_redirect_target_pid = proxy_pid;
        request.local_redirect_handle = handle;
        request.local_redirect_context = context;
        request.local_redirect_context_size = original.len();
        FwpsApplyModifiedLayerData0(classify_handle, data, 0);
        FwpsReleaseClassifyHandle0(classify_handle);
        (*out).action_type = FWP_ACTION_PERMIT;
    }
}

/// A panic in kernel mode could only stop Windows, so the release driver contains no panic
/// path at all: this handler refers to a symbol that does not exist, and a release build links
/// only if the optimizer removed every call to it, i.e. proved that no index, slice, arithmetic
/// operation or unwrap can fail. Debug builds keep their checks and stop with a dedicated bug
/// check.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    #[cfg(not(debug_assertions))]
    {
        unsafe extern "C" {
            /// Deliberately undefined (see above).
            fn wiretap_driver_must_not_contain_panic_paths() -> !;
        }
        // SAFETY: never linked into a working build; see above.
        unsafe { wiretap_driver_must_not_contain_panic_paths() }
    }
    #[cfg(debug_assertions)]
    // SAFETY: a broken kernel invariant must stop the system rather than continue corrupted.
    unsafe {
        KeBugCheckEx(BUGCHECK_RUST_PANIC, 0, 0, 0, 0)
    }
}

/// Satisfies the linker when floating-point support code is referenced; the driver itself
/// uses no floating point.
#[unsafe(no_mangle)]
#[used]
static _fltused: i32 = 0;
