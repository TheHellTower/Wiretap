//! Hand-written bindings for the few kernel and WFP APIs the driver uses, transcribed from the
//! official WDK 10.0.26100 headers (`wdm.h`, `wdmsec.h`, `fwpsk.h`, `fwpstypes.h`).
//!
//! Large kernel structures are declared as prefix views containing only the fields we touch.
//! Every size and offset below is asserted here and, independently, against the real headers
//! by `layout_check.c`; a mismatch fails one of the two builds.
#![allow(
    non_camel_case_types,
    clippy::upper_case_acronyms,
    missing_docs,
    reason = "mirrors WDK names"
)]

use core::ffi::c_void;
use core::mem::{offset_of, size_of};

pub type NTSTATUS = i32;
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000_009A_u32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = 0xC000_0010_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000D_u32 as i32;

pub const IRP_MJ_CREATE: usize = 0;
pub const IRP_MJ_CLOSE: usize = 2;
pub const IRP_MJ_DEVICE_CONTROL: usize = 14;
pub const FILE_DEVICE_SECURE_OPEN: u32 = 0x100;
pub const POOL_FLAG_NON_PAGED: u64 = 0x40;
pub const SYNCHRONIZATION_EVENT: i32 = 1;

pub const FWP_UINT8: i32 = 1;
pub const FWP_UINT16: i32 = 2;
pub const FWP_UINT32: i32 = 3;
pub const FWP_BYTE_ARRAY16_TYPE: i32 = 11;
pub const FWP_BYTE_BLOB_TYPE: i32 = 12;
pub const FWP_DIRECTION_INBOUND: u32 = 1;
pub const FWP_ACTION_CONTINUE: u32 = 0x2006;
pub const FWP_ACTION_PERMIT: u32 = 0x1002;
pub const FWPS_RIGHT_ACTION_WRITE: u32 = 1;
pub const FWPS_METADATA_FIELD_FLOW_HANDLE: u32 = 0x2;
pub const FWPS_METADATA_FIELD_PROCESS_PATH: u32 = 0x8;
pub const FWPS_METADATA_FIELD_PROCESS_ID: u32 = 0x20;
pub const FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE: u32 = 0x4000_0000;
pub const FWPS_CONNECTION_NOT_REDIRECTED: i32 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;
pub const FWPS_STREAM_FLAG_RECEIVE: u32 = 0x1;
pub const FWPS_STREAM_ACTION_NONE: i32 = 0;

/// Field indices shared by `FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4` and `_V6`.
pub mod field {
    pub const APP_ID: usize = 0;
    pub const LOCAL_ADDRESS: usize = 2;
    pub const LOCAL_PORT: usize = 4;
    pub const PROTOCOL: usize = 5;
    pub const REMOTE_ADDRESS: usize = 6;
    pub const REMOTE_PORT: usize = 7;
    pub const DIRECTION: usize = 12;
}

/// Field indices shared by `FWPS_FIELDS_ALE_CONNECT_REDIRECT_V4` and `_V6`.
pub mod redirect_field {
    pub const PROTOCOL: usize = 5;
    pub const REMOTE_ADDRESS: usize = 6;
    pub const REMOTE_PORT: usize = 8;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl GUID {
    /// Converts the textual-order 128-bit value used in `wiretap-driver-proto`.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "extracts fields from fixed bit positions"
    )]
    pub const fn from_u128(v: u128) -> Self {
        Self {
            data1: (v >> 96) as u32,
            data2: (v >> 80) as u16,
            data3: (v >> 64) as u16,
            data4: (v as u64).to_be_bytes(),
        }
    }
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C, align(8))]
pub struct KEVENT([u8; 24]);

pub type DRIVER_DISPATCH = unsafe extern "system" fn(*mut DEVICE_OBJECT, *mut IRP) -> NTSTATUS;
pub type DRIVER_UNLOAD = unsafe extern "system" fn(*mut DRIVER_OBJECT);

/// Opaque device object.
#[repr(C)]
pub struct DEVICE_OBJECT {
    _opaque: [u8; 0],
}

/// Prefix view of `DRIVER_OBJECT`.
#[repr(C)]
pub struct DRIVER_OBJECT {
    _head: [u8; 104],
    pub driver_unload: Option<DRIVER_UNLOAD>,
    pub major_function: [Option<DRIVER_DISPATCH>; 28],
}

/// Prefix view of `IRP`.
#[repr(C)]
pub struct IRP {
    _head: [u8; 0x18],
    pub system_buffer: *mut c_void,
    _thread_list: [u8; 0x10],
    pub status: NTSTATUS,
    _status_pad: u32,
    pub information: usize,
    _middle: [u8; 0xB8 - 0x40],
    pub current_stack_location: *const IO_STACK_LOCATION,
}

/// Prefix view of `IO_STACK_LOCATION` with `Parameters.DeviceIoControl`
/// (whose fields are `POINTER_ALIGNMENT`, i.e. 8-byte aligned, on x64).
#[repr(C)]
pub struct IO_STACK_LOCATION {
    pub major_function: u8,
    _head: [u8; 7],
    pub output_buffer_length: u32,
    _pad1: u32,
    pub input_buffer_length: u32,
    _pad2: u32,
    pub io_control_code: u32,
}

#[repr(C)]
pub struct FWP_BYTE_BLOB {
    pub size: u32,
    pub data: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union FWP_VALUE_DATA {
    pub uint8: u8,
    pub uint16: u16,
    pub uint32: u32,
    pub byte_array16: *const [u8; 16],
    pub byte_blob: *const FWP_BYTE_BLOB,
}

#[repr(C)]
pub struct FWP_VALUE0 {
    pub kind: i32,
    pub data: FWP_VALUE_DATA,
}

#[repr(C)]
pub struct FWPS_INCOMING_VALUES0 {
    pub layer_id: u16,
    pub value_count: u32,
    pub incoming_value: *const FWP_VALUE0,
}

/// Prefix view of `FWPS_INCOMING_METADATA_VALUES0` (only ever read through WFP's pointer).
#[repr(C)]
pub struct FWPS_INCOMING_METADATA_VALUES0 {
    pub current_metadata_values: u32,
    _flags: u32,
    _reserved: u64,
    _discard_metadata: [u64; 2],
    pub flow_handle: u64,
    _header_sizes: [u32; 2],
    pub process_path: *const FWP_BYTE_BLOB,
    _token: u64,
    pub process_id: u64,
    _middle: [u8; 216 - 72],
    pub redirect_records: *mut c_void,
}

#[repr(C)]
pub struct FWPS_CLASSIFY_OUT0 {
    pub action_type: u32,
    _out_context: u64,
    _filter_id: u64,
    pub rights: u32,
    _flags: u32,
    _reserved: u32,
}

#[repr(C)]
pub struct FWPS_STREAM_DATA0 {
    pub flags: u32,
    _data_offset: [u64; 5],
    pub data_length: usize,
    _net_buffer_list_chain: *mut c_void,
}

#[repr(C)]
pub struct FWPS_STREAM_CALLOUT_IO_PACKET0 {
    pub stream_data: *const FWPS_STREAM_DATA0,
    pub missed_bytes: usize,
    pub count_bytes_required: u32,
    pub count_bytes_enforced: usize,
    pub stream_action: i32,
}

pub type CLASSIFY_FN0 = unsafe extern "system" fn(
    *const FWPS_INCOMING_VALUES0,
    *const FWPS_INCOMING_METADATA_VALUES0,
    *mut c_void,
    *const c_void,
    u64,
    *mut FWPS_CLASSIFY_OUT0,
);
/// `classifyFn1`: adds the classify context needed to modify layer data (redirection).
pub type CLASSIFY_FN1 = unsafe extern "system" fn(
    *const FWPS_INCOMING_VALUES0,
    *const FWPS_INCOMING_METADATA_VALUES0,
    *mut c_void,
    *const c_void,
    *const FWPS_FILTER1,
    u64,
    *mut FWPS_CLASSIFY_OUT0,
);
pub type NOTIFY_FN0 = unsafe extern "system" fn(i32, *const GUID, *const c_void) -> NTSTATUS;
pub type FLOW_DELETE_FN0 = unsafe extern "system" fn(u16, u32, u64);

#[repr(C)]
pub struct FWPS_CALLOUT0 {
    pub callout_key: GUID,
    pub flags: u32,
    pub classify_fn: Option<CLASSIFY_FN0>,
    pub notify_fn: Option<NOTIFY_FN0>,
    pub flow_delete_fn: Option<FLOW_DELETE_FN0>,
}

/// Same layout as `FWPS_CALLOUT0`, with a `classifyFn1`.
#[repr(C)]
pub struct FWPS_CALLOUT1 {
    pub callout_key: GUID,
    pub flags: u32,
    pub classify_fn: Option<CLASSIFY_FN1>,
    pub notify_fn: Option<NOTIFY_FN0>,
    pub flow_delete_fn: Option<FLOW_DELETE_FN0>,
}

/// Prefix view of `FWPS_FILTER1`.
#[repr(C)]
pub struct FWPS_FILTER1 {
    pub filter_id: u64,
}

/// `FWPS_CONNECT_REQUEST0`: the writable data of the ALE connect-redirect layers. The
/// addresses are `SOCKADDR_STORAGE` (128 bytes).
#[repr(C)]
pub struct FWPS_CONNECT_REQUEST0 {
    pub local_address_and_port: [u8; 128],
    pub remote_address_and_port: [u8; 128],
    pub port_reservation_token: u64,
    pub local_redirect_target_pid: u32,
    _pad: u32,
    pub previous_version: *mut FWPS_CONNECT_REQUEST0,
    pub modifier_filter_id: u64,
    pub local_redirect_handle: *mut c_void,
    pub local_redirect_context: *mut c_void,
    pub local_redirect_context_size: usize,
}

const _: () = {
    assert!(offset_of!(FWPS_INCOMING_METADATA_VALUES0, redirect_records) == 216);
    assert!(offset_of!(FWPS_CONNECT_REQUEST0, remote_address_and_port) == 128);
    assert!(offset_of!(FWPS_CONNECT_REQUEST0, local_redirect_target_pid) == 264);
    assert!(offset_of!(FWPS_CONNECT_REQUEST0, local_redirect_handle) == 288);
    assert!(offset_of!(FWPS_CONNECT_REQUEST0, local_redirect_context) == 296);
    assert!(offset_of!(FWPS_CONNECT_REQUEST0, local_redirect_context_size) == 304);
    assert!(size_of::<FWPS_CONNECT_REQUEST0>() == 312);
    assert!(size_of::<FWPS_CALLOUT1>() == 48 && offset_of!(FWPS_CALLOUT1, classify_fn) == 24);
};

const _: () = {
    assert!(size_of::<UNICODE_STRING>() == 16 && size_of::<GUID>() == 16);
    assert!(size_of::<KEVENT>() == 24);
    assert!(offset_of!(DRIVER_OBJECT, driver_unload) == 104);
    assert!(offset_of!(DRIVER_OBJECT, major_function) == 112 && size_of::<DRIVER_OBJECT>() == 336);
    assert!(offset_of!(IRP, system_buffer) == 0x18);
    assert!(offset_of!(IRP, status) == 0x30 && offset_of!(IRP, information) == 0x38);
    assert!(offset_of!(IRP, current_stack_location) == 0xB8);
    assert!(offset_of!(IO_STACK_LOCATION, output_buffer_length) == 8);
    assert!(offset_of!(IO_STACK_LOCATION, input_buffer_length) == 16);
    assert!(offset_of!(IO_STACK_LOCATION, io_control_code) == 24);
    assert!(size_of::<FWP_VALUE0>() == 16 && offset_of!(FWP_VALUE0, data) == 8);
    assert!(size_of::<FWP_BYTE_BLOB>() == 16 && offset_of!(FWP_BYTE_BLOB, data) == 8);
    assert!(offset_of!(FWPS_INCOMING_VALUES0, value_count) == 4);
    assert!(offset_of!(FWPS_INCOMING_VALUES0, incoming_value) == 8);
    assert!(size_of::<FWPS_INCOMING_VALUES0>() == 16);
    assert!(offset_of!(FWPS_INCOMING_METADATA_VALUES0, flow_handle) == 32);
    assert!(offset_of!(FWPS_INCOMING_METADATA_VALUES0, process_path) == 48);
    assert!(offset_of!(FWPS_INCOMING_METADATA_VALUES0, process_id) == 64);
    assert!(offset_of!(FWPS_CLASSIFY_OUT0, rights) == 24 && size_of::<FWPS_CLASSIFY_OUT0>() == 40);
    assert!(
        offset_of!(FWPS_STREAM_DATA0, data_length) == 48 && size_of::<FWPS_STREAM_DATA0>() == 64
    );
    assert!(offset_of!(FWPS_STREAM_CALLOUT_IO_PACKET0, missed_bytes) == 8);
    assert!(offset_of!(FWPS_STREAM_CALLOUT_IO_PACKET0, count_bytes_required) == 16);
    assert!(offset_of!(FWPS_STREAM_CALLOUT_IO_PACKET0, count_bytes_enforced) == 24);
    assert!(offset_of!(FWPS_STREAM_CALLOUT_IO_PACKET0, stream_action) == 32);
    assert!(size_of::<FWPS_STREAM_CALLOUT_IO_PACKET0>() == 40);
    assert!(offset_of!(FWPS_CALLOUT0, flags) == 16 && offset_of!(FWPS_CALLOUT0, classify_fn) == 24);
    assert!(
        offset_of!(FWPS_CALLOUT0, notify_fn) == 32
            && offset_of!(FWPS_CALLOUT0, flow_delete_fn) == 40
    );
    assert!(size_of::<FWPS_CALLOUT0>() == 48);
};

// ntoskrnl.lib
unsafe extern "system" {
    pub fn ExAllocatePool2(flags: u64, bytes: usize, tag: u32) -> *mut c_void;
    pub fn ExFreePoolWithTag(p: *mut c_void, tag: u32);
    pub fn IoCreateSymbolicLink(
        link: *const UNICODE_STRING,
        device: *const UNICODE_STRING,
    ) -> NTSTATUS;
    pub fn IoDeleteSymbolicLink(link: *const UNICODE_STRING) -> NTSTATUS;
    pub fn IoDeleteDevice(device: *mut DEVICE_OBJECT);
    pub fn IofCompleteRequest(irp: *mut IRP, boost: i8);
    pub fn KeAcquireSpinLockRaiseToDpc(lock: *mut usize) -> u8;
    pub fn KeReleaseSpinLock(lock: *mut usize, old_irql: u8);
    pub fn KeInitializeEvent(event: *mut KEVENT, kind: i32, signaled: u8);
    pub fn KeSetEvent(event: *mut KEVENT, increment: i32, wait: u8) -> i32;
    pub fn KeWaitForSingleObject(
        object: *mut c_void,
        reason: i32,
        mode: i8,
        alertable: u8,
        timeout: *const i64,
    ) -> NTSTATUS;
    pub fn KeQuerySystemTimePrecise(time: *mut i64);
    #[cfg(debug_assertions)]
    pub fn KeBugCheckEx(code: u32, p1: usize, p2: usize, p3: usize, p4: usize) -> !;
}

// wdmsec.lib (static library; `IoCreateDeviceSecure` is a macro for this symbol)
unsafe extern "system" {
    pub fn WdmlibIoCreateDeviceSecure(
        driver: *mut DRIVER_OBJECT,
        extension_size: u32,
        name: *const UNICODE_STRING,
        device_type: u32,
        characteristics: u32,
        exclusive: u8,
        sddl: *const UNICODE_STRING,
        class_guid: *const GUID,
        device: *mut *mut DEVICE_OBJECT,
    ) -> NTSTATUS;
}

// fwpkclnt.lib
unsafe extern "system" {
    pub fn FwpsCalloutRegister0(
        device: *mut c_void,
        callout: *const FWPS_CALLOUT0,
        id: *mut u32,
    ) -> NTSTATUS;
    pub fn FwpsCalloutRegister1(
        device: *mut c_void,
        callout: *const FWPS_CALLOUT1,
        id: *mut u32,
    ) -> NTSTATUS;
    pub fn FwpsCalloutUnregisterById0(id: u32) -> NTSTATUS;
    pub fn FwpsRedirectHandleCreate0(
        provider: *const GUID,
        flags: u32,
        handle: *mut *mut c_void,
    ) -> NTSTATUS;
    pub fn FwpsRedirectHandleDestroy0(handle: *mut c_void);
    pub fn FwpsQueryConnectionRedirectState0(
        records: *mut c_void,
        handle: *mut c_void,
        context: *mut *mut c_void,
    ) -> i32;
    pub fn FwpsAcquireClassifyHandle0(
        context: *const c_void,
        flags: u32,
        handle: *mut u64,
    ) -> NTSTATUS;
    pub fn FwpsReleaseClassifyHandle0(handle: u64);
    pub fn FwpsAcquireWritableLayerDataPointer0(
        handle: u64,
        filter_id: u64,
        flags: u32,
        data: *mut *mut c_void,
        out: *mut FWPS_CLASSIFY_OUT0,
    ) -> NTSTATUS;
    pub fn FwpsApplyModifiedLayerData0(handle: u64, data: *mut c_void, flags: u32);
    pub fn FwpsCopyStreamDataToBuffer0(
        data: *const FWPS_STREAM_DATA0,
        buffer: *mut c_void,
        bytes: usize,
        copied: *mut usize,
    );
}
