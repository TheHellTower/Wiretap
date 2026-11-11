//! Wiretap's own window: a native Win32 window hosting the UI in WebView2, the Microsoft Edge
//! WebView2 Runtime that ships with Windows. Nothing of a browser remains: no browser UI,
//! context menus, script dialogs, DevTools, status bar, browser shortcuts, zoom, autofill,
//! password saving, popups, downloads UI or permission prompts, and navigation is pinned to the
//! Wiretap origin. It runs InPrivate in a throwaway data folder: no browser profile persists.
//!
//! COM interfaces are called through their vtables; slot numbers come from the WebView2 SDK's
//! `WebView2.h` (pinned in `tools/webview2-sdk.txt`). Interfaces newer than the base ones are
//! obtained with `QueryInterface`, so an older runtime degrades instead of misbehaving.
#![allow(
    unsafe_code,
    reason = "Win32 and WebView2 COM FFI; every block carries a SAFETY comment"
)]

use std::cell::RefCell;
use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{E_NOINTERFACE, HWND, LPARAM, LRESULT, RECT, S_OK, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::CreateSolidBrush;
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetClientRect, GetMessageW, IDC_ARROW, IDI_APPLICATION, LoadCursorW, LoadIconW, MB_ICONERROR,
    MB_OK, MSG, MessageBoxW, PostQuitMessage, RegisterClassExW, SPI_GETWORKAREA, SW_SHOW,
    SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPos, ShowWindow, SystemParametersInfoW,
    TranslateMessage, WM_DESTROY, WM_DPICHANGED, WM_SETFOCUS, WM_SIZE, WNDCLASSEXW,
    WS_OVERLAPPEDWINDOW,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

unsafe extern "system" {
    /// From `WebView2LoaderStatic.lib` (linked by build.rs).
    fn CreateCoreWebView2EnvironmentWithOptions(
        browser_folder: PCWSTR,
        user_data_folder: PCWSTR,
        options: *mut c_void,
        handler: *mut c_void,
    ) -> HRESULT;
}

const IID_IUNKNOWN: GUID = GUID::from_u128(0x0000_0000_0000_0000_c000_0000_0000_0046);
const IID_ENVIRONMENT_COMPLETED: GUID = GUID::from_u128(0x4e8a_3389_c9d8_4bd2_b6b5_124f_ee6c_c14d);
const IID_CONTROLLER_COMPLETED: GUID = GUID::from_u128(0x6c48_19f3_c9b7_4260_8127_c9f5_bde7_f68c);
const IID_NAVIGATION_STARTING: GUID = GUID::from_u128(0x9adb_e429_f36d_432b_9ddc_f888_1fbd_76e3);
const IID_NEW_WINDOW_REQUESTED: GUID = GUID::from_u128(0xd4c1_85fe_c81c_4989_97af_2d3f_a7ab_5651);
const IID_PERMISSION_REQUESTED: GUID = GUID::from_u128(0x15e1_c6a3_c72a_4df3_91d7_d097_fbec_6bfd);
const IID_DOWNLOAD_STARTING: GUID = GUID::from_u128(0xefed_c989_c396_41ca_83f7_07f8_45a5_5724);
const IID_ENVIRONMENT10: GUID = GUID::from_u128(0xee0e_b9df_6f12_46ce_b53f_3f47_b9c9_28e0);
const IID_CONTROLLER2: GUID = GUID::from_u128(0xc979_903e_d4ca_4228_92eb_47ee_3fa9_6eab);
const IID_WEBVIEW2_4: GUID = GUID::from_u128(0x20d0_2d59_6df2_42dc_bd06_f98a_694b_1302);
const IID_SETTINGS9: GUID = GUID::from_u128(0x0528_a73b_e92d_49f4_927a_e547_ddda_a37d);

// Vtable slots (WebView2.h, C interface layout; 0-2 are IUnknown).
const QUERY_INTERFACE: usize = 0;
const RELEASE: usize = 2;
const ENV10_CREATE_CONTROLLER_OPTIONS: usize = 20;
const ENV10_CREATE_CONTROLLER_WITH_OPTIONS: usize = 21;
const OPTIONS_PUT_IN_PRIVATE: usize = 6;
const CONTROLLER_PUT_BOUNDS: usize = 6;
const CONTROLLER_MOVE_FOCUS: usize = 12;
const CONTROLLER_CLOSE: usize = 24;
const CONTROLLER_GET_WEBVIEW: usize = 25;
const CONTROLLER2_PUT_BACKGROUND: usize = 27;
const WEBVIEW_GET_SETTINGS: usize = 3;
const WEBVIEW_NAVIGATE: usize = 5;
const WEBVIEW_ADD_NAVIGATION_STARTING: usize = 7;
const WEBVIEW_ADD_PERMISSION_REQUESTED: usize = 23;
const WEBVIEW_ADD_NEW_WINDOW_REQUESTED: usize = 44;
const WEBVIEW4_ADD_DOWNLOAD_STARTING: usize = 75;
const NAVIGATION_GET_URI: usize = 3;
const NAVIGATION_PUT_CANCEL: usize = 8;
const NEW_WINDOW_PUT_HANDLED: usize = 6;
const PERMISSION_PUT_STATE: usize = 7;
const PERMISSION_DENY: i32 = 2;
const DOWNLOAD_PUT_HANDLED: usize = 9;
/// `ICoreWebView2Settings` (1-9) setters turned off: web messages, script dialogs, status
/// bar, DevTools, context menus, host objects, zoom, built-in error page; then (`Settings3`+)
/// browser accelerator keys, password autosave, autofill, pinch zoom, swipe navigation and
/// SmartScreen lookups of our own loopback page.
const SETTINGS_OFF: [usize; 8] = [6, 8, 10, 12, 14, 16, 18, 20];
const SETTINGS9_OFF: [usize; 6] = [24, 26, 28, 30, 32, 36];

/// The controller of the one window (UI thread only).
static CONTROLLER: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Method `slot` of the COM object `obj`.
///
/// # Safety
/// `obj` is a live interface pointer whose vtable has `slot`, and `F` is that method's exact
/// `extern "system"` signature.
unsafe fn method<F: Copy>(obj: *mut c_void, slot: usize) -> F {
    // SAFETY: per the contract above; a COM object starts with its vtable pointer.
    unsafe {
        let vtbl = *obj.cast::<*const *const c_void>();
        std::mem::transmute_copy::<*const c_void, F>(&*vtbl.add(slot))
    }
}

type Setter<T> = unsafe extern "system" fn(*mut c_void, T) -> HRESULT;

/// `COREWEBVIEW2_COLOR`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Color {
    a: u8,
    r: u8,
    g: u8,
    b: u8,
}
type Getter = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;
type AddHandler = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i64) -> HRESULT;

/// # Safety
/// `obj` is null or a live COM interface pointer we own a reference to.
unsafe fn release(obj: *mut c_void) {
    if !obj.is_null() {
        // SAFETY: IUnknown::Release on a live interface.
        unsafe { method::<unsafe extern "system" fn(*mut c_void) -> u32>(obj, RELEASE)(obj) };
    }
}

/// `QueryInterface`; null when unsupported.
///
/// # Safety
/// `obj` is a live COM interface pointer.
unsafe fn query(obj: *mut c_void, iid: &GUID) -> *mut c_void {
    let mut out = null_mut();
    type Qi = unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT;
    // SAFETY: IUnknown::QueryInterface on a live interface.
    let hr = unsafe { method::<Qi>(obj, QUERY_INTERFACE)(obj, iid, &mut out) };
    if hr < 0 { null_mut() } else { out }
}

/// A COM callback object (completion or event handler) wrapping a Rust closure. Called on the
/// UI thread only; the closure gets `(HRESULT, result)` for completions and `(0, args)` for
/// events.
#[repr(C)]
struct Handler {
    vtbl: *const c_void,
    refs: AtomicU32,
    iid: GUID,
    call: RefCell<Box<dyn FnMut(HRESULT, *mut c_void)>>,
}

#[repr(C)]
struct Vtbl<I> {
    query_interface:
        unsafe extern "system" fn(*mut Handler, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut Handler) -> u32,
    release: unsafe extern "system" fn(*mut Handler) -> u32,
    invoke: I,
}

type CompletedInvoke = unsafe extern "system" fn(*mut Handler, HRESULT, *mut c_void) -> HRESULT;
type EventInvoke = unsafe extern "system" fn(*mut Handler, *mut c_void, *mut c_void) -> HRESULT;

static COMPLETED: Vtbl<CompletedInvoke> = Vtbl {
    query_interface: handler_query,
    add_ref: handler_add_ref,
    release: handler_release,
    invoke: completed_invoke,
};
static EVENT: Vtbl<EventInvoke> = Vtbl {
    query_interface: handler_query,
    add_ref: handler_add_ref,
    release: handler_release,
    invoke: event_invoke,
};

unsafe extern "system" fn handler_query(
    this: *mut Handler,
    iid: *const GUID,
    out: *mut *mut c_void,
) -> HRESULT {
    // SAFETY: COM passes our live object, a valid IID and a valid out pointer.
    unsafe {
        let (want, own) = (&*iid, &(*this).iid);
        let same = |a: &GUID, b: &GUID| {
            a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
        };
        if same(want, own) || same(want, &IID_IUNKNOWN) {
            (*this).refs.fetch_add(1, Ordering::SeqCst);
            *out = this.cast();
            S_OK
        } else {
            *out = null_mut();
            E_NOINTERFACE
        }
    }
}

unsafe extern "system" fn handler_add_ref(this: *mut Handler) -> u32 {
    // SAFETY: COM only calls this on our live object.
    unsafe { (*this).refs.fetch_add(1, Ordering::SeqCst) + 1 }
}

unsafe extern "system" fn handler_release(this: *mut Handler) -> u32 {
    // SAFETY: COM only calls this on our live object; the last release frees it once.
    unsafe {
        let left = (*this).refs.fetch_sub(1, Ordering::SeqCst) - 1;
        if left == 0 {
            drop(Box::from_raw(this));
        }
        left
    }
}

unsafe extern "system" fn completed_invoke(
    this: *mut Handler,
    hr: HRESULT,
    result: *mut c_void,
) -> HRESULT {
    // SAFETY: our live object; a re-entrant call is refused rather than aliasing the closure.
    if let Ok(mut call) = unsafe { (*this).call.try_borrow_mut() } {
        call(hr, result);
    }
    S_OK
}

unsafe extern "system" fn event_invoke(
    this: *mut Handler,
    _sender: *mut c_void,
    args: *mut c_void,
) -> HRESULT {
    // SAFETY: as in `completed_invoke`.
    if let Ok(mut call) = unsafe { (*this).call.try_borrow_mut() } {
        call(0, args);
    }
    S_OK
}

/// A new handler with one reference, owned by the caller (release it after handing it over).
fn handler(
    iid: GUID,
    event: bool,
    call: impl FnMut(HRESULT, *mut c_void) + 'static,
) -> *mut c_void {
    let vtbl: *const c_void = if event {
        (&raw const EVENT).cast()
    } else {
        (&raw const COMPLETED).cast()
    };
    Box::into_raw(Box::new(Handler {
        vtbl,
        refs: AtomicU32::new(1),
        iid,
        call: RefCell::new(Box::new(call)),
    }))
    .cast()
}

/// Registers an event handler on `obj` (method `slot`).
///
/// # Safety
/// `obj` is a live interface with an `add_*` event method at `slot` taking handler `iid`.
unsafe fn on(obj: *mut c_void, slot: usize, iid: GUID, call: impl FnMut(*mut c_void) + 'static) {
    let mut call = call;
    let h = handler(iid, true, move |_, args| call(args));
    let mut token = 0i64;
    // SAFETY: per the contract; the runtime keeps its own reference to `h`.
    unsafe {
        method::<AddHandler>(obj, slot)(obj, h, &mut token);
        release(h);
    }
}

fn fit(hwnd: HWND) {
    let controller = CONTROLLER.load(Ordering::SeqCst);
    if controller.is_null() {
        return;
    }
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: valid window and RECT; `controller` is live while stored.
    unsafe {
        GetClientRect(hwnd, &mut rect);
        method::<Setter<RECT>>(controller, CONTROLLER_PUT_BOUNDS)(controller, rect);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_SIZE => {
            fit(hwnd);
            0
        }
        WM_SETFOCUS => {
            let controller = CONTROLLER.load(Ordering::SeqCst);
            if !controller.is_null() {
                // SAFETY: live controller; reason 0 = programmatic.
                unsafe { method::<Setter<i32>>(controller, CONTROLLER_MOVE_FOCUS)(controller, 0) };
            }
            0
        }
        WM_DPICHANGED => {
            // SAFETY: for WM_DPICHANGED, `lparam` points to the suggested window RECT.
            unsafe {
                let r = &*(lparam as *const RECT);
                SetWindowPos(
                    hwnd,
                    null_mut(),
                    r.left,
                    r.top,
                    r.right - r.left,
                    r.bottom - r.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
            0
        }
        WM_DESTROY => {
            // SAFETY: ends this thread's message loop.
            unsafe { PostQuitMessage(0) };
            0
        }
        // SAFETY: default processing for everything else.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Window bounds `(x, y, width, height)`: 1480×920 at 100% scaling, at most 92% of the work
/// area (the status bar never hides under the taskbar), centred.
fn bounds() -> (i32, i32, i32, i32) {
    let mut area = RECT {
        left: 0,
        top: 0,
        right: 1366,
        bottom: 728,
    };
    // SAFETY: SPI_GETWORKAREA writes one RECT.
    unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, (&raw mut area).cast(), 0) };
    // SAFETY: no preconditions.
    let dpi = i32::try_from(unsafe { GetDpiForSystem() })
        .unwrap_or(96)
        .max(96);
    let (w, h) = (area.right - area.left, area.bottom - area.top);
    let (width, height) = (
        (1480 * dpi / 96).min(w * 23 / 25),
        (920 * dpi / 96).min(h * 23 / 25),
    );
    (
        area.left + (w - width) / 2,
        area.top + (h - height) / 2,
        width,
        height,
    )
}

fn fail(hwnd: HWND, what: &str, hr: HRESULT) {
    let text = wide(&format!(
        "{what} (0x{:08X}).\n\nWiretap's window needs the Microsoft Edge WebView2 Runtime, which is part of Windows 11 and of current Windows 10 updates. Install it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and start Wiretap again.",
        hr.cast_unsigned()
    ));
    let caption = wide("Wiretap");
    // SAFETY: NUL-terminated strings; `hwnd` is our window.
    unsafe {
        MessageBoxW(hwnd, text.as_ptr(), caption.as_ptr(), MB_OK | MB_ICONERROR);
        DestroyWindow(hwnd);
    }
}

/// Configures the new WebView and navigates to `url` (the only origin it may show).
///
/// # Safety
/// `controller` is the live controller just created for `hwnd`.
unsafe fn setup(hwnd: HWND, controller: *mut c_void, url: &str, origin: String) {
    // SAFETY: all objects come from the live controller; each reference we take is released.
    unsafe {
        method::<unsafe extern "system" fn(*mut c_void) -> u32>(controller, 1)(controller); // AddRef: kept
        CONTROLLER.store(controller, Ordering::SeqCst);
        let controller2 = query(controller, &IID_CONTROLLER2);
        if !controller2.is_null() {
            // The app background (#090B10): no white flash while loading.
            let color = Color {
                a: 255,
                r: 9,
                g: 11,
                b: 16,
            };
            method::<Setter<Color>>(controller2, CONTROLLER2_PUT_BACKGROUND)(controller2, color);
            release(controller2);
        }
        fit(hwnd);
        let mut webview = null_mut();
        method::<Getter>(controller, CONTROLLER_GET_WEBVIEW)(controller, &mut webview);
        if webview.is_null() {
            return;
        }
        let mut settings = null_mut();
        method::<Getter>(webview, WEBVIEW_GET_SETTINGS)(webview, &mut settings);
        if !settings.is_null() {
            for slot in SETTINGS_OFF {
                method::<Setter<i32>>(settings, slot)(settings, 0);
            }
            let settings9 = query(settings, &IID_SETTINGS9);
            if !settings9.is_null() {
                for slot in SETTINGS9_OFF {
                    method::<Setter<i32>>(settings9, slot)(settings9, 0);
                }
                release(settings9);
            }
            release(settings);
        }
        on(
            webview,
            WEBVIEW_ADD_NAVIGATION_STARTING,
            IID_NAVIGATION_STARTING,
            move |args| {
                let mut uri: PWSTR = null_mut();
                type GetUri = unsafe extern "system" fn(*mut c_void, *mut PWSTR) -> HRESULT;
                method::<GetUri>(args, NAVIGATION_GET_URI)(args, &mut uri);
                let allowed = !uri.is_null() && {
                    let len = (0..).take_while(|&i| *uri.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(uri, len))
                        .starts_with(&origin)
                };
                CoTaskMemFree(uri.cast());
                if !allowed {
                    method::<Setter<i32>>(args, NAVIGATION_PUT_CANCEL)(args, 1);
                }
            },
        );
        on(
            webview,
            WEBVIEW_ADD_NEW_WINDOW_REQUESTED,
            IID_NEW_WINDOW_REQUESTED,
            |args| {
                method::<Setter<i32>>(args, NEW_WINDOW_PUT_HANDLED)(args, 1); // no popups
            },
        );
        on(
            webview,
            WEBVIEW_ADD_PERMISSION_REQUESTED,
            IID_PERMISSION_REQUESTED,
            |args| {
                method::<Setter<i32>>(args, PERMISSION_PUT_STATE)(args, PERMISSION_DENY);
            },
        );
        let webview4 = query(webview, &IID_WEBVIEW2_4);
        if !webview4.is_null() {
            on(
                webview4,
                WEBVIEW4_ADD_DOWNLOAD_STARTING,
                IID_DOWNLOAD_STARTING,
                |args| {
                    method::<Setter<i32>>(args, DOWNLOAD_PUT_HANDLED)(args, 1); // saves without browser UI
                },
            );
            release(webview4);
        }
        let url = wide(url);
        method::<Setter<PCWSTR>>(webview, WEBVIEW_NAVIGATE)(webview, url.as_ptr());
        release(webview);
    }
}

/// Shows the Wiretap window on `url` until the user closes it. `data` is WebView2's working
/// folder (InPrivate: it holds no browsing data); the caller deletes it afterwards.
///
/// # Errors
/// The window cannot be created.
pub(crate) fn run(url: &str, data: &Path) -> io::Result<()> {
    let origin = url.split('/').take(3).collect::<Vec<_>>().join("/") + "/";
    let class = wide("WiretapWindow");
    let title = wide("Wiretap");
    // SAFETY: plain Win32 window setup on this thread; every pointer outlives its call.
    let hwnd = unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        CoInitializeEx(null(), COINIT_APARTMENTTHREADED.cast_unsigned());
        let instance = GetModuleHandleW(null());
        let wc = WNDCLASSEXW {
            cbSize: u32::try_from(size_of::<WNDCLASSEXW>()).unwrap_or(0),
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: LoadIconW(null_mut(), IDI_APPLICATION),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: CreateSolidBrush(0x0010_0B09), // #090B10 (BGR)
            lpszMenuName: null(),
            lpszClassName: class.as_ptr(),
            hIconSm: null_mut(),
        };
        RegisterClassExW(&wc);
        let (x, y, w, h) = bounds();
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            x,
            y,
            w,
            h,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        if hwnd.is_null() {
            return Err(io::Error::last_os_error());
        }
        let dark: i32 = 1;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE.cast_unsigned(),
            (&raw const dark).cast(),
            4,
        );
        ShowWindow(hwnd, SW_SHOW);
        hwnd
    };

    let url = url.to_owned();
    let environment_created = handler(IID_ENVIRONMENT_COMPLETED, false, move |hr, environment| {
        if hr < 0 || environment.is_null() {
            return fail(hwnd, "The WebView2 Runtime could not start", hr);
        }
        // SAFETY: `environment` is live for this call; references taken here are released.
        unsafe {
            let environment10 = query(environment, &IID_ENVIRONMENT10);
            if environment10.is_null() {
                return fail(hwnd, "The WebView2 Runtime is too old", hr);
            }
            let mut options = null_mut();
            method::<Getter>(environment10, ENV10_CREATE_CONTROLLER_OPTIONS)(
                environment10,
                &mut options,
            );
            if !options.is_null() {
                method::<Setter<i32>>(options, OPTIONS_PUT_IN_PRIVATE)(options, 1);
            }
            let (url, origin) = (url.clone(), origin.clone());
            let controller_created =
                handler(IID_CONTROLLER_COMPLETED, false, move |hr, controller| {
                    if hr < 0 || controller.is_null() {
                        return fail(hwnd, "The WebView2 view could not be created", hr);
                    }
                    // `controller` is the live controller for `hwnd` (inside the outer unsafe).
                    setup(hwnd, controller, &url, origin.clone());
                });
            type Create =
                unsafe extern "system" fn(*mut c_void, HWND, *mut c_void, *mut c_void) -> HRESULT;
            method::<Create>(environment10, ENV10_CREATE_CONTROLLER_WITH_OPTIONS)(
                environment10,
                hwnd,
                options,
                controller_created,
            );
            release(controller_created);
            release(options);
            release(environment10);
        }
    });
    let data = wide(&data.to_string_lossy());
    // SAFETY: NUL-terminated folder; the loader keeps its own reference to the handler.
    let hr = unsafe {
        CreateCoreWebView2EnvironmentWithOptions(
            null(),
            data.as_ptr(),
            null_mut(),
            environment_created,
        )
    };
    // SAFETY: we own one reference.
    unsafe { release(environment_created) };
    if hr < 0 {
        fail(hwnd, "The WebView2 Runtime was not found", hr);
    }

    // SAFETY: standard message loop; then the controller is closed and released once.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let controller = CONTROLLER.swap(null_mut(), Ordering::SeqCst);
        if !controller.is_null() {
            method::<unsafe extern "system" fn(*mut c_void) -> HRESULT>(
                controller,
                CONTROLLER_CLOSE,
            )(controller);
            release(controller);
        }
        CoUninitialize();
    }
    Ok(())
}
