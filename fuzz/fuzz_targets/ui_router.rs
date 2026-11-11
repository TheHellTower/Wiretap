#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "ui_router",
    data,
    wiretap_fuzz::ui_router
));
