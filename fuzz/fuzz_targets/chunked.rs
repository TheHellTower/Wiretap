#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "chunked",
    data,
    wiretap_fuzz::chunked
));
