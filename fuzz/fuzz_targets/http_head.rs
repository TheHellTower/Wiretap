#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "http_head",
    data,
    wiretap_fuzz::http_head
));
