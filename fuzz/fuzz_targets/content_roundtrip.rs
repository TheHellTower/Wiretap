#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "content_roundtrip",
    data,
    wiretap_fuzz::content_roundtrip
));
