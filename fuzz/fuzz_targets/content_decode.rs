#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "content_decode",
    data,
    wiretap_fuzz::content_decode
));
