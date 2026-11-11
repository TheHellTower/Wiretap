#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "tls_hello",
    data,
    wiretap_fuzz::tls_hello
));
