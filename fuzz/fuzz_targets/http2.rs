#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard("http2", data, wiretap_fuzz::http2));
