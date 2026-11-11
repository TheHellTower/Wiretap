#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "storage_ops",
    data,
    wiretap_fuzz::storage_ops
));
