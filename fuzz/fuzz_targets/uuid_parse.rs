#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "uuid_parse",
    data,
    wiretap_fuzz::uuid_parse
));
