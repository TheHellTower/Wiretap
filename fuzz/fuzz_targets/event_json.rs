#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "event_json",
    data,
    wiretap_fuzz::event_json
));
