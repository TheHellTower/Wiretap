#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "os_classify",
    data,
    wiretap_fuzz::os_classify
));
