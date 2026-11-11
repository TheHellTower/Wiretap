#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "redirect_records",
    data,
    wiretap_fuzz::redirect_records
));
