#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "driver_ring",
    data,
    wiretap_fuzz::driver_ring
));
