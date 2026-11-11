#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wiretap_fuzz::guard(
    "cli_args",
    data,
    wiretap_fuzz::cli_args
));
