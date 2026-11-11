//! Replays every seed (`corpus/<target>`) and regression input (`regressions/<target>`) through
//! its harness on stable Rust: `cargo test --manifest-path fuzz/Cargo.toml --no-default-features`.

use std::fs;
use std::path::Path;

fn replay(target: &str, harness: fn(&[u8])) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut inputs = 0;
    for kind in ["corpus", "regressions"] {
        let Ok(entries) = fs::read_dir(root.join(kind).join(target)) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            eprintln!("replaying {}", path.display());
            harness(&fs::read(&path).unwrap());
            inputs += 1;
        }
    }
    assert!(inputs > 0, "no seed inputs for {target}");
}

#[test]
fn event_json() {
    replay("event_json", wiretap_fuzz::event_json);
}

#[test]
fn flow_json() {
    replay("flow_json", wiretap_fuzz::flow_json);
}

#[test]
fn uuid_parse() {
    replay("uuid_parse", wiretap_fuzz::uuid_parse);
}

#[test]
fn storage_ops() {
    replay("storage_ops", wiretap_fuzz::storage_ops);
}

#[test]
fn os_classify() {
    replay("os_classify", wiretap_fuzz::os_classify);
}

#[test]
fn driver_records() {
    replay("driver_records", wiretap_fuzz::driver_records);
}

#[test]
fn driver_ring() {
    replay("driver_ring", wiretap_fuzz::driver_ring);
}

#[test]
fn http_head() {
    replay("http_head", wiretap_fuzz::http_head);
}

#[test]
fn tls_hello() {
    replay("tls_hello", wiretap_fuzz::tls_hello);
}

#[test]
fn tracker() {
    replay("tracker", wiretap_fuzz::tracker);
}

#[test]
fn cli_args() {
    replay("cli_args", wiretap_fuzz::cli_args);
}

#[test]
fn rules() {
    replay("rules", wiretap_fuzz::rules);
}

#[test]
fn redirect_records() {
    replay("redirect_records", wiretap_fuzz::redirect_records);
}

#[test]
fn tls_host() {
    replay("tls_host", wiretap_fuzz::tls_host);
}

#[test]
fn chunked() {
    replay("chunked", wiretap_fuzz::chunked);
}

#[test]
fn ui_router() {
    replay("ui_router", wiretap_fuzz::ui_router);
}

#[test]
fn content_roundtrip() {
    replay("content_roundtrip", wiretap_fuzz::content_roundtrip);
}

#[test]
fn content_decode() {
    replay("content_decode", wiretap_fuzz::content_decode);
}

#[test]
fn websocket() {
    replay("websocket", wiretap_fuzz::websocket);
}

#[test]
fn http2() {
    replay("http2", wiretap_fuzz::http2);
}

#[test]
fn grpc() {
    replay("grpc", wiretap_fuzz::grpc);
}
