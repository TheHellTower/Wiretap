//! Wire-format stability and validation rules of the public model.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test helpers")]

use std::collections::HashSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use wiretap_core::*;

const EVENT: &str = include_str!("fixtures/event.json");
const FLOW: &str = include_str!("fixtures/flow.json");

/// Parses a fixture, validates it and checks that it re-serializes to exactly the same JSON:
/// field names, enum spellings and number formats are a contract for every SDK.
fn canonical<T: Serialize + DeserializeOwned>(fixture: &str) -> T {
    let value: T = serde_json::from_str(fixture).unwrap();
    let expected: serde_json::Value = serde_json::from_str(fixture).unwrap();
    assert_eq!(serde_json::to_value(&value).unwrap(), expected);
    value
}

fn event() -> NetworkEvent {
    canonical(EVENT)
}

fn flow() -> Flow {
    canonical(FLOW)
}

fn rejected(result: Result<(), ModelError>, field: &str) {
    assert_eq!(result.expect_err("must be rejected").field, field);
}

#[test]
fn fixtures_are_canonical_and_valid() {
    event().validate().unwrap();
    flow().validate().unwrap();
}

#[test]
fn strict_deserialization() {
    let extra = EVENT.replacen("\"protocol\"", "\"unexpected\": 1, \"protocol\"", 1);
    assert!(
        serde_json::from_str::<NetworkEvent>(&extra).is_err(),
        "unknown field accepted"
    );
    let bad_enum = EVENT.replace("\"tls\"", "\"TLS\"");
    assert!(
        serde_json::from_str::<NetworkEvent>(&bad_enum).is_err(),
        "enum is case-sensitive"
    );
    let bad_id = EVENT.replace(
        "019a4f2e-8c41-7a3b-9d2e-5f6a7b8c9d0e",
        "019a4f2e8c417a3b9d2e5f6a7b8c9d0e",
    );
    assert!(
        serde_json::from_str::<NetworkEvent>(&bad_id).is_err(),
        "unhyphenated UUID accepted"
    );
    let negative_port = EVENT.replace("51544", "-1");
    assert!(serde_json::from_str::<NetworkEvent>(&negative_port).is_err());
    let missing = EVENT.replace("\"direction\": \"outbound\",", "");
    assert!(
        serde_json::from_str::<NetworkEvent>(&missing).is_err(),
        "required field missing"
    );
}

#[test]
fn uuid_text_round_trip() {
    let id = Uuid::now_v7();
    let text = id.to_string();
    assert_eq!(text.len(), 36);
    assert_eq!(text.parse::<Uuid>().unwrap(), id);
    assert_eq!(text.to_uppercase().parse::<Uuid>().unwrap(), id);
    assert_eq!(Uuid::from_bytes(id.to_bytes()), id);
    assert_eq!(&text[14..15], "7", "version nibble");
    assert!(
        matches!(&text[19..20], "8" | "9" | "a" | "b"),
        "RFC 9562 variant"
    );
    for bad in [
        "",
        "019a4f2e-8c41-7a3b-9d2e-5f6a7b8c9d0",
        "019a4f2e-8c41-7a3b-9d2e-5f6a7b8c9d0g",
        "019a4f2e+8c41-7a3b-9d2e-5f6a7b8c9d0e",
        "019a4f2e-8c41-7a3b-9d2e-5f6a7b8c9d0é",
    ] {
        assert!(bad.parse::<Uuid>().is_err(), "{bad:?}");
    }
}

#[test]
fn generated_ids_are_unique_and_time_ordered() {
    let ids: Vec<Uuid> = (0..50_000).map(|_| Uuid::now_v7()).collect();
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "IDs from one thread must increase"
    );
    let threads: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(|| (0..10_000).map(|_| Uuid::now_v7()).collect::<Vec<_>>()))
        .collect();
    let all: HashSet<Uuid> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    assert_eq!(all.len(), 80_000);
}

#[test]
fn encrypted_traffic_is_never_reported_as_decrypted() {
    let mut e = event();
    e.metadata.inspection = Inspection::Intercepted; // passive packet capture cannot intercept
    rejected(e.validate(), "metadata.inspection");

    let mut e = event();
    e.metadata.inspection = Inspection::Plaintext; // payload is ciphertext
    rejected(e.validate(), "payload.encryption");

    let mut e = event();
    e.payload.as_mut().unwrap().encryption = PayloadEncryption::Decrypted;
    rejected(e.validate(), "payload.encryption");

    let mut e = event();
    e.source = CaptureSource::ExplicitProxy;
    e.metadata.inspection = Inspection::Intercepted;
    e.payload.as_mut().unwrap().encryption = PayloadEncryption::Decrypted;
    e.validate().unwrap();

    let mut f = flow();
    f.source = CaptureSource::Wfp; // decrypted body from a passive source
    rejected(f.validate(), "request.body");
    let mut f = flow();
    f.request
        .as_mut()
        .unwrap()
        .body
        .as_mut()
        .unwrap()
        .encryption = PayloadEncryption::Encrypted;
    rejected(f.validate(), "request.body");
}

#[test]
fn http_values_cannot_inject_protocol_or_terminal_sequences() {
    for value in [
        "a\r\nX-Injected: 1",
        "a\nb",
        "a\0b",
        "\u{1b}[2J",
        "\u{9b}31m",
        "\u{7f}",
    ] {
        let mut f = flow();
        f.request.as_mut().unwrap().headers[0].value = value.to_owned();
        rejected(f.validate(), "request.headers");
        let mut f = flow();
        f.response.as_mut().unwrap().reason = value.to_owned();
        rejected(f.validate(), "response.reason");
        let mut f = flow();
        f.request.as_mut().unwrap().url = format!("https://example.com/{value}");
        rejected(f.validate(), "request.url");
        let mut e = event();
        e.process.as_mut().unwrap().name = Some(value.to_owned());
        rejected(e.validate(), "process.name");
    }
    let mut f = flow();
    f.request.as_mut().unwrap().headers[0].value = "tab\tallowed".to_owned();
    f.validate().unwrap();
}

#[test]
fn http_syntax_rules() {
    for method in ["", "GE T", "GET\r", "GÉT", "(GET)"] {
        let mut f = flow();
        f.request.as_mut().unwrap().method = method.to_owned();
        rejected(f.validate(), "request.method");
    }
    for name in ["", "Host:", "X Y", "Ünicode"] {
        let mut f = flow();
        f.request.as_mut().unwrap().headers[0].name = name.to_owned();
        rejected(f.validate(), "request.headers");
    }
    for status in [0, 99, 1000, u16::MAX] {
        let mut f = flow();
        f.response.as_mut().unwrap().status = status;
        rejected(f.validate(), "response.status");
    }
    let mut f = flow();
    f.request.as_mut().unwrap().url.clear();
    rejected(f.validate(), "request.url");
}

#[test]
fn resource_limits() {
    let mut f = flow();
    let header = HttpHeader {
        name: "X".to_owned(),
        value: String::new(),
    };
    f.request.as_mut().unwrap().headers = vec![header; limits::HEADERS + 1];
    rejected(f.validate(), "request.headers");

    let mut f = flow();
    let big = HttpHeader {
        name: "X".to_owned(),
        value: "v".repeat(limits::HEADER_BYTES),
    };
    f.request.as_mut().unwrap().headers = vec![big];
    rejected(f.validate(), "request.headers");

    let mut f = flow();
    f.request.as_mut().unwrap().url = format!("https://e.com/{}", "a".repeat(limits::URL));
    rejected(f.validate(), "request.url");

    let mut f = flow();
    f.tags = vec!["t".to_owned(); limits::TAGS + 1];
    rejected(f.validate(), "tags");
    let mut f = flow();
    f.tags = vec![String::new()];
    rejected(f.validate(), "tags");

    let mut e = event();
    e.metadata.attributes = (0..=limits::ATTRIBUTES)
        .map(|i| (i.to_string(), String::new()))
        .collect();
    rejected(e.validate(), "metadata.attributes");

    let mut e = event();
    e.process.as_mut().unwrap().path = Some("p".repeat(limits::TEXT + 1));
    rejected(e.validate(), "process.path");

    rejected(
        Session::new("x".repeat(limits::LABEL + 1)).validate(),
        "session.name",
    );
    rejected(Session::new("").validate(), "session.name");
}

#[test]
fn payload_and_timing_consistency() {
    let mut e = event();
    let p = e.payload.as_mut().unwrap();
    p.stored = p.size + 1;
    rejected(e.validate(), "payload.stored");

    let mut f = flow();
    f.timing.response_complete = Some(Timestamp(f.timing.started.0 - 1));
    rejected(f.validate(), "timing");
}
