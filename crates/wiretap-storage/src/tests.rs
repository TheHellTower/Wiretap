use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use std::{fs, thread};

use wiretap_core::{
    CaptureSource, Direction, EventMetadata, Inspection, NetworkEvent, PayloadEncryption, Protocol,
};

use super::*;

/// Unique temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("wiretap-test-{}", Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("wiretap.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn event(session: SessionId, ts: i64) -> NetworkEvent {
    NetworkEvent {
        id: EventId::generate(),
        session_id: session,
        timestamp: Timestamp(ts),
        source: CaptureSource::PacketCapture,
        protocol: Protocol::Dns,
        direction: Direction::Outbound,
        process: None,
        local_endpoint: None,
        remote_endpoint: None,
        payload: None,
        metadata: EventMetadata {
            inspection: Inspection::Metadata,
            flow_id: None,
            attributes: [("dns.qname".to_owned(), "example.com".to_owned())].into(),
        },
    }
}

fn store_with_session(dir: &TempDir) -> (Store, Session) {
    let store = Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
    let session = Session::new("test");
    store.insert_session(&session).unwrap();
    (store, session)
}

fn count(store: &Store, table: &str) -> i64 {
    store
        .conn
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn open_applies_hardened_configuration_and_is_idempotent() {
    let dir = TempDir::new();
    for _ in 0..2 {
        let store = Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
        let pragma = |name: &str| -> String {
            store
                .conn
                .query_row(&format!("PRAGMA {name}"), [], |r| {
                    r.get::<_, rusqlite::types::Value>(0)
                })
                .map(|v| format!("{v:?}"))
                .unwrap()
        };
        assert_eq!(pragma("journal_mode"), r#"Text("wal")"#);
        assert_eq!(pragma("foreign_keys"), "Integer(1)");
        assert_eq!(pragma("auto_vacuum"), "Integer(2)"); // incremental
        assert_eq!(pragma("secure_delete"), "Integer(2)"); // fast
        assert_eq!(pragma("trusted_schema"), "Integer(0)");
        assert_eq!(
            pragma("user_version"),
            format!("Integer({})", MIGRATIONS.len())
        );
        store.check_integrity().unwrap();
    }
}

#[test]
fn refuses_databases_from_newer_versions() {
    let dir = TempDir::new();
    Store::open(dir.db(), DEFAULT_QUOTA)
        .unwrap()
        .conn
        .pragma_update(None, "user_version", 99)
        .unwrap();
    assert!(matches!(
        Store::open(dir.db(), DEFAULT_QUOTA),
        Err(StoreError::NewerSchema)
    ));
}

#[test]
fn failed_migration_rolls_back_completely() {
    let dir = TempDir::new();
    Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
    let mut broken = MIGRATIONS.to_vec();
    broken.push("CREATE TABLE extra (x INTEGER) STRICT; INSERT INTO missing VALUES (1);");
    let conn = Connection::open(dir.db()).unwrap();
    assert!(Store::init(conn, DEFAULT_QUOTA, &broken).is_err());
    let store = Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
    let extra: i64 = store
        .conn
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'extra'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(extra, 0);
    let version: u32 = store
        .conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version as usize, MIGRATIONS.len());
}

#[test]
fn rejects_files_that_are_not_databases() {
    let dir = TempDir::new();
    fs::write(dir.db(), vec![0xA5; 64 * 1024]).unwrap();
    assert!(matches!(
        Store::open(dir.db(), DEFAULT_QUOTA),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn detects_damaged_pages() {
    let dir = TempDir::new();
    {
        let (mut store, session) = store_with_session(&dir);
        let batch: Vec<_> = (0..2000).map(|i| event(session.id, i)).collect();
        store.insert_events(&batch).unwrap();
        store
            .conn
            .pragma_update(None, "wal_checkpoint", "TRUNCATE")
            .unwrap();
    }
    let mut bytes = fs::read(dir.db()).unwrap();
    assert!(bytes.len() > 16 * 4096);
    for b in &mut bytes[8 * 4096..12 * 4096] {
        *b = 0x5A;
    }
    fs::write(dir.db(), bytes).unwrap();
    let outcome = Store::open(dir.db(), DEFAULT_QUOTA).and_then(|s| s.check_integrity());
    assert!(
        matches!(outcome, Err(StoreError::Corrupt(_))),
        "{outcome:?}"
    );
}

#[test]
fn events_round_trip_in_order_with_pagination() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    let mut events: Vec<_> = (0..25).map(|i| event(session.id, 1_000 - i)).collect();
    store.insert_events(&events).unwrap();
    events.sort_by_key(|e| (e.timestamp, e.id.0.to_bytes()));

    let mut read = Vec::new();
    let mut cursor = None;
    loop {
        let page = store.events(session.id, cursor, 10).unwrap();
        let Some(last) = page.last() else { break };
        cursor = Some((last.timestamp, last.id));
        read.extend(page);
    }
    assert_eq!(read, events);
    assert!(
        store
            .events(SessionId::generate(), None, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn page_size_is_capped() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    let batch: Vec<_> = (0..i64::try_from(MAX_PAGE).unwrap() + 5)
        .map(|i| event(session.id, i))
        .collect();
    store.insert_events(&batch).unwrap();
    assert_eq!(
        store.events(session.id, None, usize::MAX).unwrap().len(),
        MAX_PAGE
    );
}

#[test]
fn batches_are_atomic() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    let first = event(session.id, 1);
    let duplicate = NetworkEvent {
        timestamp: Timestamp(2),
        ..first.clone()
    };
    assert!(
        store
            .insert_events(&[first, event(session.id, 3), duplicate])
            .is_err()
    );
    assert_eq!(count(&store, "events"), 0);

    let orphan = event(SessionId::generate(), 1);
    assert!(
        store
            .insert_events(&[event(session.id, 1), orphan])
            .is_err()
    );
    assert_eq!(count(&store, "events"), 0);
}

#[test]
fn invalid_input_is_rejected_before_writing() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    let mut lying = event(session.id, 1);
    lying.metadata.inspection = Inspection::Intercepted; // passive capture cannot decrypt
    assert!(matches!(
        store.insert_events(&[lying]),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.insert_session(&Session::new("")),
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.insert_payload(session.id, b"abc", 2, PayloadEncryption::Cleartext),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(count(&store, "events") + count(&store, "payloads"), 0);
}

#[test]
fn payloads_round_trip() {
    let dir = TempDir::new();
    let (store, session) = store_with_session(&dir);
    let reference = store
        .insert_payload(
            session.id,
            b"GET / HTTP/1.1",
            100,
            PayloadEncryption::Cleartext,
        )
        .unwrap();
    assert_eq!((reference.size, reference.stored), (100, 14));
    assert_eq!(
        store.payload(reference.id).unwrap().as_deref(),
        Some(&b"GET / HTTP/1.1"[..])
    );
    assert_eq!(store.payload(PayloadId::generate()).unwrap(), None);
}

#[test]
fn deleting_a_session_cascades() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    let other = Session::new("other");
    store.insert_session(&other).unwrap();
    store
        .insert_events(&[event(session.id, 1), event(other.id, 1)])
        .unwrap();
    store
        .insert_payload(session.id, &[1; 512], 512, PayloadEncryption::Encrypted)
        .unwrap();

    assert!(store.delete_session(session.id).unwrap());
    assert!(!store.delete_session(session.id).unwrap());
    assert_eq!(store.session(session.id).unwrap(), None);
    assert_eq!(store.sessions().unwrap(), vec![other]);
    assert_eq!((count(&store, "events"), count(&store, "payloads")), (1, 0));
}

#[test]
fn retention_purges_old_sessions() {
    let dir = TempDir::new();
    let store = Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
    let old = Session {
        created: Timestamp(1_000),
        ..Session::new("old")
    };
    let new = Session {
        created: Timestamp(5_000),
        ..Session::new("new")
    };
    store.insert_session(&old).unwrap();
    store.insert_session(&new).unwrap();
    assert_eq!(store.purge_sessions_before(Timestamp(5_000)).unwrap(), 1);
    assert_eq!(store.sessions().unwrap(), vec![new]);
}

#[test]
fn quota_is_enforced_and_recoverable() {
    let dir = TempDir::new();
    let store = Store::open(dir.db(), 1 << 20).unwrap();
    let session = Session::new("big");
    store.insert_session(&session).unwrap();
    let chunk = vec![7u8; 64 * 1024];
    let mut stored = 0;
    let err = loop {
        match store.insert_payload(session.id, &chunk, 65_536, PayloadEncryption::Cleartext) {
            Ok(_) => stored += 1,
            Err(e) => break e,
        }
        assert!(stored < 64, "quota not enforced");
    };
    assert!(matches!(err, StoreError::Full), "{err:?}");
    // Deleting data frees space for new writes.
    assert!(store.delete_session(session.id).unwrap());
    let fresh = Session::new("fresh");
    store.insert_session(&fresh).unwrap();
    store
        .insert_payload(fresh.id, &chunk, 65_536, PayloadEncryption::Cleartext)
        .unwrap();
    store.check_integrity().unwrap();
}

#[test]
fn tampered_rows_are_rejected_on_read() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    store.insert_events(&[event(session.id, 1)]).unwrap();

    store
        .conn
        .execute("UPDATE events SET data = '{\"not\":\"an event\"}'", [])
        .unwrap();
    assert!(matches!(
        store.events(session.id, None, 10),
        Err(StoreError::Codec(_))
    ));

    let mut lying = event(session.id, 1);
    lying.metadata.inspection = Inspection::Intercepted;
    let json = serde_json::to_string(&lying).unwrap();
    store
        .conn
        .execute("UPDATE events SET data = ?1", [json])
        .unwrap();
    assert!(matches!(
        store.events(session.id, None, 10),
        Err(StoreError::Invalid(_))
    ));

    store
        .conn
        .execute("UPDATE sessions SET name = 'bad\u{1b}[31m'", [])
        .unwrap();
    assert!(matches!(store.sessions(), Err(StoreError::Invalid(_))));
}

#[test]
fn concurrent_writers_do_not_lose_batches() {
    let dir = TempDir::new();
    let (_store, session) = store_with_session(&dir);
    let writers: Vec<_> = (0..4)
        .map(|_| {
            let path = dir.db();
            thread::spawn(move || {
                let mut store = Store::open(path, DEFAULT_QUOTA).unwrap();
                for i in 0..50 {
                    let batch: Vec<_> = (0..10).map(|j| event(session.id, i * 10 + j)).collect();
                    store.insert_events(&batch).unwrap();
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }
    let store = Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
    assert_eq!(count(&store, "events"), 4 * 50 * 10);
}

const CHILD_ENV: &str = "WIRETAP_STORAGE_CRASH_CHILD";
const BATCH: i64 = 20;

/// Kills a writer process mid-stream (TerminateProcess on Windows) and verifies that the
/// database is intact and only contains whole batches.
#[test]
fn killed_writer_leaves_a_consistent_database() {
    if let Ok(path) = std::env::var(CHILD_ENV) {
        let mut store = Store::open(&path, DEFAULT_QUOTA).unwrap();
        let session = store.sessions().unwrap().remove(0);
        for i in 0..i64::MAX / BATCH {
            let batch: Vec<_> = (0..BATCH)
                .map(|j| event(session.id, i * BATCH + j))
                .collect();
            store.insert_events(&batch).unwrap();
            if i == 0 {
                writeln!(std::io::stdout(), "ready").unwrap();
            }
        }
        return;
    }

    let dir = TempDir::new();
    drop(store_with_session(&dir));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::killed_writer_leaves_a_consistent_database",
            "--nocapture",
        ])
        .env(CHILD_ENV, dir.db())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let ready = BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .any(|l| l.trim() == "ready");
    assert!(ready, "child writer never became ready");
    thread::sleep(Duration::from_millis(300));
    child.kill().unwrap();
    child.wait().unwrap();

    let store = Store::open(dir.db(), DEFAULT_QUOTA).unwrap();
    store.check_integrity().unwrap();
    let events = count(&store, "events");
    assert!(events >= BATCH, "child wrote nothing");
    assert_eq!(
        events % BATCH,
        0,
        "partial batch persisted: {events} events"
    );
}

fn flow(session: SessionId, started: i64) -> wiretap_core::Flow {
    use wiretap_core::{Flow, FlowId, FlowTiming, HttpRequest, HttpVersion};
    Flow {
        id: FlowId::generate(),
        session_id: session,
        source: CaptureSource::Driver,
        process: None,
        client: None,
        server: None,
        request: Some(HttpRequest {
            method: "GET".into(),
            url: "http://example.com/".into(),
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: None,
        }),
        response: None,
        timing: FlowTiming {
            started: Timestamp(started),
            request_complete: None,
            response_started: None,
            response_complete: None,
        },
        tags: Vec::new(),
    }
}

#[test]
fn flows_are_upserted_and_paginated() {
    use wiretap_core::{HttpResponse, HttpVersion};
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    let mut flows: Vec<_> = (0..15).map(|i| flow(session.id, 100 - i)).collect();
    store.upsert_flows(&flows).unwrap();
    flows[3].response = Some(HttpResponse {
        status: 200,
        reason: "OK".into(),
        version: HttpVersion::Http11,
        headers: Vec::new(),
        body: None,
    });
    store.upsert_flows(&flows[3..4]).unwrap();
    flows.sort_by_key(|f| (f.timing.started, f.id.0.to_bytes()));

    let mut read = Vec::new();
    let mut cursor = None;
    loop {
        let page = store.flows(session.id, cursor, 4).unwrap();
        let Some(last) = page.last() else { break };
        cursor = Some((last.timing.started, last.id));
        read.extend(page);
    }
    assert_eq!(read, flows, "update replaced the stored flow");
    assert_eq!(count(&store, "flows"), 15);

    let other = Session::new("other");
    store.insert_session(&other).unwrap();
    let mut moved = flows[0].clone();
    moved.session_id = other.id;
    store.upsert_flows(&[moved]).unwrap();
    assert!(
        store.flows(other.id, None, 10).unwrap().is_empty(),
        "flows never move between sessions"
    );

    store.delete_session(session.id).unwrap();
    assert_eq!(count(&store, "flows"), 0);
}

#[test]
fn settings_and_single_flow_lookup() {
    let dir = TempDir::new();
    let (mut store, session) = store_with_session(&dir);
    assert_eq!(store.setting("autoreply.rules").unwrap(), None);
    store.set_setting("autoreply.rules", "[]").unwrap();
    store.set_setting("autoreply.rules", "[1]").unwrap();
    assert_eq!(
        store.setting("autoreply.rules").unwrap().as_deref(),
        Some("[1]")
    );
    assert!(matches!(
        store.set_setting("big", &"x".repeat(MAX_SETTING + 1)),
        Err(StoreError::Invalid(_))
    ));

    let f = flow(session.id, 5);
    store.upsert_flows(std::slice::from_ref(&f)).unwrap();
    assert_eq!(store.flow(f.id).unwrap(), Some(f));
    assert_eq!(store.flow(wiretap_core::FlowId::generate()).unwrap(), None);
}
