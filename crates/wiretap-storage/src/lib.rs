//! Wiretap storage: crash-safe SQLite persistence for sessions, events, HTTP flows and payloads.
//!
//! A [`Store`] owns one SQLite connection. SQLite admits one writer at a time, so the service
//! funnels writes through a single `Store` and batches them; further `Store`s on the same file
//! read concurrently (WAL mode).
//!
//! Durability: WAL with `synchronous=NORMAL` survives process crashes without corruption or
//! partially written batches. A power loss can drop the most recent commits, never corrupt.
//!
//! Hardening: defensive mode, untrusted schema, no double-quoted string literals, STRICT
//! tables, foreign keys, a hard size quota, and `secure_delete` with incremental vacuum so
//! deleted captures do not linger in the file. Everything read back is re-validated, so a
//! tampered database cannot inject invalid model data. Untrusted SQLite files are never
//! opened: imports use validated export formats instead.
#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, Row, params};
use serde::de::DeserializeOwned;
use wiretap_core::{
    EventId, Flow, FlowId, ModelError, NetworkEvent, PayloadEncryption, PayloadId,
    PayloadReference, Session, SessionId, Timestamp, Uuid,
};

/// Schema migrations in order; `PRAGMA user_version` records how many have been applied.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_flows.sql"),
    include_str!("../migrations/0003_settings.sql"),
];

/// Largest setting value accepted (bytes).
pub const MAX_SETTING: usize = 32 << 20;

const EVENTS_PAGE: &str = "SELECT data FROM events WHERE session_id = ?1 AND (ts, id) > (?2, ?3) ORDER BY ts, id LIMIT ?4";
const FLOWS_PAGE: &str = "SELECT data FROM flows WHERE session_id = ?1 AND (started, id) > (?2, ?3) ORDER BY started, id LIMIT ?4";

/// Default storage quota in bytes (8 GiB).
pub const DEFAULT_QUOTA: u64 = 8 << 30;

/// Maximum records returned by one [`Store::events`] or [`Store::flows`] call.
pub const MAX_PAGE: usize = 10_000;

/// Storage failure.
#[derive(Debug)]
pub enum StoreError {
    /// The file is damaged or is not a Wiretap database.
    Corrupt(String),
    /// The database was written by a newer Wiretap version; it is left untouched.
    NewerSchema,
    /// The storage quota or the disk is full.
    Full,
    /// The file system does not support write-ahead logging.
    WalUnavailable,
    /// The data failed model validation.
    Invalid(ModelError),
    /// A record could not be encoded or decoded.
    Codec(serde_json::Error),
    /// Any other SQLite failure.
    Sqlite(rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(detail) => write!(f, "database is corrupt: {detail}"),
            Self::NewerSchema => f.write_str("database was created by a newer Wiretap version"),
            Self::Full => f.write_str("storage quota or disk is full"),
            Self::WalUnavailable => f.write_str("file system does not support write-ahead logging"),
            Self::Invalid(e) => e.fmt(f),
            Self::Codec(e) => write!(f, "record encoding failed: {e}"),
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::Codec(e) => Some(e),
            Self::Sqlite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
                Self::Corrupt(e.to_string())
            }
            Some(ErrorCode::DiskFull) => Self::Full,
            _ => Self::Sqlite(e),
        }
    }
}

impl From<ModelError> for StoreError {
    fn from(e: ModelError) -> Self {
        Self::Invalid(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Codec(e)
    }
}

/// A connection to a Wiretap database.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens or creates the database at `path`, capped at `quota` bytes, and applies pending
    /// migrations. `":memory:"` opens a private in-memory database (tests and fuzzing).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for damaged files, [`StoreError::NewerSchema`] for databases
    /// from newer versions, or the underlying SQLite error.
    pub fn open(path: impl AsRef<Path>, quota: u64) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        Self::init(Connection::open_with_flags(path, flags)?, quota, MIGRATIONS)
    }

    fn init(mut conn: Connection, quota: u64, migrations: &[&str]) -> Result<Self, StoreError> {
        for (option, enable) in [
            (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
            (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
            (DbConfig::SQLITE_DBCONFIG_DQS_DDL, false),
            (DbConfig::SQLITE_DBCONFIG_DQS_DML, false),
        ] {
            conn.set_db_config(option, enable)?;
        }
        conn.busy_timeout(Duration::from_secs(5))?;
        // Only takes effect before the first table exists, i.e. on new databases.
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if mode != "wal" && mode != "memory" {
            return Err(StoreError::WalUnavailable);
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "FAST")?;
        conn.pragma_update(None, "journal_size_limit", 64_i64 << 20)?;
        let page_size: i64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let max_pages = i64::try_from(quota).unwrap_or(i64::MAX) / page_size.max(1);
        conn.pragma_update(None, "max_page_count", max_pages.max(1))?;
        migrate(&mut conn, migrations)?;
        Ok(Self { conn })
    }

    /// Persists a new session.
    ///
    /// # Errors
    /// Validation failures or SQLite errors (including a duplicate ID).
    pub fn insert_session(&self, session: &Session) -> Result<(), StoreError> {
        session.validate()?;
        self.conn.execute(
            "INSERT INTO sessions (id, name, created) VALUES (?1, ?2, ?3)",
            params![session.id.0.to_bytes(), session.name, session.created.0],
        )?;
        Ok(())
    }

    /// Returns the session with `id`, if any.
    ///
    /// # Errors
    /// SQLite errors, or [`StoreError::Invalid`] for tampered rows.
    pub fn session(&self, id: SessionId) -> Result<Option<Session>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, created FROM sessions WHERE id = ?1",
                [id.0.to_bytes()],
                session_row,
            )
            .optional()?;
        if let Some(s) = &row {
            s.validate()?;
        }
        Ok(row)
    }

    /// Returns all sessions, oldest first.
    ///
    /// # Errors
    /// SQLite errors, or [`StoreError::Invalid`] for tampered rows.
    pub fn sessions(&self) -> Result<Vec<Session>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, created FROM sessions ORDER BY created, id")?;
        let rows = stmt.query_map([], session_row)?;
        rows.map(|row| {
            let s = row?;
            s.validate()?;
            Ok(s)
        })
        .collect()
    }

    /// Deletes a session with all of its events and payloads. Returns whether it existed.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn delete_session(&self, id: SessionId) -> Result<bool, StoreError> {
        let deleted = self
            .conn
            .execute("DELETE FROM sessions WHERE id = ?1", [id.0.to_bytes()])?;
        self.reclaim()?;
        Ok(deleted > 0)
    }

    /// Retention: deletes sessions created before `cutoff`. Returns how many were deleted.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn purge_sessions_before(&self, cutoff: Timestamp) -> Result<usize, StoreError> {
        let deleted = self
            .conn
            .execute("DELETE FROM sessions WHERE created < ?1", [cutoff.0])?;
        self.reclaim()?;
        Ok(deleted)
    }

    /// Validates and persists `events` atomically: either all are stored or none.
    ///
    /// # Errors
    /// Validation failures (nothing is written), or SQLite errors such as an unknown session
    /// or duplicate ID (the whole batch is rolled back).
    pub fn insert_events(&mut self, events: &[NetworkEvent]) -> Result<(), StoreError> {
        for event in events {
            event.validate()?;
        }
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx
                .prepare("INSERT INTO events (id, session_id, ts, data) VALUES (?1, ?2, ?3, ?4)")?;
            for e in events {
                let json = serde_json::to_string(e)?;
                stmt.execute(params![
                    e.id.0.to_bytes(),
                    e.session_id.0.to_bytes(),
                    e.timestamp.0,
                    json
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Returns up to `limit` (at most [`MAX_PAGE`]) events of `session` in `(timestamp, id)`
    /// order, starting after the `after` cursor (the last event of the previous page).
    ///
    /// # Errors
    /// SQLite errors, or [`StoreError::Codec`] / [`StoreError::Invalid`] for tampered rows.
    pub fn events(
        &self,
        session: SessionId,
        after: Option<(Timestamp, EventId)>,
        limit: usize,
    ) -> Result<Vec<NetworkEvent>, StoreError> {
        let cursor = after.map(|(t, id)| (t, id.0));
        self.page(EVENTS_PAGE, session, cursor, limit, NetworkEvent::validate)
    }

    /// Validates and inserts or updates `flows` atomically (a flow is first stored with its
    /// request and later completed with its response). A flow never moves between sessions.
    ///
    /// # Errors
    /// Validation failures (nothing is written), or SQLite errors (the batch is rolled back).
    pub fn upsert_flows(&mut self, flows: &[Flow]) -> Result<(), StoreError> {
        for flow in flows {
            flow.validate()?;
        }
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(concat!(
                "INSERT INTO flows (id, session_id, started, data) VALUES (?1, ?2, ?3, ?4) ",
                "ON CONFLICT (id) DO UPDATE SET started = excluded.started, data = excluded.data ",
                "WHERE flows.session_id = excluded.session_id",
            ))?;
            for f in flows {
                let json = serde_json::to_string(f)?;
                stmt.execute(params![
                    f.id.0.to_bytes(),
                    f.session_id.0.to_bytes(),
                    f.timing.started.0,
                    json
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Returns up to `limit` (at most [`MAX_PAGE`]) flows of `session` in `(start, id)` order,
    /// starting after the `after` cursor.
    ///
    /// # Errors
    /// SQLite errors, or [`StoreError::Codec`] / [`StoreError::Invalid`] for tampered rows.
    pub fn flows(
        &self,
        session: SessionId,
        after: Option<(Timestamp, FlowId)>,
        limit: usize,
    ) -> Result<Vec<Flow>, StoreError> {
        let cursor = after.map(|(t, id)| (t, id.0));
        self.page(FLOWS_PAGE, session, cursor, limit, Flow::validate)
    }

    /// Returns the flow with `id`, if stored.
    ///
    /// # Errors
    /// SQLite errors, or [`StoreError::Codec`] / [`StoreError::Invalid`] for tampered rows.
    pub fn flow(&self, id: FlowId) -> Result<Option<Flow>, StoreError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT data FROM flows WHERE id = ?1",
                [id.0.to_bytes()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(json) = json else { return Ok(None) };
        let flow: Flow = serde_json::from_str(&json)?;
        flow.validate()?;
        Ok(Some(flow))
    }

    /// Returns a setting's value (its owner validates the content).
    ///
    /// # Errors
    /// SQLite errors.
    pub fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Stores a setting.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for oversized values, or SQLite errors.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        if value.len() > MAX_SETTING {
            return Err(StoreError::Invalid(ModelError {
                field: "setting",
                reason: "too large",
            }));
        }
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Keyset-paginated read of JSON records, re-validated so tampered rows are rejected.
    fn page<T: DeserializeOwned>(
        &self,
        sql: &str,
        session: SessionId,
        after: Option<(Timestamp, Uuid)>,
        limit: usize,
        validate: fn(&T) -> Result<(), ModelError>,
    ) -> Result<Vec<T>, StoreError> {
        let (ts, id) = after.map_or((i64::MIN, [0; 16]), |(t, i)| (t.0, i.to_bytes()));
        let limit = i64::try_from(limit.min(MAX_PAGE)).unwrap_or(0);
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![session.0.to_bytes(), ts, id, limit], |r| {
            r.get::<_, String>(0)
        })?;
        rows.map(|row| {
            let value: T = serde_json::from_str(&row?)?;
            validate(&value)?;
            Ok(value)
        })
        .collect()
    }

    /// Stores payload bytes for `session`; `wire_size` is the length observed on the wire,
    /// which may exceed `data` when the capture truncated it.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] if `data` is longer than `wire_size`, or SQLite errors.
    pub fn insert_payload(
        &self,
        session: SessionId,
        data: &[u8],
        wire_size: u64,
        encryption: PayloadEncryption,
    ) -> Result<PayloadReference, StoreError> {
        let reference = PayloadReference {
            id: PayloadId::generate(),
            size: wire_size,
            stored: u64::try_from(data.len()).unwrap_or(u64::MAX),
            encryption,
        };
        reference.validate()?;
        self.conn.execute(
            "INSERT INTO payloads (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![reference.id.0.to_bytes(), session.0.to_bytes(), data],
        )?;
        Ok(reference)
    }

    /// Returns the bytes stored under `id`, if any.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn payload(&self, id: PayloadId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT data FROM payloads WHERE id = ?1",
                [id.0.to_bytes()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Verifies the structural integrity of the whole database file.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] describing the first problem found.
    pub fn check_integrity(&self) -> Result<(), StoreError> {
        let result: String = self
            .conn
            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(StoreError::Corrupt(result))
        }
    }

    /// Returns freed pages to the file system so deleted data leaves the file.
    fn reclaim(&self) -> Result<(), StoreError> {
        self.conn.execute_batch("PRAGMA incremental_vacuum")?;
        Ok(())
    }
}

fn session_row(r: &Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: SessionId(Uuid::from_bytes(r.get(0)?)),
        name: r.get(1)?,
        created: Timestamp(r.get(2)?),
    })
}

/// Applies pending migrations, each in its own transaction. Refuses databases with more
/// migrations than this build knows (downgrade protection).
fn migrate(conn: &mut Connection, migrations: &[&str]) -> Result<(), StoreError> {
    let applied: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let applied = usize::try_from(applied).unwrap_or(usize::MAX);
    if applied > migrations.len() {
        return Err(StoreError::NewerSchema);
    }
    for (version, sql) in migrations.iter().enumerate().skip(applied) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(
            None,
            "user_version",
            u32::try_from(version + 1).unwrap_or(u32::MAX),
        )?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
