-- Wiretap storage schema, version 1.
-- STRICT enforces column types. Rows that can grow large (events, payloads) use rowid tables;
-- small fixed-size rows use WITHOUT ROWID. Child foreign keys are indexed so cascading
-- deletes stay proportional to the deleted data.

CREATE TABLE sessions (
    id      BLOB PRIMARY KEY CHECK (length(id) = 16),
    name    TEXT NOT NULL,
    created INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX sessions_by_created ON sessions (created);

CREATE TABLE events (
    id         BLOB NOT NULL UNIQUE CHECK (length(id) = 16),
    session_id BLOB NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    ts         INTEGER NOT NULL,
    data       TEXT NOT NULL
) STRICT;

CREATE INDEX events_by_session_time ON events (session_id, ts, id);

CREATE TABLE payloads (
    id         BLOB NOT NULL UNIQUE CHECK (length(id) = 16),
    session_id BLOB NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    data       BLOB NOT NULL
) STRICT;

CREATE INDEX payloads_by_session ON payloads (session_id);
