-- Wiretap storage schema, version 2: HTTP flows.
-- A flow is written when its request head is seen and updated when its response completes
-- it, so `data` always holds the latest state.

CREATE TABLE flows (
    id         BLOB PRIMARY KEY CHECK (length(id) = 16),
    session_id BLOB NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    started    INTEGER NOT NULL,
    data       TEXT NOT NULL
) STRICT;

CREATE INDEX flows_by_session_time ON flows (session_id, started, id);
