-- Wiretap storage schema, version 3: application settings (e.g. automatic-response rules).
-- Values are JSON documents validated by their owners when read.

CREATE TABLE settings (
    key   TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 128),
    value TEXT NOT NULL
) STRICT, WITHOUT ROWID;
