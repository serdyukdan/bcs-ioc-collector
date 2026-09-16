-- Frozen schema from the previously shipped version.

CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ok', 'error')),
    last_attempt TEXT NOT NULL,
    last_success TEXT,
    error TEXT,
    valid_count INTEGER NOT NULL DEFAULT 0,
    invalid_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('ipv4', 'ipv6', 'domain')),
    value TEXT NOT NULL,
    source_count INTEGER NOT NULL DEFAULT 1 CHECK (source_count >= 1),
    level TEXT GENERATED ALWAYS AS (
        CASE WHEN source_count >= 3 THEN 'Critical'
             WHEN source_count = 2 THEN 'High' ELSE 'Medium' END
    ) STORED,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(type, value)
);
CREATE TABLE IF NOT EXISTS observations (
    indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES sources(id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY(indicator_id, source_id)
);
CREATE INDEX IF NOT EXISTS observations_by_source ON observations(source_id, indicator_id);
CREATE INDEX IF NOT EXISTS indicators_by_level ON indicators(level, type, value);
