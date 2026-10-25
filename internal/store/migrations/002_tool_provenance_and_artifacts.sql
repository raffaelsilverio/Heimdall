ALTER TABLE authorizations ADD COLUMN expires_at_ns INTEGER;
UPDATE authorizations SET expires_at_ns = expires_at * 1000000000 WHERE expires_at_ns IS NULL;

CREATE TABLE tool_runs (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool_id TEXT NOT NULL,
    binary TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('complete', 'missing', 'failed', 'not_applicable')),
    error TEXT,
    PRIMARY KEY (run_id, tool_id)
);

CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
