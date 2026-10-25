CREATE TABLE program_source_snapshots (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    source_hash TEXT NOT NULL,
    candidate_scope_hash TEXT,
    source_json TEXT NOT NULL,
    candidate_scope_json TEXT,
    applied_scope_hash TEXT,
    applied_scope_json TEXT,
    warnings_json TEXT NOT NULL,
    blockers_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'unchanged', 'superseded')),
    scope_applied INTEGER NOT NULL DEFAULT 0 CHECK (scope_applied IN (0, 1)),
    fetched_at INTEGER NOT NULL,
    reviewed_at INTEGER
);

CREATE INDEX program_source_snapshots_by_program
    ON program_source_snapshots(program_id, fetched_at DESC);

CREATE INDEX pending_program_source_snapshots
    ON program_source_snapshots(program_id, status, fetched_at DESC);
