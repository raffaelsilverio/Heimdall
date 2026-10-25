CREATE TABLE programs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'paused')),
    scope_json TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    scope_revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE authorizations (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    reference TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    replaced_at INTEGER
);

CREATE UNIQUE INDEX one_current_authorization_per_program
    ON authorizations(program_id) WHERE replaced_at IS NULL;

CREATE TABLE stage_schedules (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    timezone TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    next_run_at INTEGER NOT NULL,
    last_scheduled_for INTEGER,
    last_run_at INTEGER,
    lease_until INTEGER,
    PRIMARY KEY (program_id, stage)
);

CREATE INDEX due_stage_schedules ON stage_schedules(enabled, next_run_at);

CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    authorization_id TEXT NOT NULL REFERENCES authorizations(id),
    stage TEXT NOT NULL,
    trigger TEXT NOT NULL CHECK (trigger IN ('schedule', 'manual', 'agent')),
    scheduled_for INTEGER,
    scope_hash TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    normalizer_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed', 'interrupted')),
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    error TEXT,
    UNIQUE (program_id, stage, trigger, scheduled_for)
);

CREATE INDEX runs_by_program ON runs(program_id, started_at DESC);

CREATE TABLE observations (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (run_id, category, stable_key)
);

CREATE TABLE baselines (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    normalizer_version TEXT NOT NULL,
    established_at INTEGER NOT NULL,
    last_complete_run_id TEXT NOT NULL REFERENCES runs(id),
    PRIMARY KEY (program_id, stage, scope_hash, profile_version, normalizer_version)
);

CREATE TABLE baseline_observations (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    normalizer_version TEXT NOT NULL,
    category TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    missing_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (program_id, stage, scope_hash, profile_version, normalizer_version, category, stable_key)
);

CREATE TABLE change_events (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    category TEXT NOT NULL,
    stable_key TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN ('added', 'changed', 'removed')),
    old_value TEXT,
    new_value TEXT,
    material INTEGER NOT NULL CHECK (material IN (0, 1)),
    created_at INTEGER NOT NULL,
    UNIQUE (run_id, category, stable_key, change_type)
);

CREATE TABLE agent_tasks (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE REFERENCES change_events(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'failed')),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT
);
