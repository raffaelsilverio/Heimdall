CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('interactive', 'agent_event')),
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'closed', 'complete', 'failed')),
    scope_hash TEXT NOT NULL,
    trigger_event_id TEXT UNIQUE REFERENCES change_events(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    closed_at INTEGER,
    CHECK ((kind = 'interactive' AND trigger_event_id IS NULL) OR (kind = 'agent_event' AND trigger_event_id IS NOT NULL))
);

CREATE INDEX sessions_by_program ON sessions(program_id, updated_at DESC);

CREATE TABLE session_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
    content TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    provider TEXT,
    model TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE (session_id, sequence)
);

CREATE INDEX session_messages_by_session ON session_messages(session_id, sequence);

ALTER TABLE agent_tasks ADD COLUMN session_id TEXT REFERENCES sessions(id);
ALTER TABLE agent_tasks ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agent_tasks ADD COLUMN lease_until INTEGER;
ALTER TABLE agent_tasks ADD COLUMN result_json TEXT;

CREATE UNIQUE INDEX agent_task_session ON agent_tasks(session_id) WHERE session_id IS NOT NULL;
