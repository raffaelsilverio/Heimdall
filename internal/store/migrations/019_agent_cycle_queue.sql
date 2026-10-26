CREATE TABLE agent_cycle_jobs (
    task_id TEXT PRIMARY KEY REFERENCES agent_tasks(id) ON DELETE CASCADE,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL UNIQUE REFERENCES change_events(id) ON DELETE CASCADE,
    event_scope_hash TEXT NOT NULL,
    automation_revision INTEGER NOT NULL CHECK (automation_revision > 0),
    action_run_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'needs_review', 'cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_until INTEGER,
    error TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    finished_at INTEGER,
    UNIQUE (task_id, program_id)
);

CREATE INDEX agent_cycle_jobs_pending
    ON agent_cycle_jobs(status, lease_until, created_at);

CREATE INDEX agent_cycle_jobs_by_program
    ON agent_cycle_jobs(program_id, created_at DESC);

CREATE TABLE agent_cycle_daily_usage (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    utc_day TEXT NOT NULL,
    cycles_started INTEGER NOT NULL DEFAULT 0 CHECK (cycles_started >= 0),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (program_id, utc_day)
);

CREATE TRIGGER enqueue_consented_agent_cycle
AFTER INSERT ON agent_tasks
WHEN EXISTS (
    SELECT 1 FROM change_events e
    JOIN programs p ON p.id = e.program_id
    JOIN authorizations a ON a.program_id = p.id AND a.replaced_at IS NULL
    JOIN program_agent_automation aa ON aa.program_id = p.id
    WHERE e.id = NEW.event_id AND e.material = 1 AND p.status = 'active'
      AND e.scope_hash = p.scope_hash AND a.expires_at_ns > unixepoch() * 1000000000
      AND aa.enabled = 1 AND aa.allow_model_context_egress = 1 AND aa.allow_active_requests = 1
      AND aa.context_egress_expires_at > unixepoch()
      AND NOT EXISTS (SELECT 1 FROM program_source_snapshots ps WHERE ps.program_id = p.id AND ps.status = 'pending')
)
BEGIN
    INSERT INTO agent_cycle_jobs(task_id, program_id, event_id, event_scope_hash, automation_revision, status, created_at, updated_at)
    SELECT NEW.id, e.program_id, e.id, e.scope_hash, aa.revision, 'pending', unixepoch(), unixepoch()
    FROM change_events e JOIN program_agent_automation aa ON aa.program_id = e.program_id
    WHERE e.id = NEW.event_id AND e.material = 1;
END;
