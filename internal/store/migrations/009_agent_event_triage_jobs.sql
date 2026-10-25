CREATE TABLE agent_event_triage_jobs (
    task_id TEXT PRIMARY KEY REFERENCES agent_tasks(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until INTEGER,
    triaged_at INTEGER,
    error TEXT,
    result_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX agent_event_triage_jobs_due
    ON agent_event_triage_jobs(status, lease_until, created_at);

INSERT INTO agent_event_triage_jobs(
    task_id, status, attempts, lease_until, triaged_at, error, result_json, created_at, updated_at
)
SELECT id, triage_status, triage_attempts, triage_lease_until, triaged_at, triage_error, result_json,
    created_at, COALESCE(triaged_at, created_at)
FROM agent_tasks;
