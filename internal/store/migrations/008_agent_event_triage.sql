ALTER TABLE agent_tasks ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (triage_status IN ('pending', 'running', 'complete', 'failed'));
ALTER TABLE agent_tasks ADD COLUMN triage_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agent_tasks ADD COLUMN triage_lease_until INTEGER;
ALTER TABLE agent_tasks ADD COLUMN triaged_at INTEGER;
ALTER TABLE agent_tasks ADD COLUMN triage_error TEXT;

CREATE INDEX agent_tasks_for_triage
    ON agent_tasks(triage_status, triage_lease_until, created_at);
