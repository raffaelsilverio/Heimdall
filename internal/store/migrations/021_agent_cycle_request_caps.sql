ALTER TABLE program_agent_automation ADD COLUMN max_requests_per_day INTEGER NOT NULL DEFAULT 0
    CHECK (max_requests_per_day >= 0);
ALTER TABLE agent_cycle_daily_usage ADD COLUMN requests_reserved INTEGER NOT NULL DEFAULT 0
    CHECK (requests_reserved >= 0);
ALTER TABLE agent_cycle_jobs ADD COLUMN request_budget INTEGER NOT NULL DEFAULT 0
    CHECK (request_budget >= 0);

-- Earlier persistent consent did not contain a real daily request ceiling.
-- Disable it until the operator re-consents with an explicit cap.
UPDATE program_agent_automation SET enabled = 0, revision = revision + 1,
    reviewed_by = 'system-migration',
    review_reason = 'Re-consent required to set a daily native request cap',
    updated_at = unixepoch()
WHERE enabled = 1;

UPDATE agent_cycle_jobs SET status = 'cancelled', lease_until = NULL,
    error = 'automation consent was reset by a request-budget migration',
    finished_at = unixepoch(), updated_at = unixepoch()
WHERE status = 'pending';

UPDATE agent_cycle_jobs SET status = 'needs_review', lease_until = NULL,
    error = 'running cycle requires review after a request-budget migration',
    finished_at = unixepoch(), updated_at = unixepoch()
WHERE status = 'running';
