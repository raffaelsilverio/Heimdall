ALTER TABLE program_agent_automation ADD COLUMN policy_revision INTEGER NOT NULL DEFAULT 0
    CHECK (policy_revision >= 0);

-- Automation consent must be reconfirmed against the current action policy.
UPDATE program_agent_automation SET enabled = 0, revision = revision + 1,
    reviewed_by = 'system-migration',
    review_reason = 'Re-consent required to bind automation consent to the current policy revision',
    updated_at = unixepoch()
WHERE enabled = 1;

UPDATE agent_cycle_jobs SET status = 'cancelled', lease_until = NULL,
    error = 'automation consent was reset to bind it to the current policy revision',
    finished_at = unixepoch(), updated_at = unixepoch()
WHERE status = 'pending';

UPDATE agent_cycle_jobs SET status = 'needs_review', lease_until = NULL,
    error = 'running cycle requires review after automation policy revision reset',
    finished_at = unixepoch(), updated_at = unixepoch()
WHERE status = 'running';
