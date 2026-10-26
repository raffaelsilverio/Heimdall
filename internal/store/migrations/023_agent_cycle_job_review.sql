ALTER TABLE agent_cycle_jobs ADD COLUMN review_decision TEXT
    CHECK (review_decision IS NULL OR review_decision IN ('assessed_completed', 'assessed_failed', 'assessed_no_action'));
ALTER TABLE agent_cycle_jobs ADD COLUMN reviewed_by TEXT;
ALTER TABLE agent_cycle_jobs ADD COLUMN review_note TEXT;
ALTER TABLE agent_cycle_jobs ADD COLUMN reviewed_at INTEGER;
