ALTER TABLE agent_action_reservations ADD COLUMN review_decision TEXT
    CHECK (review_decision IS NULL OR review_decision IN ('assessed_completed', 'assessed_not_executed'));
ALTER TABLE agent_action_reservations ADD COLUMN reviewed_by TEXT;
ALTER TABLE agent_action_reservations ADD COLUMN review_note TEXT;
ALTER TABLE agent_action_reservations ADD COLUMN reviewed_at INTEGER;

CREATE INDEX agent_action_reservations_needing_review
    ON agent_action_reservations(action_run_id, program_id, status, reviewed_at);
