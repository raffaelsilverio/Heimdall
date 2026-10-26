ALTER TABLE agent_action_runs ADD COLUMN requests_consumed INTEGER NOT NULL DEFAULT 0
    CHECK (requests_consumed >= 0 AND requests_consumed <= max_requests);

ALTER TABLE agent_action_reservations ADD COLUMN requests_consumed INTEGER NOT NULL DEFAULT 0
    CHECK (requests_consumed >= 0 AND requests_consumed <= request_budget);
