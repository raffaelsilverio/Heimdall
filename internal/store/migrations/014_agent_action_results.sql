ALTER TABLE agent_action_reservations ADD COLUMN result_json TEXT NOT NULL DEFAULT '{}'
    CHECK (length(result_json) <= 65536);
