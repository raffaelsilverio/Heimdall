ALTER TABLE agent_action_runs ADD COLUMN memory_ids_sent_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(memory_ids_sent_json));
