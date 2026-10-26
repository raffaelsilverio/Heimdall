ALTER TABLE agent_action_runs ADD COLUMN automation_revision INTEGER NOT NULL DEFAULT 0
    CHECK (automation_revision >= 0);
