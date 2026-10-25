CREATE TABLE program_agent_policies (
    program_id TEXT PRIMARY KEY REFERENCES programs(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    allowed_stages_json TEXT NOT NULL DEFAULT '[]',
    allowed_classes_json TEXT NOT NULL DEFAULT '[]',
    max_actions_per_run INTEGER NOT NULL DEFAULT 0 CHECK (max_actions_per_run >= 0),
    max_requests_per_run INTEGER NOT NULL DEFAULT 0 CHECK (max_requests_per_run >= 0),
    max_requests_per_action INTEGER NOT NULL DEFAULT 0 CHECK (max_requests_per_action >= 0),
    max_targets_per_action INTEGER NOT NULL DEFAULT 0 CHECK (max_targets_per_action >= 0),
    updated_at INTEGER NOT NULL
);

INSERT INTO program_agent_policies(program_id, revision, updated_at)
SELECT id, 1, updated_at FROM programs;

CREATE TRIGGER create_default_program_agent_policy
AFTER INSERT ON programs
BEGIN
    INSERT INTO program_agent_policies(program_id, revision, updated_at)
    VALUES (NEW.id, 1, NEW.updated_at);
END;
