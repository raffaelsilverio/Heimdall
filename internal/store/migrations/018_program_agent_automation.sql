CREATE TABLE program_agent_automation (
    program_id TEXT PRIMARY KEY REFERENCES programs(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    planner_provider TEXT NOT NULL DEFAULT '',
    planner_model TEXT NOT NULL DEFAULT '',
    context_egress_expires_at INTEGER,
    allow_model_context_egress INTEGER NOT NULL DEFAULT 0 CHECK (allow_model_context_egress IN (0, 1)),
    allow_active_requests INTEGER NOT NULL DEFAULT 0 CHECK (allow_active_requests IN (0, 1)),
    include_memory INTEGER NOT NULL DEFAULT 0 CHECK (include_memory IN (0, 1)),
    max_cycles_per_day INTEGER NOT NULL DEFAULT 0 CHECK (max_cycles_per_day >= 0),
    max_steps_per_cycle INTEGER NOT NULL DEFAULT 0 CHECK (max_steps_per_cycle >= 0),
    reviewed_by TEXT NOT NULL DEFAULT '',
    review_reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (enabled = 0 OR (
        planner_provider <> '' AND planner_model <> '' AND context_egress_expires_at IS NOT NULL AND
        allow_model_context_egress = 1 AND allow_active_requests = 1 AND
        max_cycles_per_day BETWEEN 1 AND 50 AND max_steps_per_cycle BETWEEN 1 AND 20 AND
        reviewed_by <> '' AND review_reason <> ''
    ))
);

INSERT INTO program_agent_automation(program_id, revision, enabled, created_at, updated_at)
SELECT id, 1, 0, updated_at, updated_at FROM programs;

CREATE TRIGGER create_default_program_agent_automation
AFTER INSERT ON programs
BEGIN
    INSERT INTO program_agent_automation(program_id, revision, enabled, created_at, updated_at)
    VALUES (NEW.id, 1, 0, NEW.updated_at, NEW.updated_at);
END;
