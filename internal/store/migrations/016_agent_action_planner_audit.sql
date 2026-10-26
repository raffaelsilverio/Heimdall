ALTER TABLE agent_action_runs ADD COLUMN planner_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_action_runs ADD COLUMN planner_model TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_action_runs ADD COLUMN planner_calls INTEGER NOT NULL DEFAULT 0 CHECK (planner_calls >= 0);
ALTER TABLE agent_action_runs ADD COLUMN memory_items_sent INTEGER NOT NULL DEFAULT 0 CHECK (memory_items_sent >= 0);
