CREATE TABLE agent_action_runs (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    authorization_id TEXT NOT NULL REFERENCES authorizations(id),
    scope_hash TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    max_actions INTEGER NOT NULL CHECK (max_actions > 0),
    max_requests INTEGER NOT NULL CHECK (max_requests > 0),
    max_requests_per_action INTEGER NOT NULL CHECK (max_requests_per_action > 0),
    max_targets_per_action INTEGER NOT NULL CHECK (max_targets_per_action > 0),
    actions_reserved INTEGER NOT NULL DEFAULT 0 CHECK (actions_reserved >= 0 AND actions_reserved <= max_actions),
    requests_reserved INTEGER NOT NULL DEFAULT 0 CHECK (requests_reserved >= 0 AND requests_reserved <= max_requests),
    status TEXT NOT NULL CHECK (status IN ('active', 'completed', 'failed', 'cancelled', 'needs_review')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    closed_at INTEGER,
    UNIQUE (id, program_id)
);

CREATE INDEX agent_action_runs_by_program
    ON agent_action_runs(program_id, created_at DESC);

CREATE TABLE agent_action_reservations (
    id TEXT PRIMARY KEY,
    action_run_id TEXT NOT NULL,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    stage TEXT NOT NULL,
    action_class TEXT NOT NULL CHECK (action_class IN ('passive', 'safe_active', 'sensitive')),
    proposal_json TEXT NOT NULL,
    proposal_sha256 TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    request_budget INTEGER NOT NULL CHECK (request_budget > 0),
    target_count INTEGER NOT NULL CHECK (target_count > 0),
    rate_limit_per_second INTEGER NOT NULL CHECK (rate_limit_per_second > 0),
    max_concurrency INTEGER NOT NULL CHECK (max_concurrency > 0),
    max_targets INTEGER NOT NULL CHECK (max_targets > 0),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds > 0),
    grant_valid_until INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'running', 'completed', 'failed', 'uncertain', 'cancelled')),
    lease_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    FOREIGN KEY (action_run_id, program_id) REFERENCES agent_action_runs(id, program_id) ON DELETE CASCADE,
    UNIQUE (action_run_id, sequence)
);

CREATE INDEX agent_action_reservations_by_run
    ON agent_action_reservations(action_run_id, sequence);

CREATE INDEX agent_action_reservations_for_recovery
    ON agent_action_reservations(status, lease_until);
