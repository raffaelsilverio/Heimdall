ALTER TABLE program_agent_policies
ADD COLUMN approval_required_classes_json TEXT NOT NULL DEFAULT '[]';

CREATE TABLE agent_action_approvals (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scope_hash TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    stage TEXT NOT NULL,
    tool TEXT NOT NULL,
    action_class TEXT NOT NULL CHECK (action_class IN ('passive', 'safe_active', 'sensitive')),
    impact TEXT NOT NULL CHECK (impact IN ('passive', 'low', 'active', 'high')),
    targets_json TEXT NOT NULL,
    target_count INTEGER NOT NULL CHECK (target_count > 0),
    request_budget INTEGER NOT NULL CHECK (request_budget > 0),
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    requested_by TEXT NOT NULL,
    reviewed_by TEXT NOT NULL DEFAULT '',
    review_note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    decided_at INTEGER,
    consumed_at INTEGER,
    updated_at INTEGER NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (status NOT IN ('approved', 'denied') OR (reviewed_by <> '' AND decided_at IS NOT NULL)),
    CHECK (status <> 'consumed' OR consumed_at IS NOT NULL)
);

CREATE INDEX agent_action_approvals_lookup
ON agent_action_approvals(program_id, fingerprint, status, expires_at);

CREATE INDEX agent_action_approvals_program_status
ON agent_action_approvals(program_id, status, created_at);
