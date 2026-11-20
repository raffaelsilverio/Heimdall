CREATE TABLE program_data_access (
    program_id TEXT PRIMARY KEY REFERENCES programs(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'test_accounts_only' CHECK (mode = 'test_accounts_only'),
    allow_owned_test_accounts INTEGER NOT NULL DEFAULT 1 CHECK (allow_owned_test_accounts IN (0, 1)),
    allow_explicitly_authorized_accounts INTEGER NOT NULL DEFAULT 1 CHECK (allow_explicitly_authorized_accounts IN (0, 1)),
    allow_other_users_data INTEGER NOT NULL DEFAULT 0 CHECK (allow_other_users_data = 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at INTEGER NOT NULL
);

INSERT INTO program_data_access(program_id, revision, updated_at)
SELECT id, 1, updated_at FROM programs;

CREATE TRIGGER create_default_program_data_access
AFTER INSERT ON programs
BEGIN
    INSERT INTO program_data_access(program_id, revision, updated_at)
    VALUES (NEW.id, 1, NEW.updated_at);
END;

CREATE TABLE program_test_accounts (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    identity TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'administrator', 'other')),
    status TEXT NOT NULL CHECK (status IN ('authorized', 'revoked')),
    source TEXT NOT NULL CHECK (source IN ('owned', 'explicitly_authorized')),
    credential_ref TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (program_id, account_id)
);

CREATE INDEX program_test_accounts_status
ON program_test_accounts(program_id, status);
