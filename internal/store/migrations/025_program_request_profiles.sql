CREATE TABLE program_request_profiles (
    program_id TEXT PRIMARY KEY REFERENCES programs(id) ON DELETE CASCADE,
    user_agent TEXT NOT NULL DEFAULT '',
    headers_json TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at INTEGER NOT NULL
);

INSERT INTO program_request_profiles(program_id, revision, updated_at)
SELECT id, 1, updated_at FROM programs;

CREATE TRIGGER create_default_program_request_profile
AFTER INSERT ON programs
BEGIN
    INSERT INTO program_request_profiles(program_id, revision, updated_at)
    VALUES (NEW.id, 1, NEW.updated_at);
END;
