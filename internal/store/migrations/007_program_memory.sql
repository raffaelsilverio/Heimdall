CREATE TABLE program_memories (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN (
        'fact', 'hypothesis', 'negative_result', 'decision',
        'finding_candidate', 'finding_verified', 'procedure', 'handoff'
    )),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN (
        'operator', 'run', 'event', 'session', 'source_snapshot', 'artifact'
    )),
    source_id TEXT,
    scope_hash TEXT,
    source_hash TEXT,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'archived')),
    observed_at INTEGER NOT NULL,
    verified_at INTEGER,
    expires_at INTEGER,
    supersedes_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (id, program_id),
    FOREIGN KEY (supersedes_id, program_id) REFERENCES program_memories(id, program_id)
);

CREATE INDEX program_memories_by_program
    ON program_memories(program_id, status, observed_at DESC);

CREATE INDEX program_memories_by_source
    ON program_memories(program_id, source_kind, source_id);

CREATE VIRTUAL TABLE program_memory_fts USING fts5(
    memory_id UNINDEXED,
    program_id UNINDEXED,
    title,
    content,
    tokenize = 'unicode61'
);

CREATE TRIGGER program_memory_fts_insert AFTER INSERT ON program_memories BEGIN
    INSERT INTO program_memory_fts(rowid, memory_id, program_id, title, content)
    VALUES (new.rowid, new.id, new.program_id, new.title, new.content);
END;

CREATE TRIGGER program_memory_fts_update AFTER UPDATE OF program_id, title, content ON program_memories BEGIN
    DELETE FROM program_memory_fts WHERE rowid = old.rowid;
    INSERT INTO program_memory_fts(rowid, memory_id, program_id, title, content)
    VALUES (new.rowid, new.id, new.program_id, new.title, new.content);
END;

CREATE TRIGGER program_memory_fts_delete AFTER DELETE ON program_memories BEGIN
    DELETE FROM program_memory_fts WHERE rowid = old.rowid;
END;
