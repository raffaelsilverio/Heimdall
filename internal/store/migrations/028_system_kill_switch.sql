CREATE TABLE system_kill_switch (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    engaged INTEGER NOT NULL DEFAULT 0 CHECK (engaged IN (0, 1)),
    reason TEXT NOT NULL DEFAULT '',
    changed_by TEXT NOT NULL DEFAULT '',
    changed_at INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    CHECK (engaged = 0 OR (reason <> '' AND changed_by <> ''))
);

INSERT INTO system_kill_switch(id, engaged, reason, changed_by, changed_at, revision)
VALUES (1, 0, '', '', 0, 1);
