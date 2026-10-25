ALTER TABLE stage_schedules ADD COLUMN rate_limit_per_second INTEGER NOT NULL DEFAULT 2;
ALTER TABLE stage_schedules ADD COLUMN max_concurrency INTEGER NOT NULL DEFAULT 2;
ALTER TABLE stage_schedules ADD COLUMN max_targets INTEGER NOT NULL DEFAULT 5000;
ALTER TABLE stage_schedules ADD COLUMN timeout_seconds INTEGER NOT NULL DEFAULT 1200;
