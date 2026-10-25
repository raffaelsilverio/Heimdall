ALTER TABLE programs ADD COLUMN source_platform TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE programs ADD COLUMN source_url TEXT;
