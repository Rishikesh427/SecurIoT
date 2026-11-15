ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware text;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS identification jsonb NOT NULL DEFAULT '{}'::jsonb;
