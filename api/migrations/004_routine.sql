-- Separate telemetry freshness from actual last packet time.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snapshot_at timestamptz;
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_kind_check;
ALTER TABLE events ADD CONSTRAINT events_kind_check
CHECK (kind IN ('scan_arp','scan_targets','decoy_touch','new_domain','new_device','volume'));
