CREATE EXTENSION IF NOT EXISTS timescaledb WITH SCHEMA public;

CREATE TABLE devices (
    mac macaddr PRIMARY KEY,
    ip inet NOT NULL,
    name text NOT NULL,
    label text NOT NULL,
    type text NOT NULL,
    vendor text,
    model text,
    kev text CHECK (kev IN ('confirmed', 'possible', 'none', 'unknown')),
    ports jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(ports) = 'array'),
    bytes_in bigint NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out bigint NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    dests jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(dests) = 'array'),
    last_seen timestamptz NOT NULL,
    simulated boolean NOT NULL DEFAULT false,
    has_feed boolean NOT NULL DEFAULT false,
    eol boolean,
    default_creds boolean,
    cloud_only boolean,
    anomaly double precision NOT NULL DEFAULT 0 CHECK (anomaly BETWEEN 0 AND 40),
    risk integer NOT NULL DEFAULT 0 CHECK (risk BETWEEN 0 AND 100),
    band text NOT NULL CHECK (band IN ('low', 'medium', 'high')),
    confidence text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    reasons jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(reasons) = 'array'),
    status text NOT NULL DEFAULT 'normal' CHECK (status IN ('normal', 'wan_blocked', 'quarantined', 'offline'))
);

CREATE TABLE events (
    id uuid NOT NULL,
    mac macaddr NOT NULL,
    ts timestamptz NOT NULL,
    kind text NOT NULL CHECK (kind IN ('scan_arp', 'scan_targets', 'decoy_touch', 'new_domain', 'new_device')),
    evidence jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object'),
    actions_taken jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(actions_taken) = 'array'),
    would_have jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(would_have) = 'array'),
    source text NOT NULL CHECK (source IN ('agent', 'simulator')),
    PRIMARY KEY (id, ts)
);
SELECT create_hypertable('securiot.events', by_range('ts'), if_not_exists => TRUE);
CREATE INDEX events_mac_ts_idx ON events (mac, ts DESC);

CREATE TABLE commands (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    action text NOT NULL CHECK (action IN ('block_wan', 'quarantine', 'restore', 'restore_all')),
    mac macaddr,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'failed')),
    ack_ts timestamptz,
    detail text,
    CHECK ((action = 'restore_all' AND mac IS NULL) OR (action <> 'restore_all' AND mac IS NOT NULL)),
    CHECK ((status = 'pending' AND ack_ts IS NULL) OR (status <> 'pending' AND ack_ts IS NOT NULL))
);
CREATE INDEX commands_pending_idx ON commands (created_at) WHERE status = 'pending';

CREATE TABLE policy (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    learning_mode boolean NOT NULL DEFAULT true,
    protected_macs jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(protected_macs) = 'array'),
    ladder jsonb NOT NULL DEFAULT '{"notify":true,"block_wan":true,"quarantine":true}' CHECK (jsonb_typeof(ladder) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO policy (id) VALUES (true);

CREATE TABLE audit (
    id uuid PRIMARY KEY,
    ts timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    mac macaddr,
    command_id uuid REFERENCES commands(id),
    outcome text NOT NULL CHECK (outcome IN ('requested', 'applied', 'failed', 'would_have'))
);
CREATE INDEX audit_ts_idx ON audit (ts DESC);

-- Supporting auth table, deliberately not a hypertable.
CREATE TABLE users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'judge' CHECK (role IN ('judge', 'admin')),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);
