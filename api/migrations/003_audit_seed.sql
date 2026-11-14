-- Seeded, explicitly labelled history lets the digest/demo path work before hardware arrives.
INSERT INTO audit (id, ts, actor, action, mac, command_id, outcome)
SELECT id, COALESCE(ack_ts, created_at), 'system-backfill', action, mac, id,
       CASE status WHEN 'pending' THEN 'requested' WHEN 'cancelled' THEN 'failed' ELSE status END
FROM commands
ON CONFLICT (id) DO NOTHING;

INSERT INTO audit (id, ts, actor, action, outcome) VALUES
    ('00000000-0000-4000-8000-000000000301', now() - interval '4 minutes', 'seeded-demo', 'notify', 'applied'),
    ('00000000-0000-4000-8000-000000000302', now() - interval '3 minutes', 'seeded-demo', 'block_wan', 'would_have'),
    ('00000000-0000-4000-8000-000000000303', now() - interval '2 minutes', 'seeded-demo', 'quarantine', 'would_have'),
    ('00000000-0000-4000-8000-000000000304', now() - interval '1 minute', 'seeded-demo', 'restore', 'applied')
ON CONFLICT (id) DO NOTHING;
