-- Retain historical events/audit, retire simulated inventory and its pending actions.
UPDATE commands SET status='cancelled', ack_ts=now(), detail='Retired simulated inventory'
WHERE status='pending' AND mac IN (SELECT mac FROM devices WHERE simulated=true);
UPDATE audit SET outcome='failed', ts=now()
WHERE outcome='requested' AND command_id IN
    (SELECT id FROM commands WHERE status='cancelled' AND detail='Retired simulated inventory');
DELETE FROM devices WHERE simulated=true;
