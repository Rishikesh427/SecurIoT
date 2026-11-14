ALTER TABLE commands DROP CONSTRAINT commands_status_check;
ALTER TABLE commands ADD CONSTRAINT commands_status_check
    CHECK (status IN ('pending', 'applied', 'failed', 'cancelled'));
