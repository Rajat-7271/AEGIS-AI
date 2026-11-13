-- Separate v2 staging table. Never run on production.
-- A verified source_epoch is required to disambiguate reused EventRecordID.
BEGIN;
CREATE SCHEMA IF NOT EXISTS windows_pilot;
-- Membership is granted separately to the dedicated staging database login.
-- No browser/authenticated/anon role receives this capability.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='windows_security_receiver') THEN
        CREATE ROLE windows_security_receiver NOLOGIN NOSUPERUSER NOBYPASSRLS;
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='windows_security_receiver'
                 AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION 'Existing receiver capability role has unsafe attributes';
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS windows_pilot.security_events_v2 (
    device_id text NOT NULL CHECK (length(device_id) BETWEEN 1 AND 128),
    channel text NOT NULL CHECK (channel = 'Security'),
    source_epoch char(32) NOT NULL CHECK (source_epoch ~ '^[a-f0-9]{32}$'),
    computer text NOT NULL,
    record_id bigint NOT NULL CHECK (record_id > 0),
    event_id integer NOT NULL CHECK (event_id IN (4624,4625,4672,4688,4720,1102)),
    event_json jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, channel, source_epoch, computer, record_id)
);
CREATE INDEX IF NOT EXISTS security_events_v2_received_at_idx
    ON windows_pilot.security_events_v2 (received_at DESC);
ALTER TABLE windows_pilot.security_events_v2 ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS receiver_select ON windows_pilot.security_events_v2;
CREATE POLICY receiver_select ON windows_pilot.security_events_v2 FOR SELECT
    TO windows_security_receiver
    USING (device_id = current_setting('app.windows_device_id', true));
DROP POLICY IF EXISTS receiver_insert ON windows_pilot.security_events_v2;
CREATE POLICY receiver_insert ON windows_pilot.security_events_v2 FOR INSERT
    TO windows_security_receiver
    WITH CHECK (device_id = current_setting('app.windows_device_id', true));
GRANT USAGE ON SCHEMA windows_pilot TO windows_security_receiver;
GRANT SELECT, INSERT ON windows_pilot.security_events_v2 TO windows_security_receiver;
REVOKE ALL ON SCHEMA windows_pilot FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA windows_pilot FROM PUBLIC;
COMMIT;
