-- AEGIS AI Windows Security staging storage.
-- Apply ONLY to an explicitly provisioned, isolated staging PostgreSQL database.
-- Do not run against the existing production Supabase project.
BEGIN;
CREATE SCHEMA IF NOT EXISTS windows_pilot;
CREATE TABLE IF NOT EXISTS windows_pilot.security_events (
  device_id text NOT NULL CHECK (length(device_id) BETWEEN 1 AND 128),
  computer text NOT NULL,
  channel text NOT NULL CHECK (channel = 'Security'),
  record_id bigint NOT NULL CHECK (record_id > 0),
  event_id integer NOT NULL CHECK (event_id IN (4624,4625,4672,4688,4720,1102)),
  event_json jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, computer, channel, record_id)
);
CREATE INDEX IF NOT EXISTS security_events_received_at_idx
  ON windows_pilot.security_events (received_at DESC);
-- Deny default API roles; explicit, least-privilege service grants
-- must be configured during staging provisioning.
REVOKE ALL ON SCHEMA windows_pilot FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA windows_pilot FROM PUBLIC;
COMMIT;
