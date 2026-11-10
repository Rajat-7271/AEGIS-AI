-- Minimal Windows Security telemetry store for deployments without Kafka/ClickHouse.
-- Tenant-bound inbox tokens authenticate writes; the primary key makes retries idempotent.
CREATE TABLE IF NOT EXISTS windows_security_events (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    connector_id UUID NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    event_code INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    severity TEXT NOT NULL,
    provider TEXT NOT NULL,
    record_id BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS windows_security_events_recent_idx
    ON windows_security_events (tenant_id, event_time DESC);
ALTER TABLE windows_security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_security_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS windows_security_events_tenant ON windows_security_events;
CREATE POLICY windows_security_events_tenant ON windows_security_events
    USING ((tenant_id = current_tenant_id() OR current_tenant_id() IS NULL))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
