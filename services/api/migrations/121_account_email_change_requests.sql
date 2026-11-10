-- Pending login-email verification requests. No login identity changes in this migration.
-- Tokens are random high-entropy values; store SHA-256 digests only.
CREATE TABLE IF NOT EXISTS account_email_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    previous_email VARCHAR(255) NOT NULL,
    proposed_email VARCHAR(255) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    CONSTRAINT email_change_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT email_change_terminal_exclusive CHECK (consumed_at IS NULL OR cancelled_at IS NULL)
);
CREATE INDEX IF NOT EXISTS ix_email_change_user_pending
    ON account_email_change_requests (tenant_id, user_id, expires_at)
    WHERE consumed_at IS NULL AND cancelled_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_email_change_one_pending_per_user
    ON account_email_change_requests (user_id)
    WHERE consumed_at IS NULL AND cancelled_at IS NULL;
ALTER TABLE account_email_change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_email_change_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS account_email_change_tenant ON account_email_change_requests;
CREATE POLICY account_email_change_tenant ON account_email_change_requests
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());
