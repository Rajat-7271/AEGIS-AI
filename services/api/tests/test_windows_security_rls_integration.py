"""Optional isolated PostgreSQL RLS integration test.

Run against a disposable LOCAL PostgreSQL database:
  DATABASE_MIGRATION_URL=postgresql://postgres:...@127.0.0.1:5432/aegis_rls_test \
    pytest -q tests/test_windows_security_rls_integration.py

Never point this test at Supabase, staging, or production. The privileged\nconnection is used only to create test objects; assertions run under SET ROLE\nwith an unprivileged NOLOGIN role. It creates only a
transaction-scoped test table and role, then rolls everything back.
"""
import os
import uuid
from urllib.parse import urlparse

import pytest


@pytest.mark.asyncio
async def test_windows_security_cross_tenant_rls_in_disposable_postgres():
    dsn = os.getenv("DATABASE_MIGRATION_URL")
    if not dsn:
        pytest.skip("Requires explicit DATABASE_MIGRATION_URL for disposable local Postgres")
    parsed = urlparse(dsn)
    if parsed.scheme not in {"postgresql", "postgres"} or parsed.hostname not in {
        "localhost", "127.0.0.1", "::1"
    }:
        pytest.fail("Refusing non-local PostgreSQL: use a disposable local database")
    if parsed.path.lstrip("/") != "aegis_rls_test":
        pytest.fail("Refusing database other than aegis_rls_test")

    import asyncpg

    connection = await asyncpg.connect(dsn)
    role = "aegis_rls_test_" + uuid.uuid4().hex[:12]
    table = "aegis_windows_test_" + uuid.uuid4().hex[:12]
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    transaction = connection.transaction()
    try:
        await transaction.start()
        await connection.execute(f'CREATE ROLE "{role}" NOLOGIN')
        await connection.execute(
            f'CREATE TABLE "{table}" (tenant_id uuid NOT NULL, event_code integer NOT NULL)'
        )
        await connection.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        await connection.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        await connection.execute(
            f"""CREATE POLICY tenant_scope ON "{table}" FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)"""
        )
        await connection.execute(f'GRANT SELECT ON "{table}" TO "{role}"')
        await connection.execute(
            f'INSERT INTO "{table}" (tenant_id, event_code) VALUES ($1, 4624), ($2, 4625)',
            tenant_a, tenant_b,
        )
        await connection.execute(f'SET LOCAL ROLE "{role}"')
        for tenant, expected in [(tenant_a, 4624), (tenant_b, 4625)]:
            await connection.execute(
                "SELECT set_config('app.current_tenant_id', $1, true)", str(tenant)
            )
            rows = await connection.fetch(f'SELECT event_code FROM "{table}"')
            assert [row["event_code"] for row in rows] == [expected]
        await connection.execute("SELECT set_config('app.current_tenant_id', '', true)")
        assert await connection.fetch(f'SELECT event_code FROM "{table}"') == []
    finally:
        try:
            await transaction.rollback()
        finally:
            await connection.close()
