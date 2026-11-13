"""Opt-in read-only acceptance against a disposable local API and real database.

The positive alert must come from the real synthetic ingest/fusion path.
This suite never manufactures an alert or opens a hosted connection.
"""

import os
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

import pytest


@dataclass(repr=False)
class LocalContext:
    client: object
    token_a: str
    token_b: str
    alert: str

    def headers(self, tenant: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token_a if tenant == 'a' else self.token_b}"}


@pytest.fixture
def live():
    if os.environ.get("AISOC_LOCAL_STAGING_ACCEPTANCE") != "1":
        pytest.skip("Disposable local API, two tenant credentials and a persisted synthetic alert not configured")
    import httpx

    endpoint = os.environ["AISOC_LOCAL_STAGING_API"]
    parsed = urlsplit(endpoint)
    assert parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
    assert not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    assert parsed.path in {"", "/"}
    token_a = os.environ["AISOC_LOCAL_TENANT_A_TOKEN"]
    token_b = os.environ["AISOC_LOCAL_TENANT_B_TOKEN"]
    assert token_a and token_b and token_a != token_b
    alert = str(UUID(os.environ["AISOC_LOCAL_SYNTHETIC_ALERT_ID"]))
    with httpx.Client(base_url=endpoint, follow_redirects=False, trust_env=False, timeout=10) as client:
        yield LocalContext(client, token_a, token_b, alert)


def test_real_tenant_isolation(live):
    client, alert = live.client, live.alert
    for tenant in ("a", "b"):
        assert client.get("/api/v1/auth/me", headers=live.headers(tenant)).status_code == 200
    own = client.get(f"/api/v1/alerts/{alert}", headers=live.headers("a"))
    assert own.status_code == 200
    # Caller-supplied tenant hints cannot expand the authenticated principal.
    for suffix in ("", f"?tenant_id={own.json()['tenant_id']}"):
        assert client.get(f"/api/v1/alerts/{alert}{suffix}", headers=live.headers("b")).status_code == 404
    assert client.get(f"/api/v1/alerts/{alert}").status_code == 401
    assert client.get(f"/api/v1/alerts/{alert}", headers={"Authorization": "Bearer synthetic-invalid"}).status_code == 401


def test_real_health_and_upload_denial(live):
    client = live.client
    assert client.get("/livez").status_code == 200
    assert client.get("/readyz").status_code == 200
    assert client.post("/v1/ingest/batch", json={"synthetic": True}, headers=live.headers("a")).status_code == 403


def test_synthetic_rule_persistence_and_negative_control(live):
    """Read the consumer's persisted result; never create an alert to pass."""
    import asyncio

    import asyncpg

    dsn = os.environ["AISOC_LOCAL_SYNTHETIC_DATABASE_URL"]
    parsed = urlsplit(dsn)
    assert parsed.scheme in {"postgresql", "postgres"} and parsed.hostname == "127.0.0.1"
    assert parsed.path.startswith("/synthetic_") and not parsed.fragment
    positive = os.environ["AISOC_LOCAL_SYNTHETIC_POSITIVE_EXTERNAL_ID"]
    negative = os.environ["AISOC_LOCAL_SYNTHETIC_NEGATIVE_EXTERNAL_ID"]
    rule_id = os.environ["AISOC_LOCAL_SYNTHETIC_RULE_ID"]
    assert positive != negative and positive.startswith("windows-v2:") and negative.startswith("windows-v2:")

    async def check():
        try:
            connection = await asyncpg.connect(dsn, timeout=5)
        except Exception:
            pytest.fail("Disposable synthetic alert database unavailable", pytrace=False)
        try:
            async with connection.transaction(readonly=True):
                row = await connection.fetchrow("SELECT tenant_id, external_id, rule_id FROM alerts WHERE id=$1", UUID(live.alert))
                assert row is not None and row["rule_id"] == rule_id and row["external_id"] == positive
                assert (
                    await connection.fetchval(
                        "SELECT count(*) FROM alerts WHERE tenant_id=$1 AND external_id=$2", row["tenant_id"], positive
                    )
                    == 1
                )
                assert (
                    await connection.fetchval(
                        "SELECT count(*) FROM alerts WHERE tenant_id=$1 AND external_id=$2", row["tenant_id"], negative
                    )
                    == 0
                )
        finally:
            await connection.close()

    asyncio.run(check())
