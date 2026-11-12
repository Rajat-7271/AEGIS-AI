"""Focused tests for vault-backed connector credential replacement."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import connectors as endpoint
from app.api.v1.endpoints.connectors import UpdateConnectorRequest
from app.models.connector import Connector
from app.security.credential_vault import CredentialVault, CredentialVaultError
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import Select

TENANT = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()
CONNECTOR_ID = uuid.uuid4()
CATALOG = {
    "connector_id": "splunk",
    "fields": [
        {"name": "api_token", "type": "secret", "required": True},
        {"name": "secondary_token", "type": "secret", "required": False},
        {"name": "endpoint", "type": "string", "required": True},
    ],
}


def test_published_credential_patch_schema_is_object_or_null() -> None:
    from app.main import app
    from fastapi.testclient import TestClient

    response = TestClient(app).get("/api/openapi.json")
    assert response.status_code == 200
    schema = response.json()["components"]["schemas"]["UpdateConnectorRequest"]["properties"]["auth_config"]
    assert schema["anyOf"] == [{"type": "object", "additionalProperties": True}, {"type": "null"}]
    assert "type" not in schema


def _connector(vault: CredentialVault) -> Connector:
    return Connector(
        id=CONNECTOR_ID,
        tenant_id=TENANT,
        name="SIEM",
        connector_type="splunk",
        category="siem",
        is_enabled=True,
        auth_config=vault.encrypt_dict({"api_token": "old-token", "secondary_token": "old-secondary", "legacy": "keep-me"}),
    )


@pytest.mark.asyncio
async def test_partial_credential_update_merges_with_real_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    vault = CredentialVault(Fernet.generate_key())
    monkeypatch.setattr(endpoint, "get_vault", lambda: vault)
    monkeypatch.setattr(endpoint, "_validate_connector_type", AsyncMock(return_value=CATALOG))
    connector = _connector(vault)

    encrypted = await endpoint._merge_connector_credential_patch(
        connector=connector,
        tenant_id=TENANT,
        submitted={"api_token": "replacement-token"},
    )

    assert encrypted is not None
    assert vault.decrypt_dict(encrypted) == {
        "api_token": "replacement-token",
        "secondary_token": "old-secondary",
        "legacy": "keep-me",
    }


@pytest.mark.asyncio
async def test_blank_credentials_leave_existing_vault_values_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    vault = CredentialVault(Fernet.generate_key())
    monkeypatch.setattr(endpoint, "get_vault", lambda: vault)
    catalog_lookup = AsyncMock(return_value=CATALOG)
    monkeypatch.setattr(endpoint, "_validate_connector_type", catalog_lookup)
    connector = _connector(vault)
    before = connector.auth_config

    encrypted = await endpoint._merge_connector_credential_patch(
        connector=connector,
        tenant_id=TENANT,
        submitted={"api_token": "  "},
    )

    assert encrypted is None
    assert connector.auth_config == before
    catalog_lookup.assert_awaited_once_with("splunk", TENANT)


@pytest.mark.asyncio
async def test_non_secret_field_is_rejected_without_echoing_value(monkeypatch: pytest.MonkeyPatch) -> None:
    vault = CredentialVault(Fernet.generate_key())
    monkeypatch.setattr(endpoint, "get_vault", lambda: vault)
    monkeypatch.setattr(endpoint, "_validate_connector_type", AsyncMock(return_value=CATALOG))

    with pytest.raises(HTTPException) as exc:
        await endpoint._merge_connector_credential_patch(
            connector=_connector(vault),
            tenant_id=TENANT,
            submitted={"endpoint": "https://sensitive.example"},
        )

    assert exc.value.status_code == 422
    assert "sensitive.example" not in str(exc.value.detail)


@pytest.mark.asyncio
async def test_required_credentials_must_exist_after_replacement(monkeypatch: pytest.MonkeyPatch) -> None:
    vault = CredentialVault(Fernet.generate_key())
    monkeypatch.setattr(endpoint, "get_vault", lambda: vault)
    monkeypatch.setattr(endpoint, "_validate_connector_type", AsyncMock(return_value=CATALOG))
    connector = _connector(vault)
    connector.auth_config = vault.encrypt_dict({"legacy": "keep-me"})

    with pytest.raises(HTTPException) as exc:
        await endpoint._merge_connector_credential_patch(
            connector=connector,
            tenant_id=TENANT,
            submitted={"secondary_token": "optional-value"},
        )

    assert exc.value.status_code == 422
    assert "required" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_vault_failure_returns_generic_error_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "must-not-appear-in-error"

    class BrokenVault:
        def decrypt_dict(self, _value: dict[str, object]) -> dict[str, str]:
            raise CredentialVaultError(f"provider rejected token: {secret}")

    monkeypatch.setattr(endpoint, "get_vault", BrokenVault)
    monkeypatch.setattr(endpoint, "_validate_connector_type", AsyncMock(return_value=CATALOG))

    with pytest.raises(HTTPException) as exc:
        await endpoint._merge_connector_credential_patch(
            connector=_connector(CredentialVault(Fernet.generate_key())),
            tenant_id=TENANT,
            submitted={"api_token": secret},
        )

    assert exc.value.status_code == 500
    assert secret not in str(exc.value.detail)


@pytest.mark.asyncio
async def test_cross_tenant_connector_lookup_returns_not_found() -> None:
    class MissingResult:
        @staticmethod
        def scalar_one_or_none() -> None:
            return None

    class TenantScopedDB:
        def __init__(self) -> None:
            self.statement: Select[Any] | None = None

        async def execute(self, statement: Select[Any]) -> MissingResult:
            self.statement = statement
            return MissingResult()

    db = TenantScopedDB()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=OTHER_TENANT, role="admin", email="other@example.test")

    with pytest.raises(HTTPException) as exc:
        await endpoint.update_connector(
            CONNECTOR_ID,
            UpdateConnectorRequest(auth_config={"api_token": "x"}),
            user,
            db,  # type: ignore[arg-type]
        )

    assert exc.value.status_code == 404
    assert db.statement is not None
    where_clauses = db.statement.whereclause
    assert "tenant_id" in str(where_clauses)
