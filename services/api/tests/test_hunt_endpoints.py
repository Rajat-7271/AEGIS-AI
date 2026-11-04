"""Unit tests for Hunt search and saved-searches endpoints.

Verifies:
- GET /api/v1/hunt/saved returns empty list when tenant has no saved searches
- GET /api/v1/hunt/saved returns tenant-scoped saved searches
- POST /api/v1/hunt/saved persists saved search for authenticated tenant
- POST /api/v1/hunt/saved validates non-empty name and query
- DELETE /api/v1/hunt/saved/{id} deletes search belonging to tenant (204)
- DELETE /api/v1/hunt/saved/{id} returns 404 if not found or belongs to another tenant
- POST /api/v1/hunt/search returns valid HuntResponse with honest 'sample' source marker
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.hunt import (
    HuntQuery,
    SavedSearchCreate,
    delete_saved_search,
    hunt_search,
    list_saved_searches,
    save_search,
)
from app.models.saved_search import SavedSearch
from fastapi import HTTPException
from pydantic import ValidationError


def _build_user(
    *,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    role: str = "analyst",
) -> SimpleNamespace:
    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        role=role,
        email="analyst@example.com",
    )


@pytest.mark.asyncio
async def test_list_saved_searches_empty():
    user = _build_user()
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    db.execute.return_value = mock_result

    res = await list_saved_searches(user=user, db=db)
    assert res.searches == []
    assert db.execute.called


@pytest.mark.asyncio
async def test_list_saved_searches_populated():
    tenant_id = uuid.uuid4()
    user = _build_user(tenant_id=tenant_id)
    search_id = uuid.uuid4()
    now = datetime.now(UTC)

    mock_row = SavedSearch(
        id=search_id,
        tenant_id=tenant_id,
        user_id=user.user_id,
        name="Suspicious PowerShell",
        query="powershell -enc",
        backend="lucene",
        created_at=now,
        updated_at=now,
    )

    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_row]
    db.execute.return_value = mock_result

    res = await list_saved_searches(user=user, db=db)
    assert len(res.searches) == 1
    assert res.searches[0].id == str(search_id)
    assert res.searches[0].name == "Suspicious PowerShell"
    assert res.searches[0].query == "powershell -enc"
    assert res.searches[0].language == "lucene"
    assert not res.searches[0].pinned


@pytest.mark.asyncio
async def test_save_search_creates_row():
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    user = _build_user(tenant_id=tenant_id, user_id=user_id)

    db = AsyncMock()
    db.add = MagicMock()

    async def mock_refresh(instance):
        instance.id = uuid.uuid4()

    db.refresh.side_effect = mock_refresh

    payload = SavedSearchCreate(
        name="Failed Logins",
        query="event_type:SignInLog AND resultType:50126",
        language="lucene",
    )

    created = await save_search(data=payload, user=user, db=db)
    assert created.name == "Failed Logins"
    assert created.query == "event_type:SignInLog AND resultType:50126"
    assert created.language == "lucene"
    assert db.add.called
    assert db.commit.called


@pytest.mark.asyncio
async def test_save_search_validation_empty_fields():
    user = _build_user()
    db = AsyncMock()
    db.add = MagicMock()

    with pytest.raises((HTTPException, ValidationError)):
        data = SavedSearchCreate(name="   ", query="test")
        await save_search(data=data, user=user, db=db)

    with pytest.raises((HTTPException, ValidationError)):
        data = SavedSearchCreate(name="test", query="   ")
        await save_search(data=data, user=user, db=db)


@pytest.mark.asyncio
async def test_delete_saved_search_success():
    tenant_id = uuid.uuid4()
    user = _build_user(tenant_id=tenant_id)
    search_id = uuid.uuid4()

    mock_row = SavedSearch(
        id=search_id,
        tenant_id=tenant_id,
        user_id=user.user_id,
        name="To Delete",
        query="powershell",
    )

    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_row
    db.execute.return_value = mock_result

    await delete_saved_search(search_id=str(search_id), user=user, db=db)
    db.delete.assert_called_once_with(mock_row)
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_delete_saved_search_not_found_or_cross_tenant():
    user = _build_user()
    search_id = uuid.uuid4()

    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await delete_saved_search(search_id=str(search_id), user=user, db=db)
    assert exc_info.value.status_code == 404
    assert not db.delete.called


@pytest.mark.asyncio
async def test_delete_saved_search_invalid_uuid():
    user = _build_user()
    db = AsyncMock()

    with pytest.raises(HTTPException) as exc_info:
        await delete_saved_search(search_id="not-a-valid-uuid", user=user, db=db)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_hunt_search_fallback():
    user = _build_user()
    query = HuntQuery(query="powershell.exe", limit=10)

    res = await hunt_search(query=query, user=user)
    assert res.query == "powershell.exe"
    assert res.source == "sample"
    assert res.notice is not None
    assert "illustrative sample events" in res.notice
    assert len(res.hits) > 0
    assert res.hits[0].fields["process.name"] == "powershell.exe"
