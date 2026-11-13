"""Exercise the storage adapter against the installed SDK and a local database."""

from unittest.mock import AsyncMock

import pytest
from app.storage.qdrant import IOC_COLLECTION, QdrantStore
from qdrant_client import AsyncQdrantClient


@pytest.mark.asyncio
async def test_semantic_search_with_real_local_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = AsyncQdrantClient(":memory:")
    store = QdrantStore(client)
    # Only inference is substituted: the real SDK stores and filters vectors.
    vector = [1.0] + [0.0] * 1535
    monkeypatch.setattr(store, "_embed", AsyncMock(side_effect=lambda texts: [vector for _ in texts]))
    try:
        await store.initialize()
        await store.upsert_iocs([{"type": "domain", "value": "fixture.example"}], tenant_id="tenant-a")
        results = await store.semantic_search("fixture", collection=IOC_COLLECTION, tenant_id="tenant-a")
        assert [item["value"] for item in results] == ["fixture.example"]
        assert await store.semantic_search("fixture", tenant_id="tenant-b") == []
    finally:
        await client.close()
