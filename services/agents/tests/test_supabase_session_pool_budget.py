"""Regression coverage for the small Supabase session-pool budget.

These tests mock asyncpg pool construction: no production database or
network access is required.
"""
import asyncio
import uuid

import pytest

from app.api import conversation_store
from app.hunt import store as hunt_store
from app.investigator import ledger


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module,pool_function",
    [
        (conversation_store, "_pool"),
        (hunt_store, "_get_pool"),
        (ledger, "get_pool"),
    ],
)
async def test_agents_pool_stays_within_free_tier_budget(monkeypatch, module, pool_function):
    calls = []

    class FakePool:
        async def close(self):
            pass

    async def fake_create_pool(**kwargs):
        calls.append(kwargs)
        return FakePool()

    monkeypatch.setenv("DATABASE_URL", "postgresql://example:example@localhost:5432/test")
    monkeypatch.setattr(module, "_POOL", None)
    monkeypatch.setattr(module.asyncpg, "create_pool", fake_create_pool)

    pool = await getattr(module, pool_function)()
    assert pool is not None
    assert len(calls) == 1
    assert calls[0]["min_size"] == 0
    assert calls[0]["max_size"] == 1
    assert calls[0]["max_inactive_connection_lifetime"] == 30

    # Repeated calls must reuse the same pool instead of reserving more sessions.
    assert await getattr(module, pool_function)() is pool
    assert len(calls) == 1
    assert all(p is pool for p in await asyncio.gather(*(getattr(module, pool_function)() for _ in range(12))))
    monkeypatch.setattr(module, "_POOL", None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module,pool_function",
    [
        (conversation_store, "_pool"),
        (hunt_store, "_get_pool"),
        (ledger, "get_pool"),
    ],
)
async def test_concurrent_first_requests_create_only_one_pool(monkeypatch, module, pool_function):
    calls = 0

    class FakePool:
        async def close(self):
            pass

    async def fake_create_pool(**kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)  # Force a scheduling point during initialization.
        return FakePool()

    monkeypatch.setenv("DATABASE_URL", "postgresql://example:example@localhost:5432/test")
    monkeypatch.setattr(module, "_POOL", None)
    monkeypatch.setattr(module.asyncpg, "create_pool", fake_create_pool)
    pools = await asyncio.gather(*(getattr(module, pool_function)() for _ in range(12)))
    assert calls == 1
    assert pools[0] is not None
    assert all(pool is pools[0] for pool in pools)
    monkeypatch.setattr(module, "_POOL", None)
