"""Operator-only control surface for beginning and observing a drain."""

from __future__ import annotations

import asyncio
import hmac
import os

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response

from app.drain import drain_controller, run_drain_workers

router = APIRouter(tags=["operations"])
_DRAIN_TOKEN_ENV = "AISOC_DRAIN_TOKEN"


def _authorize(presented: str | None) -> None:
    expected = (os.getenv(_DRAIN_TOKEN_ENV) or "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="drain control is not configured")
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="invalid drain credential")


async def _begin(request: Request) -> None:
    await drain_controller.begin()
    lock = getattr(request.app.state, "drain_start_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        request.app.state.drain_start_lock = lock
    async with lock:
        if getattr(request.app.state, "drain_task", None) is None:
            request.app.state.drain_task = asyncio.create_task(run_drain_workers(request.app))


@router.post("/ops/drain")
async def begin_drain(
    request: Request,
    response: Response,
    wait_seconds: float = Query(default=0, ge=0, le=30),
    x_aisoc_drain_token: str | None = Header(default=None, alias="X-AiSOC-Drain-Token"),
) -> dict:
    """Close admission, stop owned background workers, and optionally wait."""
    _authorize(x_aisoc_drain_token)
    await _begin(request)
    if wait_seconds:
        await drain_controller.wait_drained(wait_seconds)
    snapshot = await drain_controller.snapshot()
    if not snapshot["drained"]:
        response.status_code = 202
        snapshot["wait_timed_out"] = bool(wait_seconds)
    return snapshot


@router.get("/ops/drain")
async def drain_status(
    x_aisoc_drain_token: str | None = Header(default=None, alias="X-AiSOC-Drain-Token"),
) -> dict:
    """Return aggregate work counts only; no tenant or run identifiers."""
    _authorize(x_aisoc_drain_token)
    return await drain_controller.snapshot()
