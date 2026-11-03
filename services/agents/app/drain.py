"""Process-local admission control and work accounting for safe shutdown."""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send


class DrainController:
    """Async-safe gate and counters shared by request middleware and workers."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._changed = asyncio.Condition(self._lock)
        self._draining = False
        self._active: Counter[str] = Counter()
        self._workers: dict[str, str] = {}

    async def reset(self) -> None:
        """Reset process-local state at app startup; never discard live leases."""
        async with self._changed:
            if self._active:
                raise RuntimeError("cannot reset drain state while work is active")
            self._draining = False
            self._workers.clear()
            self._changed.notify_all()
            # A test client or a replacement app may serve this singleton on a
            # new event loop after the previous loop has closed.
            self._lock = asyncio.Lock()
            self._changed = asyncio.Condition(self._lock)

    @property
    def draining(self) -> bool:
        return self._draining

    async def begin(self) -> None:
        async with self._changed:
            self._draining = True
            self._changed.notify_all()

    async def enter(self, kind: str) -> WorkLease | None:
        async with self._changed:
            if self._draining:
                return None
            self._active[kind] += 1
            self._changed.notify_all()
            return WorkLease(self, kind)

    async def _release(self, kind: str) -> None:
        async with self._changed:
            if self._active[kind] <= 0:
                raise RuntimeError(f"drain work counter underflow: {kind}")
            self._active[kind] -= 1
            if not self._active[kind]:
                del self._active[kind]
            self._changed.notify_all()

    async def set_worker(self, name: str, status: str) -> None:
        if status not in {"running", "stopping", "stopped", "failed"}:
            raise ValueError(f"invalid drain worker state: {status}")
        async with self._changed:
            self._workers[name] = status
            self._changed.notify_all()

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            drained = self._is_drained()
            return {
                "draining": self._draining,
                "drained": drained,
                "active": dict(sorted(self._active.items())),
                "workers": dict(sorted(self._workers.items())),
            }

    def _is_drained(self) -> bool:
        return (
            self._draining
            and not self._active
            and self._workers.get("drain_supervisor") == "stopped"
            and all(status == "stopped" for status in self._workers.values())
        )

    async def wait_drained(self, timeout: float) -> bool:
        async with self._changed:
            try:
                async with asyncio.timeout(timeout):
                    await self._changed.wait_for(self._is_drained)
                return True
            except TimeoutError:
                return self._is_drained()


class WorkLease:
    """Idempotent finally-safe accounting token."""

    def __init__(self, controller: DrainController, kind: str) -> None:
        self._controller = controller
        self._kind = kind
        self._released = False
        self._release_lock = asyncio.Lock()

    async def release(self) -> None:
        async with self._release_lock:
            if self._released:
                return
            release_task = asyncio.create_task(self._controller._release(self._kind))
            try:
                await asyncio.shield(release_task)
            except asyncio.CancelledError:
                await asyncio.shield(release_task)
                self._released = True
                raise
            self._released = True


class DrainMiddleware:
    """Count full ASGI request lifetimes and refuse new work after draining.

    Starlette background tasks finish before the ASGI request scope returns,
    so this also counts route-owned BackgroundTasks and streaming responses.
    Operational probes and the drain status/control routes remain reachable.
    """

    _ALLOWED_DURING_DRAIN = {"/livez", "/readyz", "/health", "/metrics", "/ops/drain"}

    @staticmethod
    def _http_kind(path: str) -> str:
        if path == "/api/v1/agent-runs" or path.endswith("/investigate") or path.endswith("/triage"):
            return "active_investigations"
        return "http_requests"

    def __init__(self, app: ASGIApp, controller: DrainController) -> None:
        self.app = app
        self.controller = controller

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope["type"]
        path = scope.get("path", "")
        if scope_type == "lifespan" or (
            scope_type == "http" and path in self._ALLOWED_DURING_DRAIN
        ):
            await self.app(scope, receive, send)
            return

        kind = "websocket_streams" if scope_type == "websocket" else self._http_kind(path)
        lease = await self.controller.enter(kind)
        if lease is None:
            if scope_type == "websocket":
                await send({"type": "websocket.close", "code": 1013, "reason": "service is draining"})
            elif scope_type == "http":
                body = json.dumps({"detail": "Agents service is draining"}).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 503,
                        "headers": [(b"content-type", b"application/json"), (b"retry-after", b"30")],
                    }
                )
                await send({"type": "http.response.body", "body": body})
            return

        try:
            await self.app(scope, receive, send)
        finally:
            await lease.release()


drain_controller = DrainController()


async def run_drain_workers(app: Any) -> None:
    """Run the app's worker-stop callback and record fail-closed status."""
    await drain_controller.set_worker("drain_supervisor", "running")
    try:
        stop_workers = getattr(app.state, "stop_drain_workers", None)
        if stop_workers is None:
            raise RuntimeError("background worker drain is not configured")
        await stop_workers()
    except Exception:
        await drain_controller.set_worker("drain_supervisor", "failed")
        return
    else:
        await drain_controller.set_worker("drain_supervisor", "stopped")
