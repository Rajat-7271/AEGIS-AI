from __future__ import annotations

import asyncio

import httpx
import pytest
from app.api.drain import router as drain_router
from app.drain import DrainController, DrainMiddleware, drain_controller
from app.workers.fused_alert_consumer import FusedAlertTriageWorker
from fastapi import BackgroundTasks, FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


@pytest.mark.asyncio
async def test_concurrent_admission_closes_atomically_and_releases_once() -> None:
    controller = DrainController()
    leases = await asyncio.gather(*(controller.enter("investigations") for _ in range(32)))
    assert all(leases)
    await controller.begin()
    await controller.set_worker("drain_supervisor", "stopped")
    assert await controller.enter("investigations") is None

    await asyncio.gather(*(lease.release() for lease in leases if lease is not None))
    await leases[0].release()  # idempotent; does not underflow
    snapshot = await controller.snapshot()
    assert snapshot["draining"] is True
    assert snapshot["active"] == {}
    assert snapshot["drained"] is True


@pytest.mark.asyncio
async def test_wait_timeout_fails_closed_until_active_work_finishes() -> None:
    controller = DrainController()
    lease = await controller.enter("http_requests")
    assert lease is not None
    await controller.begin()
    await controller.set_worker("drain_supervisor", "stopped")

    assert await controller.wait_drained(0.001) is False
    assert (await controller.snapshot())["drained"] is False
    await lease.release()
    assert await controller.wait_drained(0.05) is True


@pytest.mark.asyncio
async def test_cancelled_http_request_releases_its_lease() -> None:
    controller = DrainController()
    app = FastAPI()
    app.add_middleware(DrainMiddleware, controller=controller)
    entered = asyncio.Event()

    @app.get("/hang")
    async def hang() -> dict[str, bool]:
        entered.set()
        await asyncio.Event().wait()
        return {"ok": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://agents"
    ) as client:
        request = asyncio.create_task(client.get("/hang"))
        await entered.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

    assert (await controller.snapshot())["active"] == {}


@pytest.mark.asyncio
async def test_cancel_during_lease_release_still_decrements_counter() -> None:
    controller = DrainController()
    lease = await controller.enter("http_requests")
    assert lease is not None

    async with controller._changed:
        release_task = asyncio.create_task(lease.release())
        await asyncio.sleep(0)
        release_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await release_task
    assert (await controller.snapshot())["active"] == {}


@pytest.mark.asyncio
async def test_kafka_stop_waits_for_accepted_lanes_before_reporting_stopped() -> None:
    order: list[str] = []
    lane_started = asyncio.Event()
    finish_lane = asyncio.Event()

    class FakeConsumer:
        async def stop(self) -> None:
            order.append("consumer_stopped")

    class FakeProducer:
        async def stop(self) -> None:
            order.append("producer_stopped")

    class FakeLanes:
        async def drain(self) -> None:
            order.append("lanes_draining")
            lane_started.set()
            await finish_lane.wait()
            order.append("lanes_drained")

    worker = FusedAlertTriageWorker(bootstrap_servers="unused")
    worker._consumer = FakeConsumer()
    worker._producer = FakeProducer()
    worker._lanes = FakeLanes()
    worker._running = True
    worker._attached = True

    stopping = asyncio.create_task(worker.stop())
    await lane_started.wait()
    assert not stopping.done()
    assert order == ["consumer_stopped", "lanes_draining"]
    finish_lane.set()
    await stopping
    assert order == ["consumer_stopped", "lanes_draining", "lanes_drained", "producer_stopped"]
    assert worker.attached is False


@pytest.mark.asyncio
async def test_in_flight_background_investigation_finishes_and_new_one_is_rejected() -> None:
    controller = DrainController()
    app = FastAPI()
    app.add_middleware(DrainMiddleware, controller=controller)
    started = asyncio.Event()
    finish = asyncio.Event()

    async def fake_investigation() -> None:
        started.set()
        await finish.wait()

    @app.post("/api/v1/cases/case-1/investigate")
    async def launch(background_tasks: BackgroundTasks) -> dict[str, str]:
        background_tasks.add_task(fake_investigation)
        return {"status": "running"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://agents"
    ) as client:
        existing = asyncio.create_task(client.post("/api/v1/cases/case-1/investigate"))
        await started.wait()
        assert (await controller.snapshot())["active"] == {"active_investigations": 1}
        await controller.begin()
        rejected = await client.post("/api/v1/cases/case-1/investigate")
        assert rejected.status_code == 503
        finish.set()
        assert (await existing).status_code == 200

    assert (await controller.snapshot())["active"] == {}
    await controller.set_worker("drain_supervisor", "stopped")
    assert (await controller.snapshot())["drained"] is True


def test_http_lease_is_released_after_exception() -> None:
    controller = DrainController()
    app = FastAPI()
    app.add_middleware(DrainMiddleware, controller=controller)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("expected test failure")

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, raise_server_exceptions=False) as client:
        successful = client.get("/ok")
        assert successful.status_code == 200
        assert asyncio.run(controller.snapshot())["active"] == {}
        response = client.get("/boom")
    assert response.status_code == 500
    assert asyncio.run(controller.snapshot())["active"] == {}


def test_websocket_disconnect_releases_stream_lease() -> None:
    controller = DrainController()
    app = FastAPI()
    app.add_middleware(DrainMiddleware, controller=controller)

    @app.websocket("/stream")
    async def stream(ws: WebSocket) -> None:
        await ws.accept()
        try:
            await ws.receive_text()
        except WebSocketDisconnect:
            return

    with TestClient(app) as client:
        with client.websocket_connect("/stream"):
            pass

    assert asyncio.run(controller.snapshot())["active"] == {}


def test_websocket_is_refused_after_drain_starts() -> None:
    controller = DrainController()
    asyncio.run(controller.begin())
    app = FastAPI()
    app.add_middleware(DrainMiddleware, controller=controller)

    @app.websocket("/stream")
    async def stream(ws: WebSocket) -> None:
        await ws.accept()

    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as error:
            with client.websocket_connect("/stream"):
                pytest.fail("draining service accepted a new WebSocket")
    assert error.value.code == 1013


@pytest.mark.asyncio
async def test_drain_endpoint_auth_and_repeated_requests_are_idempotent(monkeypatch) -> None:
    await drain_controller.reset()
    monkeypatch.setenv("AISOC_DRAIN_TOKEN", "test-drain-secret")
    app = FastAPI()
    calls = 0

    async def stop_workers() -> None:
        nonlocal calls
        calls += 1
        await drain_controller.set_worker("fake_worker", "stopped")

    app.state.stop_drain_workers = stop_workers
    app.state.drain_task = None
    app.include_router(drain_router)
    headers = {"X-AiSOC-Drain-Token": "test-drain-secret"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://agents"
    ) as client:
        denied = await client.get("/ops/drain")
        assert denied.status_code == 401
        first = await client.post("/ops/drain?wait_seconds=1", headers=headers)
        second = await client.post("/ops/drain?wait_seconds=1", headers=headers)
        status = await client.get("/ops/drain", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert status.json() == {
        "draining": True,
        "drained": True,
        "active": {},
        "workers": {"drain_supervisor": "stopped", "fake_worker": "stopped"},
    }
    assert calls == 1


def test_real_investigation_http_route_is_rejected_after_drain() -> None:
    from app.main import app

    asyncio.run(drain_controller.reset())
    asyncio.run(drain_controller.begin())
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/api/v1/cases/case-1/investigate",
        json={"tenant_id": "not-reached", "alert_summary": "not-run"},
    )
    assert response.status_code == 503
    assert asyncio.run(drain_controller.snapshot())["active"] == {}


def test_real_investigation_websocket_is_rejected_after_drain() -> None:
    from app.main import app

    asyncio.run(drain_controller.reset())
    asyncio.run(drain_controller.begin())
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/api/v1/investigations/unknown/stream?case_id=case-1&alert_summary=explicit"
        ):
            pytest.fail("draining service accepted a new investigation stream")
    assert error.value.code == 1013


def test_readiness_reports_drain_as_degraded() -> None:
    from app.main import app

    asyncio.run(drain_controller.reset())
    app.state.mark_ready()
    asyncio.run(drain_controller.begin())
    response = TestClient(app).get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["detached"] == ["drain"]
    asyncio.run(drain_controller.reset())
