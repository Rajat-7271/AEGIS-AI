"""Startup over HTTP with PostgreSQL; the upstream is a controlled test server.

These tests prove dispatch and state handling, not LLM findings or completion.
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from app.api.v1 import deps
from app.api.v1.endpoints import cases
from fastapi import FastAPI
from sqlalchemy import text
from test_investigation_payload import TENANT, _seed

pytest_plugins = ["test_investigation_payload"]


@pytest.fixture
def upstream():
    requests = []
    reply = {"status": 200}
    run_id = str(uuid.uuid4())

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, dict(self.headers), payload))
            self.send_response(reply["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"run_id": run_id, "status": "running"}).encode())

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}", requests, reply, run_id
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, 401, 503, "connection"])
@pytest.mark.parametrize("scheme", ["", "http://"])
async def test_startup_transport_and_case_state(db, upstream, monkeypatch, failure, scheme):
    address, requests, reply, run_id = upstream
    cid, alert_ids = await _seed(db)
    monkeypatch.setattr(cases, "_AGENTS_URL", f"{scheme}{address}" if failure != "connection" else "http://127.0.0.1:1")
    monkeypatch.setattr(cases, "_AGENTS_SERVICE_TOKEN", "test-only-service-credential")
    if isinstance(failure, int):
        reply["status"] = failure

    app = FastAPI()
    app.include_router(cases.router, prefix="/api/v1")

    async def database():
        yield db

    async def user():
        return deps.CurrentUser(uuid.uuid4(), TENANT, "admin", "test@example.invalid", scopes=["cases:write"])

    app.dependency_overrides[deps.get_db] = database
    app.dependency_overrides[deps.get_current_user] = user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/api/v1/cases/{cid}/investigate", json={})

    case_status = (await db.execute(text("SELECT status FROM aisoc_cases WHERE id=:id"), {"id": cid})).scalar_one()
    alert_status = (await db.execute(text("SELECT status FROM alerts WHERE id=:id"), {"id": alert_ids[0]})).scalar_one()
    if failure is None:
        assert response.status_code == 200, response.text
        assert response.json()["run_id"] == run_id
        assert case_status == alert_status == "investigating"
        path, headers, payload = requests[0]
        assert path == f"/api/v1/cases/{cid}/investigate"
        assert headers["Authorization"] == "Bearer test-only-service-credential"
        assert headers["X-AiSOC-Tenant-ID"] == str(TENANT)
        assert payload["tenant_id"] == str(TENANT)
        assert payload["raw_alert"]["alerts"][0]["raw_event"]["marker"] == "needle-0"
    else:
        assert response.status_code == (503 if failure == "connection" else failure)
        assert case_status == alert_status == "new"
