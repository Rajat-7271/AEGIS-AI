"""Offline ingestion contract verification using a local in-memory HTTP transport.

No socket, network, credentials, database or production service is used.
Runs the existing connector IngestClient against httpx.MockTransport to assert
tenant scoping, authorization headers, event shape and acknowledgement.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "services" / "connectors" / "app" / "ingest_client.py"
spec = importlib.util.spec_from_file_location("aegis_windows_ingest_client", MODULE_PATH)
if spec is None or spec.loader is None:
    raise ImportError("Cannot load connector ingestion client")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")
CONNECTOR = uuid.UUID("22222222-2222-4222-8222-222222222222")


async def check_contract() -> dict:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append({
            "method": request.method,
            "path": request.url.path,
            "tenant": request.headers.get("X-Tenant-ID"),
            "authenticated": request.headers.get("Authorization") == "Bearer offline-test-only",
            "connector_id": payload.get("connector_id"),
            "connector_type": payload.get("connector_type"),
            "source_format": payload.get("source_format"),
            "event_count": len(payload.get("events", [])),
        })
        return httpx.Response(200, json={"accepted": len(payload["events"]), "rejected": 0})

    client = module.IngestClient("http://offline.invalid", service_token="offline-test-only")
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        sample = [{
            "source": "windows_event",
            "event_type": "windows.security.4624",
            "external_id": "12345",
            "hostname": "synthetic-lab",
            "severity": "info",
            "created_at": "2026-11-09T00:00:00Z",
        }]
        result = await client.push_events(
            tenant_id=TENANT,
            connector_id=CONNECTOR,
            connector_type="windows_event",
            events=sample,
        )
    finally:
        await client.aclose()

    if result != {"accepted": 1, "rejected": 0}:
        raise RuntimeError("Unexpected ingestion acknowledgement")
    expected = {
        "method": "POST",
        "path": "/v1/ingest/batch",
        "tenant": str(TENANT),
        "authenticated": True,
        "connector_id": str(CONNECTOR),
        "connector_type": "windows_event",
        "source_format": "raw_json",
        "event_count": 1,
    }
    if requests != [expected]:
        raise RuntimeError(f"Ingestion contract mismatch: {requests!r}")
    return {"contract": "passed", "requests_intercepted_locally": len(requests),
            "synthetic_events_accepted": result["accepted"], "real_events_sent": 0,
            "production_contacted": False}


if __name__ == "__main__":
    print(json.dumps(asyncio.run(check_contract()), indent=2))
