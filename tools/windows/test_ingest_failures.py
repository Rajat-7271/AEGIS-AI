"""Offline failure-path tests for the existing connector ingestion client.

No real Windows events, sockets, credentials or production services.
Run: python tools/windows/test_ingest_failures.py
"""
from __future__ import annotations

import asyncio
import json

import httpx
from test_ingest_contract import CONNECTOR, TENANT, module

EVENT = {"source": "windows_event", "external_id": "synthetic-1",
         "event_type": "windows.security.4624", "created_at": "2026-11-09T00:00:00Z"}


async def exercise(response_factory):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return response_factory(request)

    client = module.IngestClient("http://offline.invalid", service_token="dummy")
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        try:
            result = await client.push_events(
                tenant_id=TENANT, connector_id=CONNECTOR,
                connector_type="windows_event", events=[EVENT])
            return {"result": result, "calls": calls}
        except module.IngestClientError as exc:
            # Do not print the response body: error messages can contain source data.
            return {"error_type": type(exc).__name__, "calls": calls}
    finally:
        await client.aclose()


async def main():
    cases = {
        "unauthorized": lambda _: httpx.Response(401, json={"error": "unauthorized"}),
        "forbidden": lambda _: httpx.Response(403, json={"error": "forbidden"}),
        "rate_limited": lambda _: httpx.Response(429, json={"error": "rate limited"}),
        "server_error": lambda _: httpx.Response(503, json={"error": "unavailable"}),
        "non_json_success": lambda _: httpx.Response(200, text="not-json"),
        "partial_ack": lambda _: httpx.Response(200, json={"accepted": 0, "rejected": 1}),
        "timeout": lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("simulated", request=request)),
    }
    outcomes = {}
    for name, factory in cases.items():
        outcome = await exercise(factory)
        if name == "partial_ack":
            if outcome != {"result": {"accepted": 0, "rejected": 1}, "calls": 1}:
                raise AssertionError(f"{name}: unexpected outcome {outcome}")
            outcomes[name] = "returned partial acknowledgement to caller"
        else:
            if outcome != {"error_type": "IngestClientError", "calls": 1}:
                raise AssertionError(f"{name}: unexpected outcome {outcome}")
            outcomes[name] = "raised IngestClientError"
    print(json.dumps({"status": "passed", "cases": outcomes,
                      "network_requests": 0, "real_events_sent": 0}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
