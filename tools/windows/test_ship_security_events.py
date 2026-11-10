"""Offline regression for Windows shipper; synthetic JSONL and MockTransport only."""
import asyncio
import importlib.util
import json
import tempfile
from pathlib import Path
import sys

import httpx

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("windows_shipper", HERE / "ship_security_events.py")
shipper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = shipper
spec.loader.exec_module(shipper)


def main():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "events.jsonl"
        records = [
            {"System": {"EventID": 4624, "Channel": "Security",
                        "Computer": "synthetic-host", "EventRecordID": i,
                        "TimeCreated": "2026-11-10T10:00:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing"},
             "EventData": {}}
            for i in (1, 2, 3)
        ]
        path.write_text("".join(json.dumps(r) + chr(10) for r in records), encoding="utf-8")
        first, cursor = shipper.read_batch(path, 0, 2)
        assert len(first) == 2 and cursor == 2
        remaining, cursor = shipper.read_batch(path, 2, 2)
        assert len(remaining) == 1 and cursor == 3
        try:
            shipper.read_batch(path, 4, 2)
        except ValueError as exc:
            assert "shorter than saved shipper cursor" in str(exc)
        else:
            raise AssertionError("Truncated export must not silently skip events")
        saved = Path(temp) / "cursor"
        shipper.save_cursor(saved, cursor)
        assert saved.read_text() == "3"

        calls = []
        def handle(req):
            calls.append(req)
            assert req.url.path == "/v1/ingest/batch"
            assert req.headers["Authorization"] == "Bearer synthetic-token"
            assert req.headers["X-Tenant-ID"] == "11111111-1111-4111-8111-111111111111"
            payload = json.loads(req.content)
            assert len(payload["events"]) == 2
            return httpx.Response(200, json={"accepted": 2, "rejected": 0})

        # Override the module's httpx.AsyncClient for an entirely in-memory request.
        original = shipper.httpx.AsyncClient
        class MockClient:
            def __init__(self, **kwargs):
                self.client = original(transport=httpx.MockTransport(handle))
            async def __aenter__(self):
                return await self.client.__aenter__()
            async def __aexit__(self, *args):
                return await self.client.__aexit__(*args)
            async def post(self, *args, **kwargs):
                return await self.client.post(*args, **kwargs)

        shipper.httpx.AsyncClient = MockClient
        try:
            ack = asyncio.run(shipper.send_batch(
                "https://staging.invalid", "synthetic-token",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                [{"external_id": "synthetic-1"}, {"external_id": "synthetic-2"}],
            ))
        finally:
            shipper.httpx.AsyncClient = original
        assert ack == {"accepted": 2, "rejected": 0}
        assert len(calls) == 1

        def partial(req):
            return httpx.Response(200, json={"accepted": 1, "rejected": 1})

        class PartialClient:
            def __init__(self, **kwargs):
                self.client = original(transport=httpx.MockTransport(partial))
            async def __aenter__(self):
                return await self.client.__aenter__()
            async def __aexit__(self, *args):
                return await self.client.__aexit__(*args)
            async def post(self, *args, **kwargs):
                return await self.client.post(*args, **kwargs)

        shipper.httpx.AsyncClient = PartialClient
        try:
            try:
                asyncio.run(shipper.send_batch(
                    "https://staging.invalid", "synthetic-token",
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222",
                    [{"external_id": "synthetic-1"}, {"external_id": "synthetic-2"}],
                ))
            except RuntimeError as exc:
                assert "Incomplete ingestion acknowledgement" in str(exc)
            else:
                raise AssertionError("Partial acknowledgement must not succeed")
        finally:
            shipper.httpx.AsyncClient = original
    print(json.dumps({"status": "passed", "synthetic_records": 3,
                      "intercepted_requests": 1, "network_requests": 0,
                      "production_contacted": False}))


if __name__ == "__main__":
    main()
