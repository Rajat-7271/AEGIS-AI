"""Offline regression for Windows shipper; synthetic JSONL and MockTransport only."""
import asyncio
import hashlib
import hmac
import importlib.util
import json
import os
import tempfile
from argparse import Namespace
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
            assert 1 <= len(payload["events"]) <= 2
            return httpx.Response(200, json={"accepted": len(payload["events"]), "rejected": 0})

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
        # Minted connector-push tokens may require a signature of the
        # exact transmitted JSON bytes, not a reserialized payload.
        previous_secret = os.environ.get("AEGIS_WINDOWS_INGEST_HMAC_SECRET")
        os.environ["AEGIS_WINDOWS_INGEST_HMAC_SECRET"] = "synthetic-signing-key"
        calls.clear()
        shipper.httpx.AsyncClient = MockClient
        try:
            asyncio.run(shipper.send_batch(
                "https://staging.invalid", "synthetic-token",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                [{"external_id": "synthetic-signed"}],
            ))
        finally:
            shipper.httpx.AsyncClient = original
            if previous_secret is None:
                os.environ.pop("AEGIS_WINDOWS_INGEST_HMAC_SECRET", None)
            else:
                os.environ["AEGIS_WINDOWS_INGEST_HMAC_SECRET"] = previous_secret
        expected = hmac.new(b"synthetic-signing-key", calls[0].content, hashlib.sha256).hexdigest()
        assert calls[0].headers["X-Signature"] == "sha256=" + expected
        # Hosted deployments use the FastAPI/Postgres route, not the Go ingest route.
        hosted_calls = []
        def hosted_handle(req):
            hosted_calls.append(req)
            assert req.url.path == "/api/v1/windows-security/batch"
            assert req.headers["X-Tenant-ID"] == "11111111-1111-4111-8111-111111111111"
            body = json.loads(req.content)
            assert body["connector_type"] == "windows_event"
            return httpx.Response(200, json={"accepted": len(body["events"]), "rejected": 0})

        class HostedClient:
            def __init__(self, **kwargs):
                self.client = original(transport=httpx.MockTransport(hosted_handle))
            async def __aenter__(self):
                return await self.client.__aenter__()
            async def __aexit__(self, *args):
                return await self.client.__aexit__(*args)
            async def post(self, *args, **kwargs):
                return await self.client.post(*args, **kwargs)

        shipper.httpx.AsyncClient = HostedClient
        try:
            hosted_ack = asyncio.run(shipper.send_batch(
                "https://staging.invalid", "synthetic-token",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                [{"external_id": "synthetic-hosted"}], direct_api=True,
            ))
        finally:
            shipper.httpx.AsyncClient = original
        assert hosted_ack == {"accepted": 1, "rejected": 0}
        assert len(hosted_calls) == 1
        calls.clear()
        # A scheduled invocation must drain multiple batches and persist
        # the cursor after each fully acknowledged batch.
        calls.clear()
        saved.write_text("0", encoding="utf-8")
        shipper.httpx.AsyncClient = MockClient
        previous_token = os.environ.get("AEGIS_WINDOWS_INGEST_TOKEN")
        os.environ["AEGIS_WINDOWS_INGEST_TOKEN"] = "synthetic-token"
        try:
            asyncio.run(shipper.run(Namespace(
                cursor=saved, input=path, limit=2, max_batches=5,
                send=True, url="https://staging.invalid",
                tenant="11111111-1111-4111-8111-111111111111",
                connector="22222222-2222-4222-8222-222222222222",
            )))
        finally:
            shipper.httpx.AsyncClient = original
            if previous_token is None:
                os.environ.pop("AEGIS_WINDOWS_INGEST_TOKEN", None)
            else:
                os.environ["AEGIS_WINDOWS_INGEST_TOKEN"] = previous_token
        assert saved.read_text() == "3"
        assert len(calls) == 2

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
