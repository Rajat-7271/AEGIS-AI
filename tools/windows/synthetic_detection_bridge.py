"""Opt-in local synthetic delivery experiment; never reads a receipt store.

No scheduler, environment loading, production registration, or alert writes.
The ledger records ingest acceptance, not detection or exactly-once delivery.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from source_epoch_contract import validate_epoch_batch


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirects are forbidden")


class SyntheticBridge:
    """Bindings and credentials are supplied by the local harness, never JSON.

    A private disposable ledger must be used per experiment. Binding changes
    cannot relabel previously queued events. Concurrent/restarted delivery may
    repeat HTTP requests; the canonical external ID stays identical.
    """

    def __init__(self, database: Path, *, enabled: bool = False):
        if not enabled:
            raise ValueError("Synthetic bridge requires explicit opt-in")
        self.database = database
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (device TEXT PRIMARY KEY, tenant TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS delivery (tenant TEXT, connector TEXT, "
                "external_id TEXT, body TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, "
                "PRIMARY KEY(tenant, connector, external_id))"
            )

    def connect(self):
        return sqlite3.connect(self.database, timeout=10)

    def enqueue(self, fixture: dict, *, bindings: dict[str, str], connector: str) -> int:
        if set(fixture) != {"synthetic", "batch"} or fixture["synthetic"] is not True:
            raise ValueError("Only explicitly labelled synthetic fixtures are eligible")
        (device, channel, epoch), events = validate_epoch_batch(fixture["batch"])
        tenant = str(UUID(bindings[device]))
        connector = str(UUID(connector))
        inserted = 0
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            binding = db.execute("SELECT tenant FROM binding WHERE device=?", (device,)).fetchone()
            if binding and binding[0] != tenant:
                raise ValueError("Device tenant binding cannot change within an experiment")
            db.execute("INSERT OR IGNORE INTO binding VALUES(?,?)", (device, tenant))
            for event in events:
                system = event["System"]
                identity = [device, channel, epoch, system["Computer"], system["EventRecordID"]]
                external_id = "windows-v2:" + json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
                body = json.dumps(
                    {
                        "source": "windows_event",
                        "external_id": external_id,
                        "title": f"Synthetic Windows Security EventID {system['EventID']}",
                        "severity": "info",
                        "hostname": system["Computer"],
                        "created_at": system["TimeCreated"],
                        "raw_event": {**system, **event, "synthetic": True, "receipt_identity": identity},
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                key = (tenant, connector, external_id)
                old = db.execute("SELECT body FROM delivery WHERE tenant=? AND connector=? AND external_id=?", key).fetchone()
                if old:
                    if old[0] != body:
                        raise ValueError("Conflicting synthetic replay")
                    continue
                db.execute("INSERT INTO delivery(tenant,connector,external_id,body) VALUES(?,?,?,?)", (*key, body))
                inserted += 1
        return inserted

    def deliver_one(self, *, tenant: str, connector: str, endpoint: str, token: str) -> bool:
        target = urlsplit(endpoint)
        if (
            target.scheme != "http"
            or target.hostname != "127.0.0.1"
            or target.username
            or target.password
            or target.query
            or target.fragment
            or target.path != "/v1/ingest/batch"
        ):
            raise ValueError("Only a literal loopback ingest endpoint is permitted")
        tenant, connector = str(UUID(tenant)), str(UUID(connector))
        if not token or not token.isascii() or any(c in token for c in "\r\n"):
            raise ValueError("Invalid synthetic credential")
        with self.connect() as db:
            row = db.execute(
                "SELECT external_id,body FROM delivery WHERE tenant=? AND connector=? AND delivered=0 ORDER BY external_id LIMIT 1",
                (tenant, connector),
            ).fetchone()
        if not row:
            return False
        payload = {
            "connector_id": connector,
            "connector_type": "windows_event",
            "source_format": "raw_json",
            "events": [json.loads(row[1])],
        }
        request = Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": tenant,
            },
            method="POST",
        )
        with build_opener(ProxyHandler({}), NoRedirect).open(request, timeout=5) as response:
            result = json.loads(response.read(65536))
            if response.status != 200 or type(result.get("accepted")) is not int or result["accepted"] != 1 or result.get("rejected") != 0:
                raise ValueError("Ingest did not accept the complete event")
        with self.connect() as db:
            db.execute("UPDATE delivery SET delivered=1 WHERE tenant=? AND connector=? AND external_id=?", (tenant, connector, row[0]))
        return True
