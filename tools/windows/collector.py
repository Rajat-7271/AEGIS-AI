"""Opt-in Security metadata collector with a transactional disk outbox.

An exact retained-record XML hash is a continuity witness, not a Windows log
instance identifier. A missing witness requires explicit recovery. V1 files
are never imported or overwritten. No network unless --send is supplied.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import time
import uuid
from contextlib import AbstractContextManager
from pathlib import Path

from source_epoch_contract import validate_source_identity
from staging_receiver import validate
from upload_security_events_v2 import build_envelope, send_epoch_batch


class ContinuityLost(ValueError):
    pass


def check_anchor(record, digest):
    if type(record) is not int or not 1 <= record <= 2**63 - 1 or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ContinuityLost("Invalid source anchor")


class Spool(AbstractContextManager):
    def __init__(self, path, max_pending=100_000):
        self.path = Path(path)
        self.max_pending = max_pending

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ContinuityLost("Spool must not be a symlink")
        self.lock = open(str(self.path) + ".lock", "a+b")
        self.lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                # Ensure byte zero exists, without changing it on another owner.
                if self.lock.read(1) == b"":
                    self.lock.write(b"0")
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock.close()
            raise RuntimeError("Collector already owns this spool") from exc
        try:
            self.db = sqlite3.connect(self.path)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS source (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    device TEXT NOT NULL, epoch TEXT NOT NULL,
                    record_id INTEGER NOT NULL, record_hash TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS events (
                    record_id INTEGER PRIMARY KEY, body TEXT NOT NULL);
            """)
            return self
        except BaseException:
            self.lock.close()
            raise

    def __exit__(self, *args):
        self.db.close()
        self.lock.close()

    def state(self):
        row = self.db.execute("SELECT device,epoch,record_id,record_hash,acknowledged FROM source").fetchone()
        if row is None:
            raise ContinuityLost("Initialize a new spool explicitly before collection")
        device, epoch, record, digest, acknowledged = row
        validate_source_identity({"device_id": device, "channel": "Security", "source_epoch": epoch})
        check_anchor(record, digest)
        return {"device_id": device, "source_epoch": epoch, "record_id": record, "record_hash": digest, "acknowledged": acknowledged}

    def initialize(self, device, record, digest):
        check_anchor(record, digest)
        epoch = uuid.uuid4().hex
        validate_source_identity({"device_id": device, "channel": "Security", "source_epoch": epoch})
        if self.db.execute("SELECT count(*) FROM source").fetchone()[0]:
            raise ContinuityLost("Refusing to replace an existing source epoch")
        with self.db:
            self.db.execute(
                "INSERT INTO source(singleton,device,epoch,record_id,record_hash) VALUES(1,?,?,?,?)", (device, epoch, record, digest)
            )

    def collect(self, observation):
        state = self.state()
        if not isinstance(observation, dict) or set(observation) != {
            "previous_record_id",
            "previous_hash",
            "record_id",
            "record_hash",
            "events",
        }:
            raise ContinuityLost("Invalid Security probe response")
        check_anchor(observation["previous_record_id"], observation["previous_hash"])
        check_anchor(observation["record_id"], observation["record_hash"])
        if (
            observation["previous_record_id"] != state["record_id"]
            or observation["previous_hash"] != state["record_hash"]
            or observation["record_id"] < state["record_id"]
        ):
            raise ContinuityLost("Security anchor changed or disappeared; preserve spool and review source")
        check_anchor(observation["record_id"], observation["record_hash"])
        events = observation["events"]
        if not isinstance(events, list):
            raise ContinuityLost("Invalid Security probe events")
        if events:
            validate({"device_id": state["device_id"], "events": events})
        if any(not state["record_id"] < e["System"]["EventRecordID"] <= observation["record_id"] for e in events):
            raise ContinuityLost("Events are outside the observed scan range")
        if observation["record_id"] == state["record_id"] and observation["record_hash"] != state["record_hash"]:
            raise ContinuityLost("Anchor content changed")
        if self.status()["pending"] + len(events) > self.max_pending:
            raise BufferError("Spool pending limit reached; deliver backlog before collecting")
        with self.db:
            for event in events:
                self.db.execute("INSERT INTO events VALUES(?,?)", (event["System"]["EventRecordID"], json.dumps(event, sort_keys=True)))
            self.db.execute(
                "UPDATE source SET record_id=?,record_hash=? WHERE singleton=1", (observation["record_id"], observation["record_hash"])
            )

    def pending(self):
        state = self.state()
        events = [json.loads(row[0]) for row in self.db.execute("SELECT body FROM events ORDER BY record_id LIMIT 100")]
        return build_envelope(state["device_id"], state["source_epoch"], events) if events else None

    def acknowledge(self, batch, record):
        if not batch or batch != self.pending() or type(record) is not int or record != batch["events"][-1]["System"]["EventRecordID"]:
            raise ValueError("Acknowledgement does not match pending batch")
        with self.db:
            self.db.execute("DELETE FROM events WHERE record_id<=?", (record,))
            self.db.execute("UPDATE source SET acknowledged=acknowledged+? WHERE singleton=1", (len(batch["events"]),))

    def status(self):
        return {"pending": self.db.execute("SELECT count(*) FROM events").fetchone()[0], "acknowledged": self.state()["acknowledged"]}


def probe(state=None):
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(Path(__file__).with_name("read-security-batch.ps1"))]
    if state:
        command += ["-AfterRecordId", str(state["record_id"]), "-AnchorHash", state["record_hash"]]
    result = subprocess.run(command, capture_output=True, timeout=60, check=False)
    if result.returncode:
        # Do not echo source exception text, which may contain local identities.
        raise ContinuityLost("Security probe failed: check log read permission and retained anchor")
    return json.loads(result.stdout.decode("utf-8-sig"))


def cycle(spool, *, send=False, collect=True):
    """One bounded scan and upload; return False when upload needs retry."""
    delivered = True
    # Sending durable backlog remains possible when source continuity is lost.
    if send:
        batch = spool.pending()
        if batch:
            try:
                record = send_epoch_batch(
                    os.environ.get("AEGIS_WINDOWS_STAGING_ENDPOINT", ""), os.environ.get("AEGIS_WINDOWS_STAGING_TOKEN", ""), batch
                )
            except (OSError, ValueError):
                delivered = False
                print(json.dumps({"upload": "failed", "checkpoint_advanced": False}), flush=True)
            else:
                # Disk errors must stop collection, not be misreported as a network failure.
                spool.acknowledge(batch, record)
    if collect:
        try:
            spool.collect(probe(spool.state()))
        except BufferError:
            print(json.dumps({"collection": "backpressure"}), flush=True)
    print(json.dumps(spool.status() | {"send_enabled": send}), flush=True)
    return delivered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spool", type=Path, default=Path(os.environ.get("LOCALAPPDATA", ".")) / "AEGIS-AI" / "security-v2.sqlite")
    parser.add_argument("--initialize", action="store_true", help="Start at the current newest real record; no history import")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--send", action="store_true", help="Explicit approval to transmit metadata to configured staging endpoint")
    parser.add_argument("--continuous", action="store_true")
    parser.add_argument("--upload-only", action="store_true", help="Replay durable backlog without accessing the source; requires --send")
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()
    if not 10 <= args.interval <= 3600:
        parser.error("interval must be between 10 and 3600 seconds")
    if args.upload_only and not args.send:
        parser.error("upload-only requires --send")
    with Spool(args.spool) as spool:
        if args.initialize:
            if args.send or args.continuous or args.status:
                parser.error("initialize must run separately from collection and transmission")
            anchor = probe()
            spool.initialize(os.environ.get("AEGIS_WINDOWS_DEVICE_ID", ""), anchor["record_id"], anchor["record_hash"])
            print(json.dumps({"initialized": True, "historical_import": False}))
            return
        if args.status:
            print(json.dumps(spool.status()))
            return
        while True:
            previous_record = spool.state()["record_id"]
            delivered = cycle(spool, send=args.send, collect=not args.upload_only)
            if not args.continuous:
                if not delivered:
                    raise SystemExit(2)
                return
            # Catch up immediately while full pages or acknowledged backlog remain.
            # Offline and backpressure cycles still sleep to avoid a hot retry loop.
            progressed = spool.state()["record_id"] - previous_record >= 100
            backlog = args.send and spool.status()["pending"] >= 100
            if delivered and (progressed or backlog) and spool.status()["pending"] < spool.max_pending:
                continue
            time.sleep(min(300, args.interval * 2) if not delivered else args.interval)


if __name__ == "__main__":
    main()
