"""Synthetic contract inputs; no generated or transmitted Windows events."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from collector import ContinuityLost, Spool
from test_upload_security_events_v2 import event


def observation(previous=10, record=11, fingerprint="b" * 64):
    return {
        "previous_record_id": previous,
        "previous_hash": "a" * 64,
        "record_id": record,
        "record_hash": fingerprint,
        "events": [event(record)],
    }


def test_restart_and_lost_ack_replays_identical_batch(tmp_path):
    path = tmp_path / "spool.sqlite"
    with Spool(path) as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        spool.collect(observation())
        first = spool.pending()
    with Spool(path) as spool:
        assert spool.pending() == first
        assert spool.state()["record_id"] == 11
        spool.acknowledge(first, 11)
        assert spool.pending() is None
        assert spool.status()["acknowledged"] == 1


@pytest.mark.parametrize("field,value", [("previous_hash", "c" * 64), ("previous_record_id", 9), ("record_id", 9)])
def test_continuity_failure_never_advances(tmp_path, field, value):
    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        with pytest.raises(ContinuityLost):
            spool.collect(observation() | {field: value})
        assert spool.state()["record_id"] == 10
        assert spool.pending() is None


def test_disk_transaction_rolls_back_progress_with_event_failure(tmp_path):
    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        spool.db.execute("CREATE TRIGGER disk_failure BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
        with pytest.raises(Exception, match="disk failure"):
            spool.collect(observation())
        assert spool.state()["record_id"] == 10
        assert spool.pending() is None


def test_checkpoint_mismatch_and_reinitialization_fail_closed(tmp_path):
    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        with pytest.raises(ContinuityLost):
            spool.initialize("ci-device", 10, "a" * 64)
        spool.collect(observation())
        batch = spool.pending()
        with pytest.raises(ValueError):
            spool.acknowledge(batch, 12)
        assert spool.pending() == batch


def test_non_allowlisted_scan_advances_anchor_without_fake_event(tmp_path):
    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        spool.collect(observation() | {"events": []})
        assert spool.state()["record_id"] == 11
        assert spool.pending() is None


def test_backpressure_keeps_cursor(tmp_path):
    with Spool(tmp_path / "spool.sqlite", max_pending=1) as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        spool.collect(observation())
        with pytest.raises(BufferError):
            spool.collect(
                {"previous_record_id": 11, "previous_hash": "b" * 64, "record_id": 12, "record_hash": "c" * 64, "events": [event(12)]}
            )
        assert spool.state()["record_id"] == 11


def test_one_process_owns_spool(tmp_path):
    with Spool(tmp_path / "spool.sqlite"):
        with pytest.raises(RuntimeError, match="already"):
            with Spool(tmp_path / "spool.sqlite"):
                pytest.fail("second owner")


def test_cycle_network_failure_collects_without_losing_backlog(tmp_path, monkeypatch):
    import collector

    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        spool.collect(observation())
        first = spool.pending()
        monkeypatch.setattr(collector, "send_epoch_batch", lambda *args: (_ for _ in ()).throw(OSError("offline")))
        monkeypatch.setattr(
            collector,
            "probe",
            lambda state: {
                "previous_record_id": 11,
                "previous_hash": "b" * 64,
                "record_id": 12,
                "record_hash": "c" * 64,
                "events": [event(12)],
            },
        )
        assert collector.cycle(spool, send=True) is False
        assert spool.pending()["events"] == first["events"] + [event(12)]
        assert spool.status() == {"pending": 2, "acknowledged": 0}
        monkeypatch.setattr(collector, "send_epoch_batch", lambda *args: 12)
        monkeypatch.setattr(collector, "probe", lambda state: pytest.fail("upload-only accessed source"))
        assert collector.cycle(spool, send=True, collect=False)
        assert spool.status() == {"pending": 0, "acknowledged": 2}


def test_default_cycle_never_sends(tmp_path, monkeypatch):
    import collector

    monkeypatch.setattr(collector, "send_epoch_batch", lambda *args: pytest.fail("network attempted"))
    monkeypatch.setattr(collector, "probe", lambda state: observation())
    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        collector.cycle(spool)
        assert spool.status()["pending"] == 1


def test_failed_ack_transaction_preserves_replay(tmp_path):
    with Spool(tmp_path / "spool.sqlite") as spool:
        spool.initialize("ci-device", 10, "a" * 64)
        spool.collect(observation())
        batch = spool.pending()
        spool.db.execute("CREATE TRIGGER ack_failure BEFORE UPDATE ON source BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
        with pytest.raises(Exception, match="disk failure"):
            spool.acknowledge(batch, 11)
        assert spool.pending() == batch
        assert spool.status()["acknowledged"] == 0
