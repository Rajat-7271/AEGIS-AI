"""Source continuity guard tests; no Windows log access or state mutation."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from source_continuity import (
    ContinuityError, load_state, verify_observation, write_new_state
)


def state():
    return {
        "version": 1, "device_id": "ci-device", "channel": "Security",
        "source_epoch": "a" * 32, "log_instance": "trusted-instance-1",
        "last_record_id": 100
    }


def test_restart_continuity(tmp_path):
    path = tmp_path / "continuity.json"
    write_new_state(path, state())
    saved = load_state(path)
    assert verify_observation(saved, log_instance="trusted-instance-1",
                              newest_record_id=101) == saved
    assert verify_observation(saved, log_instance="trusted-instance-1",
                              newest_record_id=100) == saved


def test_log_reset_detected_even_if_record_id_surpasses_checkpoint():
    with pytest.raises(ContinuityError, match="instance changed"):
        verify_observation(state(), log_instance="trusted-instance-2",
                           newest_record_id=999999)


def test_record_regression_fails_closed():
    with pytest.raises(ContinuityError, match="regressed"):
        verify_observation(state(), log_instance="trusted-instance-1",
                           newest_record_id=99)


def test_missing_or_corrupt_state_fails_closed(tmp_path):
    path = tmp_path / "state.json"
    with pytest.raises(ContinuityError, match="Missing or invalid"):
        load_state(path)
    path.write_text("{bad json", encoding="utf-8")
    with pytest.raises(ContinuityError, match="Missing or invalid"):
        load_state(path)


def test_existing_state_never_overwritten(tmp_path):
    path = tmp_path / "state.json"
    write_new_state(path, state())
    original = path.read_bytes()
    with pytest.raises(ContinuityError, match="already exists"):
        write_new_state(path, {**state(), "source_epoch": "b" * 32})
    assert path.read_bytes() == original


def test_invalid_state_rejected(tmp_path):
    path = tmp_path / "state.json"
    for invalid in [
        {**state(), "last_record_id": -1},
        {**state(), "last_record_id": True},
        {**state(), "log_instance": ""},
        {**state(), "source_epoch": "bad"},
    ]:
        with pytest.raises(ValueError):
            write_new_state(path, invalid)


def test_symlink_state_rejected(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "state.json"
    link.symlink_to(target)
    with pytest.raises(ContinuityError, match="symlink"):
        load_state(link)
    with pytest.raises(ContinuityError, match="symlink"):
        write_new_state(link, state())


def test_oversized_state_rejected(tmp_path):
    path = tmp_path / "state.json"
    path.write_bytes(b" " * 4097)
    with pytest.raises(ContinuityError, match="size limit"):
        load_state(path)


def test_nonregular_state_rejected(tmp_path):
    with pytest.raises(ContinuityError, match="Missing or invalid"):
        load_state(tmp_path)


def test_invalid_utf8_state_rejected(tmp_path):
    path = tmp_path / "state.json"
    path.write_bytes(b"\\xff\\xfe")
    with pytest.raises(ContinuityError, match="Missing or invalid"):
        load_state(path)
