"""Verify metadata-only Windows events normalize without leaking user fields."""
from app.connectors.windows_event import WindowsEventConnector


def test_real_pilot_security_logon_metadata():
    connector = WindowsEventConnector("https://unused.invalid/spool", "unused")
    event = {
        "System": {
            "EventID": 4624, "Channel": "Security", "Computer": "lab-machine",
            "EventRecordID": 2970171, "TimeCreated": "2026-11-09T10:22:18Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
        },
        "EventData": {},
    }
    result = connector.normalize(event)
    assert result["event_type"] == "windows.security.4624"
    assert result["external_id"] == "2970171"
    assert result["hostname"] == "lab-machine"
    assert result["created_at"] == "2026-11-09T10:22:18Z"
    assert result["username"] is None
    assert result["process_name"] is None
    assert result["severity"] == "info"


def test_real_pilot_privileged_logon_is_not_high_alert():
    connector = WindowsEventConnector("https://unused.invalid/spool", "unused")
    event = {
        "System": {
            "EventID": 4672, "Channel": "Security", "Computer": "lab-machine",
            "EventRecordID": 2970172, "TimeCreated": "2026-11-09T10:22:18Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
        },
        "EventData": {},
    }
    result = connector.normalize(event)
    assert result["event_type"] == "windows.security.4672"
    assert result["severity"] == "low"
    assert result["external_id"] == "2970172"
