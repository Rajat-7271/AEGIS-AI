"""Regression tests for the existing Windows Security/Sysmon adapter.

No Windows host, credentials, network access, or production data required.
"""
import pytest

from app.connectors.windows_event import WindowsEventConnector


def test_security_event_normalization_preserves_evidence():
    connector = WindowsEventConnector("https://collector.example.test/spool", "test-token")
    raw = {
        "System": {
            "EventID": 4720,
            "Channel": "Security",
            "Computer": "lab-host",
            "EventRecordID": 1234,
            "TimeCreated": "2026-11-09T10:00:00Z",
        },
        "EventData": {"TargetUserName": "lab-user", "SubjectUserName": "lab-admin"},
    }
    event = connector.normalize(raw)
    assert event["source"] == "windows_event"
    assert event["severity"] == "medium"
    assert event["hostname"] == "lab-host"
    assert event["username"] == "lab-user"
    assert event["external_id"] == "winrec:v1:8:lab-host8:security4:1234"
    assert event["created_at"] == "2026-11-09T10:00:00Z"
    assert event["raw_event"]["EventID"] == 4720
    assert event["raw_event"]["TargetUserName"] == "lab-user"


def test_sysmon_fields_lifted_for_detection_rules():
    connector = WindowsEventConnector("https://collector.example.test/spool", "test-token")
    raw = {
        "System": {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"},
        "EventData": {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c echo test"},
    }
    event = connector.normalize(raw)
    assert event["process_name"].endswith("cmd.exe")
    assert event["raw_event"]["Image"] == raw["EventData"]["Image"]
    assert event["raw_event"]["CommandLine"] == raw["EventData"]["CommandLine"]


def test_log_clear_is_high_severity():
    connector = WindowsEventConnector("https://collector.example.test/spool", "test-token")
    event = connector.normalize({"EventID": 1102, "Channel": "Security"})
    assert event["severity"] == "high"


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_protected_environment_rejects_disabled_tls(monkeypatch, environment):
    monkeypatch.setenv("ENVIRONMENT", environment)
    with pytest.raises(ValueError, match="TLS verification is required"):
        WindowsEventConnector("https://collector.example.test/spool", "dummy", verify_tls=False)


def test_protected_environment_accepts_verified_tls(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    connector = WindowsEventConnector("https://collector.example.test/spool", "dummy")
    assert connector._verify is True


def test_local_synthetic_environment_can_disable_tls(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    connector = WindowsEventConnector("https://collector.example.test/spool", "dummy", verify_tls=False)
    assert connector._verify is False
