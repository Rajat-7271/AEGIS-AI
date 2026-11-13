"""Targeted sender retry tests: no network, credentials, or telemetry."""
import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from upload_security_events_v2 import send_epoch_batch

ENDPOINT = "https://staging.example.test/v2/windows-security/events"
TOKEN = "x" * 64


class Response:
    status = 200

    def __init__(self, record):
        self.body = io.BytesIO(('{"accepted":true,"last_record_id":%d}' % record).encode())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        return self.body.read(size)


class SenderRetryTests(unittest.TestCase):
    def setUp(self):
        self.envelope = {
            "protocol_version": 2, "device_id": "test-device",
            "channel": "Security", "source_epoch": "a" * 32,
            "events": [{
                "System": {
                    "EventID": 4624, "Channel": "Security",
                    "Computer": "test-host", "EventRecordID": 7,
                    "TimeCreated": "2026-11-13T00:00:00Z",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                }, "EventData": {},
            }],
        }

    @patch("upload_security_events_v2.time.sleep")
    @patch("upload_security_events_v2.urllib.request.build_opener")
    def test_retries_transient_503_with_same_request(self, build, sleep):
        opener = build.return_value
        opener.open.side_effect = [
            HTTPError(ENDPOINT, 503, "unavailable", {}, None),
            Response(7),
        ]
        self.assertEqual(send_epoch_batch(ENDPOINT, TOKEN, self.envelope), 7)
        self.assertEqual(opener.open.call_count, 2)
        self.assertIs(opener.open.call_args_list[0].args[0],
                      opener.open.call_args_list[1].args[0])
        sleep.assert_called_once_with(1)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 120)

    @patch("upload_security_events_v2.time.sleep")
    @patch("upload_security_events_v2.urllib.request.build_opener")
    def test_does_not_retry_auth_failure(self, build, sleep):
        opener = build.return_value
        opener.open.side_effect = HTTPError(ENDPOINT, 401, "unauthorized", {}, None)
        with self.assertRaises(HTTPError):
            send_epoch_batch(ENDPOINT, TOKEN, self.envelope)
        self.assertEqual(opener.open.call_count, 1)
        sleep.assert_not_called()

    @patch("upload_security_events_v2.time.sleep")
    @patch("upload_security_events_v2.urllib.request.build_opener")
    def test_exhausts_transient_errors_without_ack(self, build, sleep):
        opener = build.return_value
        opener.open.side_effect = HTTPError(ENDPOINT, 503, "unavailable", {}, None)
        with self.assertRaises(HTTPError):
            send_epoch_batch(ENDPOINT, TOKEN, self.envelope)
        self.assertEqual(opener.open.call_count, 3)
        self.assertEqual(sleep.call_count, 2)


if __name__ == "__main__":
    unittest.main()
