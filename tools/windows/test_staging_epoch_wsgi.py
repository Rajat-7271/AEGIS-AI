"""Request-boundary tests; no network or database access."""

import io
import json
import sys
from collections import deque
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import staging_epoch_wsgi
from staging_epoch_wsgi import application


@pytest.fixture
def wsgi_request(monkeypatch):
    monkeypatch.setattr(staging_epoch_wsgi, "_request_times", deque())
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_TOKEN", "synthetic-" + "a" * 32)
    monkeypatch.setenv("AEGIS_WINDOWS_DEVICE_ID", "ci-device")
    monkeypatch.setenv("AEGIS_WINDOWS_STAGING_DATABASE_URL", "unused")

    def call(**overrides):
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v2/windows-security/events",
            "HTTP_AUTHORIZATION": "Bearer synthetic-" + "a" * 32,
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "2",
            "wsgi.input": io.BytesIO(b"{}"),
        }
        environ.update(overrides)
        status = []
        body = b"".join(application(environ, lambda value, headers: status.append(value)))
        return int(status[0][:3]), json.loads(body)

    return call


def test_auth_rejects_non_ascii_without_crashing(wsgi_request):
    assert wsgi_request(HTTP_AUTHORIZATION="Bearer \u00e9")[0] == 401


@pytest.mark.parametrize(
    "overrides,status",
    [
        ({"CONTENT_LENGTH": ""}, 411),
        ({"CONTENT_LENGTH": "260097"}, 413),
        ({"CONTENT_TYPE": "text/plain"}, 415),
        ({"PATH_INFO": "/unknown"}, 404),
        ({"HTTP_AUTHORIZATION": "Bearer wrong"}, 401),
        ({"CONTENT_LENGTH": "3"}, 400),
        ({}, 403),
    ],
)
def test_invalid_requests_never_reach_database(wsgi_request, overrides, status):
    assert wsgi_request(**overrides)[0] == status


def test_wsgi_authenticated_rate_limit(wsgi_request, monkeypatch):
    monkeypatch.setattr(staging_epoch_wsgi.time, "monotonic", lambda: 1.0)
    for _ in range(60):
        assert wsgi_request()[0] == 403
    assert wsgi_request()[0] == 429
    assert wsgi_request(HTTP_AUTHORIZATION="Bearer wrong")[0] == 401
    monkeypatch.setattr(staging_epoch_wsgi.time, "monotonic", lambda: 62.0)
    assert wsgi_request()[0] == 403
