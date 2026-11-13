"""Exercise the task launcher with a synthetic executable, never the event log."""

import json
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell and DPAPI")


@pytest.mark.parametrize("send,exit_code", [(False, 0), (True, 7)])
def test_launcher_opt_in_dpapi_and_exit_status(tmp_path, send, exit_code):
    fixture = tmp_path / "synthetic-python.cmd"
    credential_check = (
        "if not defined AEGIS_WINDOWS_STAGING_TOKEN exit /b 99" if send else "if defined AEGIS_WINDOWS_STAGING_TOKEN exit /b 99"
    )
    fixture.write_text(f"@echo off\n{credential_check}\necho synthetic-collector-status\nexit /b {exit_code}\n", encoding="ascii")
    config_path = tmp_path / "collector.json"
    config_path.write_text(
        json.dumps(
            {
                "python": str(fixture),
                "device": "synthetic-device",
                "spool": str(tmp_path / "unused.sqlite"),
                "send": send,
                "endpoint": "unused-no-network",
            }
        ),
        encoding="utf-8",
    )
    wrapper = tmp_path / "launch-fixture.ps1"
    wrapper.write_text(
        """
param([string]$Launcher, [string]$ConfigPath, [string]$TokenPath)
$ErrorActionPreference = 'Stop'
$secret = ConvertTo-SecureString ('synthetic-token-' + ('a' * 32)) -AsPlainText -Force
ConvertFrom-SecureString $secret | Set-Content -LiteralPath $TokenPath -Encoding ASCII
& $Launcher -ConfigPath $ConfigPath
exit $LASTEXITCODE
""",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("AEGIS_WINDOWS_STAGING_TOKEN", None)
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(wrapper),
            "-Launcher",
            str(Path(__file__).with_name("run-security-collector.ps1")),
            "-ConfigPath",
            str(config_path),
            "-TokenPath",
            str(tmp_path / "token.dpapi"),
        ],
        capture_output=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == exit_code, result.stderr.decode(errors="replace")
    log = (tmp_path / "collector-status.log").read_text(encoding="utf-8-sig")
    assert "synthetic-collector-status" in log
    assert "synthetic-token" not in log
