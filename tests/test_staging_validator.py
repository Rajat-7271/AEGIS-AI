"""Run the staging validator against real Compose merges with synthetic credentials."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from run_staging_ci import SmokeError, validate_model
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.staging.yml",
    "docker-compose.staging-build.yml",
    "docker-compose.staging-isolation.yml",
)
CANARY = "fixture-only-secret-never-print"
PUBLISHED_PASSWORD = "aisoc_dev_secret"
SMOKE = "api, kafka, postgres, preflight-secrets, realtime, redis, web, zookeeper"


class StagingFixture(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="aegis-validator-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "scripts").mkdir()
        for name in (
            *COMPOSE_FILES,
            ".env.example",
            "scripts/Test-AegisStaging.ps1",
            "scripts/check_published_secrets.py",
            "scripts/gate_toolkit.py",
        ):
            shutil.copyfile(REPO / name, self.root / name)
        required = set()
        for name in COMPOSE_FILES:
            for line in (self.root / name).read_text(encoding="utf-8").splitlines():
                if not line.lstrip().startswith("#"):
                    required.update(re.findall(r"\$\{([A-Z0-9_]+):\?", line))
        self.fixture_env = {name: f"{CANARY}-{name.lower()}" for name in sorted(required)}

    def edit(self, filename: str, before: str, after: str) -> None:
        path = self.root / filename
        text = path.read_text(encoding="utf-8")
        self.assertIn(before, text)
        path.write_text(text.replace(before, after, 1), encoding="utf-8")

@unittest.skipUnless(os.name == "nt", "The staging validator targets Windows")
class StagingValidatorTests(StagingFixture):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pwsh = shutil.which("pwsh.exe")
        docker = shutil.which("docker.exe")
        if not cls.pwsh or not docker or not shutil.which("python.exe"):
            raise unittest.SkipTest("PowerShell, Docker CLI, and Python are required")
        compose = subprocess.run([docker, "compose", "version"], capture_output=True, check=False)
        if compose.returncode:
            raise unittest.SkipTest("Docker Compose plugin is required")

    def run_validator(self, expected_code: int) -> str:
        dotenv = "".join(f"{name}={value}\n" for name, value in self.fixture_env.items())
        (self.root / ".env").write_text(dotenv, encoding="utf-8")
        inherited = {
            **os.environ,
            "COMPOSE_PROFILES": "*",
            "DOCKER_HOST": "npipe:////./pipe/aegis-validator-nonexistent",
            "POSTGRES_PASSWORD": f"{CANARY}-inherited",
            "LITELLM_MASTER_KEY": f"{CANARY}-inherited",
        }
        result = subprocess.run(
            [self.pwsh, "-NoProfile", "-File", "scripts/Test-AegisStaging.ps1", "-ConfigOnly"],
            cwd=self.root,
            env=inherited,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotIn(CANARY, output, "The validator exposed a fixture secret")
        self.assertNotIn(PUBLISHED_PASSWORD, output, "The validator exposed a published fixture value")
        self.assertEqual(result.returncode, expected_code, output)
        self.assertNotIn("[PASS] Docker resources", output)
        return output

    def test_default_profile_passes_static_checks(self) -> None:
        output = self.run_validator(2)
        self.assertIn("[PASS] Compose - Default profile resolves with 18 services.", output)
        self.assertIn(f"Web smoke dependency set: {SMOKE}", output)
        for check in ("Dependencies", "Secrets", "Isolation", "Ports", "Image policy", "Ollama cache gate"):
            self.assertIn(f"[PASS] {check} -", output)
        self.assertIn("[WARN] Live checks -", output)
        self.assertNotIn("[FAIL]", output)

    def test_missing_staging_key_cannot_be_filled_by_inherited_environment(self) -> None:
        del self.fixture_env["LITELLM_MASTER_KEY"]
        self.assertIn("[FAIL] Compose -", self.run_validator(1))

    def test_published_password_is_rejected_without_echoing_it(self) -> None:
        self.fixture_env["POSTGRES_PASSWORD"] = PUBLISHED_PASSWORD
        self.assertIn("[FAIL] Secrets -", self.run_validator(1))

    def test_optional_preflight_dependency_is_rejected(self) -> None:
        self.edit(
            "docker-compose.staging-isolation.yml",
            "services:\n",
            "services:\n  redis:\n    depends_on:\n      preflight-secrets:\n        required: false\n",
        )
        self.assertIn("[FAIL] Dependencies -", self.run_validator(1))

    def test_web_smoke_cannot_add_another_service(self) -> None:
        self.edit("docker-compose.staging.yml", "  web:\n", "  web:\n    depends_on:\n      - actions\n")
        self.assertIn("[FAIL] Web smoke scope -", self.run_validator(1))

    def test_noninternal_network_is_rejected(self) -> None:
        self.edit("docker-compose.staging-isolation.yml", "internal: true", "internal: false")
        self.assertIn("[FAIL] Isolation -", self.run_validator(1))

    def test_foreign_env_file_is_rejected_before_its_contents_are_read(self) -> None:
        self.edit(
            "docker-compose.staging.yml",
            "  web:\n",
            "  web:\n    env_file: ../aegis-missing-foreign.env\n",
        )
        output = self.run_validator(1)
        self.assertIn("[PASS] Compose -", output)
        self.assertIn("[FAIL] Isolation -", output)

    def test_non_loopback_console_is_rejected(self) -> None:
        self.edit("docker-compose.staging.yml", "127.0.0.1:3200:3000", "0.0.0.0:3200:3000")
        self.assertIn("[FAIL] Ports -", self.run_validator(1))

    def test_preflight_image_cannot_rebuild(self) -> None:
        self.edit("docker-compose.staging-build.yml", "pull_policy: never", "pull_policy: build")
        self.assertIn("[FAIL] Image policy -", self.run_validator(1))

    def test_nonstaging_container_name_is_rejected(self) -> None:
        self.edit("docker-compose.staging.yml", "container_name: ${AEGIS_STAGING_NAMESPACE:-aegis-stage}-postgres", "container_name: aisoc-postgres")
        self.assertIn("[FAIL] Isolation -", self.run_validator(1))

    def test_disabled_dependency_healthcheck_is_rejected(self) -> None:
        self.edit("docker-compose.staging.yml", "  redis:\n", "  redis:\n    healthcheck:\n      test: ['NONE']\n")
        self.assertIn("[FAIL] Dependencies -", self.run_validator(1))

    def test_litellm_model_must_match_the_cache_gate(self) -> None:
        self.edit(
            "docker-compose.staging-isolation.yml",
            "AISOC_LLM_MODEL_DEEP: ollama_chat/llama3.2:3b-instruct-q4_K_M",
            "AISOC_LLM_MODEL_DEEP: ollama_chat/unseeded-model",
        )
        self.assertIn("[FAIL] Ollama cache gate -", self.run_validator(1))

    def test_ollama_registry_pull_is_rejected(self) -> None:
        self.edit("docker-compose.staging-isolation.yml", '"ollama", "show"', '"ollama", "pull"')
        self.assertIn("[FAIL] Ollama cache gate -", self.run_validator(1))



class CIStagingValidatorTests(StagingFixture):
    @classmethod
    def setUpClass(cls) -> None:
        cls.docker = shutil.which("docker")
        if not cls.docker:
            raise unittest.SkipTest("Docker CLI is required")
        compose = subprocess.run([cls.docker, "compose", "version"], capture_output=True, check=False)
        if compose.returncode:
            raise unittest.SkipTest("Docker Compose plugin is required")

    def model(self) -> dict:
        self.fixture_env["AEGIS_STAGING_NAMESPACE"] = "aegis-ci-123-1"
        dotenv = "".join(f"{name}={value}\n" for name, value in self.fixture_env.items())
        (self.root / ".env").write_text(dotenv, encoding="utf-8")
        cmd = [self.docker, "compose", "-p", "aegis-ci-123-1", "--env-file", ".env"]
        for file in COMPOSE_FILES:
            cmd.extend(("-f", file))
        result = subprocess.run(
            [*cmd, "config", "--no-env-resolution", "--format", "json"],
            cwd=self.root,
            env={
                **{key: os.environ[key] for key in ("PATH", "HOME", "SystemRoot", "WINDIR",
                                                   "USERPROFILE", "LOCALAPPDATA", "APPDATA",
                                                   "TEMP", "TMP") if key in os.environ},
                "COMPOSE_PROFILES": "",
            },
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, "Synthetic Compose model did not resolve")
        return json.loads(result.stdout)

    def test_ci_isolation_and_dependency_set(self) -> None:
        validate_model(self.model(), self.root.resolve(), "aegis-ci-123-1")

    def test_ci_refuses_unisolated_network(self) -> None:
        self.edit("docker-compose.staging-isolation.yml", "internal: true", "internal: false")
        with self.assertRaisesRegex(SmokeError, "internal bridge"):
            validate_model(self.model(), self.root.resolve(), "aegis-ci-123-1")

    def test_ci_refuses_added_dependency(self) -> None:
        self.edit("docker-compose.staging.yml", "  web:\n", "  web:\n    depends_on:\n      - actions\n")
        with self.assertRaisesRegex(SmokeError, "Unexpected dependencies for web"):
            validate_model(self.model(), self.root.resolve(), "aegis-ci-123-1")

    def test_ci_refuses_foreign_bind(self) -> None:
        model = self.model()
        model["services"]["web"]["volumes"] = [
            {"type": "bind", "source": str(self.root.parent), "target": "/outside", "read_only": True}
        ]
        with self.assertRaisesRegex(SmokeError, "Unsafe bind mount"):
            validate_model(model, self.root.resolve(), "aegis-ci-123-1")

    def test_ci_refuses_an_extra_host_port(self) -> None:
        self.edit("docker-compose.staging.yml", "127.0.0.1:3200:3000", "0.0.0.0:3200:3000")
        with self.assertRaisesRegex(SmokeError, "Unexpected console port"):
            validate_model(self.model(), self.root.resolve(), "aegis-ci-123-1")


if __name__ == "__main__":
    unittest.main()
