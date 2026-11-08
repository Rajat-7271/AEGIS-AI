"""Build and test the isolated staging web target on a disposable hosted runner."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from check_published_secrets import COMPOSE_REQUIRED_RE, offending, published_literals

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.staging.yml",
    "docker-compose.staging-build.yml",
    "docker-compose.staging-isolation.yml",
)
PREFLIGHT = "preflight-secrets"
GATE = {PREFLIGHT: "service_completed_successfully"}
DEPENDENCIES = {
    PREFLIGHT: {},
    "postgres": GATE,
    "redis": GATE,
    "zookeeper": GATE,
    "kafka": {**GATE, "zookeeper": "service_healthy"},
    "api": {**GATE, **dict.fromkeys(("kafka", "postgres", "redis"), "service_healthy")},
    "realtime": {**GATE, **dict.fromkeys(("kafka", "redis"), "service_healthy")},
    "web": {**GATE, **dict.fromkeys(("api", "realtime"), "service_started")},
}
BUILDS = {"api": "aegis-stage-api:local", "web": "aegis-stage-web:local", "realtime": "aegis-stage-realtime:local"}
STORES = {
    "postgres": "postgres:16-alpine",
    "redis": "redis:7-alpine",
    "zookeeper": "confluentinc/cp-zookeeper:7.5.0",
    "kafka": "confluentinc/cp-kafka:7.5.0",
}
BUILD_CONTEXTS = {
    "api": ("services/api", "Dockerfile"),
    "web": (".", "apps/web/Dockerfile"),
    "realtime": ("services/realtime", "Dockerfile"),
}
VOLUMES = {"postgres_data", "redis_data", "zookeeper_data", "zookeeper_log", "kafka_data"}
GIB = 1024**3


class SmokeError(Exception):
    """An error with a message safe for the Actions log."""


def require(condition, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def validate_model(model: dict, root: Path, project: str) -> None:
    """Check the effective Compose model before allowing any CI Docker writes."""
    require(model["name"] == project, "Unexpected Compose project.")
    services = model["services"]
    networks = model["networks"]
    require(set(networks) == {"aisoc", "default"}, "Unexpected staging network set.")
    for name, network in networks.items():
        require(
            network.get("internal") is True
            and not network.get("external")
            and network["name"] == f"{project}_{name}"
            and network.get("driver", "bridge") == "bridge"
            and not network.get("driver_opts"),
            "Expected project-owned internal bridge networks.",
        )
    for name, volume in model["volumes"].items():
        require(
            volume["name"] == f"{project}_{name}"
            and not volume.get("external")
            and volume.get("driver", "local") == "local"
            and not volume.get("driver_opts"),
            "Expected project-owned local volumes.",
        )
    used_volumes = set()
    names = set()
    for name, expected in DEPENDENCIES.items():
        service = services.get(name, {})
        edges = service.get("depends_on", {})
        require(
            {key: edge["condition"] for key, edge in edges.items()} == expected
            and all(edge.get("required", True) for edge in edges.values()),
            f"Unexpected dependencies for {name}.",
        )
        if name in (*STORES, "api"):
            probe = service.get("healthcheck", {})
            require(probe.get("test") and probe["test"][0] != "NONE" and not probe.get("disable"),
                    f"Missing readiness probe for {name}.")
        container = service.get("container_name", "")
        require(container.startswith(f"{project}-") and container not in names, "Unexpected container name.")
        names.add(container)
        require(set(service.get("networks", {})) == {"default" if name == PREFLIGHT else "aisoc"},
                f"Unexpected network attachment for {name}.")
        unsafe = ("network_mode", "privileged", "volumes_from", "env_file", "extra_hosts", "devices",
                  "pid", "ipc", "use_api_socket", "cap_add", "secrets", "configs")
        require(not any(service.get(key) for key in unsafe), f"Unsafe runtime options for {name}.")
        ports = service.get("ports", [])
        if name == "web":
            actual = [(p["host_ip"], str(p["published"]), p["target"], p["protocol"]) for p in ports]
            require(actual == [("127.0.0.1", "3200", 3000, "tcp")], "Unexpected console port binding.")
        else:
            require(not ports, f"Unexpected published port for {name}.")
        for mount in service.get("volumes", []):
            if mount["type"] == "volume":
                source = mount.get("source")
                require(source in model["volumes"], "Unexpected anonymous or undeclared volume.")
                used_volumes.add(source)
            else:
                source = Path(mount["source"]).resolve()
                require(mount["type"] == "bind" and mount.get("read_only") and source.is_relative_to(root),
                        f"Unsafe bind mount for {name}.")
        image = BUILDS.get(name, BUILDS["api"] if name == PREFLIGHT else STORES.get(name))
        require(service["image"] == image, f"Unexpected smoke image for {name}.")
        if name not in STORES:
            require(service.get("pull_policy") == "never",
                    f"Expected a local-only image for {name}.")
        build = service.get("build")
        require(bool(build) == (name in BUILDS), f"Unexpected build scope for {name}.")
        if build:
            context, dockerfile = BUILD_CONTEXTS[name]
            require(
                Path(build["context"]).resolve() == root / context
                and build["dockerfile"] == dockerfile
                and not any(build.get(key) for key in ("ssh", "secrets", "additional_contexts")),
                f"Unexpected build inputs for {name}.",
            )
    require(used_volumes == VOLUMES, "Unexpected smoke volume set.")
    pre = services[PREFLIGHT]
    require(
        pre["entrypoint"] == ["python3", "/repo/scripts/check_published_secrets.py", "--check-env"]
        and pre["restart"] == "no"
        and pre["environment"]["AISOC_REPO_ROOT"] == "/repo"
        and len(pre["volumes"]) == 1
        and pre["volumes"][0]["target"] == "/repo"
        and Path(pre["volumes"][0]["source"]).resolve() == root,
        "Unexpected preflight command or mount.",
    )
    web = services["web"]["environment"]
    require(web["API_URL"] == "http://api:8000" and web["REALTIME_URL"] == "http://realtime:4000",
            "Web must use the isolated API and realtime routes.")


def guarded_names() -> set[str]:
    return {
        name
        for file in FILES
        for line in (ROOT / file).read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
        for name in COMPOSE_REQUIRED_RE.findall(line)
    }


def runner_environment() -> tuple[str, Path]:
    require(
        sys.platform == "linux" and os.getenv("GITHUB_ACTIONS") == "true"
        and os.getenv("RUNNER_ENVIRONMENT") == "github-hosted",
        "This smoke test only runs on a GitHub-hosted Linux runner.",
    )
    run, attempt = (os.environ[key] for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    require(run.isascii() and run.isdecimal() and attempt.isascii() and attempt.isdecimal(),
            "Unexpected Actions run identity.")
    project = f"aegis-ci-{run}-{attempt}"
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(temp.is_dir() and not temp.is_relative_to(ROOT), "Expected a runner temp directory outside the checkout.")
    return project, temp / project


def docker(*args: str, operation: str, timeout: int = 60) -> str:
    # Only use the runner's local socket. Keep inherited Compose values, Docker
    # contexts and credentials out of the Docker CLI environment.
    _, scratch = runner_environment()
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "COMPOSE_PROFILES": "",
        "DOCKER_CONFIG": str(scratch / "docker-config"),
    }
    try:
        result = subprocess.run(
            ["docker", "--host", "unix:///var/run/docker.sock", *args],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise SmokeError(f"{operation} timed out.") from None
    if result.returncode:
        raw = (result.stdout + result.stderr).lower()
        categories = {
            "no space left on device": "disk exhausted",
            "out of memory": "out of memory",
            "unhealthy": "a dependency became unhealthy",
            "address already in use": "port already in use",
            "permission denied": "permission denied",
            "connection refused": "connection refused",
        }
        detail = next((value for key, value in categories.items() if key in raw), "output withheld")
        raise SmokeError(f"{operation} failed with exit {result.returncode} ({detail}).")
    return result.stdout.strip()


def check_capacity(memory_gib: int, disk_gib: int) -> None:
    engine = json.loads(docker("info", "--format", "{{json .}}", operation="Read Docker capacity"))
    memory = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemAvailable:"))
    disk = shutil.disk_usage(engine["DockerRootDir"]).free
    print(f"Available runner RAM: {memory / GIB:.1f} GiB; Docker storage free: {disk / GIB:.1f} GiB.")
    require(
        engine["OSType"] == "linux" and engine["MemTotal"] >= 8 * GIB and engine["NCPU"] >= 2
        and memory >= memory_gib * GIB and disk >= disk_gib * GIB,
        f"Runner headroom insufficient (need {memory_gib} GiB available RAM and {disk_gib} GiB free Docker storage).",
    )


def resource_names(kind: str, project: str) -> list[str]:
    query = ("ps", "-a", "--no-trunc") if kind == "container" else (kind, "ls")
    field = {"container": "ID", "network": "Name", "volume": "Name"}[kind]
    return docker(
        *query, "--filter", f"label=com.docker.compose.project={project}", "--format", "{{." + field + "}}",
        operation=f"List CI {kind} resources",
    ).splitlines()


def collect_states(project: str) -> dict[str, tuple[str, int]]:
    states = {}
    for container in resource_names("container", project):
        fields = docker(
            "inspect", "--type", "container", "--format",
            '{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{.State.ExitCode}}|'
            '{{.State.OOMKilled}}|{{.RestartCount}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}',
            container, operation="Read sanitized container state",
        ).split("|")
        service, state, exit_code, oom, restarts, health = fields
        require(service in DEPENDENCIES and service not in states, "Unexpected CI container service.")
        require(state in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
                and exit_code.isdecimal() and oom in {"true", "false"} and restarts.isdecimal()
                and health in {"none", "healthy", "unhealthy", "starting"}, "Unexpected diagnostic format.")
        print(f"{service}: {state}, exit={exit_code}, health={health}, OOM={oom}, restarts={restarts}")
        states[service] = (state, int(exit_code))
    return states


def verify_runtime_isolation(project: str, model: dict) -> None:
    containers = set(resource_names("container", project))
    networks = set(resource_names("network", project))
    volumes = set(resource_names("volume", project))
    require(networks == {f"{project}_aisoc", f"{project}_default"}, "Unexpected runtime network set.")
    require(volumes == {f"{project}_{volume}" for volume in VOLUMES}, "Unexpected runtime volume set.")
    for network in networks:
        internal, driver, members = docker(
            "network", "inspect", network, "--format", "{{.Internal}}|{{.Driver}}|{{json .Containers}}",
            operation="Verify runtime network isolation",
        ).split("|", 2)
        require(internal == "true" and driver == "bridge"
                and set(json.loads(members) or {}).issubset(containers), "Unexpected network member or driver.")
    for service in DEPENDENCIES:
        network = "default" if service == PREFLIGHT else "aisoc"
        name = model["services"][service]["container_name"]
        attached = docker(
            "inspect", "--type", "container", name, "--format", "{{json .NetworkSettings.Networks}}",
            operation="Verify runtime container attachment",
        )
        require(set(json.loads(attached)) == {f"{project}_{network}"}, "Unexpected container network attachment.")
        published = docker(
            "inspect", "--type", "container", name, "--format", "{{json .NetworkSettings.Ports}}",
            operation="Verify runtime port isolation",
        )
        bindings = {port: value for port, value in (json.loads(published) or {}).items() if value}
        require(
            not bindings or (service == "web" and bindings == {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3200"}]}),
            "Unexpected runtime host port.",
        )
    print("Runtime isolation verified for the eight-service smoke set.")


def smoke(project: str, scratch: Path) -> None:
    scratch.mkdir(mode=0o700)
    (scratch / "docker-config").mkdir(mode=0o700)
    envfile = scratch / "ci.env"
    guarded = guarded_names()
    require({"AISOC_CREDENTIAL_KEY", "LITELLM_MASTER_KEY", "POSTGRES_PASSWORD"}.issubset(guarded),
            "Expected staging credential guards.")
    generated = {name: secrets.token_hex(32) for name in guarded}
    generated["LITELLM_MASTER_KEY"] = "sk-" + generated["LITELLM_MASTER_KEY"]
    generated["AISOC_CREDENTIAL_KEY"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    with envfile.open("x", encoding="utf-8") as output:
        envfile.chmod(0o600)
        output.write(f"AEGIS_STAGING_NAMESPACE={project}\n")
        for name, value in sorted(generated.items()):
            print(f"::add-mask::{value}")
            output.write(f"{name}={value}\n")
    compose = ["compose", "--project-directory", str(ROOT), "-p", project, "--env-file", str(envfile)]
    for file in FILES:
        compose.extend(("-f", file))
    model = json.loads(docker(*compose, "config", "--no-env-resolution", "--format", "json",
                              operation="Resolve Compose configuration"))
    validate_model(model, ROOT, project)
    published = published_literals(ROOT)
    preflight = model["services"][PREFLIGHT]["environment"]
    require(all(preflight.get(name) == value for name, value in generated.items()),
            "Preflight is missing generated credential wiring.")
    require(not any(offending(model["services"][name].get("environment", {}), published) for name in DEPENDENCIES),
            "A smoke service uses a published credential default.")
    check_capacity(memory_gib=6, disk_gib=8)
    require(not docker("ps", "-aq", operation="Verify empty runner container inventory"),
            "Runner already has containers. Refusing to start the smoke test.")
    for kind in ("network", "volume"):
        existing = docker(kind, "ls", "--format", "{{.Name}}", operation=f"Check {kind} names")
        require(not any(name.startswith(f"{project}_") for name in existing.splitlines()),
                f"Runner already has project {kind} resources.")
    docker(*compose, "--parallel", "1", "build", *BUILDS, operation="Build API, web, and realtime", timeout=1500)
    docker(*compose, "--parallel", "1", "pull", *STORES, operation="Pull staging datastores", timeout=360)
    check_capacity(memory_gib=4, disk_gib=3)
    # Cleanup may touch labelled resources only after verifying a fresh namespace.
    (scratch / "startup-authorized").touch(exist_ok=False)
    docker(*compose, "up", "-d", "--no-build", "--pull", "never", "--no-recreate",
           "--wait", "--wait-timeout", "240", "web", operation="Start isolated web target", timeout=360)
    states = collect_states(project)
    require(set(states) == DEPENDENCIES.keys() and states[PREFLIGHT] == ("exited", 0)
            and all(state == "running" for name, (state, _) in states.items() if name != PREFLIGHT),
            "The eight-service set or preflight result differed from expectations.")
    verify_runtime_isolation(project, model)
    # Validate the response contract, not just HTTP status: a reverse proxy
    # or an error page returning 200 must not count as a ready API.
    for path, expected in (("/livez", "alive"), ("/readyz", "ready")):
        docker(
            *compose, "exec", "-T", "api", "python", "-c",
            "import json,sys,urllib.request; "
            "r=urllib.request.urlopen('http://127.0.0.1:8000'+sys.argv[1], timeout=5); "
            "assert r.status == 200 and 'application/json' in r.headers.get('Content-Type',''); "
            "body=json.load(r); "
            "assert isinstance(body,dict) and body.get('status')==sys.argv[2] "
            "and isinstance(body.get('service'),str) and body['service']",
            path, expected, operation=f"Verify API {path} response contract",
        )
        print(f"API {path}: HTTP 200 with {expected} JSON contract")
    # A container with only internal networks has no gateway for publishing ports.
    # Probe the real Next server and its realtime rewrite from web's own loopback.
    for path in ("/api/health", "/api/v1/realtime/healthz"):
        docker(
            *compose, "exec", "-T", "web", "node", "-e",
            "(async () => { "
            "for (let i=0; i<8; i++) { try { "
            "const r=await fetch('http://127.0.0.1:3000'+process.argv[1], "
            "{redirect:'manual',signal:AbortSignal.timeout(2500)}); "
            "if (r.status===200) return; "
            "} catch {} await new Promise(resolve => setTimeout(resolve, 1000)); } "
            "process.exitCode=1; })();",
            path, operation=f"Verify {path}",
        )
        print(f"{path}: HTTP 200")


def cleanup(project: str, scratch: Path) -> None:
    try:
        if not (scratch / "startup-authorized").is_file():
            return
        try:
            collect_states(project)
        finally:
            for kind in ("container", "network", "volume"):
                names = resource_names(kind, project)
                if kind != "container":
                    require(all(name.startswith(f"{project}_") for name in names),
                            f"Unexpected labelled {kind} name. Refusing removal.")
                if names:
                    flags = ("-f",) if kind == "container" else ()
                    docker(kind, "rm", *flags, *names, operation=f"Remove CI {kind} resources")
                require(not resource_names(kind, project), f"CI {kind} resources remain after cleanup.")
            (scratch / "startup-authorized").unlink()
            print("CI containers, networks, and volumes removed.")
    finally:
        (scratch / "ci.env").unlink(missing_ok=True)


def main() -> int:
    try:
        project, scratch = runner_environment()
        if sys.argv[1:] == ["--cleanup"]:
            cleanup(project, scratch)
        elif not sys.argv[1:]:
            smoke(project, scratch)
        else:
            raise SmokeError("Unexpected smoke arguments.")
    except SmokeError as error:
        print(f"::error::{error}")
        return 1
    except Exception as error:
        # Exceptions from JSON, env files or subprocesses may contain raw values.
        print(f"::error::Unexpected staging failure ({type(error).__name__}). Details withheld.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
