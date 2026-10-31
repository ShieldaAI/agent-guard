#!/usr/bin/env python3
"""Run integration tests only against a new, private, disposable Neo4j container.

Use the integration's Python environment. Arguments following ``--`` are passed
to pytest. No existing database URL, password or container can be supplied.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

ROOT = Path(__file__).resolve().parents[1]
LABEL = "com.shielda.agent-guard.disposable-test"
CONFIG_ENV = "AGENT_GUARD_TEST_NEO4J_CONFIG"


def docker(*args: str, timeout: float = 30, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["docker", *args],
        check=True,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env,
    )
    return result.stdout.strip()


def require_private_port_support() -> str:
    """Older daemons can expose loopback-published ports to the local network."""
    version = docker("version", "--format", "{{.Server.Version}}")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?", version)
    if match is None or int(match[1]) < 28:
        raise RuntimeError("PILOT_DOCKER_28_REQUIRED")
    return version


def remove_owned_container(name: str, run_id: str) -> None:
    """Never remove a container unless its unique ownership label matches."""
    try:
        info = json.loads(docker("inspect", name))[0]
    except (subprocess.SubprocessError, ValueError, IndexError):
        return
    if info.get("Config", {}).get("Labels", {}).get(LABEL) != run_id:
        raise RuntimeError("Refusing to remove a container with a different test owner")
    docker("rm", "--force", "--volumes", info["Id"], timeout=45)


def loopback_uri(address: str, directory: Path) -> tuple[str, subprocess.Popen | None]:
    """Colima's VM loopback listeners need a dedicated host loopback tunnel."""
    context = docker("context", "show")
    if sys.platform != "darwin" or not (context == "colima" or context.startswith("colima-")):
        return f"bolt://{address}", None
    profile = "default" if context == "colima" else context.removeprefix("colima-")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", profile):
        raise RuntimeError("Invalid Colima profile name")
    config_text = subprocess.run(
        ["colima", "ssh-config", profile],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout
    hosts = re.findall(r"^Host\s+(\S+)\s*$", config_text, re.MULTILINE)
    if len(hosts) != 1 or not re.search(
        r"^\s+Hostname 127\.0\.0\.1\s*$", config_text, re.MULTILINE
    ):
        raise RuntimeError("Colima SSH config must point to one local virtual machine")
    ssh_config = directory / "ssh.config"
    ssh_config.write_text(config_text, encoding="utf-8")
    ssh_config.chmod(0o600)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        host_port = listener.getsockname()[1]
    tunnel = subprocess.Popen(
        [
            "ssh",
            "-F",
            str(ssh_config),
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ExitOnForwardFailure=yes",
            "-N",
            "-L",
            f"127.0.0.1:{host_port}:{address}",
            hosts[0],
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return f"bolt://127.0.0.1:{host_port}", tunnel


def wait_ready(
    uri: str, password: str, tunnel: subprocess.Popen | None, timeout: float = 120
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no connection attempt completed"
    with GraphDatabase.driver(
        uri,
        auth=("neo4j", password),
        connection_timeout=2,
        # TCP connect can succeed while Bolt is still starting. The acquisition
        # deadline, not connection_timeout, bounds that handshake exchange.
        connection_acquisition_timeout=2,
        max_transaction_retry_time=0,
    ) as driver:
        while time.monotonic() < deadline:
            if tunnel is not None and tunnel.poll() is not None:
                raise RuntimeError("Colima loopback tunnel terminated before Neo4j became ready")
            try:
                driver.verify_connectivity()
                with driver.session(database="neo4j") as session:
                    session.run("RETURN 1 AS ready").consume()
                return
            except (Neo4jError, ServiceUnavailable, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.5)
    raise RuntimeError(f"Disposable Neo4j did not become ready within 120 seconds: {last_error}")


def main() -> int:
    image = (ROOT / "neo4j-image.txt").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"neo4j:5\.26\.\d+-community@sha256:[0-9a-f]{64}", image):
        raise RuntimeError("The test image must be pinned by version and SHA256 digest")
    pytest_args = sys.argv[1:]
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]
    run_id = uuid.uuid4().hex
    name = f"agent-guard-neo4j-test-{run_id}"
    password = secrets.token_urlsafe(32)
    env = os.environ.copy()
    env["NEO4J_AUTH"] = f"neo4j/{password}"
    tunnel = None

    def interrupted(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"Signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        require_private_port_support()
        container_id = docker(
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "--label",
            f"{LABEL}={run_id}",
            "--publish",
            "127.0.0.1::7687",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--pids-limit",
            "256",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/data:rw,size=384m",
            "--env",
            "NEO4J_AUTH",
            "--env",
            "NEO4J_server_memory_heap_initial__size=256m",
            "--env",
            "NEO4J_server_memory_heap_max__size=256m",
            "--env",
            "NEO4J_server_memory_pagecache_size=128m",
            "--env",
            "NEO4J_dbms_usage__report_enabled=false",
            "--env",
            "NEO4J_db_tx__log_preallocate=false",
            "--env",
            "NEO4J_db_tx__log_rotation_size=16m",
            image,
            timeout=240,
            env=env,
        )
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("Docker returned an invalid disposable container identifier")
        address = docker("port", container_id, "7687/tcp")
        if not re.fullmatch(r"127\.0\.0\.1:\d+", address):
            raise RuntimeError("The disposable Bolt listener is not restricted to loopback")
        with tempfile.TemporaryDirectory(prefix="agent-guard-neo4j-") as directory:
            uri, tunnel = loopback_uri(address, Path(directory))
            wait_ready(uri, password, tunnel)
            with GraphDatabase.driver(uri, auth=("neo4j", password)) as driver:
                with driver.session(database="neo4j") as session:
                    session.run(
                        "CREATE (:GuardDisposableTestRun {id: $runId})", runId=run_id
                    ).consume()
            print(f"Testing against disposable {image.split('@')[0]} on {uri}", flush=True)
            config = Path(directory) / "connection.json"
            config.write_text(
                json.dumps(
                    {
                        "containerId": container_id,
                        "runId": run_id,
                        "image": image,
                        "uri": uri,
                        "dockerPort": address.rsplit(":", 1)[1],
                        "username": "neo4j",
                        "password": password,
                    }
                ),
                encoding="utf-8",
            )
            config.chmod(0o600)
            test_env = os.environ.copy()
            # Tests may only use the owned container in this temporary config.
            for key in tuple(test_env):
                if key.startswith("NEO4J_") or key == CONFIG_ENV:
                    test_env.pop(key)
            test_env[CONFIG_ENV] = str(config)
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/integration", *pytest_args],
                cwd=ROOT,
                env=test_env,
                check=False,
            )
            return result.returncode
    except KeyboardInterrupt:
        return 130
    except (subprocess.SubprocessError, RuntimeError, OSError) as exc:
        # Do not print command environments or authentication material.
        reason = str(exc).replace(password, "[redacted]")
        print(
            f"Disposable Neo4j test setup failed: {type(exc).__name__}: {reason}", file=sys.stderr
        )
        try:
            tail = docker("logs", "--tail", "30", name)
            if tail:
                print(tail.replace(password, "[redacted]"), file=sys.stderr)
        except subprocess.SubprocessError:
            pass
        return 1
    finally:
        if tunnel is not None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)
        # Label verification also handles interrupted `docker run` outcomes.
        remove_owned_container(name, run_id)


if __name__ == "__main__":
    raise SystemExit(main())
