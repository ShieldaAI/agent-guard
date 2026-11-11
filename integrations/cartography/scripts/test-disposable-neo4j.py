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
from neo4j.exceptions import (
    AuthError,
    ConnectionAcquisitionTimeoutError,
    DriverError,
    Neo4jError,
    ServiceUnavailable,
    SessionExpired,
)

ROOT = Path(__file__).resolve().parents[1]
LABEL = "com.shielda.agent-guard.disposable-test"
CONFIG_ENV = "AGENT_GUARD_TEST_NEO4J_CONFIG"


def neo4j_initial_password() -> str:
    """Keep all 256 random bits while avoiding an option-like admin argument."""
    # The pinned Docker entrypoint passes the password to neo4j-admin without
    # an end-of-options marker. A URL-safe token can begin with a hyphen.
    return "guard-" + secrets.token_urlsafe(32)


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


def remove_owned_container(name: str, run_id: str) -> bool:
    """Remove only our container; confirm absence rather than guessing after errors."""
    try:
        inspected = json.loads(docker("inspect", name))
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        return False
    info = inspected[0]
    config = info.get("Config")
    if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict):
        return False
    if config["Labels"].get(LABEL) != run_id:
        raise RuntimeError("Refusing to remove a container with a different test owner")
    if not isinstance(info.get("Id"), str) or not re.fullmatch(r"[0-9a-f]{64}", info["Id"]):
        return False
    docker("rm", "--force", "--volumes", info["Id"], timeout=45)
    remaining = docker(
        "ps",
        "--all",
        "--no-trunc",
        "--filter",
        f"id={info['Id']}",
        "--format",
        "{{.ID}}",
        timeout=5,
    )
    return not remaining


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


class ReadinessTimeout(RuntimeError):
    """Safe diagnostics only: never retain a driver message, URI or credential."""

    def __init__(self, attempts: int, elapsed: float, last_failure: str):
        super().__init__("Disposable Neo4j did not become ready before its deadline")
        self.diagnostics = {
            "code": "PILOT_NEO4J_READINESS_TIMEOUT",
            "attempts": attempts,
            "elapsedSeconds": round(elapsed, 3),
            "lastFailure": last_failure,
        }


def database_error_type(error: BaseException) -> str:
    """Fixed driver categories, never exception text or arbitrary class names."""
    for kind, category in (
        (ConnectionAcquisitionTimeoutError, "connection-acquisition-timeout"),
        (ServiceUnavailable, "service-unavailable"),
        (SessionExpired, "session-expired"),
        (AuthError, "authentication-error"),
        (Neo4jError, "database-error"),
        (DriverError, "driver-error"),
    ):
        if isinstance(error, kind):
            return category
    return "other-error"


def owned_container_state(name: str, run_id: str) -> dict:
    """Allowlisted lifecycle fields from this run's container, never logs or env."""
    try:
        inspected = json.loads(docker("inspect", name, timeout=5))
        if (
            not isinstance(inspected, list)
            or len(inspected) != 1
            or not isinstance(inspected[0], dict)
        ):
            return {"available": False, "reason": "invalid-state"}
        info = inspected[0]
        config, state = info.get("Config"), info.get("State")
        if (
            not isinstance(config, dict)
            or not isinstance(config.get("Labels"), dict)
            or not isinstance(state, dict)
        ):
            return {"available": False, "reason": "invalid-state"}
        if config["Labels"].get(LABEL) != run_id:
            return {"available": False, "reason": "owner-mismatch"}
        if (
            type(state.get("Running")) is not bool
            or type(state.get("OOMKilled")) is not bool
            or type(state.get("ExitCode")) is not int
            or not 0 <= state["ExitCode"] <= 255
        ):
            return {"available": False, "reason": "invalid-state"}
        return {
            "available": True,
            "running": state["Running"],
            "oomKilled": state["OOMKilled"],
            "exitCode": state["ExitCode"],
        }
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError):
        return {"available": False, "reason": "inspect-failed"}


def wait_ready(
    uri: str, password: str, tunnel: subprocess.Popen | None, timeout: float = 120
) -> dict:
    started = time.monotonic()
    deadline = started + timeout
    attempts = 0
    last_failure = "no-attempt"
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
                attempts += 1
                driver.verify_connectivity()
                with driver.session(database="neo4j") as session:
                    session.run("RETURN 1 AS ready").consume()
                completed = time.monotonic()
                # The acquisition limit does not bound the complete query. A
                # probe finishing late must not turn a missed deadline into PASS.
                if completed >= deadline:
                    raise ReadinessTimeout(
                        attempts, completed - started, "probe-completed-after-deadline"
                    )
                return {
                    "attempts": attempts,
                    "elapsedSeconds": round(completed - started, 3),
                }
            except (
                Neo4jError,
                ServiceUnavailable,
                ConnectionAcquisitionTimeoutError,
                OSError,
            ) as exc:
                if isinstance(exc, ConnectionAcquisitionTimeoutError):
                    last_failure = "connection-acquisition-timeout"
                elif isinstance(exc, ServiceUnavailable):
                    last_failure = "service-unavailable"
                elif isinstance(exc, OSError):
                    last_failure = "io-error"
                elif getattr(exc, "code", None) in (
                    "Neo.ClientError.Security.Unauthorized",
                    "Neo.ClientError.Security.AuthenticationRateLimit",
                    "Neo.ClientError.Security.CredentialsExpired",
                ):
                    last_failure = "authentication-rejected"
                else:
                    last_failure = "database-error"
                time.sleep(0.5)
    raise ReadinessTimeout(attempts, time.monotonic() - started, last_failure)


def main() -> int:
    image = (ROOT / "neo4j-image.txt").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"neo4j:5\.26\.\d+-community@sha256:[0-9a-f]{64}", image):
        raise RuntimeError("The test image must be pinned by version and SHA256 digest")
    pytest_args = sys.argv[1:]
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]
    run_id = uuid.uuid4().hex
    name = f"agent-guard-neo4j-test-{run_id}"
    password = neo4j_initial_password()
    env = os.environ.copy()
    env["NEO4J_AUTH"] = f"neo4j/{password}"
    tunnel = None
    stage = "container-preflight"
    readiness = None
    result_code = 1

    def report_failure(reason: str, error: BaseException | None = None) -> None:
        # Fixed fields and coarse categories only; no exception text, logs,
        # environment, connection details or Docker's unfiltered inspection.
        try:
            report = {
                "kind": "disposable-neo4j-setup",
                "stage": stage,
                "status": "failed",
                "reason": reason,
                "containerStateAtFailure": owned_container_state(name, run_id),
            }
            if isinstance(error, ReadinessTimeout):
                report["readiness"] = error.diagnostics
            elif readiness is not None:
                report["readiness"] = readiness
            if isinstance(error, (Neo4jError, DriverError)):
                report["databaseErrorType"] = database_error_type(error)
            print(json.dumps(report, allow_nan=False), file=sys.stderr, flush=True)
        except (OSError, ValueError, TypeError):
            # Reporting cannot replace the original failure or prevent finally.
            pass

    def interrupted(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"Signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        require_private_port_support()
        stage = "container-start"
        container_id = docker(
            "run",
            "--detach",
            # Keep an exited container inspectable until label-checked finally
            # cleanup. An uncatchable kill can leave this private owned fixture;
            # it must never be mistaken for confirmed cleanup.
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
        stage = "listener-validation"
        address = docker("port", container_id, "7687/tcp")
        if not re.fullmatch(r"127\.0\.0\.1:\d+", address):
            raise RuntimeError("The disposable Bolt listener is not restricted to loopback")
        with tempfile.TemporaryDirectory(prefix="agent-guard-neo4j-") as directory:
            stage = "loopback-connection"
            uri, tunnel = loopback_uri(address, Path(directory))
            stage = "database-readiness"
            readiness = wait_ready(uri, password, tunnel)
            stage = "ownership-marker"
            with GraphDatabase.driver(uri, auth=("neo4j", password)) as driver:
                with driver.session(database="neo4j") as session:
                    session.run(
                        "CREATE (:GuardDisposableTestRun {id: $runId})", runId=run_id
                    ).consume()
            print(f"Testing against disposable {image.split('@')[0]}", flush=True)
            stage = "test-configuration"
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
            stage = "integration-tests"
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/integration", *pytest_args],
                cwd=ROOT,
                env=test_env,
                check=False,
            )
            result_code = result.returncode
            if result_code:
                report_failure("test-process-failed")
    except KeyboardInterrupt:
        result_code = 130
        report_failure("interrupted")
    except (
        subprocess.SubprocessError,
        RuntimeError,
        OSError,
        Neo4jError,
        DriverError,
    ) as exc:
        result_code = result_code or 1
        reason = (
            "readiness-timeout"
            if isinstance(exc, ReadinessTimeout)
            else "subprocess-error"
            if isinstance(exc, subprocess.SubprocessError)
            else "io-error"
            if isinstance(exc, OSError)
            else "database-error"
            if isinstance(exc, (Neo4jError, DriverError))
            else "setup-error"
        )
        report_failure(reason, exc)
    finally:
        tunnel_closed = tunnel is None
        try:
            if tunnel is not None:
                tunnel.terminate()
                try:
                    tunnel.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    tunnel.kill()
                    tunnel.wait(timeout=5)
                tunnel_closed = True
        except (OSError, subprocess.SubprocessError):
            pass
        # Also handles interrupted docker run. Inspection failure, owner mismatch,
        # removal failure or unavailable absence verification remain unconfirmed.
        removed = False
        try:
            removed = remove_owned_container(name, run_id)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass
        if not removed or not tunnel_closed:
            result_code = result_code or 1
        try:
            print(
                json.dumps(
                    {
                        "kind": "disposable-neo4j-cleanup",
                        "containerCleanupAttempted": True,
                        "containerRemovalConfirmed": removed,
                        "tunnelClosedConfirmed": tunnel_closed,
                    }
                ),
                file=sys.stderr,
                flush=True,
            )
        except OSError:
            result_code = result_code or 1
    return result_code


if __name__ == "__main__":
    raise SystemExit(main())
