"""Exercise readiness deadlines against local sockets without starting Docker."""

import builtins
import importlib.util
import json
import socket
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import Neo4jError, ServiceUnavailable, SessionExpired

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "test-disposable-neo4j.py"
spec = importlib.util.spec_from_file_location("disposable_neo4j_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_silent_bolt_peer_cannot_consume_the_default_sixty_second_acquisition_deadline():
    release = threading.Event()
    handshake = bytearray()
    failures = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        uri = f"bolt://127.0.0.1:{listener.getsockname()[1]}"

        def silent_peer():
            try:
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(5)
                    while len(handshake) < 20:
                        chunk = connection.recv(20 - len(handshake))
                        if not chunk:
                            return
                        handshake.extend(chunk)
                    # A finite fallback also makes the old implementation fail
                    # promptly instead of hanging the test for sixty seconds.
                    release.wait(5)
            except (OSError, TimeoutError) as exc:
                failures.append(exc)

        peer = threading.Thread(target=silent_peer, daemon=True)
        peer.start()
        started = time.monotonic()
        try:
            with pytest.raises(RuntimeError, match="did not become ready"):
                # One attempt is enough: the peer accepts TCP but never sends
                # the Bolt handshake response. No database or auth is involved.
                runner.wait_ready(uri, "unused-test-password", None, timeout=1)
            elapsed = time.monotonic() - started
            assert elapsed < 4, f"Silent Bolt handshake exceeded its attempt bound: {elapsed:.2f}s"
        finally:
            release.set()
            peer.join(timeout=2)
        assert not peer.is_alive()
        assert not failures
        assert len(handshake) == 20 and handshake[:4] == b"\x60\x60\xb0\x17"


def test_readiness_retries_connectivity_then_requires_a_successful_database_query(monkeypatch):
    driver = MagicMock()
    driver.__enter__.return_value = driver
    driver.verify_connectivity.side_effect = [ServiceUnavailable("still starting"), None]
    session = driver.session.return_value.__enter__.return_value
    monkeypatch.setattr(runner.GraphDatabase, "driver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(runner.time, "sleep", lambda _duration: None)

    runner.wait_ready("bolt://127.0.0.1:1", "unused-test-password", None, timeout=1)

    assert driver.verify_connectivity.call_count == 2
    driver.session.assert_called_once_with(database="neo4j")
    session.run.assert_called_once_with("RETURN 1 AS ready")
    session.run.return_value.consume.assert_called_once_with()
    driver.__exit__.assert_called_once()


def test_readiness_timeout_preserves_safe_cause_without_connection_details(monkeypatch):
    driver = MagicMock()
    driver.__enter__.return_value = driver
    driver.verify_connectivity.side_effect = ServiceUnavailable("private-password@private-host")
    monkeypatch.setattr(runner.GraphDatabase, "driver", lambda *_args, **_kwargs: driver)
    clock = iter([0, 0, 121, 121])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(runner.time, "sleep", lambda _duration: None)
    with pytest.raises(runner.ReadinessTimeout) as failed:
        runner.wait_ready("bolt://private-host", "private-password", None)
    assert failed.value.diagnostics == {
        "code": "PILOT_NEO4J_READINESS_TIMEOUT",
        "attempts": 1,
        "elapsedSeconds": 121,
        "lastFailure": "service-unavailable",
    }
    assert "private-" not in str(failed.value)
    assert "private-" not in json.dumps(failed.value.diagnostics)
    driver.__exit__.assert_called_once()


@pytest.mark.parametrize("completed", [120, 120.25])
def test_successful_probe_at_or_after_deadline_is_not_ready(monkeypatch, completed):
    driver = MagicMock()
    driver.__enter__.return_value = driver
    session = driver.session.return_value.__enter__.return_value
    clock = iter([0, 0, completed])
    monkeypatch.setattr(runner.GraphDatabase, "driver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))

    with pytest.raises(runner.ReadinessTimeout) as failed:
        runner.wait_ready("bolt://private-canary", "private-canary", None)

    assert failed.value.diagnostics == {
        "code": "PILOT_NEO4J_READINESS_TIMEOUT",
        "attempts": 1,
        "elapsedSeconds": completed,
        "lastFailure": "probe-completed-after-deadline",
    }
    session.run.return_value.consume.assert_called_once_with()
    driver.__exit__.assert_called_once()


def test_successful_probe_before_deadline_retains_elapsed_measurement(monkeypatch):
    driver = MagicMock()
    driver.__enter__.return_value = driver
    clock = iter([0, 0, 119.75])
    monkeypatch.setattr(runner.GraphDatabase, "driver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    assert runner.wait_ready("bolt://private-canary", "private-canary", None) == {
        "attempts": 1,
        "elapsedSeconds": 119.75,
    }


def test_failure_container_diagnostics_require_owner_and_allowlist_fields(monkeypatch):
    info = {
        "Config": {"Labels": {runner.LABEL: "our-run"}, "Env": ["SECRET=private-canary"]},
        "State": {
            "Running": False,
            "OOMKilled": True,
            "ExitCode": 137,
            "Error": "private-canary",
            "Status": "private-canary",
        },
    }
    monkeypatch.setattr(runner, "docker", lambda *_args, **_kwargs: json.dumps([info]))
    assert runner.owned_container_state("owned-container", "our-run") == {
        "available": True,
        "running": False,
        "oomKilled": True,
        "exitCode": 137,
    }
    assert runner.owned_container_state("owned-container", "other-run") == {
        "available": False,
        "reason": "owner-mismatch",
    }


@pytest.mark.parametrize(
    "inspected",
    [
        None,
        "private-canary",
        [],
        [None],
        [{"Config": None}],
        [{"Config": {"Labels": None}}],
        [{"Config": {"Labels": "private-canary"}}],
        [{"Config": {"Labels": {runner.LABEL: "our-run"}}, "State": None}],
    ],
)
def test_malformed_failure_diagnostics_cannot_prevent_cleanup(monkeypatch, inspected):
    monkeypatch.setattr(runner, "docker", lambda *_args, **_kwargs: json.dumps(inspected))
    assert runner.owned_container_state("owned-container", "our-run") == {
        "available": False,
        "reason": "invalid-state",
    }


@pytest.fixture
def owned_main(monkeypatch):
    """Exercise the actual runner/cleanup path with no Docker or child process."""
    run_id = "b" * 32
    harness = SimpleNamespace(calls=[], mode="normal", removed=False, tunnel=None)
    info = {
        "Id": "a" * 64,
        "Config": {"Labels": {runner.LABEL: run_id}, "Env": ["private-canary"]},
        "State": {
            "Running": False,
            "OOMKilled": True,
            "ExitCode": 137,
            "Error": "private-canary",
        },
    }

    def docker(*args, **_kwargs):
        harness.calls.append(args)
        if args[0] == "run":
            return info["Id"]
        if args[0] == "port":
            return "127.0.0.1:12345"
        if args[0] == "inspect":
            if harness.mode == "inspect-failed":
                raise subprocess.CalledProcessError(1, ["private-canary"])
            if harness.mode == "malformed-inspection":
                return json.dumps([{"Config": {"Labels": None}, "State": None}])
            if harness.mode == "owner-mismatch":
                info["Config"]["Labels"][runner.LABEL] = "someone-else"
            return json.dumps([info])
        if args[0] == "rm":
            assert args == ("rm", "--force", "--volumes", info["Id"])
            if harness.mode == "remove-failed":
                raise subprocess.CalledProcessError(1, ["private-canary"])
            harness.removed = True
            return info["Id"]
        if args[0] == "ps":
            assert args == (
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"id={info['Id']}",
                "--format",
                "{{.ID}}",
            )
            if harness.mode == "absence-unavailable":
                raise subprocess.CalledProcessError(1, ["private-canary"])
            return info["Id"] if harness.mode == "still-present" else ""
        pytest.fail("Unexpected Docker command; logs must never be collected")

    monkeypatch.setattr(runner, "docker", docker)
    monkeypatch.setattr(runner.sys, "argv", [str(SCRIPT), "--", "-q"])
    monkeypatch.setattr(runner.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(runner.uuid, "uuid4", lambda: SimpleNamespace(hex=run_id))
    monkeypatch.setattr(runner.secrets, "token_urlsafe", lambda *_args: "private-canary")
    monkeypatch.setattr(runner, "require_private_port_support", lambda: "29.4.2")
    monkeypatch.setattr(
        runner, "loopback_uri", lambda *_args: ("bolt://private-canary", harness.tunnel)
    )
    harness.readiness = MagicMock(return_value={"attempts": 2, "elapsedSeconds": 1.25})
    monkeypatch.setattr(runner, "wait_ready", harness.readiness)
    driver = MagicMock()
    driver.__enter__.return_value = driver
    harness.driver = driver
    monkeypatch.setattr(runner.GraphDatabase, "driver", lambda *_args, **_kwargs: driver)
    harness.pytest = MagicMock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(runner.subprocess, "run", harness.pytest)
    return harness


def test_runner_readiness_failure_reports_owned_exit_before_verified_cleanup(owned_main, capsys):
    owned_main.readiness.side_effect = runner.ReadinessTimeout(48, 120.4, "service-unavailable")
    assert runner.main() == 1
    captured = capsys.readouterr()
    failure, cleanup = [json.loads(line) for line in captured.err.splitlines()]
    assert failure == {
        "kind": "disposable-neo4j-setup",
        "stage": "database-readiness",
        "status": "failed",
        "reason": "readiness-timeout",
        "readiness": {
            "code": "PILOT_NEO4J_READINESS_TIMEOUT",
            "attempts": 48,
            "elapsedSeconds": 120.4,
            "lastFailure": "service-unavailable",
        },
        "containerStateAtFailure": {
            "available": True,
            "running": False,
            "oomKilled": True,
            "exitCode": 137,
        },
    }
    assert cleanup == {
        "kind": "disposable-neo4j-cleanup",
        "containerCleanupAttempted": True,
        "containerRemovalConfirmed": True,
        "tunnelClosedConfirmed": True,
    }
    assert [call[0] for call in owned_main.calls] == [
        "run",
        "port",
        "inspect",
        "inspect",
        "rm",
        "ps",
    ]
    launch = owned_main.calls[0]
    assert "--rm" not in launch
    assert launch[launch.index("--memory") + 1] == "1g"
    assert launch[launch.index("--cpus") + 1] == "2"
    assert launch[launch.index("--tmpfs") + 1] == "/data:rw,size=384m"
    assert "private-canary" not in captured.out + captured.err
    assert len(captured.err) < 2048
    owned_main.pytest.assert_not_called()


@pytest.mark.parametrize(
    "mode",
    [
        "inspect-failed",
        "malformed-inspection",
        "owner-mismatch",
        "remove-failed",
        "absence-unavailable",
        "still-present",
    ],
)
def test_runner_cannot_pass_when_cleanup_is_unconfirmed(owned_main, capsys, mode):
    owned_main.mode = mode
    assert runner.main() == 1
    captured = capsys.readouterr()
    cleanup = json.loads(captured.err)
    assert cleanup["containerCleanupAttempted"] is True
    assert cleanup["containerRemovalConfirmed"] is False
    assert "private-canary" not in captured.out + captured.err
    owned_main.pytest.assert_called_once()
    if mode in {"inspect-failed", "malformed-inspection", "owner-mismatch"}:
        assert not any(call[0] == "rm" for call in owned_main.calls)


def test_runner_success_requires_tests_and_verified_removal(owned_main, capsys):
    assert runner.main() == 0
    captured = capsys.readouterr()
    assert json.loads(captured.err)["containerRemovalConfirmed"] is True
    assert "private-canary" not in captured.out + captured.err
    owned_main.pytest.assert_called_once()


def test_runner_preserves_nonzero_test_exit_after_verified_cleanup(owned_main, capsys):
    owned_main.pytest.return_value.returncode = 5
    assert runner.main() == 5
    captured = capsys.readouterr()
    failure, cleanup = [json.loads(line) for line in captured.err.splitlines()]
    assert failure["stage"] == "integration-tests"
    assert failure["reason"] == "test-process-failed"
    assert cleanup["containerRemovalConfirmed"] is True


def test_runner_generic_setup_failure_does_not_print_exception_or_logs(owned_main, capsys):
    owned_main.readiness.side_effect = RuntimeError("private-canary")
    assert runner.main() == 1
    captured = capsys.readouterr()
    failure, cleanup = [json.loads(line) for line in captured.err.splitlines()]
    assert failure["reason"] == "setup-error"
    assert "readiness" not in failure
    assert cleanup["containerRemovalConfirmed"] is True
    assert "private-canary" not in captured.out + captured.err


@pytest.mark.parametrize("error_type", [Neo4jError, ServiceUnavailable, SessionExpired])
@pytest.mark.parametrize("failure_point", ["driver", "query"])
def test_marker_driver_failure_is_safe_and_still_cleans_up(
    owned_main, monkeypatch, capsys, error_type, failure_point
):
    failure = error_type("private-canary bolt://user:private-password@private-host:7687")
    if failure_point == "driver":
        monkeypatch.setattr(runner.GraphDatabase, "driver", MagicMock(side_effect=failure))
    else:
        session = owned_main.driver.session.return_value.__enter__.return_value
        session.run.side_effect = failure

    assert runner.main() == 1
    captured = capsys.readouterr()
    report, cleanup = [json.loads(line) for line in captured.err.splitlines()]
    assert report["stage"] == "ownership-marker"
    assert report["reason"] == "database-error"
    assert report["status"] == "failed"
    assert cleanup["containerRemovalConfirmed"] is True
    assert "private-" not in captured.out + captured.err
    assert "bolt://" not in captured.out + captured.err
    owned_main.pytest.assert_not_called()


def test_tunnel_cleanup_failure_still_attempts_container_removal(owned_main, capsys):
    owned_main.tunnel = MagicMock()
    owned_main.tunnel.terminate.side_effect = OSError("private-canary")
    assert runner.main() == 1
    captured = capsys.readouterr()
    cleanup = json.loads(captured.err)
    assert cleanup["tunnelClosedConfirmed"] is False
    assert cleanup["containerRemovalConfirmed"] is True
    assert "private-canary" not in captured.out + captured.err


def test_directory_cleanup_error_after_passing_tests_cannot_pass(
    owned_main, monkeypatch, tmp_path, capsys
):
    directory = MagicMock()
    directory.__enter__.return_value = str(tmp_path)
    directory.__exit__.side_effect = OSError("private-canary")
    monkeypatch.setattr(runner.tempfile, "TemporaryDirectory", lambda **_kwargs: directory)
    assert runner.main() == 1
    captured = capsys.readouterr()
    failure, cleanup = [json.loads(line) for line in captured.err.splitlines()]
    assert failure["reason"] == "io-error"
    assert cleanup["containerRemovalConfirmed"] is True
    assert "private-canary" not in captured.out + captured.err
    owned_main.pytest.assert_called_once()


def test_failure_reporting_error_does_not_replace_interrupt_or_prevent_cleanup(
    owned_main, monkeypatch, capsys
):
    owned_main.readiness.side_effect = KeyboardInterrupt()

    def print_with_failed_diagnostic(value, **kwargs):
        if json.loads(value)["kind"] == "disposable-neo4j-setup":
            raise OSError("private-canary")
        builtins.print(value, **kwargs)

    monkeypatch.setattr(runner, "print", print_with_failed_diagnostic, raising=False)
    assert runner.main() == 130
    captured = capsys.readouterr()
    assert json.loads(captured.err)["containerRemovalConfirmed"] is True
    assert "private-canary" not in captured.out + captured.err
