"""Capture real pilot orchestration failures without Docker, secrets or retries."""

import importlib.util
import json
from pathlib import Path

import pytest


def load_pilot():
    script = Path(__file__).resolve().parents[2] / "scripts" / "run-pilot.py"
    spec = importlib.util.spec_from_file_location("live_pilot_failure_test", script)
    pilot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pilot)
    return pilot


def failed_start(
    monkeypatch, tmp_path, *, empty_ps=False, cleanup_failure=False, inspection="owned"
):
    pilot = load_pilot()
    output = tmp_path / "failed.json"
    monkeypatch.setattr(
        pilot.sys,
        "argv",
        ["run-pilot.py", "--directory", str(tmp_path / "state"), "--output", str(output)],
    )
    monkeypatch.setattr(pilot.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(pilot.helpers, "require_private_port_support", lambda: "29.4.2")
    monkeypatch.setattr(
        pilot.helpers, "neo4j_initial_password", lambda: "guard-private-password-canary"
    )
    monkeypatch.setattr(
        pilot.helpers, "loopback_uri", lambda *_args: ("bolt://private-uri-canary", None)
    )
    calls = []
    state = {"removed": False, "project": None, "run_id": None, "inspected_before_remove": False}

    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == "compose":
            state["project"] = args[args.index("--project-name") + 1]
            state["run_id"] = kwargs["env"]["PILOT_RUN_ID"]
            if "ps" in args:
                return "" if empty_ps else "a" * 64
            if "port" in args:
                return "127.0.0.1:12345"
            if "down" in args:
                if cleanup_failure:
                    raise RuntimeError("private-cleanup-canary")
                state["removed"] = True
            return ""
        if "inspect" in args:
            labels = {pilot.LABEL: state["run_id"], "com.docker.compose.project": state["project"]}
            if args[0] == "inspect":
                assert not state["removed"]
                state["inspected_before_remove"] = True
                if inspection == "foreign":
                    labels[pilot.LABEL] = "foreign-owner"
                if inspection == "malformed":
                    return json.dumps([{"Config": None, "State": None}])
            return json.dumps(
                [
                    {
                        "Id": "a" * 64,
                        "Config": {"Labels": labels, "Env": ["private-env-canary"]},
                        "Labels": labels,
                        "State": {
                            "Running": False,
                            "OOMKilled": False,
                            "ExitCode": 64,
                            "Error": "private-error-canary",
                        },
                    }
                ]
            )
        if args[0] == "ps":
            return "" if state["removed"] else "a" * 64
        if args[0] in ("volume", "network") and "ls" in args:
            return "" if state["removed"] else "owned-resource"
        raise AssertionError("Unexpected Docker operation")

    def readiness(*_args):
        raise pilot.helpers.ReadinessTimeout(240, 120.157, "service-unavailable")

    monkeypatch.setattr(pilot.helpers, "docker", docker)
    monkeypatch.setattr(pilot.helpers, "wait_ready", readiness)
    return pilot, output, calls, state


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_live_readiness_failure_is_saved_before_cleanup_without_losing_original_cause(
    monkeypatch, tmp_path, capsys, cleanup_failure
):
    pilot, output, calls, state = failed_start(
        monkeypatch, tmp_path, cleanup_failure=cleanup_failure
    )
    assert pilot.main() == 1
    report = json.loads(output.read_text())
    assert output.stat().st_mode & 0o777 == 0o600
    assert report["status"] == "failed" and report["stage"] == "original-database-start"
    assert report["failureCategory"] == "readiness-timeout"
    assert report["readiness"] == {
        "code": "PILOT_NEO4J_READINESS_TIMEOUT",
        "attempts": 240,
        "elapsedSeconds": 120.157,
        "lastFailure": "service-unavailable",
    }
    assert report["databases"] == [
        {
            "role": "original",
            "stage": "database-readiness",
            "containerStateAtFailure": {
                "available": True,
                "running": False,
                "oomKilled": False,
                "exitCode": 64,
            },
        }
    ]
    assert state["inspected_before_remove"] is True
    assert report["cleanupFailed"] is cleanup_failure
    assert report["cleanup"]["databases"] == [
        {"role": "original", "attempted": True, "absenceVerified": not cleanup_failure}
    ]
    assert any("down" in call for call in calls)
    assert not any("logs" in call for call in calls)
    captured = capsys.readouterr()
    for value in [output.read_text(), captured.out, captured.err]:
        assert "private-" not in value and "bolt://" not in value
    assert "PILOT_FAILED" in captured.err


def test_exited_owned_container_is_discovered_when_compose_ps_returns_empty(monkeypatch, tmp_path):
    pilot, output, calls, state = failed_start(monkeypatch, tmp_path, empty_ps=True)
    assert pilot.main() == 1
    report = json.loads(output.read_text())
    assert report["failureCategory"] == "setup-error"
    assert report["databases"][0]["stage"] == "listener-validation"
    assert report["databases"][0]["containerStateAtFailure"]["exitCode"] == 64
    lookup = next(call for call in calls if call[0] == "ps" and "--no-trunc" in call)
    assert f"label=com.docker.compose.project={state['project']}" in lookup
    assert f"label={pilot.LABEL}={state['run_id']}" in lookup
    assert report["cleanupFailed"] is False


@pytest.mark.parametrize(
    "inspection,reason", [("foreign", "owner-mismatch"), ("malformed", "invalid-state")]
)
def test_live_failure_never_trusts_foreign_or_malformed_container_state(
    monkeypatch, tmp_path, inspection, reason
):
    pilot, output, _, _ = failed_start(monkeypatch, tmp_path, inspection=inspection)
    assert pilot.main() == 1
    report = json.loads(output.read_text())
    assert report["databases"][0]["containerStateAtFailure"] == {
        "available": False,
        "reason": reason,
    }
    assert "private-" not in output.read_text()


def test_live_failure_report_never_overwrites_existing_output(monkeypatch, tmp_path, capsys):
    pilot, output, _, _ = failed_start(monkeypatch, tmp_path)
    output.write_text("preserved-existing-evidence")
    assert pilot.main() == 1
    assert output.read_text() == "preserved-existing-evidence"
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "failed" and report["reportWriteFailed"] is True
