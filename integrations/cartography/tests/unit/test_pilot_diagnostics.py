"""Keep startup failure diagnostics useful without exporting private inputs."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("malformed_inspection", [False, True])
def test_benchmark_readiness_failure_retains_safe_stage_state_and_cleanup(
    monkeypatch, tmp_path, malformed_inspection
):
    script = Path(__file__).resolve().parents[2] / "scripts" / "benchmark-pilot.py"
    spec = importlib.util.spec_from_file_location("benchmark_pilot_diagnostics", script)
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    monkeypatch.setattr(benchmark, "REPOSITORY", tmp_path)
    built = tmp_path / "packages" / "agent-map" / "dist" / "index.js"
    built.parent.mkdir(parents=True)
    built.write_text("// Readiness failure must never invoke this fixture.\n")
    output = tmp_path / "failed.json"
    monkeypatch.setattr(benchmark.sys, "argv", [str(script), "--output", str(output)])
    monkeypatch.setattr(benchmark.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(benchmark.shutil, "which", lambda _name: "/private-canary/node")
    monkeypatch.setattr(benchmark.importlib.metadata, "version", lambda _name: "test-version")
    monkeypatch.setattr(benchmark.uuid, "uuid4", lambda: SimpleNamespace(hex="our-run"))
    monkeypatch.setattr(benchmark.runner, "require_private_port_support", lambda: "29.4.2")
    monkeypatch.setattr(
        benchmark.runner, "loopback_uri", lambda *_args: ("bolt://private-canary", None)
    )
    removed = []
    monkeypatch.setattr(
        benchmark.runner, "remove_owned_container", lambda *args: removed.append(args)
    )

    def docker(*args, **_kwargs):
        if args[0] == "run":
            assert "--rm" not in args
            assert args[args.index("--memory") + 1] == "4g"
            assert args[args.index("--cpus") + 1] == "4"
            return "a" * 64
        if args[0] == "port":
            return "127.0.0.1:12345"
        if args[0] == "ps":
            return ""
        assert args == ("inspect", "agent-guard-pilot-benchmark-our-run")
        if malformed_inspection:
            return json.dumps([{"Config": {"Labels": None}, "State": None}])
        return json.dumps(
            [
                {
                    "Config": {
                        "Labels": {benchmark.runner.LABEL: "our-run"},
                        "Env": ["private-canary"],
                    },
                    "State": {
                        "Running": False,
                        "OOMKilled": True,
                        "ExitCode": 137,
                        "Error": "private-canary",
                    },
                }
            ]
        )

    def fail_readiness(*_args):
        raise benchmark.runner.ReadinessTimeout(4, 120.4, "service-unavailable")

    monkeypatch.setattr(benchmark.runner, "docker", docker)
    monkeypatch.setattr(benchmark.runner, "wait_ready", fail_readiness)
    assert benchmark.main() == 1
    report = json.loads(output.read_text())
    assert report["passed"] is False
    assert report["stage"] == "database-readiness"
    assert report["readiness"]["code"] == "PILOT_NEO4J_READINESS_TIMEOUT"
    assert report["readiness"]["attempts"] == 4
    expected_state = (
        {"available": False, "reason": "invalid-state"}
        if malformed_inspection
        else {
            "available": True,
            "running": False,
            "oomKilled": True,
            "exitCode": 137,
        }
    )
    assert report["containerStateAtFailure"] == expected_state
    assert report["disposableCleanup"] is True
    assert "gates" not in report and "publicationSeconds" not in report
    assert removed == [("agent-guard-pilot-benchmark-our-run", "our-run")]
    assert "private-canary" not in output.read_text()
