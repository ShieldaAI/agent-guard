"""Exercise ownership and secret-file boundaries without starting Docker."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run-pilot.py"
spec = importlib.util.spec_from_file_location("pilot_runner", SCRIPT)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


@pytest.mark.parametrize("version", ["27.5.1", "", "unknown", "28", "29.5.2 extra"])
def test_unsafe_or_unrecognized_daemon_cannot_start_containers(tmp_path, monkeypatch, version):
    database = pilot.Database(tmp_path / "database")
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return version

    monkeypatch.setattr(pilot.helpers, "docker", docker)
    with pytest.raises(RuntimeError, match="PILOT_DOCKER_28_REQUIRED"):
        database.start()
    assert calls == [("version", "--format", "{{.Server.Version}}")]


@pytest.mark.parametrize("version", ["28.0.0", "29.5.2", "28.5.1+vendor.1"])
def test_supported_daemon_versions(monkeypatch, version):
    monkeypatch.setattr(pilot.helpers, "docker", lambda *args: version)
    assert pilot.helpers.require_private_port_support() == version


def test_private_configuration_never_overwrites_existing_file(tmp_path):
    path = tmp_path / "config.json"
    pilot.private_json(path, {"private": "canary"})
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == {"private": "canary"}
    with pytest.raises(FileExistsError):
        pilot.private_json(path, {"private": "replacement"})
    assert "canary" in path.read_text()
    target = tmp_path / "link"
    target.symlink_to(path)
    with pytest.raises(FileExistsError):
        pilot.private_json(target, {"private": "replacement"})


def test_cleanup_refuses_a_foreign_resource_even_if_compose_project_matches(tmp_path, monkeypatch):
    database = pilot.Database(tmp_path / "database")
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("container", "inspect"):
            return json.dumps([{"Config": {"Labels": {pilot.LABEL: "somebody-else"}}}])
        return "container-id"

    monkeypatch.setattr(pilot.helpers, "docker", docker)
    with pytest.raises(RuntimeError, match="PILOT_CLEANUP_OWNER_MISMATCH"):
        database.close()
    assert not any("down" in args or "rm" in args for args in calls)
    assert (tmp_path / "database/neo4j-auth.txt").stat().st_mode & 0o777 == 0o600
    assert database.password not in repr(calls)


def test_cleanup_checks_each_resource_kind_before_removing_owned_project(tmp_path, monkeypatch):
    database = pilot.Database(tmp_path / "database")
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        if "inspect" in args:
            labels = {pilot.LABEL: database.run_id}
            return json.dumps([{"Config": {"Labels": labels}, "Labels": labels}])
        return "owned-resource" if "ls" in args or "ps" in args else ""

    monkeypatch.setattr(pilot.helpers, "docker", docker)
    database.close()
    inspected = [args[0] for args in calls if "inspect" in args]
    assert inspected == ["container", "volume", "network"]
    assert calls[-1][-3:] == ("down", "--volumes", "--remove-orphans")
    assert os.path.isabs(database.env["PILOT_AUTH_FILE"])
