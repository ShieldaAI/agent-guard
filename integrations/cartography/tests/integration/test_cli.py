"""Exercise the public file-import command against the owned test database."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_cli_import_and_replay(neo4j_session, snapshot_factory, tmp_path):
    snapshot = snapshot_factory()
    snapshot_file = tmp_path / "snapshot.json"
    enrollment_file = tmp_path / "source.json"
    snapshot_file.write_text(json.dumps(snapshot), encoding="utf-8")
    enrollment_file.write_text(json.dumps(snapshot["source"]), encoding="utf-8")
    connection = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())
    env = {**os.environ, "GUARD_TEST_DATABASE_PASSWORD": connection["password"]}
    command = [
        sys.executable,
        "-m",
        "agent_guard_cartography.cli",
        "--snapshot",
        str(snapshot_file),
        "--expected-source",
        str(enrollment_file),
        "--neo4j-uri",
        connection["uri"],
        "--neo4j-password-env-var",
        "GUARD_TEST_DATABASE_PASSWORD",
        "--lock-file",
        str(tmp_path / "collector.lock"),
    ]
    first = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
    assert first.returncode == 0, first.stderr
    receipt = json.loads(first.stdout)
    assert receipt["published"] and not receipt["idempotent"]
    source = neo4j_session.run(
        "MATCH (s:GuardSource {id:$id}) RETURN s.current_snapshot_id AS current",
        id=receipt["source_id"],
    ).single(strict=True)
    assert source["current"] == receipt["projection_id"]
    replay = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
    assert replay.returncode == 0, replay.stderr
    duplicate = json.loads(replay.stdout)
    assert duplicate["idempotent"] and not duplicate["published"]
    assert duplicate["projection_id"] == receipt["projection_id"]
    assert connection["password"] not in first.stdout + first.stderr + replay.stdout + replay.stderr
