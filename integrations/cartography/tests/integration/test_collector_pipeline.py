"""Real executor observer -> bounded Python collector -> protected archive -> Neo4j."""

import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from agent_guard_cartography.archive import SnapshotArchive
from agent_guard_cartography.collector import collect_snapshot, validate_enrollment
from agent_guard_cartography.publish import collect_and_publish, retire_obsolete

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[4]


def read_line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(timeout=15), "Child did not return a bounded response"
    line = process.stdout.readline()
    assert line, "Child closed without a response"
    return json.loads(line)


@pytest.fixture
def observer():
    node = shutil.which("node")
    assert node is not None, "Build Node packages before integration validation"
    process = subprocess.Popen(
        [node, str(Path(__file__).parents[1] / "fixtures" / "serve-observer.mjs")],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        config = read_line(process)
        enrollment = validate_enrollment(
            {
                "source": config["source"],
                "profile": config["profile"],
                "endpoint": config["endpoint"],
                "tokenEnv": "GUARD_COLLECTOR_TEST_TOKEN",
                "timeoutSeconds": 3,
            }
        )
        yield process, config, enrollment
    finally:
        if process.poll() is None:
            process.stdin.write("close\n")
            process.stdin.flush()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def cli_config(tmp_path, config):
    connection = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())
    enrollment_path = tmp_path / "enrollment.json"
    enrollment_path.write_text(
        json.dumps(
            {
                "source": config["source"],
                "profile": config["profile"],
                "endpoint": config["endpoint"],
                "tokenEnv": "GUARD_COLLECTOR_TEST_TOKEN",
                "timeoutSeconds": 3,
            }
        )
    )
    command = [
        sys.executable,
        "-m",
        "agent_guard_cartography.cli",
        "--enrollment",
        str(enrollment_path),
        "--archive-dir",
        str(tmp_path / "archive"),
        "--neo4j-uri",
        connection["uri"],
        "--neo4j-password-env-var",
        "GUARD_DATABASE_TEST_PASSWORD",
        "--lock-file",
        str(tmp_path / "ingest.lock"),
    ]
    environment = {
        **os.environ,
        "GUARD_DATABASE_TEST_PASSWORD": connection["password"],
        "GUARD_COLLECTOR_TEST_TOKEN": config["token"],
    }
    return command, environment


def current(session, source_id):
    return session.run(
        "MATCH (s:GuardSource {id:$id}) RETURN s.current_snapshot_id AS id", id=source_id
    ).single(strict=True)["id"]


def test_live_observer_collection_revocation_and_scoped_retention(
    neo4j_session, observer, tmp_path
):
    process, config, enrollment = observer
    with SnapshotArchive(tmp_path / "archive") as archive:
        first = collect_and_publish(neo4j_session, enrollment, config["token"], archive)
        process.stdin.write("revoke\n")
        process.stdin.flush()
        assert read_line(process)["status"] == "ok"
        second = collect_and_publish(neo4j_session, enrollment, config["token"], archive)
        third = collect_and_publish(neo4j_session, enrollment, config["token"], archive)
        assert (
            current(neo4j_session, first.import_result.source_id)
            == third.import_result.projection_id
        )
        task = neo4j_session.run(
            "MATCH (t:GuardTask {projection_id:$id}) RETURN t.revoked AS revoked",
            id=second.import_result.projection_id,
        ).single(strict=True)
        assert task["revoked"] is True
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {id:$id}) SET p.published_at_ms=0",
            id=first.import_result.projection_id,
        ).consume()
        assert (
            retire_obsolete(
                neo4j_session, first.import_result.source_id, minimum_retention_seconds=60
            )
            == 1
        )
        counts = neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source}) RETURN p.id AS id,p.status AS status",
            source=first.import_result.source_id,
        ).data()
        assert {row["id"]: row["status"] for row in counts} == {
            first.import_result.projection_id: "retired",
            second.import_result.projection_id: "published",
            third.import_result.projection_id: "published",
        }
        for filename in (tmp_path / "archive").iterdir():
            content = filename.read_bytes()
            for secret in [config["token"], "private-description-canary", "private-alias-canary"]:
                assert secret.encode() not in content


def test_cli_replays_pending_after_restart_and_failure_preserves_current(
    neo4j_session, observer, tmp_path
):
    _process, config, enrollment = observer
    with SnapshotArchive(tmp_path / "archive") as archive:
        receipt = archive.store(collect_snapshot(enrollment, config["token"]))
    command, environment = cli_config(tmp_path, config)
    # The original process could have crashed after durable store or after a graph commit.
    replay_command = [*command, "--replay-receipt", receipt.receipt_id]
    replay_environment = {
        key: value for key, value in environment.items() if key != "GUARD_COLLECTOR_TEST_TOKEN"
    }
    first = subprocess.run(
        replay_command, env=replay_environment, capture_output=True, text=True, timeout=30
    )
    assert first.returncode == 0, first.stderr
    published = json.loads(first.stdout)
    assert published["import_result"]["published"]
    second = subprocess.run(
        replay_command, env=replay_environment, capture_output=True, text=True, timeout=30
    )
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)["import_result"]["idempotent"]
    bad = subprocess.run(
        command,
        env={**environment, "GUARD_COLLECTOR_TEST_TOKEN": "agi_v1." + "x" * 43},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert bad.returncode == 2
    assert current(neo4j_session, receipt.source_id) == published["import_result"]["projection_id"]
    with SnapshotArchive(tmp_path / "archive") as archive:
        health = archive.read_health(enrollment.source, enrollment.profile)
        assert health["lastError"] is not None
        assert health["lastSnapshotId"] == receipt.snapshot_id
    assert (
        config["token"]
        not in first.stdout + first.stderr + second.stdout + second.stderr + bad.stderr
    )
    assert (
        environment["GUARD_DATABASE_TEST_PASSWORD"]
        not in first.stdout + first.stderr + second.stdout + second.stderr + bad.stderr
    )


def test_polling_worker_holds_lock_between_polls_and_releases_on_shutdown(observer, tmp_path):
    _process, config, _enrollment = observer
    command, environment = cli_config(tmp_path, config)
    watcher = subprocess.Popen(
        [*command, "--watch"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert read_line(watcher)["status"] == "complete"
        overlapping = subprocess.run(
            command, env=environment, capture_output=True, text=True, timeout=20
        )
        assert overlapping.returncode == 2
        assert "INGESTION_ALREADY_RUNNING" in overlapping.stderr
        watcher.send_signal(signal.SIGINT)
        watcher.communicate(timeout=10)
        assert watcher.returncode == 0
        restarted = subprocess.run(
            command, env=environment, capture_output=True, text=True, timeout=30
        )
        assert restarted.returncode == 0, restarted.stderr
    finally:
        if watcher.poll() is None:
            watcher.kill()
            watcher.communicate(timeout=5)


def test_multiple_enrollments_continue_after_one_scope_failure(neo4j_session, observer, tmp_path):
    _process, config, _enrollment = observer
    command, environment = cli_config(tmp_path, config)
    bad = json.loads((tmp_path / "enrollment.json").read_text())
    bad["source"]["sourceId"] = "another-unenrolled-executor"
    bad_path = tmp_path / "bad-enrollment.json"
    bad_path.write_text(json.dumps(bad))
    command[command.index("--enrollment") + 1] = str(bad_path)
    command += ["--enrollment", str(tmp_path / "enrollment.json")]
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
    assert json.loads(result.stderr)["code"] == "COLLECTOR_SCOPE_MISMATCH"
    published = json.loads(result.stdout)
    assert published["import_result"]["published"] is True
    assert (
        current(neo4j_session, published["import_result"]["source_id"])
        == published["import_result"]["projection_id"]
    )
    assert config["token"] not in result.stdout + result.stderr
