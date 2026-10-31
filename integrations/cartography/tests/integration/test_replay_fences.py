"""Normal collector receipt replay cannot bypass durable recovery/lifecycle fences."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from agent_guard_cartography.archive import REPLAY_PENDING, SnapshotArchive
from agent_guard_cartography.graph import import_snapshot
from agent_guard_cartography.lifecycle import preflight_transition

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("fence", ["recovery", "transition"])
@pytest.mark.parametrize("receipt_status", ["pending", "published"])
def test_cli_replay_refuses_fenced_archives_without_graph_or_evidence_changes(
    neo4j_session, snapshot_factory, tmp_path, fence, receipt_status
):
    before = snapshot_factory()
    imported = import_snapshot(neo4j_session, before, before["source"])
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        confirmed = archive.store(before)
        archive.record_result(confirmed.receipt_id, imported)
        if receipt_status == "pending":
            candidate = snapshot_factory("alpha-v2")
            target = archive.store(candidate)
        else:
            target = confirmed

        if fence == "transition":
            successor = deepcopy(before)
            successor["source"]["enrollmentGeneration"] = "replacement"
            successor["snapshotId"] = uuid4().hex
            replacement = import_snapshot(neo4j_session, successor, successor["source"])
            evidence = archive.store(successor)
            archive.record_result(evidence.receipt_id, replacement)
            transition = {
                "schemaVersion": 1,
                "predecessor": before["source"],
                "successor": successor["source"],
                "profile": before["profile"],
            }
            # Model an interruption after verified preflight and durable intent,
            # before the graph commits the retirement. The old graph is active.
            assert preflight_transition(neo4j_session, transition) is None
            archive.require_transition_evidence(transition)
            archive.stage_transition(transition)
        else:
            marker = folder / REPLAY_PENDING
            marker.write_text('{"schemaVersion":1}\n')
            marker.chmod(0o600)

    files_before = {path.name: path.read_bytes() for path in folder.iterdir()}

    def graph_state():
        return (
            neo4j_session.run(
                "MATCH (s:GuardSource {id:$source}) "
                "OPTIONAL MATCH (p:GuardSnapshot {source_id:$source}) "
                "RETURN properties(s) AS source,collect(properties(p)) AS snapshots",
                source=imported.source_id,
            )
            .single()
            .data()
        )

    graph_before = graph_state()
    enrollment = tmp_path / "enrollment.json"
    enrollment.write_text(
        json.dumps(
            {
                "source": before["source"],
                "profile": before["profile"],
                "endpoint": "http://127.0.0.1:8788/v1/inventory/snapshot",
                "tokenEnv": "TEST_REPLAY_FENCE_OBSERVER",
            }
        )
    )
    configuration = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_guard_cartography.cli",
            "--enrollment",
            str(enrollment),
            "--archive-dir",
            str(folder),
            "--replay-receipt",
            target.receipt_id,
            "--neo4j-uri",
            configuration["uri"],
            "--neo4j-password-env-var",
            "TEST_REPLAY_FENCE_PASSWORD",
            "--lock-file",
            str(tmp_path / "ingestion.lock"),
        ],
        cwd=ROOT,
        env={**os.environ, "TEST_REPLAY_FENCE_PASSWORD": configuration["password"]},
        capture_output=True,
        text=True,
        timeout=30,
    )
    expected = "ARCHIVE_RECOVERY_PENDING" if fence == "recovery" else "ARCHIVE_SOURCE_SUPERSEDED"
    assert process.returncode == 2, process.stderr
    assert expected in process.stderr and not process.stdout
    assert configuration["password"] not in process.stderr
    assert graph_state() == graph_before
    assert {path.name: path.read_bytes() for path in folder.iterdir()} == files_before
