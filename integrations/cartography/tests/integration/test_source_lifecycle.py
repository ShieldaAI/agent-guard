"""Actual atomic source supersession, replay fences and retained-row cleanup."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from test_reference_queries import query, scope
from test_reference_queries import reference_snapshot as reference_snapshot

from agent_guard_cartography.archive import SnapshotArchive
from agent_guard_cartography.graph import (
    GraphImportError,
    import_snapshot,
    retire_projection,
)
from agent_guard_cartography.lifecycle import (
    LifecycleError,
    preflight_transition,
    supersede_source,
    transition_id,
)
from agent_guard_cartography.publish import retire_obsolete, retire_superseded

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


def successor(snapshot, generation="replacement"):
    result = deepcopy(snapshot)
    result["source"].update(
        enrollmentGeneration=generation, inventoryInstanceId="ledger-" + generation
    )
    result["snapshotId"] = uuid4().hex
    if "manifest" in result:
        result["manifest"]["source"] = dict(result["source"])
    return result


def transition(before, after):
    return {
        "schemaVersion": 1,
        "predecessor": before["source"],
        "successor": after["source"],
        "profile": before["profile"],
    }


def state(session, identifier):
    return dict(session.run("MATCH (s:GuardSource {id:$id}) RETURN s", id=identifier).single()["s"])


@pytest.fixture
def pair(neo4j_session, snapshot_factory):
    before = snapshot_factory()
    after = successor(before)
    previous = import_snapshot(neo4j_session, before, before["source"])
    current = import_snapshot(neo4j_session, after, after["source"])
    return before, after, previous, current


def test_complete_replacement_is_atomic_idempotent_and_fences_known_and_new_receipts(
    neo4j_session, pair
):
    before, after, previous, current = pair
    value = transition(before, after)
    assert preflight_transition(neo4j_session, value) is None
    result = supersede_source(neo4j_session, value, timestamp_ms=123)
    assert result == {
        "schemaVersion": 1,
        "transitionId": transition_id(value),
        "predecessorSourceId": previous.source_id,
        "successorSourceId": current.source_id,
        "profile": "core",
        "supersededAtMs": 123,
    }
    original = state(neo4j_session, previous.source_id)
    assert original["lifecycle_status"] == "superseded"
    assert original["superseded_current_snapshot_id"] == previous.projection_id
    assert "current_snapshot_id" not in original and "previous_snapshot_id" not in original
    assert original["superseded_by"] == current.source_id
    assert state(neo4j_session, current.source_id)["current_snapshot_id"] == current.projection_id
    assert supersede_source(neo4j_session, value, timestamp_ms=456) == result
    assert preflight_transition(neo4j_session, value) == result
    for snapshot in (before, {**before, "snapshotId": uuid4().hex, "ledgerRevision": 2}):
        with pytest.raises(GraphImportError, match="^SOURCE_SUPERSEDED$"):
            import_snapshot(neo4j_session, snapshot, before["source"])
    fresh = {**after, "snapshotId": uuid4().hex, "ledgerRevision": 2}
    assert import_snapshot(neo4j_session, fresh, after["source"]).published


@pytest.mark.parametrize("failed_import", [False, True])
def test_missing_or_failed_replacement_preserves_active_predecessor(
    neo4j_session, snapshot_factory, failed_import
):
    before = snapshot_factory()
    previous = import_snapshot(neo4j_session, before, before["source"])
    after = successor(before)
    if failed_import:

        def fail_load():
            raise RuntimeError("controlled staging failure")

        with pytest.raises(RuntimeError, match="controlled staging failure"):
            import_snapshot(neo4j_session, after, after["source"], after_load=fail_load)
    for function in (preflight_transition, supersede_source):
        with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_(NOT_READY|SOURCE_MISSING)$"):
            function(neo4j_session, transition(before, after))
    original = state(neo4j_session, previous.source_id)
    assert original["current_snapshot_id"] == previous.projection_id
    assert "lifecycle_status" not in original


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("profile", "SOURCE_TRANSITION_PROFILE_MISMATCH"),
        ("scope", "SOURCE_TRANSITION_SCOPE_MISMATCH"),
        ("coverage", "SOURCE_TRANSITION_NOT_READY"),
        ("status", "SOURCE_LIFECYCLE_INVALID"),
    ],
)
def test_changed_source_or_incomplete_successor_cannot_retire_predecessor(
    neo4j_session, pair, mutation, code
):
    before, after, previous, current = pair
    queries = {
        "profile": "MATCH (s:GuardSource {id:$id}) SET s.profile='host'",
        "scope": "MATCH (s:GuardSource {id:$id}) SET s.tenant_id='foreign'",
        "coverage": "MATCH (s:GuardSource {id:$id}),(p:GuardSnapshot {id:s.current_snapshot_id}) SET p.coverage_json='{}'",
        "status": "MATCH (s:GuardSource {id:$id}) SET s.lifecycle_status='unrecognized'",
    }
    neo4j_session.run(queries[mutation], id=current.source_id).consume()
    with pytest.raises(LifecycleError, match=f"^{code}$"):
        supersede_source(neo4j_session, transition(before, after))
    original = state(neo4j_session, previous.source_id)
    assert original["current_snapshot_id"] == previous.projection_id
    assert "lifecycle_status" not in original


def test_chain_and_idempotent_retry_never_reactivate_a_superseded_generation(neo4j_session, pair):
    before, after, previous, current = pair
    third = successor(after, "third")
    latest = import_snapshot(neo4j_session, third, third["source"])
    first = supersede_source(neo4j_session, transition(before, after), timestamp_ms=123)
    with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_CONFLICT$"):
        supersede_source(neo4j_session, transition(after, before))
    supersede_source(neo4j_session, transition(after, third), timestamp_ms=456)
    assert supersede_source(neo4j_session, transition(before, after), timestamp_ms=789) == first
    for value in (transition(before, third), transition(third, before), transition(after, before)):
        with pytest.raises(LifecycleError, match="^SOURCE_TRANSITION_CONFLICT$"):
            supersede_source(neo4j_session, value)
    for old in (previous, current):
        assert "current_snapshot_id" not in state(neo4j_session, old.source_id)
    assert state(neo4j_session, latest.source_id)["current_snapshot_id"] == latest.projection_id


def test_supersession_between_staging_and_publication_fences_the_inflight_import(
    neo4j_session, pair
):
    before, after, previous, current = pair
    candidate = {**before, "snapshotId": uuid4().hex, "ledgerRevision": 2}
    with pytest.raises(GraphImportError, match="^SOURCE_SUPERSEDED$"):
        import_snapshot(
            neo4j_session,
            candidate,
            before["source"],
            after_load=lambda: supersede_source(neo4j_session, transition(before, after)),
        )
    old = state(neo4j_session, previous.source_id)
    assert old["superseded_current_snapshot_id"] == previous.projection_id
    assert "current_snapshot_id" not in old
    assert state(neo4j_session, current.source_id)["current_snapshot_id"] == current.projection_id
    assert (
        neo4j_session.run(
            "MATCH (p:GuardSnapshot {source_id:$source,snapshot_id:$snapshot}) RETURN p.status AS status",
            source=previous.source_id,
            snapshot=candidate["snapshotId"],
        ).single()["status"]
        == "failed"
    )


def test_retirement_waits_from_supersession_and_preserves_receipts_other_scopes_and_provider(
    neo4j_session, snapshot_factory, monkeypatch, tmp_path
):
    before = snapshot_factory()
    first = import_snapshot(neo4j_session, before, before["source"])
    updated = snapshot_factory("alpha-v2")
    previous = import_snapshot(neo4j_session, updated, updated["source"])
    after = successor(updated)
    current = import_snapshot(neo4j_session, after, after["source"])
    other = deepcopy(before)
    other["source"]["tenantId"] = "untouched-tenant"
    for task in other["tasks"]:
        task["tenantId"] = other["source"]["tenantId"]
    foreign = import_snapshot(neo4j_session, other, other["source"])
    provider = "lifecycle-provider-" + uuid4().hex
    neo4j_session.run("CREATE (:AWSRole {id:$id})", id=provider).consume()
    now = int(time.time() * 1000)
    neo4j_session.run(
        "MATCH (p:GuardSnapshot {source_id:$source}) SET p.published_at_ms=$old",
        source=previous.source_id,
        old=now - 120_000,
    ).consume()
    value = transition(updated, after)
    with SnapshotArchive(tmp_path / "archive") as archive:
        archive.stage_transition(value)
        result = supersede_source(neo4j_session, value, timestamp_ms=now)
        # Pending intent is never a maintenance instruction, even after graph commit.
        assert retire_superseded(neo4j_session, archive, minimum_retention_seconds=60) == 0
        archive.finish_transition(value, result)
        neo4j_session.run(
            "MATCH (s:GuardSource {id:$id}) SET s.superseded_at_ms=0", id=previous.source_id
        ).consume()
        assert retire_superseded(neo4j_session, archive, minimum_retention_seconds=60) == 0
        neo4j_session.run(
            "MATCH (s:GuardSource {id:$id}) SET s.superseded_at_ms=$timestamp",
            id=previous.source_id,
            timestamp=now,
        ).consume()
        monkeypatch.setattr(
            "agent_guard_cartography.graph.time.time", lambda: (now + 59_000) / 1000
        )
        with pytest.raises(GraphImportError, match="^PROJECTION_RETENTION$"):
            retire_projection(neo4j_session, previous.projection_id, minimum_retention_seconds=60)
        monkeypatch.setattr(
            "agent_guard_cartography.graph.time.time", lambda: (now + 61_000) / 1000
        )
        assert retire_superseded(neo4j_session, archive, minimum_retention_seconds=60, limit=1) == 1
        assert retire_superseded(neo4j_session, archive, minimum_retention_seconds=60, limit=1) == 1
    for record in (first, previous):
        assert neo4j_session.run(
            "MATCH (p:GuardSnapshot {id:$id}) OPTIONAL MATCH (n)-[:G_IN_SNAPSHOT]->(p) RETURN p.status AS status,count(n) AS nodes",
            id=record.projection_id,
        ).single().data() == {"status": "retired", "nodes": 0}
    for record in (current, foreign):
        assert state(neo4j_session, record.source_id)["current_snapshot_id"] == record.projection_id
        with pytest.raises(GraphImportError, match="^PROJECTION_PROTECTED$"):
            retire_projection(neo4j_session, record.projection_id, minimum_retention_seconds=0)
    assert (
        neo4j_session.run(
            "MATCH (n:AWSRole {id:$id}) RETURN count(n) AS count", id=provider
        ).single()["count"]
        == 1
    )
    assert supersede_source(neo4j_session, value) == result
    assert retire_obsolete(neo4j_session, previous.source_id, minimum_retention_seconds=60) == 0


def test_reference_queries_hide_superseded_sources_for_team_and_all_team_readers(
    neo4j_session, reference_snapshot
):
    before = reference_snapshot
    after = successor(before)
    previous = import_snapshot(neo4j_session, before, before["source"])
    current = import_snapshot(neo4j_session, after, after["source"])
    other = deepcopy(before)
    other["source"]["sourceId"] += "-other-installation"
    other["manifest"]["source"] = dict(other["source"])
    foreign = import_snapshot(neo4j_session, other, other["source"])
    supersede_source(neo4j_session, transition(before, after))
    operations = [
        {"operation": "list_agents", "args": {}},
        {
            "operation": "get_agent_access",
            "args": {"sourceId": previous.source_id, "agentId": "visible-agent"},
        },
        {
            "operation": "explain_access",
            "args": {
                "sourceId": previous.source_id,
                "taskId": "visible-task",
                "tool": "records.read",
                "resourceId": "report-A",
            },
        },
    ]
    for all_teams in (False, True):
        result = query(scope(before, all_teams=all_teams), operations=operations)
        assert result["ok"] is True
        assert {row["id"] for row in result["view"]["sources"]} == {
            current.source_id,
            foreign.source_id,
        }
        listed, detail, explanation = result["outputs"]
        assert listed["ok"] is True
        assert {agent["sourceId"] for agent in listed["response"]["data"]["agents"]} == {
            current.source_id,
            foreign.source_id,
        }
        assert detail == explanation == {"ok": False, "code": "MAP_NOT_FOUND"}
        assert previous.source_id not in json.dumps(result)


@pytest.mark.parametrize("all_teams", [False, True])
def test_reference_read_rejects_concurrent_supersession_without_partial_history(
    neo4j_session, reference_snapshot, all_teams
):
    before = reference_snapshot
    first = import_snapshot(neo4j_session, before, before["source"])
    updated = deepcopy(before)
    updated["snapshotId"] = uuid4().hex
    updated["ledgerRevision"] += 1
    previous = import_snapshot(neo4j_session, updated, updated["source"])
    after = successor(updated)
    current = import_snapshot(neo4j_session, after, after["source"])
    value = transition(updated, after)
    timestamp = int(time.time() * 1000)
    node = shutil.which("node")
    root = Path(__file__).resolve().parents[4]
    assert node is not None and (root / "packages/agent-map/dist/index.js").is_file(), (
        "Run npm run build before reference query tests"
    )
    process = subprocess.run(
        [node, str(ROOT / "tests/fixtures/query-source-lifecycle-race.mjs")],
        input=json.dumps(
            {
                "scope": scope(updated, all_teams=all_teams),
                "request": {"sourceId": previous.source_id, "history": True},
                "predecessorSourceId": previous.source_id,
                "successorSourceId": current.source_id,
                "currentId": previous.projection_id,
                "previousId": first.projection_id,
                "successorCurrentId": current.projection_id,
                "transitionId": transition_id(value),
                "supersededAtMs": timestamp,
            }
        ),
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr
    password = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())["password"]
    assert password not in process.stdout + process.stderr
    assert json.loads(process.stdout) == {
        "result": {"ok": False, "code": "MAP_UNAVAILABLE"},
        "mutationCount": 1,
        "sourceReads": 2,
        "retainedProjectionsRead": 2,
        "sourceSelectionChanged": True,
    }
    retired = state(neo4j_session, previous.source_id)
    assert retired["lifecycle_status"] == "superseded"
    assert retired["superseded_by"] == current.source_id
    assert retired["lifecycle_operation_id"] == transition_id(value)
    assert retired["superseded_at_ms"] == timestamp
    assert retired["superseded_current_snapshot_id"] == previous.projection_id
    assert retired["superseded_previous_snapshot_id"] == first.projection_id
    assert "current_snapshot_id" not in retired and "previous_snapshot_id" not in retired
    assert state(neo4j_session, current.source_id)["current_snapshot_id"] == current.projection_id


def test_cli_missing_successor_leaves_no_pending_intent_or_predecessor_fence(
    neo4j_session, snapshot_factory, tmp_path
):
    before = snapshot_factory()
    previous = import_snapshot(neo4j_session, before, before["source"])
    value = transition(before, successor(before))
    path = tmp_path / "transition.json"
    path.write_text(json.dumps(value))
    configuration = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_guard_cartography.lifecycle",
            "--transition",
            str(path),
            "--archive-dir",
            str(tmp_path / "archive"),
            "--neo4j-uri",
            configuration["uri"],
            "--neo4j-password-env-var",
            "TEST_LIFECYCLE_PASSWORD",
            "--lock-file",
            str(tmp_path / "lock"),
        ],
        cwd=ROOT,
        env={**os.environ, "TEST_LIFECYCLE_PASSWORD": configuration["password"]},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert process.returncode == 2
    assert json.loads(process.stderr) == {"error": "SOURCE_TRANSITION_SOURCE_MISSING"}
    assert not process.stdout and configuration["password"] not in process.stderr
    with SnapshotArchive(tmp_path / "archive") as archive:
        assert not archive.list_transitions()
        stored = archive.store(before)
        assert archive.load(stored.receipt_id, before["source"], before["profile"]) == before
    assert state(neo4j_session, previous.source_id)["current_snapshot_id"] == previous.projection_id


@pytest.mark.parametrize("with_evidence", [False, True])
def test_cli_requires_exact_archived_endpoints_then_commits_and_retries_safely(
    neo4j_session, pair, tmp_path, with_evidence
):
    before, after, previous, current = pair
    value = transition(before, after)
    path = tmp_path / "transition.json"
    path.write_text(json.dumps(value))
    folder = tmp_path / "archive"
    if with_evidence:
        with SnapshotArchive(folder) as archive:
            for snapshot, imported in ((before, previous), (after, current)):
                stored = archive.store(snapshot)
                archive.record_result(stored.receipt_id, imported)
    configuration = json.loads(Path(os.environ["AGENT_GUARD_TEST_NEO4J_CONFIG"]).read_text())
    command = [
        sys.executable,
        "-m",
        "agent_guard_cartography.lifecycle",
        "--transition",
        str(path),
        "--archive-dir",
        str(folder),
        "--neo4j-uri",
        configuration["uri"],
        "--neo4j-password-env-var",
        "TEST_LIFECYCLE_PASSWORD",
        "--lock-file",
        str(tmp_path / "lock"),
    ]
    environment = {**os.environ, "TEST_LIFECYCLE_PASSWORD": configuration["password"]}
    result = subprocess.run(
        command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30
    )
    assert configuration["password"] not in result.stdout + result.stderr
    if not with_evidence:
        assert result.returncode == 2
        assert json.loads(result.stderr) == {"error": "ARCHIVE_TRANSITION_EVIDENCE_MISSING"}
        assert not result.stdout
        with SnapshotArchive(folder) as archive:
            assert not archive.list_transitions()
            archive.store(before)
        assert (
            state(neo4j_session, previous.source_id)["current_snapshot_id"]
            == previous.projection_id
        )
        return
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["transitionId"] == transition_id(value)
    assert "current_snapshot_id" not in state(neo4j_session, previous.source_id)
    assert state(neo4j_session, current.source_id)["current_snapshot_id"] == current.projection_id
    retry = subprocess.run(
        command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30
    )
    assert retry.returncode == 0, retry.stderr
    assert json.loads(retry.stdout) == receipt
    with SnapshotArchive(folder) as archive:
        (journal,) = archive.list_transitions()
        assert journal["status"] == "complete" and journal["receipt"] == receipt
