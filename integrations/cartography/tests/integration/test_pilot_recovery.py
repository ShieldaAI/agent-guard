"""A restored archive may never rewrite an existing Guard graph, even orphaned rows."""

import os
import re
import signal
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.graph import GraphImportError, import_snapshot, source_key
from agent_guard_cartography.lifecycle import supersede_source
from agent_guard_cartography.models import PROJECTION_LABELS
from agent_guard_cartography.pilot_recovery import (
    RecoveryError,
    create_backup,
    inspect_backup,
    replay_published,
    restore_backup,
)

pytestmark = pytest.mark.integration


def test_recovery_refuses_existing_projection_rows_without_mutating_provider_or_guard_data(
    neo4j_session, snapshot_factory, tmp_path: Path
):
    snapshot = snapshot_factory()
    folder = tmp_path / "restored"
    with SnapshotArchive(folder) as archive:
        archive.store(snapshot)
    guard = "recovery-orphan-" + uuid4().hex
    sentinel = "recovery-provider-" + uuid4().hex
    neo4j_session.run(
        "CREATE (:GuardTask {id:$guard,task_id:'unchanged'}), "
        "(:AWSRole {id:$sentinel,arn:'arn:aws:iam::111122223333:role/Preserved'})",
        guard=guard,
        sentinel=sentinel,
    ).consume()
    before = neo4j_session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
    try:
        with pytest.raises(RecoveryError, match="RECOVERY_GRAPH_NOT_EMPTY"):
            replay_published(
                neo4j_session,
                folder,
                [{"source": snapshot["source"], "profile": snapshot["profile"]}],
                replay_archive_directory=tmp_path / "working",
                lock_file=tmp_path / "ingest.lock",
            )
        assert not (tmp_path / "working").exists()
        assert neo4j_session.run("MATCH (n) RETURN count(n) AS count").single()["count"] == before
        assert (
            neo4j_session.run(
                "MATCH (n:GuardTask {id:$id}) RETURN n.task_id AS value", id=guard
            ).single()["value"]
            == "unchanged"
        )
        assert (
            neo4j_session.run(
                "MATCH (n:AWSRole {id:$id}) RETURN n.arn AS value", id=sentinel
            ).single()["value"]
            == "arn:aws:iam::111122223333:role/Preserved"
        )
    finally:
        # Only the two exact test-created marker nodes are cleanup targets.
        neo4j_session.run(
            "MATCH (n) WHERE n.id IN [$guard,$sentinel] DELETE n",
            guard=guard,
            sentinel=sentinel,
        ).consume()


def test_lifecycle_recovery_roundtrip_preserves_supersession_in_a_fresh_owned_graph(
    neo4j_session, snapshot_factory, tmp_path
):
    """A nested owned runner isolates the empty-Guard-graph recovery prerequisite."""
    if os.environ.get("AGENT_GUARD_LIFECYCLE_RECOVERY_CHILD") != "1":
        integration = Path(__file__).resolve().parents[2]
        process = subprocess.Popen(
            [
                sys.executable,
                str(integration / "scripts" / "test-disposable-neo4j.py"),
                "--",
                "-q",
                "-k",
                "test_lifecycle_recovery_roundtrip_preserves_supersession_in_a_fresh_owned_graph",
            ],
            cwd=integration,
            env={**os.environ, "AGENT_GUARD_LIFECYCLE_RECOVERY_CHILD": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=10)
            pytest.fail("Owned lifecycle recovery runner exceeded its deadline")
        assert process.returncode == 0, stdout + stderr
        assert re.search(r"\b1 passed(?:, \d+ deselected)? in ", stdout), stdout
        assert " skipped" not in stdout and " xfailed" not in stdout, stdout
        return

    from test_reference_queries import query

    session = neo4j_session
    original = snapshot_factory()
    sources = [
        {**original["source"], "enrollmentGeneration": f"generation-{index}"} for index in range(4)
    ]
    directory = tmp_path / "original"
    # Two legacy predecessors converge on the middle generation, then it is
    # explicitly replaced by the final active generation.
    transitions = [
        {
            "schemaVersion": 1,
            "predecessor": sources[before],
            "successor": sources[after],
            "profile": "core",
        }
        for before, after in [(0, 2), (1, 2), (2, 3)]
    ]
    ids = [source_key(source) for source in sources]
    with SnapshotArchive(directory) as archive:
        for index, source in enumerate(sources):
            snapshot = {**deepcopy(original), "source": source, "snapshotId": f"retained-{index}"}
            stored = archive.store(snapshot)
            result = import_snapshot(session, snapshot, source)
            archive.record_result(stored.receipt_id, result)
        for index, transition in enumerate(transitions):
            archive.require_transition_evidence(transition)
            archive.stage_transition(transition)
            receipt = supersede_source(session, transition, timestamp_ms=1000 + index)
            archive.finish_transition(transition, receipt)
    active = {"source": sources[-1], "profile": "core"}
    backup = tmp_path / "backup"
    create_backup(directory, backup, [active], lock_file=tmp_path / "lock")
    assert len(inspect_backup(backup)["manifest"]["sources"]) == 4
    restored = tmp_path / "restored"
    restore_backup(backup, restored, lock_file=tmp_path / "lock")

    sentinel = "lifecycle-recovery-provider-" + uuid4().hex
    session.run(
        "CREATE (:AWSRole {id:$id,source_id:$source})", id=sentinel, source=ids[0]
    ).consume()
    # Remove only rows owned by this test's exact four namespaces. The runner
    # marker and provider inventory remain; no whole-database cleanup is used.
    session.run(
        "MATCH (n) WHERE any(label IN labels(n) WHERE label IN $guard_labels) "
        "AND ((n:GuardSource AND n.id IN $ids) OR n.source_id IN $ids) DETACH DELETE n",
        ids=ids,
        guard_labels=["GuardSource", "GuardSnapshot", *PROJECTION_LABELS],
    ).consume()
    working = tmp_path / "working"
    replay = replay_published(
        session, restored, [active], replay_archive_directory=working, lock_file=tmp_path / "lock"
    )
    assert replay["published"] == 4 and replay["transitionsReplayed"] == 3
    rows = list(
        session.run(
            "MATCH (s:GuardSource) WHERE s.id IN $ids RETURN s.id AS id,s.lifecycle_status AS status,"
            "s.current_snapshot_id AS current,s.superseded_at_ms AS stamp",
            ids=ids,
        )
    )
    assert len(rows) == 4
    by_id = {row["id"]: row for row in rows}
    for index, identifier in enumerate(ids[:-1]):
        assert by_id[identifier]["status"] == "superseded"
        assert by_id[identifier]["current"] is None
        assert by_id[identifier]["stamp"] == 1000 + index
        with pytest.raises(GraphImportError, match="SOURCE_SUPERSEDED"):
            import_snapshot(
                session,
                {**deepcopy(original), "source": sources[index], "snapshotId": "revive-attempt"},
                sources[index],
            )
    assert by_id[ids[-1]]["current"]
    assert (
        session.run("MATCH (n:AWSRole {id:$id}) RETURN count(n) AS count", id=sentinel).single()[
            "count"
        ]
        == 1
    )
    reference = query(
        {
            "subject": "recovery-reader",
            "companyId": sources[-1]["companyId"],
            "tenantIds": [sources[-1]["tenantId"]],
            "teamIds": [],
            "allTeams": True,
        }
    )
    assert reference["ok"] is True
    assert [source["id"] for source in reference["view"]["sources"]] == [ids[-1]]
    with SnapshotArchive(working) as archive:
        assert len(archive.list_transitions()) == 3
        for source in sources[:-1]:
            with pytest.raises(ArchiveError, match="ARCHIVE_SOURCE_SUPERSEDED"):
                archive.store({**deepcopy(original), "source": source, "snapshotId": "new-export"})
    second_backup = tmp_path / "rebuilt-backup"
    create_backup(working, second_backup, [active], lock_file=tmp_path / "lock")
    assert len(inspect_backup(second_backup)["manifest"]["sources"]) == 4
    assert len(list(second_backup.glob("lifecycle-*.json"))) == 3
