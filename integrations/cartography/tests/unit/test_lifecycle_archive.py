"""Durable lifecycle intents cannot be lost, retargeted or used to revive old sources."""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.archive import REPLAY_PENDING, ArchiveError, SnapshotArchive
from agent_guard_cartography.graph import ImportResult, source_key
from agent_guard_cartography.lifecycle import transition_id


@pytest.fixture
def snapshot():
    return json.loads((Path(__file__).parents[1] / "fixtures" / "alpha-v1.json").read_text())


def transition(source, generation="enrollment-2"):
    return {
        "schemaVersion": 1,
        "predecessor": dict(source),
        "successor": {**source, "enrollmentGeneration": generation},
        "profile": "core",
    }


def receipt(value, stamp=1234):
    return {
        "schemaVersion": 1,
        "transitionId": transition_id(value),
        "predecessorSourceId": source_key(value["predecessor"]),
        "successorSourceId": source_key(value["successor"]),
        "profile": value["profile"],
        "supersededAtMs": stamp,
    }


def test_intent_is_private_detached_durable_and_fences_collection(snapshot, tmp_path):
    value = transition(snapshot["source"])
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        stored = archive.store(snapshot)
        pending = archive.stage_transition(value)
        assert pending["status"] == "pending" and pending["receipt"] is None
        pending["transition"]["successor"]["enrollmentGeneration"] = "mutated"
        assert archive.stage_transition(value)["transition"] == value
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        for attempted in [snapshot, {**snapshot, "snapshotId": "new-predecessor-snapshot"}]:
            with pytest.raises(ArchiveError, match="ARCHIVE_SOURCE_SUPERSEDED"):
                archive.store(attempted)
        assert before == {path.name: path.read_bytes() for path in directory.iterdir()}
        assert archive.load(stored.receipt_id, snapshot["source"]) == snapshot
        successor = {**snapshot, "source": value["successor"], "snapshotId": "new-generation"}
        archive.store(successor)
    with SnapshotArchive(directory) as reopened:
        assert reopened.list_transitions()[0]["status"] == "pending"
        completed = reopened.finish_transition(value, receipt(value))
        assert completed["status"] == "complete"
        assert reopened.finish_transition(value, receipt(value)) == completed
        assert reopened.stage_transition(value) == completed
        assert reopened.prune(now=10**12, retention_seconds=0) == 0
    journal = directory / f"lifecycle-{source_key(snapshot['source'])}.json"
    assert journal.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700


def test_completion_requires_exact_intent_and_original_receipt(snapshot, tmp_path):
    value = transition(snapshot["source"])
    with SnapshotArchive(tmp_path / "archive") as archive:
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_NOT_STAGED"):
            archive.finish_transition(value, receipt(value))
        archive.stage_transition(value)
        other = transition(snapshot["source"], "enrollment-other")
        for action in [
            lambda: archive.stage_transition(other),
            lambda: archive.finish_transition(other, receipt(other)),
        ]:
            with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_CONFLICT"):
                action()
        archive.finish_transition(value, receipt(value))
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_CONFLICT"):
            archive.finish_transition(value, receipt(value, 5678))


@pytest.mark.parametrize(
    "change",
    [
        {"schemaVersion": True},
        {"supersededAtMs": True},
        {"supersededAtMs": -1},
        {"supersededAtMs": 253_402_300_800_000},
        {"profile": "host"},
        {"transitionId": "0" * 64},
        {"successorSourceId": "0" * 64},
        {"private": "canary"},
    ],
)
def test_invalid_graph_receipt_does_not_complete_intent(snapshot, tmp_path, change):
    value = transition(snapshot["source"])
    with SnapshotArchive(tmp_path / "archive") as archive:
        archive.stage_transition(value)
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_INVALID"):
            archive.finish_transition(value, {**receipt(value), **change})
        assert archive.list_transitions()[0]["status"] == "pending"


def test_topological_chain_fan_in_and_cycles(snapshot, tmp_path):
    first = transition(snapshot["source"])
    second = transition(first["successor"], "enrollment-3")
    other = transition({**snapshot["source"], "enrollmentGeneration": "legacy"})
    with SnapshotArchive(tmp_path / "archive") as archive:
        # Insert in reverse order, then add another predecessor of the middle.
        archive.stage_transition(second)
        archive.finish_transition(second, receipt(second, 2000))
        archive.stage_transition(first)
        archive.finish_transition(first, receipt(first, 1000))
        archive.stage_transition(other)
        archive.finish_transition(other, receipt(other, 1500))
        records = archive.list_transitions()
        assert {item["transitionId"] for item in records[:2]} == {
            transition_id(first),
            transition_id(other),
        }
        assert records[-1]["transition"] == second
        cycle = {**transition(second["successor"]), "successor": first["predecessor"]}
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_CONFLICT"):
            archive.stage_transition(cycle)
        assert len(archive.list_transitions()) == 3


@pytest.mark.parametrize(
    "mutation", ["shape", "duplicate", "status", "receipt", "source", "filename", "cycle"]
)
def test_corrupt_journal_fails_closed_before_new_snapshot(snapshot, tmp_path, mutation):
    value = transition(snapshot["source"])
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        archive.stage_transition(value)
        target = next(directory.glob("lifecycle-*.json"))
        raw = json.loads(target.read_text())
        if mutation == "shape":
            raw["private"] = "canary"
        elif mutation == "status":
            raw["status"] = "complete"
        elif mutation == "receipt":
            raw["receipt"] = receipt(value)
        elif mutation == "source":
            raw["transition"]["predecessor"]["companyId"] = "another"
        elif mutation == "cycle":
            raw["transition"]["successor"] = raw["transition"]["predecessor"]
        elif mutation == "filename":
            target.rename(directory / "lifecycle-invalid.json")
        if mutation == "duplicate":
            target.write_text('{"schemaVersion":1,"schemaVersion":1}')
        elif mutation != "filename":
            target.write_text(json.dumps(raw))
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_INVALID"):
            archive.store({**snapshot, "source": value["successor"]})
        assert not list(directory.glob("*.snapshot.json"))


@pytest.mark.parametrize("unsafe", ["mode", "symlink", "hardlink"])
def test_unsafe_journal_never_gets_read(snapshot, tmp_path, unsafe):
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        archive.stage_transition(transition(snapshot["source"]))
        target = next(directory.glob("lifecycle-*.json"))
        if unsafe == "mode":
            target.chmod(0o644)
        elif unsafe == "hardlink":
            os.link(target, tmp_path / "outside")
        else:
            outside = tmp_path / "outside"
            target.rename(outside)
            target.symlink_to(outside)
        with pytest.raises(ArchiveError, match="ARCHIVE_FILE_UNSAFE"):
            archive.list_transitions()


def test_lifecycle_source_bound_is_checked_before_writing(snapshot, tmp_path):
    with SnapshotArchive(tmp_path / "archive") as archive:
        source = deepcopy(snapshot["source"])
        for index in range(127):
            value = transition(source, f"next-{index}")
            archive.stage_transition(value)
            archive.finish_transition(value, receipt(value, index))
            source = value["successor"]
        with pytest.raises(ArchiveError, match="ARCHIVE_LIMIT_EXCEEDED"):
            archive.stage_transition(transition(source, "overflow"))
        assert len(archive.list_transitions()) == 127


def test_pending_intent_must_be_reconciled_before_a_different_transition(snapshot, tmp_path):
    first = transition(snapshot["source"])
    second = transition(first["successor"], "enrollment-3")
    with SnapshotArchive(tmp_path / "archive") as archive:
        pending = archive.stage_transition(first)
        assert archive.stage_transition(first) == pending
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_PENDING"):
            archive.stage_transition(second)
        assert len(archive.list_transitions()) == 1
        archive.finish_transition(first, receipt(first))
        assert archive.stage_transition(second)["status"] == "pending"


def test_interrupted_recovery_preserves_even_otherwise_prunable_evidence(snapshot, tmp_path):
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        for index in range(3):
            candidate = {**snapshot, "snapshotId": f"recovery-{index}"}
            stored = archive.store(candidate)
            archive.record_result(
                stored.receipt_id,
                ImportResult(stored.source_id, str(index) * 64, stored.snapshot_id, True, False),
            )
        archive._write(REPLAY_PENDING, b'{"schemaVersion":1,"status":"pending"}')
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        with pytest.raises(ArchiveError, match="^ARCHIVE_RECOVERY_PENDING$"):
            archive.prune(now=10**12, retention_seconds=0)
        assert {path.name: path.read_bytes() for path in directory.iterdir()} == before


@pytest.mark.parametrize("state", ["missing", "pending", "idempotent", "wrong_profile"])
def test_transition_preflight_requires_published_evidence_for_both_exact_endpoints(
    snapshot, tmp_path, state
):
    value = transition(snapshot["source"])
    with SnapshotArchive(tmp_path / "archive") as archive:
        old = archive.store(snapshot)
        archive.record_result(
            old.receipt_id, ImportResult(old.source_id, "a" * 64, old.snapshot_id, True, False)
        )
        if state != "missing":
            fresh = archive.store({**snapshot, "source": value["successor"]})
            if state != "pending":
                archive.record_result(
                    fresh.receipt_id,
                    ImportResult(
                        fresh.source_id,
                        "b" * 64,
                        fresh.snapshot_id,
                        state != "idempotent",
                        state == "idempotent",
                    ),
                )
        if state == "wrong_profile":
            value["profile"] = "host"
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_EVIDENCE_MISSING"):
            archive.require_transition_evidence(value)
        assert archive.list_transitions() == ()


def test_transition_preflight_matches_current_projection_anchors_and_validates_bytes(
    snapshot, tmp_path
):
    value = transition(snapshot["source"])
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        expected = {}
        for source, projection in [
            (value["predecessor"], "a" * 64),
            (value["successor"], "b" * 64),
        ]:
            stored = archive.store({**snapshot, "source": source})
            archive.record_result(
                stored.receipt_id,
                ImportResult(stored.source_id, projection, stored.snapshot_id, True, False),
            )
            expected[stored.source_id] = projection
        anchors = archive.require_transition_evidence(value, projection_ids=expected)
        assert {key: item.projection_id for key, item in anchors.items()} == expected
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_EVIDENCE_MISSING"):
            archive.require_transition_evidence(
                value, projection_ids={**expected, stored.source_id: "c" * 64}
            )
        archive.stage_transition(value)
        archive.finish_transition(value, receipt(value))
        assert archive.require_transition_evidence(value, projection_ids=expected) == anchors
        target = directory / f"{stored.receipt_id}.snapshot.json"
        data = json.loads(target.read_text())
        data["ledgerRevision"] += 1
        target.write_text(json.dumps(data))
        with pytest.raises(ArchiveError, match="ARCHIVE_CONTENT_CONFLICT"):
            archive.require_transition_evidence(value, projection_ids=expected)


@pytest.mark.parametrize("raw", [b"\xff", b"\xef\xbb\xbf{}", b'{"schemaVersion":NaN}', b"[]"])
def test_journal_requires_strict_utf8_object_json(snapshot, tmp_path, raw):
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        archive.stage_transition(transition(snapshot["source"]))
        next(directory.glob("lifecycle-*.json")).write_bytes(raw)
        with pytest.raises(ArchiveError, match="ARCHIVE_TRANSITION_INVALID"):
            archive.list_transitions()
