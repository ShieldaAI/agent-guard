"""Archive-before-publication and recovery sequencing without a database."""

from dataclasses import replace
from pathlib import Path

import pytest

from agent_guard_cartography.archive import (
    REPLAY_PENDING,
    ArchiveError,
    PruneReport,
    SnapshotArchive,
)
from agent_guard_cartography.collector import CollectionError, validate_enrollment
from agent_guard_cartography.graph import GraphImportError, ImportResult, source_key
from agent_guard_cartography.inventory import load_snapshot
from agent_guard_cartography.lifecycle import transition_id
from agent_guard_cartography.publish import (
    collect_and_publish,
    prune_archive,
    publish_receipt,
    retire_obsolete,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "alpha-v1.json"


@pytest.fixture
def setup(tmp_path):
    snapshot = load_snapshot(FIXTURE)
    enrollment = validate_enrollment(
        {
            "source": snapshot["source"],
            "profile": "core",
            "endpoint": "http://127.0.0.1:12345/v1/inventory/snapshot",
            "tokenEnv": "COLLECTOR_TEST_TOKEN",
        }
    )
    with SnapshotArchive(tmp_path / "archive") as archive:
        yield snapshot, enrollment, archive


def result(snapshot, *, idempotent=False):
    return ImportResult(
        source_key(snapshot["source"]), "a" * 64, snapshot["snapshotId"], not idempotent, idempotent
    )


def test_complete_snapshot_is_persisted_before_graph_write_and_success_health(setup, monkeypatch):
    snapshot, enrollment, archive = setup
    monkeypatch.setattr("agent_guard_cartography.publish.collect_snapshot", lambda *_: snapshot)

    def publish(_session, candidate, expected_source, **kwargs):
        (receipt,) = archive.list_pending(expected_source, enrollment.profile)
        assert archive.load(receipt.receipt_id, expected_source, enrollment.profile) == candidate
        return result(candidate)

    monkeypatch.setattr("agent_guard_cartography.publish.import_snapshot", publish)
    collected = collect_and_publish(None, enrollment, "private-token-canary", archive)
    assert collected.import_result.published
    assert collected.summary()["status"] == "complete"
    assert not archive.list_pending(enrollment.source, enrollment.profile)
    health = archive.read_health(enrollment.source, enrollment.profile)
    assert health["lastSnapshotId"] == snapshot["snapshotId"]
    assert health["lastError"] is None
    assert "private-token-canary" not in str(collected.summary()) + str(health)


def test_collection_failure_writes_health_but_never_calls_graph(setup, monkeypatch):
    _snapshot, enrollment, archive = setup

    def failed(*_):
        raise CollectionError("COLLECTOR_TIMEOUT")

    monkeypatch.setattr("agent_guard_cartography.publish.collect_snapshot", failed)
    monkeypatch.setattr(
        "agent_guard_cartography.publish.import_snapshot",
        lambda *_a, **_k: pytest.fail("graph write"),
    )
    with pytest.raises(CollectionError, match="^COLLECTOR_TIMEOUT$"):
        collect_and_publish(None, enrollment, "private-token", archive)
    assert not archive.list_pending(enrollment.source, enrollment.profile)
    assert (
        archive.read_health(enrollment.source, enrollment.profile)["lastError"]
        == "COLLECTOR_TIMEOUT"
    )


def test_failed_publication_keeps_retry_material_and_previous_success_health(setup, monkeypatch):
    snapshot, enrollment, archive = setup
    archive.record_health(
        enrollment.source, enrollment.profile, result=result(snapshot), snapshot=snapshot
    )
    receipt = archive.store(snapshot)

    def failed(*_args, **_kwargs):
        raise GraphImportError("PUBLICATION_CONFLICT")

    monkeypatch.setattr("agent_guard_cartography.publish.import_snapshot", failed)
    with pytest.raises(GraphImportError, match="^PUBLICATION_CONFLICT$"):
        publish_receipt(None, enrollment, archive, receipt.receipt_id)
    assert len(archive.list_pending(enrollment.source, enrollment.profile)) == 1
    health = archive.read_health(enrollment.source, enrollment.profile)
    assert health["lastSnapshotId"] == snapshot["snapshotId"]
    assert health["lastError"] == "PUBLICATION_CONFLICT"
    monkeypatch.setattr(
        "agent_guard_cartography.publish.import_snapshot",
        lambda *_a, **_k: result(snapshot, idempotent=True),
    )
    retry = publish_receipt(None, enrollment, archive, receipt.receipt_id)
    assert retry.import_result.idempotent
    assert archive.read_health(enrollment.source, enrollment.profile)["consecutiveFailures"] == 0


def test_replay_rejects_wrong_profile_before_graph_write(setup, monkeypatch):
    snapshot, enrollment, archive = setup
    receipt = archive.store(snapshot)
    monkeypatch.setattr(
        "agent_guard_cartography.publish.import_snapshot",
        lambda *_a, **_k: pytest.fail("graph write"),
    )
    with pytest.raises(ArchiveError):
        publish_receipt(None, replace(enrollment, profile="host"), archive, receipt.receipt_id)


@pytest.mark.parametrize("fence", ["recovery", "pending", "complete"])
@pytest.mark.parametrize("operation", ["collect", "replay"])
def test_archive_fences_before_observation_or_graph_and_preserves_confirmed_evidence(
    setup, tmp_path, monkeypatch, fence, operation
):
    snapshot, enrollment, archive = setup
    stored = archive.store(snapshot)
    archive.record_result(stored.receipt_id, result(snapshot))
    transition = {
        "schemaVersion": 1,
        "predecessor": snapshot["source"],
        "successor": {**snapshot["source"], "enrollmentGeneration": "replacement"},
        "profile": "core",
    }
    if fence == "recovery":
        archive._write(REPLAY_PENDING, b'{"schemaVersion":1,"status":"pending"}')
    else:
        archive.stage_transition(transition)
        if fence == "complete":
            archive.finish_transition(
                transition,
                {
                    "schemaVersion": 1,
                    "transitionId": transition_id(transition),
                    "predecessorSourceId": source_key(transition["predecessor"]),
                    "successorSourceId": source_key(transition["successor"]),
                    "profile": "core",
                    "supersededAtMs": 123,
                },
            )
    directory = tmp_path / "archive"
    before = {path.name: path.read_bytes() for path in directory.iterdir()}
    monkeypatch.setattr(
        "agent_guard_cartography.publish.import_snapshot",
        lambda *_a, **_k: pytest.fail("graph write bypassed archive fence"),
    )
    monkeypatch.setattr(
        "agent_guard_cartography.publish.collect_snapshot",
        lambda *_a, **_k: pytest.fail("observation bypassed archive fence"),
    )
    code = "ARCHIVE_RECOVERY_PENDING" if fence == "recovery" else "ARCHIVE_SOURCE_SUPERSEDED"
    with pytest.raises(ArchiveError, match=f"^{code}$"):
        if operation == "collect":
            collect_and_publish(None, enrollment, "private-token-canary", archive)
        else:
            publish_receipt(None, enrollment, archive, stored.receipt_id)
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before


def test_pending_predecessor_does_not_block_successor_replay(setup, monkeypatch):
    snapshot, enrollment, archive = setup
    successor = {
        **snapshot,
        "source": {**snapshot["source"], "enrollmentGeneration": "replacement"},
    }
    stored = archive.store(successor)
    archive.stage_transition(
        {
            "schemaVersion": 1,
            "predecessor": snapshot["source"],
            "successor": successor["source"],
            "profile": "core",
        }
    )
    calls = []

    def publish(_session, candidate, expected_source, **_kwargs):
        calls.append(candidate)
        assert candidate == successor and expected_source == successor["source"]
        return result(candidate)

    monkeypatch.setattr("agent_guard_cartography.publish.import_snapshot", publish)
    collected = publish_receipt(
        None, replace(enrollment, source=successor["source"]), archive, stored.receipt_id
    )
    assert collected.import_result.published and len(calls) == 1


@pytest.mark.parametrize(
    "options", [{"limit": 0}, {"limit": 129}, {"minimum_retention_seconds": 59}, {"limit": True}]
)
def test_retention_rejects_unbounded_configuration_before_query(options):
    with pytest.raises(GraphImportError, match="^RETENTION_INVALID$"):
        retire_obsolete(None, "source", **options)


def test_pruning_protects_database_current_and_previous_pointers():
    class Session:
        def run(self, query):
            assert "LIMIT 10001" in query
            return [{"current": "one", "previous": "two"}, {"current": "three", "previous": None}]

    class Archive:
        def maintain(self, *, protected_projection_ids, **options):
            assert set(protected_projection_ids) == {"one", "two", "three"}
            # The operator's retention and the room one poll needs reach the archive.
            assert options == {
                "retention_seconds": 86400,
                "reserve_snapshots": 1,
                "reserve_bytes": 4096,
            }
            return PruneReport(4, 1, ())

    report = prune_archive(
        Session(), Archive(), retention_seconds=86400, reserve_snapshots=1, reserve_bytes=4096
    )
    assert (report.removed, report.pressure_removed) == (4, 1)


def test_pruning_never_truncates_database_pointer_protection():
    class Session:
        def run(self, query):
            return [{"current": "one", "previous": None}] * 10001

    with pytest.raises(GraphImportError, match="^MAINTENANCE_LIMIT_EXCEEDED$"):
        prune_archive(Session(), None)


@pytest.mark.parametrize("code", ["GENERATED_AT_ROLLBACK", "REVISION_ROLLBACK"])
def test_a_collected_snapshot_the_graph_supersedes_is_reported_but_not_kept_pending(
    setup, monkeypatch, code
):
    snapshot, enrollment, archive = setup
    polls = iter(range(100))
    monkeypatch.setattr(
        "agent_guard_cartography.publish.collect_snapshot",
        lambda *_: {**snapshot, "snapshotId": f"poll-{next(polls)}"},
    )

    def refused(*_args, **_kwargs):
        raise GraphImportError(code)

    monkeypatch.setattr("agent_guard_cartography.publish.import_snapshot", refused)
    # More polls than the pending allowance: none may leave a receipt that counts.
    for _poll in range(archive.max_pending + 2):
        with pytest.raises(GraphImportError, match=f"^{code}$") as rejected:
            collect_and_publish(None, enrollment, "private-token", archive)
        # Nothing was retained, so the failure names no receipt to replay or discard.
        assert not hasattr(rejected.value, "receipt_id")
    assert archive.list_pending() == () and archive._usage()[1] == 0
    health = archive.read_health(enrollment.source, enrollment.profile)
    assert health["lastError"] == code and health["consecutiveFailures"] == archive.max_pending + 2
    monkeypatch.setattr(
        "agent_guard_cartography.publish.import_snapshot",
        lambda _s, value, *_a, **_k: result(value),
    )
    assert collect_and_publish(None, enrollment, "private-token", archive).import_result.published


def test_an_operator_replay_the_graph_supersedes_keeps_its_receipt_for_review(setup, monkeypatch):
    snapshot, enrollment, archive = setup
    receipt = archive.store(snapshot)

    def refused(*_args, **_kwargs):
        raise GraphImportError("GENERATED_AT_ROLLBACK")

    monkeypatch.setattr("agent_guard_cartography.publish.import_snapshot", refused)
    with pytest.raises(GraphImportError, match="^GENERATED_AT_ROLLBACK$") as rejected:
        publish_receipt(None, enrollment, archive, receipt.receipt_id)
    assert rejected.value.receipt_id == receipt.receipt_id
    (kept,) = archive.list_pending(enrollment.source, enrollment.profile)
    assert kept.receipt_id == receipt.receipt_id and kept.last_error == "GENERATED_AT_ROLLBACK"


@pytest.mark.parametrize("idempotent", [False, True])
def test_a_superseded_rejection_never_removes_confirmed_or_uncertain_evidence(
    setup, monkeypatch, idempotent
):
    snapshot, enrollment, archive = setup
    stored = archive.store(snapshot)
    archive.record_result(stored.receipt_id, result(snapshot, idempotent=idempotent))
    # The observer returns the same snapshot again, and a rebuilt graph refuses it.
    monkeypatch.setattr("agent_guard_cartography.publish.collect_snapshot", lambda *_: snapshot)

    def refused(*_args, **_kwargs):
        raise GraphImportError("REVISION_ROLLBACK")

    monkeypatch.setattr("agent_guard_cartography.publish.import_snapshot", refused)
    with pytest.raises(GraphImportError, match="^REVISION_ROLLBACK$") as rejected:
        collect_and_publish(None, enrollment, "private-token", archive)
    assert rejected.value.receipt_id == stored.receipt_id
    assert archive.load(stored.receipt_id, enrollment.source, enrollment.profile) == snapshot
    assert archive.read_receipt(stored.receipt_id)["status"] == (
        "idempotent" if idempotent else "published"
    )
