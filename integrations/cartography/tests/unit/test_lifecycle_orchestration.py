"""Lifecycle maintenance remains reachable after the predecessor is unenrolled."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from agent_guard_cartography import cli
from agent_guard_cartography.archive import REPLAY_PENDING, ArchiveError, SnapshotArchive
from agent_guard_cartography.collector import validate_enrollment
from agent_guard_cartography.graph import source_key
from agent_guard_cartography.lifecycle import transition_id


@pytest.mark.parametrize("maintenance_fails", [False, True])
def test_collector_maintains_unenrolled_predecessors_after_publishing_successor(
    tmp_path, snapshot_factory, monkeypatch, capsys, maintenance_fails
):
    before = snapshot_factory()["source"]
    after = {**before, "enrollmentGeneration": "replacement"}
    transition = {"schemaVersion": 1, "predecessor": before, "successor": after, "profile": "core"}
    archive_path = tmp_path / "archive"
    with SnapshotArchive(archive_path) as archive:
        archive.stage_transition(transition)
        archive.finish_transition(
            transition,
            {
                "schemaVersion": 1,
                "transitionId": transition_id(transition),
                "predecessorSourceId": source_key(before),
                "successorSourceId": source_key(after),
                "profile": "core",
                "supersededAtMs": 1000,
            },
        )
    enrollment = validate_enrollment(
        {
            "source": after,
            "profile": "core",
            "endpoint": "http://127.0.0.1:8788/v1/inventory/snapshot",
            "tokenEnv": "TEST_LIFECYCLE_OBSERVER",
        }
    )
    args = SimpleNamespace(
        archive_dir=archive_path,
        archive_max_snapshots=4096,
        archive_max_bytes=256 * 1024**2,
        neo4j_database="neo4j",
        replay_receipt=None,
        retention_seconds=3600,
        watch=False,
    )
    events = []

    class Driver:
        @contextmanager
        def session(self, **_kwargs):
            yield object()

    def collect(_session, enrolled, _token, _archive, **_kwargs):
        assert enrolled.source == after
        events.append("publish-successor")
        return SimpleNamespace(
            import_result=SimpleNamespace(source_id=source_key(after)),
            summary=lambda: {"status": "complete", "source_id": source_key(after)},
        )

    def retire(_session, archive, *, minimum_retention_seconds):
        assert minimum_retention_seconds == 3600
        assert archive.list_transitions()[0]["transition"]["predecessor"] == before
        events.append("retire-predecessor")
        if maintenance_fails:
            raise RuntimeError("private-diagnostic-canary")
        return 2

    monkeypatch.setattr(cli, "collect_and_publish", collect)
    monkeypatch.setattr(cli, "prune_archive", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "retire_obsolete", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "retire_superseded", retire)
    assert cli._collect_sources(Driver(), args, [enrollment], {}) == (2 if maintenance_fails else 0)
    assert events == ["publish-successor", "retire-predecessor"]
    output = capsys.readouterr()
    assert '"status": "complete"' in output.out
    assert "private-diagnostic-canary" not in output.out + output.err
    if maintenance_fails:
        assert "SOURCE_RETIREMENT_FAILED" in output.err
    else:
        assert '"operation": "source_retirement"' in output.out and not output.err


@pytest.mark.parametrize("aws_enabled", [False, True])
@pytest.mark.parametrize("replay", [False, True])
def test_incomplete_recovery_rejects_collector_before_observation_or_maintenance(
    tmp_path, snapshot_factory, monkeypatch, aws_enabled, replay
):
    archive_path = tmp_path / "archive"
    with SnapshotArchive(archive_path) as archive:
        archive._write(REPLAY_PENDING, b'{"schemaVersion":1,"status":"pending"}')
    before = {path.name: path.read_bytes() for path in archive_path.iterdir()}
    enrollment = validate_enrollment(
        {
            "source": snapshot_factory()["source"],
            "profile": "core",
            "endpoint": "http://127.0.0.1:8788/v1/inventory/snapshot",
            "tokenEnv": "TEST_RECOVERY_OBSERVER",
        }
    )
    args = SimpleNamespace(
        archive_dir=archive_path,
        archive_max_snapshots=4096,
        archive_max_bytes=256 * 1024**2,
        neo4j_database="neo4j",
        replay_receipt="a" * 64 if replay else None,
        retention_seconds=3600,
        watch=False,
    )

    def forbidden(*_args, **_kwargs):
        pytest.fail("collector bypassed incomplete recovery fence")

    for name in (
        "capture_aws",
        "publish_aws_capture",
        "collect_and_publish",
        "publish_receipt",
        "prune_archive",
        "retire_obsolete",
        "retire_superseded",
    ):
        monkeypatch.setattr(cli, name, forbidden)
    with pytest.raises(ArchiveError, match="^ARCHIVE_RECOVERY_PENDING$"):
        cli._collect_sources(
            SimpleNamespace(session=forbidden),
            args,
            [enrollment],
            {},
            aws_enrollment=object() if aws_enabled else None,
        )
    assert {path.name: path.read_bytes() for path in archive_path.iterdir()} == before
