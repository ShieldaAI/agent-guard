"""Protected snapshot persistence, restart recovery and conservative retention."""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography import archive as module
from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.graph import ImportResult


@pytest.fixture
def snapshot():
    return json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "alpha-v1.json").read_text()
    )


def result(receipt, published=True, projection=None):
    return ImportResult(
        receipt.source_id,
        projection or receipt.content_hash,
        receipt.snapshot_id,
        published,
        not published,
    )


def test_archive_persists_validated_immutable_snapshot_and_reopens(snapshot, tmp_path):
    path = tmp_path / "archive"
    with SnapshotArchive(path) as archive:
        receipt = archive.store(snapshot)
        assert receipt.status == "pending"
        assert archive.load(receipt.receipt_id, snapshot["source"], "core") == snapshot
        assert archive.list_pending(snapshot["source"], "core") == (receipt,)
        assert archive.store(deepcopy(snapshot)) == receipt
        archive.record_result(receipt.receipt_id, result(receipt))
        assert not archive.list_pending(snapshot["source"], "core")
    assert path.stat().st_mode & 0o777 == 0o700
    for file in path.iterdir():
        assert file.stat().st_mode & 0o777 == 0o600
    with SnapshotArchive(path) as reopened:
        assert reopened.load(receipt.receipt_id, snapshot["source"]) == snapshot
        saved = reopened.record_result(receipt.receipt_id, result(receipt, published=False))
        assert saved.status == "published"
        assert len(list(path.iterdir())) == 2
    with pytest.raises(ArchiveError, match="ARCHIVE_CLOSED"):
        reopened.load(receipt.receipt_id, snapshot["source"])


def test_changed_snapshot_id_content_is_never_overwritten(snapshot, tmp_path):
    with SnapshotArchive(tmp_path / "archive") as archive:
        receipt = archive.store(snapshot)
        changed = deepcopy(snapshot)
        changed["ledgerRevision"] += 1
        with pytest.raises(ArchiveError, match="ARCHIVE_SNAPSHOT_CONFLICT"):
            archive.store(changed)
        assert archive.load(receipt.receipt_id, snapshot["source"]) == snapshot


@pytest.mark.parametrize("kind", ["source", "profile", "path", "missing"])
def test_replay_is_scoped_and_ids_cannot_select_arbitrary_paths(snapshot, tmp_path, kind):
    with SnapshotArchive(tmp_path / "archive") as archive:
        receipt = archive.store(snapshot)
        expected = dict(snapshot["source"])
        identifier, profile, code = receipt.receipt_id, "core", "ARCHIVE_SCOPE_MISMATCH"
        if kind == "source":
            expected["tenantId"] = "other"
        elif kind == "profile":
            profile = "host-mcp"
        elif kind == "path":
            identifier, code = "../../private-canary", "ARCHIVE_INVALID"
        else:
            identifier, code = "0" * 64, "ARCHIVE_NOT_FOUND"
        with pytest.raises(ArchiveError) as error:
            archive.load(identifier, expected, profile)
        assert str(error.value) == code
        assert "private" not in repr(error.value)


def test_corrupt_snapshot_hash_fails_before_replay(snapshot, tmp_path):
    path = tmp_path / "archive"
    with SnapshotArchive(path) as archive:
        receipt = archive.store(snapshot)
        file = path / f"{receipt.receipt_id}.snapshot.json"
        file.write_text('{"private-canary":"secret"}')
        with pytest.raises(ArchiveError, match="ARCHIVE_CONTENT_CONFLICT"):
            archive.load(receipt.receipt_id, snapshot["source"])
        with pytest.raises(ArchiveError, match="ARCHIVE_CONTENT_CONFLICT"):
            archive.store(snapshot)


@pytest.mark.parametrize(
    "change",
    [
        {"token": "private-canary"},
        {"schemaVersion": True},
        {"profile": "full"},
        {"sha256": "private-canary"},
        {"publishedAt": -1},
        {"lastError": "private:token"},
        {"sourceId": "0" * 64},
        {"snapshotId": "different"},
        {"publicationSequence": 1},
    ],
)
def test_receipt_tampering_is_closed_and_redacted(snapshot, tmp_path, change):
    path = tmp_path / "archive"
    with SnapshotArchive(path) as archive:
        receipt = archive.store(snapshot)
        filename = path / f"{receipt.receipt_id}.receipt.json"
        value = json.loads(filename.read_text())
        value.update(change)
        filename.write_text(json.dumps(value))
        with pytest.raises(ArchiveError) as error:
            archive.load(receipt.receipt_id, snapshot["source"])
        assert str(error.value) == "ARCHIVE_INVALID"
        assert "private" not in repr(error.value)


def test_archive_rejects_directory_and_file_symlinks_hardlinks_or_open_permissions(
    snapshot, tmp_path
):
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(ArchiveError, match="ARCHIVE_DIRECTORY_UNSAFE"):
        SnapshotArchive(public)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(private)
    with pytest.raises(ArchiveError, match="ARCHIVE_DIRECTORY_UNSAFE"):
        SnapshotArchive(linked)
    with pytest.raises(ArchiveError, match="ARCHIVE_DIRECTORY_UNSAFE"):
        SnapshotArchive(linked / "child")
    for kind in ("symlink", "hardlink", "permissions"):
        folder = tmp_path / kind
        with SnapshotArchive(folder) as archive:
            receipt = archive.store(snapshot)
            file = folder / f"{receipt.receipt_id}.snapshot.json"
            if kind == "symlink":
                outside = tmp_path / "outside"
                file.rename(outside)
                file.symlink_to(outside)
            elif kind == "hardlink":
                os.link(file, tmp_path / "linked-snapshot")
            else:
                file.chmod(0o644)
            with pytest.raises(ArchiveError) as error:
                archive.load(receipt.receipt_id, snapshot["source"])
            assert error.value.code in ("ARCHIVE_READ_FAILED", "ARCHIVE_FILE_UNSAFE")


def test_archive_record_count_and_byte_caps_fail_closed(snapshot, tmp_path):
    with SnapshotArchive(tmp_path / "count", max_snapshots=1) as archive:
        receipt = archive.store(snapshot)
        other = deepcopy(snapshot)
        other["snapshotId"] = "another"
        with pytest.raises(ArchiveError, match="ARCHIVE_LIMIT_EXCEEDED"):
            archive.store(other)
        assert archive.load(receipt.receipt_id, snapshot["source"]) == snapshot
    with SnapshotArchive(tmp_path / "bytes", max_bytes=1024) as archive:
        with pytest.raises(ArchiveError, match="ARCHIVE_LIMIT_EXCEEDED"):
            archive.store(snapshot)
        assert list((tmp_path / "bytes").iterdir()) == []


def test_file_count_cap_preserves_receipts_and_allows_existing_health_updates(snapshot, tmp_path):
    folder = tmp_path / "archive"
    other = {**snapshot["source"], "sourceId": "other-source"}
    with SnapshotArchive(folder, max_snapshots=1) as archive:
        receipt = archive.store(snapshot)
        archive.record_result(receipt.receipt_id, result(receipt))
        archive.record_health(snapshot["source"], "core", error_code="COLLECTOR_TIMEOUT")
        archive.record_health(other, "core", error_code="COLLECTOR_TIMEOUT")
        before = {file.name: file.read_bytes() for file in folder.iterdir()}
        assert len(before) == 4

        with pytest.raises(ArchiveError, match="^ARCHIVE_LIMIT_EXCEEDED$"):
            archive.record_health(
                {**other, "sourceId": "new-source"}, "core", error_code="COLLECTOR_TIMEOUT"
            )
        assert {file.name: file.read_bytes() for file in folder.iterdir()} == before

        updated = archive.record_health(other, "core", error_code="COLLECTOR_TIMEOUT")
        assert updated["consecutiveFailures"] == 2
        confirmed = archive.record_result(receipt.receipt_id, result(receipt, published=False))
        assert confirmed.status == "published"
        assert archive.load(receipt.receipt_id, snapshot["source"], "core") == snapshot
        assert len(list(folder.iterdir())) == 4

    with SnapshotArchive(folder, max_snapshots=1) as reopened:
        assert reopened.load(receipt.receipt_id, snapshot["source"], "core") == snapshot
        assert reopened.read_health(other, "core")["consecutiveFailures"] == 2


@pytest.mark.parametrize("health_count", [3, 4])
def test_file_count_cap_rejects_new_snapshot_before_creating_an_orphan(
    snapshot, tmp_path, health_count
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder, max_snapshots=1) as archive:
        for index in range(health_count):
            archive.record_health(
                {**snapshot["source"], "sourceId": f"failed-source-{index}"},
                "core",
                error_code="COLLECTOR_TIMEOUT",
            )
        before = {file.name: file.read_bytes() for file in folder.iterdir()}
        with pytest.raises(ArchiveError, match="^ARCHIVE_LIMIT_EXCEEDED$"):
            archive.store(snapshot)
        assert {file.name: file.read_bytes() for file in folder.iterdir()} == before

    with SnapshotArchive(folder, max_snapshots=1) as reopened:
        assert not reopened.list_pending(snapshot["source"], "core")


def test_store_preflights_snapshot_and_receipt_bytes_together(snapshot, tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: 1000)
    baseline = tmp_path / "baseline"
    with SnapshotArchive(baseline) as archive:
        receipt = archive.store(snapshot)
    required = sum(file.stat().st_size for file in baseline.iterdir())

    limited = tmp_path / "limited"
    with SnapshotArchive(limited, max_bytes=required - 1) as archive:
        with pytest.raises(ArchiveError, match="^ARCHIVE_LIMIT_EXCEEDED$"):
            archive.store(snapshot)
        assert not list(limited.iterdir())

    with SnapshotArchive(tmp_path / "exact", max_bytes=required) as archive:
        stored = archive.store(snapshot)
        assert stored == receipt
        assert archive.load(stored.receipt_id, snapshot["source"], "core") == snapshot


def test_crash_between_snapshot_and_receipt_recovers_only_identical_content(
    snapshot, tmp_path, monkeypatch
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        original = archive._write

        def interrupted(name, contents, **kwargs):
            if name.endswith(".receipt.json"):
                raise ArchiveError("ARCHIVE_WRITE_FAILED")
            original(name, contents, **kwargs)

        monkeypatch.setattr(archive, "_write", interrupted)
        with pytest.raises(ArchiveError, match="ARCHIVE_WRITE_FAILED"):
            archive.store(snapshot)
        assert len(list(folder.glob("*.snapshot.json"))) == 1
        assert not list(folder.glob("*.receipt.json"))
    with SnapshotArchive(folder) as reopened:
        changed = deepcopy(snapshot)
        changed["ledgerRevision"] += 1
        with pytest.raises(ArchiveError, match="ARCHIVE_SNAPSHOT_CONFLICT"):
            reopened.store(changed)
        receipt = reopened.store(snapshot)
        assert reopened.load(receipt.receipt_id, snapshot["source"]) == snapshot


def test_failed_import_stays_pending_and_conflicting_result_cannot_replace_receipt(
    snapshot, tmp_path
):
    with SnapshotArchive(tmp_path / "archive") as archive:
        receipt = archive.store(snapshot)
        archive.record_failure(receipt.receipt_id, "SOURCE_SCOPE_MISMATCH")
        assert archive.list_pending(snapshot["source"], "core")[0].receipt_id == receipt.receipt_id
        with pytest.raises(ArchiveError, match="ARCHIVE_INVALID"):
            archive.record_failure(receipt.receipt_id, "private-password:value")
        with pytest.raises(ArchiveError, match="ARCHIVE_INVALID"):
            archive.record_result(
                receipt.receipt_id,
                ImportResult("foreign", receipt.content_hash, receipt.snapshot_id, True, False),
            )
        archive.record_result(receipt.receipt_id, result(receipt))
        with pytest.raises(ArchiveError, match="ARCHIVE_PUBLICATION_CONFLICT"):
            archive.record_result(receipt.receipt_id, result(receipt, projection="f" * 64))


def test_retention_preserves_current_previous_pending_uncertain_and_explicit_protection(
    snapshot, tmp_path, monkeypatch
):
    # Same-second publications are ordered by persisted sequence, never hash or wall-clock ties.
    monkeypatch.setattr(module, "_now", lambda: 1000)
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        receipts = []
        for index in range(5):
            value = deepcopy(snapshot)
            value["snapshotId"] = f"snapshot-{index}"
            receipts.append(archive.store(value))
            if index < 3:
                archive.record_result(receipts[-1].receipt_id, result(receipts[-1]))
            elif index == 4:
                archive.record_result(
                    receipts[-1].receipt_id, result(receipts[-1], published=False)
                )
        assert archive.prune(now=2000, retention_seconds=2000) == 0
        assert (
            archive.prune(
                now=5000, retention_seconds=1, protected_projection_ids=(receipts[0].content_hash,)
            )
            == 0
        )
        assert archive.prune(now=5000, retention_seconds=1) == 1
        with pytest.raises(ArchiveError, match="ARCHIVE_NOT_FOUND"):
            archive.load(receipts[0].receipt_id, snapshot["source"])
        for receipt in receipts[1:]:
            assert (
                archive.load(receipt.receipt_id, snapshot["source"])["snapshotId"]
                == receipt.snapshot_id
            )
    with SnapshotArchive(folder) as reopened:
        assert reopened.prune(now=10000, retention_seconds=0) == 0
        assert len(reopened.list_pending(snapshot["source"], "core")) == 1


def test_health_persists_failure_without_erasing_last_success(snapshot, tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: 1000)
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        first = archive.record_health(snapshot["source"], "core", error_code="COLLECTOR_TIMEOUT")
        assert first["lastSuccessAt"] is None and first["consecutiveFailures"] == 1
        receipt = archive.store(snapshot)
        archive.record_result(receipt.receipt_id, result(receipt))
        success = archive.record_health(
            snapshot["source"], "core", result=result(receipt), snapshot=snapshot
        )
        assert success["lastSuccessAt"] == 1000 and success["consecutiveFailures"] == 0
        assert success["lastSnapshotGeneratedAt"] == snapshot["generatedAt"]
        monkeypatch.setattr(module, "_now", lambda: 1100)
        failed = archive.record_health(
            snapshot["source"], "core", error_code="COLLECTOR_UNAVAILABLE"
        )
        assert failed["lastSuccessAt"] == 1000 and failed["lastAttemptAt"] == 1100
        assert failed["lastSnapshotId"] == snapshot["snapshotId"]
        assert failed["lastSnapshotGeneratedAt"] == snapshot["generatedAt"]
        assert failed["lastProjectionId"] == receipt.content_hash
        with pytest.raises(ArchiveError, match="ARCHIVE_INVALID"):
            archive.record_health(snapshot["source"], "core", error_code="private-canary:token")
        with pytest.raises(ArchiveError, match="ARCHIVE_SCOPE_MISMATCH"):
            archive.read_health(snapshot["source"], "host")
    with SnapshotArchive(folder) as reopened:
        assert reopened.read_health(snapshot["source"], "core") == failed
    for file in folder.iterdir():
        assert "private-canary" not in file.read_text()


def test_archive_and_health_bounds_reject_bad_configuration(snapshot, tmp_path):
    for kwargs in ({"max_snapshots": 0}, {"max_snapshots": True}, {"max_bytes": 10}):
        with pytest.raises(ArchiveError, match="ARCHIVE_CONFIG_INVALID"):
            SnapshotArchive(tmp_path / "archive", **kwargs)
    with SnapshotArchive(tmp_path / "archive") as archive:
        with pytest.raises(ArchiveError, match="ARCHIVE_CONFIG_INVALID"):
            archive.prune(retention_seconds=-1)
        with pytest.raises(ArchiveError, match="ARCHIVE_INVALID"):
            archive.record_health(snapshot["source"], "core")


def test_interrupted_prune_is_recoverable_without_touching_protected_publications(
    snapshot, tmp_path, monkeypatch
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        receipts = []
        for index in range(3):
            value = deepcopy(snapshot)
            value["snapshotId"] = f"prune-{index}"
            receipt = archive.store(value)
            archive.record_result(receipt.receipt_id, result(receipt))
            receipts.append(receipt)
        original = module.os.unlink

        def fail_receipt(path, *args, **kwargs):
            if path == f"{receipts[0].receipt_id}.receipt.json":
                raise OSError("private-path-canary")
            return original(path, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(module.os, "unlink", fail_receipt)
            with pytest.raises(ArchiveError, match="ARCHIVE_WRITE_FAILED"):
                archive.prune(retention_seconds=0)
        assert not (folder / f"{receipts[0].receipt_id}.snapshot.json").exists()
        assert (folder / f"{receipts[0].receipt_id}.receipt.json").exists()
    with SnapshotArchive(folder) as restarted:
        assert restarted.prune(retention_seconds=0) == 1
        for receipt in receipts[1:]:
            assert (
                restarted.load(receipt.receipt_id, snapshot["source"])["snapshotId"]
                == receipt.snapshot_id
            )


def test_abandoned_atomic_write_is_removed_on_locked_restart(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        receipt = archive.store(snapshot)
    temporary = folder / (".tmp-" + "a" * 32)
    temporary.write_text("incomplete-private-payload")
    temporary.chmod(0o600)
    with SnapshotArchive(folder) as restarted:
        assert not temporary.exists()
        assert restarted.load(receipt.receipt_id, snapshot["source"]) == snapshot


def test_maximum_unicode_source_ids_fit_the_protected_receipt(snapshot, tmp_path):
    # Non-BMP UTF-8 source IDs exceed the original 64KiB receipt cap while
    # remaining inside the closed contract and aggregate inventory bound.
    for key in snapshot["source"]:
        if key != "tenantId":
            snapshot["source"][key] = "🚀" * 4096
    snapshot["snapshotId"] = "🚀" * 4096
    with SnapshotArchive(tmp_path / "archive") as archive:
        receipt = archive.store(snapshot)
        assert archive.load(receipt.receipt_id, snapshot["source"]) == snapshot
