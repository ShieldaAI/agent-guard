"""Protected snapshot persistence, restart recovery and conservative retention."""

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography import archive as module
from agent_guard_cartography.archive import ArchiveError, SnapshotArchive, required_snapshots
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


def test_retention_preserves_current_previous_pending_and_explicit_protection(
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
        # A graph pointer protects an old publication.
        pointers = (receipts[0].content_hash,)
        assert archive.prune(now=5000, retention_seconds=1, protected_projection_ids=pointers) == 0
        # Without it that publication expires under the normal retention. Pending and
        # already-known (idempotent) evidence never does, with or without a pointer.
        assert archive.prune(now=5000, retention_seconds=1) == 1
        with pytest.raises(ArchiveError, match="ARCHIVE_NOT_FOUND"):
            archive.load(receipts[0].receipt_id, snapshot["source"])
        for receipt in receipts[1:]:
            assert (
                archive.load(receipt.receipt_id, snapshot["source"])["snapshotId"]
                == receipt.snapshot_id
            )
        # Not even when the archive is out of room.
        assert archive.maintain(now=10**10, retention_seconds=0, reserve_bytes=10**12).removed == 0
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


def variant(snapshot, name, **source):
    value = deepcopy(snapshot)
    value["snapshotId"] = name
    value["source"].update(source)
    return value


def publish(archive, value):
    receipt = archive.store(value)
    return archive.record_result(receipt.receipt_id, result(receipt))


def test_steady_polling_prunes_early_instead_of_exhausting_the_archive(
    snapshot, tmp_path, monkeypatch
):
    # Every poll has a new snapshot ID, so each one needs a slot even when nothing changed.
    clock = [1000]
    monkeypatch.setattr(module, "_now", lambda: clock[0])
    early = 0
    with SnapshotArchive(tmp_path / "archive", max_snapshots=6) as archive:
        receipts = []
        for poll in range(30):
            clock[0] += 300
            for name in ("one", "two"):
                report = archive.maintain(reserve_snapshots=1)
                early += report.pressure_removed
                receipts.append(
                    publish(archive, variant(snapshot, f"{name}-{poll}", sourceId=name))
                )
        assert early and len(list((tmp_path / "archive").glob("*.snapshot.json"))) <= 6
        # The current and previous capture of every source remain recovery anchors.
        for receipt, name in zip(receipts[-4:], ("one", "two", "one", "two"), strict=True):
            assert archive.load(receipt.receipt_id, {**snapshot["source"], "sourceId": name})
    assert required_snapshots(1, 300, 7 * 86400) == 2017
    assert required_snapshots(3, 300, 7 * 86400) > 4096
    assert required_snapshots(128, 3600, 60) == 128 * 3


def test_pressure_pruning_never_removes_pending_protected_or_newest_two(
    snapshot, tmp_path, monkeypatch
):
    monkeypatch.setattr(module, "_now", lambda: 1000)
    with SnapshotArchive(tmp_path / "archive", max_snapshots=5) as archive:
        published = [
            publish(archive, variant(snapshot, f"published-{index}")) for index in range(4)
        ]
        pending = archive.store(variant(snapshot, "rejected-by-graph"))
        pointer = published[0].content_hash
        report = archive.maintain(
            now=1001, reserve_snapshots=1, protected_projection_ids=(pointer,)
        )
        assert (report.removed, report.pressure_removed) == (1, 1)
        with pytest.raises(ArchiveError, match="ARCHIVE_NOT_FOUND"):
            archive.load(published[1].receipt_id, snapshot["source"])
        for kept in (published[0], published[2], published[3], pending):
            assert archive.load(kept.receipt_id, snapshot["source"])
        # Nothing else is removable: the next attempt reports no room rather than evidence loss.
        again = archive.maintain(now=1001, reserve_snapshots=2, protected_projection_ids=(pointer,))
        assert again.removed == 0
        assert archive.list_pending(snapshot["source"], "core") == (pending,)


def test_archive_over_lowered_limits_still_opens_and_recovers(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        for index in range(5):
            publish(archive, variant(snapshot, f"before-{index}"))
    with SnapshotArchive(folder, max_snapshots=3) as lowered:
        assert lowered.maintain(reserve_snapshots=1).pressure_removed == 3
        assert publish(lowered, variant(snapshot, "after")).status == "published"


def test_one_rejected_source_cannot_fill_the_shared_archive(snapshot, tmp_path):
    with SnapshotArchive(tmp_path / "archive", max_pending=2) as archive:
        rejected = [archive.store(variant(snapshot, f"rejected-{index}")) for index in range(2)]
        before = sorted(path.name for path in (tmp_path / "archive").iterdir())
        with pytest.raises(ArchiveError, match="^ARCHIVE_PENDING_LIMIT_EXCEEDED$"):
            archive.store(variant(snapshot, "rejected-2"))
        assert sorted(path.name for path in (tmp_path / "archive").iterdir()) == before
        # Other sources continue, and an identical retry of a stored snapshot is not a new one.
        assert (
            publish(archive, variant(snapshot, "healthy", sourceId="other")).status == "published"
        )
        assert archive.store(variant(snapshot, "rejected-0")) == rejected[0]
        archive.record_failure(rejected[0].receipt_id, "REVISION_ROLLBACK")
        listed = archive.list_pending()
        assert {item.receipt_id for item in listed} == {item.receipt_id for item in rejected}
        assert {item.last_error for item in listed} == {"REVISION_ROLLBACK", None}
        discarded = archive.discard(rejected[0].receipt_id)
        assert discarded["state"] == "pending" and discarded["snapshotId"] == "rejected-0"
        assert archive.store(variant(snapshot, "rejected-2")).status == "pending"
    for kwargs in ({"max_pending": 0}, {"max_pending": 1025}, {"max_pending": True}):
        with pytest.raises(ArchiveError, match="ARCHIVE_CONFIG_INVALID"):
            SnapshotArchive(tmp_path / "archive", **kwargs)


def test_discard_refuses_recovery_anchors_and_removes_damaged_or_orphaned_records(
    snapshot, tmp_path
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        anchor = publish(archive, variant(snapshot, "published"))
        with pytest.raises(ArchiveError, match="^ARCHIVE_DISCARD_REFUSED$") as refused:
            archive.discard(anchor.receipt_id)
        assert refused.value.file == f"{anchor.receipt_id}.receipt.json"
        assert archive.load(anchor.receipt_id, snapshot["source"])
        # Retention never prunes an already-known receipt: a reviewed discard removes it.
        known = archive.store(variant(snapshot, "already-known"))
        archive.record_result(known.receipt_id, result(known, published=False))
        assert archive.discard(known.receipt_id) == {
            "receiptId": known.receipt_id,
            "state": "uncertain",
            "sourceId": known.source_id,
            "snapshotId": "already-known",
        }
        damaged = archive.store(variant(snapshot, "damaged"))
        (folder / f"{damaged.receipt_id}.receipt.json").write_text('{"truncated')
        assert archive.discard(damaged.receipt_id) == {
            "receiptId": damaged.receipt_id,
            "state": "damaged",
            "sourceId": damaged.source_id,
            "snapshotId": None,
        }
        orphan = archive.store(variant(snapshot, "orphan"))
        (folder / f"{orphan.receipt_id}.receipt.json").unlink()
        assert archive.discard(orphan.receipt_id)["state"] == "orphan"
        for identifier, code in (("0" * 64, "ARCHIVE_NOT_FOUND"), ("../escape", "ARCHIVE_INVALID")):
            with pytest.raises(ArchiveError, match=f"^{code}$"):
                archive.discard(identifier)
        assert len(list(folder.iterdir())) == 2


@pytest.mark.parametrize(
    "fault,code",
    [
        ("mode", "ARCHIVE_FILE_UNSAFE"),
        ("link", "ARCHIVE_FILE_UNSAFE"),
        ("read", "ARCHIVE_READ_FAILED"),
    ],
)
def test_discard_never_treats_an_unreadable_anchor_as_damaged(
    snapshot, tmp_path, monkeypatch, fault, code
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        anchor = publish(archive, variant(snapshot, "published"))
        name = f"{anchor.receipt_id}.receipt.json"
        with monkeypatch.context() as patch:
            if fault == "mode":
                (folder / name).chmod(0o640)
            elif fault == "link":
                os.link(folder / name, tmp_path / "second-name")
            else:
                original = module.read_private_file

                def unreadable(target, *args, **kwargs):
                    if target == name:
                        raise OSError("private-path-canary")
                    return original(target, *args, **kwargs)

                patch.setattr(module, "read_private_file", unreadable)
            # Permissions or a failed read say nothing about the content: nothing is removed.
            with pytest.raises(ArchiveError, match=f"^{code}$") as refused:
                archive.discard(anchor.receipt_id)
            assert refused.value.file == name
        assert sorted(path.name for path in folder.iterdir()) == sorted(
            [name, f"{anchor.receipt_id}.snapshot.json"]
        )
        # Repaired, it is the recovery anchor it always was.
        (folder / name).chmod(0o600)
        (tmp_path / "second-name").unlink(missing_ok=True)
        with pytest.raises(ArchiveError, match="^ARCHIVE_DISCARD_REFUSED$"):
            archive.discard(anchor.receipt_id)


def test_a_deeply_nested_receipt_is_damaged_evidence_not_a_crash(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        stored = archive.store(variant(snapshot, "nested"))
        name = f"{stored.receipt_id}.receipt.json"
        (folder / name).write_text("[" * 100_000)
        archive.refresh()
        assert archive.maintain().damaged == (name,)
        with pytest.raises(ArchiveError, match="^ARCHIVE_INVALID$"):
            archive.read_receipt(stored.receipt_id)
        assert archive.discard(stored.receipt_id)["state"] == "damaged"


def test_foreign_files_are_ignored_and_reported_but_never_read_or_counted(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        first = publish(archive, snapshot)
    stray = folder / ".DS_Store"
    stray.write_bytes(b"x" * 4096)
    stray.chmod(0o644)
    (folder / "notes with spaces.txt").write_text("private-canary")
    with SnapshotArchive(folder, max_bytes=4096) as archive:
        assert archive.ignored == (".DS_Store", "notes?with?spaces.txt")
        assert archive.load(first.receipt_id, snapshot["source"]) == snapshot
        assert archive.maintain().removed == 0
    assert stray.read_bytes() == b"x" * 4096


@pytest.mark.parametrize("attributable", [True, False])
def test_unreadable_receipt_fails_only_the_source_that_owns_it(snapshot, tmp_path, attributable):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        broken = publish(archive, variant(snapshot, "broken"))
        old = [
            publish(archive, variant(snapshot, f"other-{index}", sourceId="other"))
            for index in range(3)
        ]
        name = f"{broken.receipt_id}.receipt.json"
        (folder / name).write_text('{"schemaVersion":1,"receiptId":"')
        if not attributable:
            (folder / f"{broken.receipt_id}.snapshot.json").write_text("{")
        # Damage from outside this instance is noticed at the next reconciliation.
        archive.refresh()
        # Maintenance continues for everyone and keeps the unreadable evidence.
        report = archive.maintain(now=10**10, retention_seconds=0)
        assert report.removed == 1 and report.damaged == (name,) == archive.damaged
        with pytest.raises(ArchiveError, match="ARCHIVE_NOT_FOUND"):
            archive.load(old[0].receipt_id, {**snapshot["source"], "sourceId": "other"})
        assert (folder / name).exists()
        healthy = publish(archive, variant(snapshot, "other-new", sourceId="other"))
        assert healthy.status == "published"
        if attributable:
            with pytest.raises(ArchiveError, match="^ARCHIVE_INVALID$") as failure:
                archive.store(variant(snapshot, "next"))
            assert failure.value.file == name
            with pytest.raises(ArchiveError, match="^ARCHIVE_INVALID$"):
                archive.list_pending(snapshot["source"], "core")
        else:
            # Nothing proves whose it was: it is reported, and no source is blocked.
            assert archive.store(variant(snapshot, "next")).status == "pending"
        assert archive.list_pending() is not None and archive.damaged == (name,)
        archive.discard(broken.receipt_id)
        assert archive.maintain().damaged == ()
        assert archive.store(variant(snapshot, "after-review")).status == "pending"


def test_unsafe_snapshot_of_one_source_does_not_stop_another(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        exposed = publish(archive, snapshot)
        name = f"{exposed.receipt_id}.snapshot.json"
        (folder / name).chmod(0o644)
        assert publish(archive, variant(snapshot, "other", sourceId="other")).status == "published"
        with pytest.raises(ArchiveError, match="^ARCHIVE_FILE_UNSAFE$") as failure:
            archive.load(exposed.receipt_id, snapshot["source"])
        assert failure.value.file == name
    with SnapshotArchive(folder) as reopened:
        assert reopened.maintain().removed == 0


def test_lifecycle_and_recovery_fence_names_are_never_treated_as_foreign(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        archive.store(snapshot)
        renamed = folder / "lifecycle-renamed-journal.json"
        renamed.write_text("{}")
        renamed.chmod(0o600)
        archive.refresh()
        assert archive.ignored == ()
        with pytest.raises(ArchiveError, match="^ARCHIVE_TRANSITION_INVALID$") as failure:
            archive.store(variant(snapshot, "after"))
        assert failure.value.file == "lifecycle-renamed-journal.json"


def counted_reads(monkeypatch, archive):
    """Names this archive reads from disk from now on."""
    reads = []
    original = archive._read

    def read(name, maximum):
        reads.append(name)
        return original(name, maximum)

    monkeypatch.setattr(archive, "_read", read)
    return reads


def test_bookkeeping_reads_each_receipt_once_and_never_rescans_the_directory(
    snapshot, tmp_path, monkeypatch
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        for index in range(6):
            publish(archive, variant(snapshot, f"old-{index}", sourceId=f"source-{index % 3}"))
    with SnapshotArchive(folder) as archive:
        reads = counted_reads(monkeypatch, archive)
        listed = []
        monkeypatch.setattr(
            module.os, "listdir", lambda fd, original=os.listdir: listed.append(fd) or original(fd)
        )
        # One poll per source: prune, store, record the result, prune again.
        for index in range(3):
            archive.maintain(reserve_snapshots=1)
            receipt = archive.store(variant(snapshot, f"new-{index}", sourceId=f"source-{index}"))
            archive.record_result(receipt.receipt_id, result(receipt))
            archive.maintain()
            assert archive.list_pending() == ()
        receipt_reads = [name for name in reads if name.endswith(".receipt.json")]
        # The six existing receipts are parsed by the first scan only. Each new receipt
        # is looked up before it exists and re-read once when its result is recorded.
        assert sorted(set(receipt_reads)) == sorted(
            path.name for path in folder.glob("*.receipt.json")
        )
        assert len(receipt_reads) == 6 + 3 * 2
        assert listed == []


def test_index_matches_a_fresh_scan_after_writes_pruning_and_discards(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        kept = [publish(archive, variant(snapshot, f"kept-{index}")) for index in range(4)]
        pending = archive.store(variant(snapshot, "pending"))
        archive.record_failure(pending.receipt_id, "REVISION_ROLLBACK")
        archive.record_health(snapshot["source"], "core", error_code="COLLECTION_FAILED")
        assert archive.maintain(now=10**10, retention_seconds=0).removed == 2
        archive.discard(pending.receipt_id)
        indexed = archive._usage()
        receipts = sorted(value["receiptId"] for value in archive._scan()[0])
        with SnapshotArchive(folder) as fresh:
            assert fresh._usage() == indexed
            assert sorted(value["receiptId"] for value in fresh._scan()[0]) == receipts
        assert receipts == sorted(item.receipt_id for item in kept[2:])
        on_disk = [path for path in folder.iterdir()]
        assert indexed == (
            len(on_disk),
            sum(path.name.endswith(".snapshot.json") for path in on_disk),
            sum(path.stat().st_size for path in on_disk),
        )


def test_refresh_notices_outside_changes_without_rereading_unchanged_receipts(
    snapshot, tmp_path, monkeypatch
):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        first = publish(archive, variant(snapshot, "first"))
        second = publish(archive, variant(snapshot, "second", sourceId="other"))
        assert archive.maintain().damaged == () and archive.ignored == ()
        (folder / ".DS_Store").write_text("finder")
        (folder / f"{second.receipt_id}.receipt.json").write_text('{"truncated')
        # Within a cycle the archive answers from its index; the files it acts on are
        # still read from disk, so the damaged receipt cannot be used.
        assert archive.maintain().damaged == () and archive.ignored == ()
        with pytest.raises(ArchiveError, match="^ARCHIVE_INVALID$"):
            archive.load(second.receipt_id, {**snapshot["source"], "sourceId": "other"})
        reads = counted_reads(monkeypatch, archive)
        archive.refresh()
        assert archive.ignored == (".DS_Store",)
        assert archive.damaged == (f"{second.receipt_id}.receipt.json",)
        assert f"{first.receipt_id}.receipt.json" not in reads
        (folder / f"{second.receipt_id}.receipt.json").unlink()
        (folder / f"{second.receipt_id}.snapshot.json").unlink()
        archive.refresh()
        assert archive.damaged == ()
        assert [value["receiptId"] for value in archive._scan()[0]] == [first.receipt_id]


def test_refresh_notices_permission_and_link_changes_that_keep_the_content(snapshot, tmp_path):
    folder = tmp_path / "archive"
    other = {**snapshot["source"], "sourceId": "other"}
    with SnapshotArchive(folder) as archive:
        first = publish(archive, variant(snapshot, "first"))
        second = publish(archive, variant(snapshot, "second", sourceId="other"))
        name = f"{first.receipt_id}.receipt.json"
        assert archive.maintain().damaged == ()
        # Same bytes, same modification time; but no longer a private file.
        (folder / name).chmod(0o644)
        archive.refresh()
        assert archive.damaged == (name,)
        with pytest.raises(ArchiveError, match="^ARCHIVE_INVALID$") as blocked:
            archive.store(variant(snapshot, "next"))
        assert blocked.value.file == name
        assert archive.store(variant(snapshot, "unaffected", sourceId="other")).status == "pending"
        # Repairing the mode is enough: no restart, no discard.
        (folder / name).chmod(0o600)
        archive.refresh()
        assert archive.damaged == ()
        assert archive.store(variant(snapshot, "next")).status == "pending"
        # A second name for the same file is noticed the same way.
        os.link(folder / f"{second.receipt_id}.receipt.json", tmp_path / "second-name")
        archive.refresh()
        assert archive.damaged == (f"{second.receipt_id}.receipt.json",)
        (tmp_path / "second-name").unlink()
        archive.refresh()
        assert archive.damaged == () and archive.load(second.receipt_id, other)


def test_refresh_reattributes_an_unreadable_receipt_when_its_snapshot_changes(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        broken = publish(archive, variant(snapshot, "broken"))
        name = f"{broken.receipt_id}.receipt.json"
        snapshot_file = folder / f"{broken.receipt_id}.snapshot.json"
        (folder / name).write_text('{"truncated')
        snapshot_file.chmod(0o644)
        archive.refresh()
        # Nobody can be shown to own it while its snapshot cannot be read either.
        assert archive.damaged == (name,)
        assert archive.store(variant(snapshot, "next")).status == "pending"
        snapshot_file.chmod(0o600)
        archive.refresh()
        with pytest.raises(ArchiveError, match="^ARCHIVE_INVALID$"):
            archive.store(variant(snapshot, "after"))


@pytest.mark.parametrize(
    "change", ["damaged", "rewritten", "mode", "snapshot-removed", "snapshot-replaced"]
)
def test_pruning_never_unlinks_a_file_that_changed_since_it_was_indexed(snapshot, tmp_path, change):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        receipts = [publish(archive, variant(snapshot, f"prune-{index}")) for index in range(4)]
        assert archive.maintain().removed == 0
        victim = receipts[0]
        name = f"{victim.receipt_id}.receipt.json"
        snapshot_name = f"{victim.receipt_id}.snapshot.json"
        original = (folder / name).read_bytes()
        if change == "damaged":
            (folder / name).write_bytes(b"{damaged")
        elif change == "rewritten":
            replacement = folder / "replacement"
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            replacement.replace(folder / name)
        elif change == "mode":
            (folder / snapshot_name).chmod(0o400)
        elif change == "snapshot-removed":
            (folder / snapshot_name).unlink()
        else:
            (folder / snapshot_name).unlink()
            (folder / snapshot_name).write_bytes(b"{}")
            (folder / snapshot_name).chmod(0o600)
        # No refresh: this is the middle of a cycle. The stale record removes nothing.
        report = archive.maintain(now=10**10, retention_seconds=0)
        assert (folder / name).exists()
        assert report.removed == 1  # only the other expired publication, prune-1
        assert not (folder / f"{receipts[1].receipt_id}.receipt.json").exists()
        assert report.damaged == ((name,) if change == "damaged" else ())
        # The entry was indexed again from disk: a second pass decides on what is there.
        again = archive.maintain(now=10**10, retention_seconds=0)
        if change == "damaged":
            # Unreadable evidence is kept for review, never deleted automatically.
            assert again.removed == 0 and again.damaged == (name,) and (folder / name).exists()
        else:
            # Still a valid, expired, unprotected publication: now it goes.
            assert again.removed == 1 and not (folder / name).exists()
        indexed = archive._usage()
        with SnapshotArchive(folder) as fresh:
            assert fresh._usage() == indexed


def test_an_existing_archive_can_be_required_instead_of_created(snapshot, tmp_path):
    missing = tmp_path / "archvie"
    with pytest.raises(ArchiveError, match="^ARCHIVE_DIRECTORY_NOT_FOUND$"):
        SnapshotArchive(missing, create=False)
    assert not missing.exists()
    with SnapshotArchive(tmp_path / "archive") as created:
        created.store(snapshot)
    with SnapshotArchive(tmp_path / "archive", create=False) as existing:
        assert len(existing.list_pending()) == 1


def test_reconstruction_fences_the_archive_until_the_block_completes(snapshot, tmp_path):
    folder = tmp_path / "archive"
    with SnapshotArchive(folder) as archive:
        with pytest.raises(RuntimeError, match="interrupted"):
            with archive.reconstruction():
                # Reconstruction itself may write; nothing else may until it completes.
                archive.store(snapshot)
                raise RuntimeError("interrupted")
        assert (folder / module.REPLAY_PENDING).exists()
        with pytest.raises(ArchiveError, match="^ARCHIVE_RECOVERY_PENDING$"):
            archive.store(variant(snapshot, "after"))
    (folder / module.REPLAY_PENDING).unlink()
    with SnapshotArchive(folder) as archive:
        before = archive._usage()
        with archive.reconstruction():
            assert (folder / module.REPLAY_PENDING).exists()
        assert not (folder / module.REPLAY_PENDING).exists()
        assert archive._usage() == before
        assert archive.store(variant(snapshot, "after")).status == "pending"
