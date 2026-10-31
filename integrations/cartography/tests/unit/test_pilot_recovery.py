"""Collector backup boundaries and recovery without touching executor authority."""

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography import pilot_recovery as module
from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.cli import ingestion_lock
from agent_guard_cartography.collector import CollectorEnrollment
from agent_guard_cartography.graph import GraphImportError, ImportResult
from agent_guard_cartography.lifecycle import transition_id
from agent_guard_cartography.pilot_recovery import (
    RecoveryError,
    create_backup,
    inspect_backup,
    replay_published,
    restore_backup,
)


@pytest.fixture
def evidence(tmp_path):
    value = json.loads((Path(__file__).parents[1] / "fixtures" / "alpha-v1.json").read_text())
    enrollment = CollectorEnrollment(
        value["source"],
        "core",
        "http://127.0.0.1:1234/v1/inventory/snapshot",
        "PRIVATE_TOKEN_ENV_CANARY",
    )
    directory = tmp_path / "archive"
    with SnapshotArchive(directory) as archive:
        receipts = []
        for index, state in enumerate(["published", "published", "pending", "idempotent"]):
            snapshot = deepcopy(value)
            snapshot["snapshotId"] = f"recovery-{index}"
            snapshot["ledgerRevision"] += index
            receipt = archive.store(snapshot)
            if state != "pending":
                result = ImportResult(
                    receipt.source_id,
                    str(index) * 64,
                    receipt.snapshot_id,
                    state == "published",
                    state == "idempotent",
                )
                archive.record_result(receipt.receipt_id, result)
                archive.record_health(snapshot["source"], "core", result=result, snapshot=snapshot)
            else:
                archive.record_failure(receipt.receipt_id, "COLLECTOR_UNAVAILABLE")
            receipts.append(receipt)
    return directory, enrollment, receipts


def backup(evidence, tmp_path):
    directory, enrollment, _ = evidence
    path = tmp_path / "backup"
    summary = create_backup(directory, path, [enrollment], lock_file=tmp_path / "ingest.lock")
    return path, summary


def test_backup_roundtrip_is_private_complete_and_contains_no_credentials(
    evidence, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRIVATE_TOKEN_ENV_CANARY", "agi_v1." + "x" * 43)
    directory, enrollment, receipts = evidence
    authority = tmp_path / "authority.sqlite"
    authority.write_bytes(b"private authority ledger canary")
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    path, summary = backup(evidence, tmp_path)
    assert (summary.snapshots, summary.published, summary.pending, summary.uncertain) == (
        4,
        2,
        1,
        1,
    )
    inspected = inspect_backup(path)
    assert inspected["manifest"]["sources"] == [
        {"source": dict(enrollment.source), "profile": "core"}
    ]
    for file in path.iterdir():
        assert file.stat().st_mode & 0o777 == 0o600
        for secret in [
            "PRIVATE_TOKEN_ENV_CANARY",
            "agi_v1." + "x" * 43,
            "127.0.0.1:1234",
            "private authority ledger canary",
        ]:
            assert secret.encode() not in file.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o700
    restored = tmp_path / "restored"
    assert restore_backup(path, restored, lock_file=tmp_path / "restore.lock") == summary
    assert {p.name: p.read_bytes() for p in restored.iterdir()} == before
    assert authority.read_bytes() == b"private authority ledger canary"
    with SnapshotArchive(restored) as archive:
        assert (
            archive.load(receipts[0].receipt_id, enrollment.source)["snapshotId"]
            == receipts[0].snapshot_id
        )
        assert len(archive.list_pending(enrollment.source, "core")) == 1


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_never_overwrites_existing_destination(evidence, tmp_path, operation):
    path, _ = backup(evidence, tmp_path)
    destination = tmp_path / "existing"
    destination.mkdir(mode=0o700)
    (destination / "keep").write_bytes(b"untouched")
    with pytest.raises(RecoveryError, match="RECOVERY_DESTINATION_EXISTS"):
        if operation == "backup":
            create_backup(evidence[0], destination, [evidence[1]], lock_file=tmp_path / "lock")
        else:
            restore_backup(path, destination, lock_file=tmp_path / "lock")
    assert (destination / "keep").read_bytes() == b"untouched"


def test_live_collector_lock_blocks_backup_and_restore(evidence, tmp_path):
    path, _ = backup(evidence, tmp_path)
    lock = tmp_path / "ingest.lock"
    with ingestion_lock(lock):
        for action in [
            lambda: create_backup(evidence[0], tmp_path / "other", [evidence[1]], lock_file=lock),
            lambda: restore_backup(path, tmp_path / "other", lock_file=lock),
        ]:
            with pytest.raises(GraphImportError, match="INGESTION_ALREADY_RUNNING"):
                action()
    assert not (tmp_path / "other").exists()


@pytest.mark.parametrize(
    "mutation", ["hash", "length", "traversal", "duplicate", "unknown", "version", "source"]
)
def test_corrupt_manifest_cannot_install_partial_restore(evidence, tmp_path, mutation):
    path, _ = backup(evidence, tmp_path)
    manifest = path / "backup.json"
    value = json.loads(manifest.read_text())
    if mutation == "hash":
        value["files"][0]["sha256"] = "0" * 64
    elif mutation == "length":
        value["files"][0]["size"] += 1
    elif mutation == "traversal":
        value["files"][0]["name"] = "../authority.sqlite"
    elif mutation == "duplicate":
        value["files"].append(value["files"][0])
    elif mutation == "unknown":
        value["password"] = "private-canary"
    elif mutation == "version":
        value["schemaVersion"] = 2
    else:
        value["sources"][0]["source"]["tenantId"] = "other"
    manifest.write_text(json.dumps(value))
    with pytest.raises((RecoveryError, ArchiveError)):
        restore_backup(path, tmp_path / "restored", lock_file=tmp_path / "lock")
    assert not (tmp_path / "restored").exists()
    assert not list(tmp_path.glob(".guard-recovery-*"))


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "mode", "fifo", "extra"])
def test_unsafe_backup_files_are_rejected(evidence, tmp_path, unsafe):
    path, _ = backup(evidence, tmp_path)
    target = next(path.glob("*.snapshot.json"))
    if unsafe == "symlink":
        raw = target.read_bytes()
        target.unlink()
        outside = tmp_path / "outside"
        outside.write_bytes(raw)
        target.symlink_to(outside)
    elif unsafe == "hardlink":
        os.link(target, tmp_path / "outside")
    elif unsafe == "mode":
        target.chmod(0o644)
    elif unsafe == "fifo":
        target.unlink()
        os.mkfifo(target, mode=0o600)
    else:
        (path / ".env").write_text("SECRET=private-canary")
    with pytest.raises((RecoveryError, ArchiveError, OSError)):
        inspect_backup(path)


def test_archive_extra_files_and_orphaned_snapshots_are_not_silently_backed_up(evidence, tmp_path):
    directory, enrollment, receipts = evidence
    unknown = directory / "authority.sqlite"
    unknown.write_bytes(b"private-canary")
    unknown.chmod(0o600)
    with pytest.raises(RecoveryError, match="RECOVERY_FILE_UNEXPECTED"):
        create_backup(directory, tmp_path / "backup", [enrollment], lock_file=tmp_path / "lock")
    unknown.unlink()
    (directory / (receipts[0].receipt_id + ".receipt.json")).unlink()
    with pytest.raises(RecoveryError, match="RECOVERY_INCOMPLETE_ARCHIVE"):
        create_backup(directory, tmp_path / "backup", [enrollment], lock_file=tmp_path / "lock")
    assert not (tmp_path / "backup").exists()


def test_scope_and_size_bounds_are_enforced_before_copy(evidence, tmp_path):
    directory, enrollment, _ = evidence
    foreign = CollectorEnrollment(
        {**enrollment.source, "tenantId": "other"}, "core", enrollment.endpoint, "UNUSED"
    )
    for configured, limits in [
        ([foreign], {}),
        ([enrollment], {"max_bytes": 1024}),
        ([enrollment], {"max_snapshots": 1}),
    ]:
        with pytest.raises((ArchiveError, RecoveryError)):
            create_backup(
                directory, tmp_path / "backup", configured, lock_file=tmp_path / "lock", **limits
            )
    assert not (tmp_path / "backup").exists()


def test_interrupted_copy_publishes_nothing_and_preserves_backup(evidence, tmp_path, monkeypatch):
    path, _ = backup(evidence, tmp_path)
    original = {p.name: p.read_bytes() for p in path.iterdir()}
    counter = 0
    write = module._write

    def fail_after_one(*args):
        nonlocal counter
        counter += 1
        if counter == 2:
            raise OSError("private-error-canary")
        write(*args)

    monkeypatch.setattr(module, "_write", fail_after_one)
    with pytest.raises(OSError):
        restore_backup(path, tmp_path / "restored", lock_file=tmp_path / "lock")
    assert not (tmp_path / "restored").exists()
    assert not list(tmp_path.glob(".guard-recovery-*"))
    assert {p.name: p.read_bytes() for p in path.iterdir()} == original


def test_replay_preserves_original_receipts_and_excludes_unpublished_evidence(
    evidence, tmp_path, monkeypatch
):
    directory, enrollment, _ = evidence
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    calls = []

    class Result:
        def single(self):
            return None

    class Session:
        def run(self, query, **params):
            assert "GuardSource" in params["labels"]
            assert not any(word in query for word in ("DELETE", "SET", "MERGE", "CREATE"))
            return Result()

    def publish(_session, snapshot, source, **options):
        calls.append((snapshot["snapshotId"], options["update_tag"]))
        return ImportResult(
            module.source_key(source),
            "f" * 63 + str(len(calls)),
            snapshot["snapshotId"],
            True,
            False,
        )

    monkeypatch.setattr(module, "import_snapshot", publish)
    result = replay_published(
        Session(),
        directory,
        [enrollment],
        replay_archive_directory=tmp_path / "working",
        lock_file=tmp_path / "lock",
        update_tag=100,
    )
    assert calls == [("recovery-0", 100), ("recovery-1", 101)]
    assert result["published"] == 2
    assert result["pendingExcluded"] == result["uncertainExcluded"] == 1
    assert all(item["originalProjectionId"] != item["projectionId"] for item in result["results"])
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original
    with SnapshotArchive(tmp_path / "working") as archive:
        assert archive.read_health(enrollment.source, "core")["lastSnapshotId"] == "recovery-1"
        assert archive.list_pending(enrollment.source, "core") == ()


def test_replay_refuses_any_existing_guard_state_before_writes(evidence, tmp_path):
    class Result:
        def single(self):
            return {"occupied": 1}

    class Session:
        def run(self, *_args, **_kwargs):
            return Result()

    with pytest.raises(RecoveryError, match="RECOVERY_GRAPH_NOT_EMPTY"):
        replay_published(
            Session(),
            evidence[0],
            [evidence[1]],
            replay_archive_directory=tmp_path / "working",
            lock_file=tmp_path / "lock",
        )
    assert not (tmp_path / "working").exists()


def test_cli_diagnostics_never_echo_paths_or_configuration_secrets(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_guard_cartography.pilot_recovery",
            "inspect",
            "--backup-dir",
            str(tmp_path / "private-path-canary"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert json.loads(result.stderr) == {"error": "RECOVERY_FAILED"}


def test_atomic_publication_does_not_replace_concurrently_created_empty_directory(
    evidence, tmp_path, monkeypatch
):
    path, _ = backup(evidence, tmp_path)
    publish = module._rename_new_directory

    def concurrent(parent, source, destination):
        os.mkdir(destination, mode=0o700, dir_fd=parent)
        publish(parent, source, destination)

    monkeypatch.setattr(module, "_rename_new_directory", concurrent)
    with pytest.raises(RecoveryError, match="RECOVERY_DESTINATION_EXISTS"):
        restore_backup(path, tmp_path / "restored", lock_file=tmp_path / "lock")
    assert (tmp_path / "restored").is_dir()
    assert list((tmp_path / "restored").iterdir()) == []
    assert not list(tmp_path.glob(".guard-recovery-*"))


def test_backup_cannot_contaminate_its_source_archive(evidence, tmp_path):
    directory, enrollment, _ = evidence
    with pytest.raises(RecoveryError, match="RECOVERY_PATH_UNSAFE"):
        create_backup(directory, directory / "nested", [enrollment], lock_file=tmp_path / "lock")
    assert not (directory / "nested").exists()
    with SnapshotArchive(directory) as archive:
        assert len(archive.list_pending(enrollment.source, "core")) == 1


def test_schema_validation_rejects_rehashed_private_or_unknown_snapshot_members(evidence, tmp_path):
    from hashlib import sha256

    path, _ = backup(evidence, tmp_path)
    target = next(path.glob("*.snapshot.json"))
    value = json.loads(target.read_text())
    value["credentials"] = {"token": "private-canary"}
    raw = json.dumps(value).encode()
    target.write_bytes(raw)
    manifest_path = path / "backup.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["name"] == target.name:
            entry.update(size=len(raw), sha256=sha256(raw).hexdigest())
    receipt_path = path / target.name.replace(".snapshot.json", ".receipt.json")
    receipt = json.loads(receipt_path.read_text())
    receipt["sha256"] = sha256(raw).hexdigest()
    receipt_bytes = json.dumps(receipt).encode()
    receipt_path.write_bytes(receipt_bytes)
    for entry in manifest["files"]:
        if entry["name"] == receipt_path.name:
            entry.update(size=len(receipt_bytes), sha256=sha256(receipt_bytes).hexdigest())
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises((ArchiveError, RecoveryError)):
        restore_backup(path, tmp_path / "restored", lock_file=tmp_path / "lock")
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schemaVersion":1,"schemaVersion":1}',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"[]",
        b'{"createdAt":NaN}',
    ],
)
def test_manifest_requires_strict_utf8_object_json(evidence, tmp_path, payload):
    path, _ = backup(evidence, tmp_path)
    (path / "backup.json").write_bytes(payload)
    with pytest.raises(RecoveryError, match="RECOVERY_INVALID"):
        inspect_backup(path)


def test_failed_replay_keeps_original_evidence_and_private_pending_working_receipt(
    evidence, tmp_path, monkeypatch
):
    directory, enrollment, _ = evidence
    original = {p.name: p.read_bytes() for p in directory.iterdir()}

    class Result:
        def single(self):
            return None

    class Session:
        def run(self, *_args, **_kwargs):
            return Result()

    def fail(*_args, **_kwargs):
        raise GraphImportError("PUBLICATION_COMPARE_AND_SET_FAILED")

    monkeypatch.setattr(module, "import_snapshot", fail)
    with pytest.raises(GraphImportError, match="PUBLICATION_COMPARE_AND_SET_FAILED"):
        replay_published(
            Session(),
            directory,
            [enrollment],
            replay_archive_directory=tmp_path / "working",
            lock_file=tmp_path / "lock",
        )
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original
    with SnapshotArchive(tmp_path / "working") as archive:
        assert len(archive.list_pending(enrollment.source, "core")) == 1
        with pytest.raises(ArchiveError, match="ARCHIVE_RECOVERY_PENDING"):
            archive.store(
                archive.load(
                    archive.list_pending(enrollment.source, "core")[0].receipt_id, enrollment.source
                )
            )
    with pytest.raises(RecoveryError, match="RECOVERY_DESTINATION_EXISTS"):
        replay_published(
            Session(),
            directory,
            [enrollment],
            replay_archive_directory=tmp_path / "working",
            lock_file=tmp_path / "lock",
        )


@pytest.fixture
def lifecycle_evidence(tmp_path):
    from test_lifecycle_archive import receipt, transition

    value = json.loads((Path(__file__).parents[1] / "fixtures" / "alpha-v1.json").read_text())
    first = transition(value["source"])
    second = transition(first["successor"], "enrollment-3")
    directory = tmp_path / "lifecycle-archive"
    with SnapshotArchive(directory) as archive:
        for index, source in enumerate(
            [first["predecessor"], first["successor"], second["successor"]]
        ):
            snapshot = {**deepcopy(value), "source": source, "snapshotId": f"generation-{index}"}
            stored = archive.store(snapshot)
            archive.record_result(
                stored.receipt_id,
                ImportResult(stored.source_id, str(index) * 64, stored.snapshot_id, True, False),
            )
        for index, item in enumerate([first, second]):
            archive.stage_transition(item)
            archive.finish_transition(item, receipt(item, 1000 + index))
    active = {"source": second["successor"], "profile": "core"}
    return directory, active, [first, second]


def test_completed_lifecycle_journals_expand_backup_scope_and_roundtrip(
    lifecycle_evidence, tmp_path
):
    directory, active, transitions = lifecycle_evidence
    path = tmp_path / "backup"
    summary = create_backup(directory, path, [active], lock_file=tmp_path / "lock")
    assert summary.sources == summary.published == 3
    inspected = inspect_backup(path)
    assert len(inspected["manifest"]["sources"]) == 3
    assert len(list(path.glob("lifecycle-*.json"))) == 2
    restored = tmp_path / "restored"
    restore_backup(path, restored, lock_file=tmp_path / "lock")
    assert {p.name: p.read_bytes() for p in restored.iterdir()} == {
        p.name: p.read_bytes() for p in directory.iterdir()
    }
    with SnapshotArchive(restored) as archive:
        assert [record["transition"] for record in archive.list_transitions()] == transitions
        assert all(record["status"] == "complete" for record in archive.list_transitions())


@pytest.mark.parametrize(
    "damage", ["pending", "missing_publication", "unrelated", "wrong_profile", "cycle"]
)
def test_ambiguous_lifecycle_blocks_backup_before_copy(lifecycle_evidence, tmp_path, damage):
    from test_lifecycle_archive import receipt, transition

    directory, active, transitions = lifecycle_evidence
    expected = "RECOVERY_SCOPE_MISMATCH"
    if damage == "pending":
        target = directory / f"lifecycle-{module.source_key(transitions[0]['predecessor'])}.json"
        value = json.loads(target.read_text())
        value.update(status="pending", receipt=None)
        target.write_text(json.dumps(value))
        expected = "RECOVERY_TRANSITION_PENDING"
    elif damage == "missing_publication":
        with SnapshotArchive(directory) as archive:
            old = next(
                archive._receipt(p.name[:-13])
                for p in directory.glob("*.receipt.json")
                if archive._receipt(p.name[:-13])["source"] == transitions[0]["predecessor"]
            )
        for suffix in (".receipt.json", ".snapshot.json"):
            (directory / (old["receiptId"] + suffix)).unlink()
        expected = "RECOVERY_LIFECYCLE_EVIDENCE_MISSING"
    elif damage == "unrelated":
        other = transition({**active["source"], "companyId": "another-company"}, "other")
        with SnapshotArchive(directory) as archive:
            archive.stage_transition(other)
            archive.finish_transition(other, receipt(other))
    elif damage == "wrong_profile":
        active = {**active, "profile": "host"}
    else:
        other = {**transition(active["source"]), "successor": transitions[0]["predecessor"]}
        record = {
            "schemaVersion": 1,
            "transition": other,
            "transitionId": transition_id(other),
            "status": "complete",
            "receipt": receipt(other),
        }
        path = directory / f"lifecycle-{module.source_key(other['predecessor'])}.json"
        path.write_text(json.dumps(record))
        path.chmod(0o600)
        expected = "ARCHIVE_TRANSITION_CONFLICT"
    with pytest.raises((RecoveryError, ArchiveError), match=expected):
        create_backup(directory, tmp_path / "backup", [active], lock_file=tmp_path / "lock")
    assert not (tmp_path / "backup").exists()


def test_backup_manifest_cannot_omit_a_lifecycle_endpoint(lifecycle_evidence, tmp_path):
    directory, active, transitions = lifecycle_evidence
    path = tmp_path / "backup"
    create_backup(directory, path, [active], lock_file=tmp_path / "lock")
    manifest_path = path / "backup.json"
    value = json.loads(manifest_path.read_text())
    value["sources"] = [
        entry for entry in value["sources"] if entry["source"] != transitions[0]["predecessor"]
    ]
    manifest_path.write_text(json.dumps(value))
    with pytest.raises(RecoveryError, match="RECOVERY_SCOPE_MISMATCH"):
        restore_backup(path, tmp_path / "restored", lock_file=tmp_path / "lock")
    assert not (tmp_path / "restored").exists()


def test_replay_reapplies_journals_in_order_and_preserves_retirement_timestamp(
    lifecycle_evidence, tmp_path, monkeypatch
):
    from test_lifecycle_archive import receipt

    from agent_guard_cartography import lifecycle

    directory, active, transitions = lifecycle_evidence
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    events = []

    class Result:
        def single(self):
            return None

    class Session:
        def run(self, *_args, **_kwargs):
            return Result()

    def publish(_session, snapshot, source, **_kwargs):
        events.append(("snapshot", module.source_key(source)))
        return ImportResult(
            module.source_key(source),
            "f" * 63 + str(len(events)),
            snapshot["snapshotId"],
            True,
            False,
        )

    def supersede(_session, value, *, timestamp_ms):
        events.append(("transition", transition_id(value), timestamp_ms))
        return receipt(value, timestamp_ms)

    monkeypatch.setattr(module, "import_snapshot", publish)
    monkeypatch.setattr(lifecycle, "supersede_source", supersede)
    working = tmp_path / "working"
    result = replay_published(
        Session(),
        directory,
        [active],
        replay_archive_directory=working,
        lock_file=tmp_path / "lock",
    )
    assert result["published"] == 3 and result["transitionsReplayed"] == 2
    assert [item[0] for item in events] == ["snapshot"] * 3 + ["transition"] * 2
    assert events[-2:] == [
        ("transition", transition_id(value), 1000 + index)
        for index, value in enumerate(transitions)
    ]
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original
    with SnapshotArchive(working) as archive:
        assert [record["transition"] for record in archive.list_transitions()] == transitions
        assert not (working / module.REPLAY_PENDING).exists()
    create_backup(working, tmp_path / "rebuilt-backup", [active], lock_file=tmp_path / "lock")


def test_interrupted_reconstruction_cannot_be_backed_up_or_replayed(
    lifecycle_evidence, tmp_path, monkeypatch
):
    directory, active, _transitions = lifecycle_evidence
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    count = 0

    class Result:
        def single(self):
            return None

    class Session:
        def run(self, *_args, **_kwargs):
            return Result()

    def publish(_session, snapshot, source, **_kwargs):
        nonlocal count
        count += 1
        if count == 2:
            raise GraphImportError("PUBLICATION_COMPARE_AND_SET_FAILED")
        return ImportResult(
            module.source_key(source), "f" * 64, snapshot["snapshotId"], True, False
        )

    monkeypatch.setattr(module, "import_snapshot", publish)
    working = tmp_path / "working"
    with pytest.raises(GraphImportError):
        replay_published(
            Session(),
            directory,
            [active],
            replay_archive_directory=working,
            lock_file=tmp_path / "lock",
        )
    assert (working / module.REPLAY_PENDING).stat().st_mode & 0o777 == 0o600
    assert not list(working.glob("lifecycle-*.json"))
    for action in [
        lambda: create_backup(
            working, tmp_path / "unsafe-backup", [active], lock_file=tmp_path / "lock"
        ),
        lambda: replay_published(
            Session(),
            working,
            [active],
            replay_archive_directory=tmp_path / "unsafe-replay",
            lock_file=tmp_path / "lock",
        ),
    ]:
        with pytest.raises(RecoveryError, match="RECOVERY_REPLAY_PENDING"):
            action()
    assert not (tmp_path / "unsafe-backup").exists()
    assert not (tmp_path / "unsafe-replay").exists()
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original


def test_lifecycle_expansion_preserves_the_128_source_backup_bound(lifecycle_evidence, tmp_path):
    directory, active, _transitions = lifecycle_evidence
    configured = [active] + [
        {"source": {**active["source"], "sourceId": f"other-{index}"}, "profile": "core"}
        for index in range(127)
    ]
    with pytest.raises(RecoveryError, match="RECOVERY_LIMIT_EXCEEDED"):
        create_backup(directory, tmp_path / "backup", configured, lock_file=tmp_path / "lock")
    assert not (tmp_path / "backup").exists()


def test_interrupted_transition_replay_retains_pending_intent_and_original_evidence(
    lifecycle_evidence, tmp_path, monkeypatch
):
    from agent_guard_cartography import lifecycle

    directory, active, transitions = lifecycle_evidence
    original = {p.name: p.read_bytes() for p in directory.iterdir()}

    class Result:
        def single(self):
            return None

    class Session:
        def run(self, *_args, **_kwargs):
            return Result()

    def publish(_session, snapshot, source, **_kwargs):
        return ImportResult(
            module.source_key(source), "f" * 64, snapshot["snapshotId"], True, False
        )

    def interrupted(*_args, **_kwargs):
        raise GraphImportError("TRANSITION_INTERRUPTED")

    monkeypatch.setattr(module, "import_snapshot", publish)
    monkeypatch.setattr(lifecycle, "supersede_source", interrupted)
    working = tmp_path / "working"
    with pytest.raises(GraphImportError, match="TRANSITION_INTERRUPTED"):
        replay_published(
            Session(),
            directory,
            [active],
            replay_archive_directory=working,
            lock_file=tmp_path / "lock",
        )
    with SnapshotArchive(working) as archive:
        (record,) = archive.list_transitions()
        assert record["status"] == "pending" and record["transition"] == transitions[0]
        with pytest.raises(ArchiveError, match="ARCHIVE_RECOVERY_PENDING"):
            archive.stage_transition(transitions[0])
    with pytest.raises(RecoveryError, match="RECOVERY_TRANSITION_PENDING|RECOVERY_REPLAY_PENDING"):
        create_backup(working, tmp_path / "backup", [active], lock_file=tmp_path / "lock")
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original
