"""Private collector backups and fresh-graph reconstruction; never executor authority."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from agent_guard_cartography.archive import (
    REPLAY_PENDING,
    ArchiveError,
    SnapshotArchive,
    _encoded,
    _now,
)
from agent_guard_cartography.cli import ingestion_lock
from agent_guard_cartography.collector import (
    CollectionError,
    CollectorEnrollment,
    _pairs,
    _source,
    load_enrollment,
)
from agent_guard_cartography.graph import GraphImportError, import_snapshot, source_key
from agent_guard_cartography.inventory import MAX_SNAPSHOT_BYTES, InventoryValidationError
from agent_guard_cartography.models import PROJECTION_LABELS

FORMAT = "agent-guard-collector-backup"
MAX_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOTS = 4096
MANIFEST_LIMIT = 8 * 1024 * 1024
MANIFEST = "backup.json"
NAME = re.compile(
    r"(?:[a-f0-9]{64}\.(?:snapshot|receipt)\.json|(?:health|lifecycle)-[a-f0-9]{64}\.json)"
)
GUARD_LABELS = ["GuardSource", "GuardSnapshot", *PROJECTION_LABELS]


class RecoveryError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code="RECOVERY_INVALID"):
    raise RecoveryError(code)


@dataclass(frozen=True)
class RecoverySummary:
    backup_id: str
    sources: int
    snapshots: int
    published: int
    pending: int
    uncertain: int
    files: int
    bytes: int


def _bounds(max_bytes, max_snapshots):
    if (
        type(max_bytes) is not int
        or not 1024 <= max_bytes <= 8 * 1024**3
        or type(max_snapshots) is not int
        or not 1 <= max_snapshots <= 100_000
    ):
        _fail("RECOVERY_CONFIG_INVALID")


def _sources(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 128:
        _fail("RECOVERY_CONFIG_INVALID")
    result, seen = [], set()
    for item in values:
        if isinstance(item, CollectorEnrollment):
            item = {"source": dict(item.source), "profile": item.profile}
        if type(item) is not dict or set(item) != {"source", "profile"}:
            _fail("RECOVERY_CONFIG_INVALID")
        source = dict(_source(item["source"]))
        if item["profile"] not in ("core", "host", "host-mcp"):
            _fail("RECOVERY_CONFIG_INVALID")
        identifier = source_key(source)
        if identifier in seen:
            _fail("RECOVERY_CONFIG_INVALID")
        seen.add(identifier)
        result.append({"source": source, "profile": item["profile"]})
    return sorted(result, key=lambda item: source_key(item["source"]))


def _private_directory(path: Path) -> int:
    """Open components without following symlinks; require a private final directory."""
    path = path.absolute()
    if ".." in path.parts:
        _fail("RECOVERY_PATH_UNSAFE")
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            _fail("RECOVERY_PATH_UNSAFE")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read(descriptor, name, maximum):
    file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    try:
        info = os.fstat(file)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            _fail("RECOVERY_FILE_UNSAFE")
        if info.st_size > maximum:
            _fail("RECOVERY_LIMIT_EXCEEDED")
        with os.fdopen(file, "rb", closefd=False) as stream:
            contents = stream.read(maximum + 1)
        if len(contents) > maximum:
            _fail("RECOVERY_LIMIT_EXCEEDED")
        return contents
    finally:
        os.close(file)


def _write(descriptor, name, contents):
    file = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
    )
    with os.fdopen(file, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def _lifecycle_sources(sources, transitions, *, expand):
    """Only completed transitions connected to explicitly enrolled sources extend scope."""
    if any(record["status"] != "complete" for record in transitions):
        _fail("RECOVERY_TRANSITION_PENDING")
    source_map = {source_key(item["source"]): item for item in sources}
    remaining = list(transitions)
    while remaining:
        progress = False
        for record in remaining[:]:
            transition = record["transition"]
            endpoints = {
                source_key(transition[key]): {
                    "source": transition[key],
                    "profile": transition["profile"],
                }
                for key in ("predecessor", "successor")
            }
            if not any(identifier in source_map for identifier in endpoints):
                continue
            for identifier, entry in endpoints.items():
                if identifier not in source_map:
                    if not expand:
                        _fail("RECOVERY_SCOPE_MISMATCH")
                    source_map[identifier] = entry
                elif source_map[identifier] != entry:
                    _fail("RECOVERY_SCOPE_MISMATCH")
            if len(source_map) > 128:
                _fail("RECOVERY_LIMIT_EXCEEDED")
            remaining.remove(record)
            progress = True
        if not progress:
            _fail("RECOVERY_SCOPE_MISMATCH")
    return sorted(source_map.values(), key=lambda item: source_key(item["source"]))


def _archive_records(path, sources, max_bytes, max_snapshots, *, backup=False, expand=False):
    with SnapshotArchive(
        path, max_bytes=max_bytes, max_snapshots=100_000 if backup else max_snapshots
    ) as archive:
        transitions = archive.list_transitions()
        sources = _lifecycle_sources(sources, transitions, expand=expand)
        source_map = {source_key(item["source"]): item for item in sources}
        names = sorted(
            name for name in os.listdir(archive._fd) if not (backup and name == MANIFEST)
        )
        if REPLAY_PENDING in names:
            _fail("RECOVERY_REPLAY_PENDING")
        if (
            len(names) > 4 * max_snapshots
            or sum(name.endswith(".snapshot.json") for name in names) > max_snapshots
        ):
            _fail("RECOVERY_LIMIT_EXCEEDED")
        if any(NAME.fullmatch(name) is None for name in names):
            _fail("RECOVERY_FILE_UNEXPECTED")
        receipts, files, snapshots, sequences, total = [], [], set(), set(), 0
        for name in names:
            maximum = MAX_SNAPSHOT_BYTES if name.endswith(".snapshot.json") else 256 * 1024
            raw = archive._read(name, maximum)
            total += len(raw)
            if total > max_bytes:
                _fail("RECOVERY_LIMIT_EXCEEDED")
            files.append({"name": name, "size": len(raw), "sha256": sha256(raw).hexdigest()})
            if name.endswith(".receipt.json"):
                receipt = archive._receipt(name[:-13])
                source = source_map.get(receipt["sourceId"])
                if not source:
                    _fail("RECOVERY_SCOPE_MISMATCH")
                archive.load(receipt["receiptId"], source["source"], source["profile"])
                snapshots.add(receipt["receiptId"] + ".snapshot.json")
                if receipt["status"] == "published":
                    order = (receipt["sourceId"], receipt["publicationSequence"])
                    if order in sequences:
                        _fail("RECOVERY_ORDER_AMBIGUOUS")
                    sequences.add(order)
                receipts.append(receipt)
            elif name.startswith("health-"):
                source = source_map.get(name[7:-5])
                if not source:
                    _fail("RECOVERY_SCOPE_MISMATCH")
                archive.read_health(source["source"], source["profile"])
        if snapshots != {name for name in names if name.endswith(".snapshot.json")}:
            _fail("RECOVERY_INCOMPLETE_ARCHIVE")
        published_sources = {
            receipt["sourceId"] for receipt in receipts if receipt["status"] == "published"
        }
        if any(
            source_key(record["transition"][key]) not in published_sources
            for record in transitions
            for key in ("predecessor", "successor")
        ):
            _fail("RECOVERY_LIFECYCLE_EVIDENCE_MISSING")
        return files, receipts, transitions, sources


def _summary(manifest, receipts):
    return RecoverySummary(
        manifest["backupId"],
        len(manifest["sources"]),
        len(receipts),
        sum(item["status"] == "published" for item in receipts),
        sum(item["status"] == "pending" for item in receipts),
        sum(item["status"] == "idempotent" for item in receipts),
        len(manifest["files"]),
        sum(item["size"] for item in manifest["files"]),
    )


def _rename_new_directory(parent, source_name, destination_name):
    """Atomic publish without replacing even a concurrently created empty target.

    Supported pilot hosts are Linux/macOS. Refuse other hosts/filesystems instead
    of weakening the fresh-destination guarantee with a check-then-rename race.
    """
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function, flag = getattr(library, "renameatx_np", None), 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function, flag = getattr(library, "renameat2", None), 1  # RENAME_NOREPLACE
    else:
        function = None
    if function is None:
        _fail("RECOVERY_ATOMIC_RENAME_UNSUPPORTED")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(source_name), parent, os.fsencode(destination_name), flag) != 0:
        error = ctypes.get_errno()
        if error in (errno.EEXIST, errno.ENOTEMPTY):
            _fail("RECOVERY_DESTINATION_EXISTS")
        _fail("RECOVERY_PUBLISH_FAILED")


def _install(source, destination, files, manifest=None):
    """Stage complete private files, then publish a new directory under the ingestion lock."""
    destination = Path(destination).absolute()
    if destination.is_relative_to(Path(source).absolute()):
        _fail("RECOVERY_PATH_UNSAFE")
    parent = _private_directory(destination.parent)
    stage_name = f".guard-recovery-{uuid4().hex}"
    stage = destination.parent / stage_name
    source_fd = stage_fd = -1
    try:
        if destination.name in os.listdir(parent):
            _fail("RECOVERY_DESTINATION_EXISTS")
        os.mkdir(stage_name, mode=0o700, dir_fd=parent)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        source_fd = _private_directory(Path(source))
        for entry in files:
            raw = _read(source_fd, entry["name"], min(entry["size"], MAX_SNAPSHOT_BYTES))
            if len(raw) != entry["size"] or sha256(raw).hexdigest() != entry["sha256"]:
                _fail("RECOVERY_CONTENT_CHANGED")
            _write(stage_fd, entry["name"], raw)
        if manifest is not None:
            _write(stage_fd, MANIFEST, _encoded(manifest))
        os.fsync(stage_fd)
        if destination.name in os.listdir(parent):
            _fail("RECOVERY_DESTINATION_EXISTS")
        _rename_new_directory(parent, stage_name, destination.name)
        os.fsync(parent)
    finally:
        for descriptor in (source_fd, stage_fd, parent):
            if descriptor >= 0:
                os.close(descriptor)
        if stage.exists():
            shutil.rmtree(stage)


def create_backup(
    archive_directory,
    destination,
    enrollments: Sequence[CollectorEnrollment],
    *,
    lock_file,
    max_bytes=MAX_BYTES,
    max_snapshots=MAX_SNAPSHOTS,
) -> RecoverySummary:
    """Acquire the collector lock and copy only enrolled schema-validated evidence."""
    _bounds(max_bytes, max_snapshots)
    sources = _sources(enrollments)
    with ingestion_lock(Path(lock_file)):
        descriptor = _private_directory(Path(archive_directory))
        os.close(descriptor)
        files, receipts, _transitions, sources = _archive_records(
            archive_directory, sources, max_bytes, max_snapshots, expand=True
        )
        manifest = {
            "format": FORMAT,
            "schemaVersion": 1,
            "backupId": uuid4().hex,
            "createdAt": _now(),
            "sources": sources,
            "files": files,
        }
        manifest_bytes = len(_encoded(manifest))
        if (
            manifest_bytes > MANIFEST_LIMIT
            or manifest_bytes + sum(item["size"] for item in files) > 8 * 1024**3
        ):
            _fail("RECOVERY_LIMIT_EXCEEDED")
        _install(archive_directory, destination, files, manifest)
        return _summary(manifest, receipts)


def inspect_backup(backup_directory, *, max_bytes=MAX_BYTES, max_snapshots=MAX_SNAPSHOTS):
    """Validate every byte before returning metadata. Hashes detect corruption, not authorship."""
    _bounds(max_bytes, max_snapshots)
    descriptor = _private_directory(Path(backup_directory))
    try:
        try:
            value = json.loads(
                _read(descriptor, MANIFEST, MANIFEST_LIMIT).decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=lambda _value: _fail(),
            )
        except (ValueError, UnicodeError, RecursionError):
            raise RecoveryError("RECOVERY_INVALID") from None
        if (
            type(value) is not dict
            or set(value)
            != {"format", "schemaVersion", "backupId", "createdAt", "sources", "files"}
            or value["format"] != FORMAT
            or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1
            or type(value["backupId"]) is not str
            or not re.fullmatch(r"[a-f0-9]{32}", value["backupId"])
            or type(value["createdAt"]) is not int
            or not 0 <= value["createdAt"] <= 253_402_300_799
        ):
            _fail()
        sources = _sources(value["sources"])
        if (
            sources != value["sources"]
            or type(value["files"]) is not list
            or len(value["files"]) > 4 * max_snapshots
        ):
            _fail()
        names, total = [], 0
        for entry in value["files"]:
            if (
                type(entry) is not dict
                or set(entry) != {"name", "size", "sha256"}
                or type(entry["name"]) is not str
                or not NAME.fullmatch(entry["name"])
                or type(entry["size"]) is not int
                or not 0 <= entry["size"] <= MAX_SNAPSHOT_BYTES
                or type(entry["sha256"]) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])
            ):
                _fail()
            names.append(entry["name"])
            total += entry["size"]
            if total > max_bytes:
                _fail("RECOVERY_LIMIT_EXCEEDED")
            raw = _read(descriptor, entry["name"], entry["size"])
            if len(raw) != entry["size"] or sha256(raw).hexdigest() != entry["sha256"]:
                _fail("RECOVERY_CONTENT_CHANGED")
        if names != sorted(set(names)) or set(os.listdir(descriptor)) != {MANIFEST, *names}:
            _fail("RECOVERY_FILE_UNEXPECTED")
    finally:
        os.close(descriptor)
    files, receipts, _transitions, _sources_checked = _archive_records(
        backup_directory,
        sources,
        min(max_bytes + MANIFEST_LIMIT, 8 * 1024**3),
        max_snapshots,
        backup=True,
    )
    if files != value["files"]:
        _fail("RECOVERY_CONTENT_CHANGED")
    return {"manifest": value, "summary": asdict(_summary(value, receipts))}


def restore_backup(
    backup_directory, destination, *, lock_file, max_bytes=MAX_BYTES, max_snapshots=MAX_SNAPSHOTS
) -> RecoverySummary:
    """Restore a new archive only; never activate it or overwrite an existing directory."""
    with ingestion_lock(Path(lock_file)):
        inspected = inspect_backup(
            backup_directory, max_bytes=max_bytes, max_snapshots=max_snapshots
        )
        _install(backup_directory, destination, inspected["manifest"]["files"])
        return RecoverySummary(**inspected["summary"])


def replay_published(
    session, archive_directory, sources, *, replay_archive_directory, lock_file, update_tag=None
):
    """Reconstruct a fresh Guard graph and new working archive, preserving original evidence.

    Physical projection IDs are regenerated. Source/snapshot/logical entity IDs
    remain stable. Provider inventory is not backed up or replayed. Pending and
    uncertain receipts remain in the original restored archive for manual review.
    Interrupted replay requires another fresh Guard graph and working archive.
    """
    sources = _sources(sources)
    if update_tag is not None and (type(update_tag) is not int or not 0 <= update_tag <= 2**53 - 1):
        _fail("RECOVERY_CONFIG_INVALID")
    with ingestion_lock(Path(lock_file)):
        _files, receipts, transitions, sources = _archive_records(
            archive_directory, sources, MAX_BYTES, MAX_SNAPSHOTS, expand=True
        )
        existing = session.run(
            "MATCH (n) WHERE any(label IN labels(n) WHERE label IN $labels) RETURN 1 AS occupied LIMIT 1",
            labels=GUARD_LABELS,
        ).single()
        if existing is not None:
            _fail("RECOVERY_GRAPH_NOT_EMPTY")
        published = sorted(
            (r for r in receipts if r["status"] == "published"),
            key=lambda r: (r["sourceId"], r["publicationSequence"]),
        )
        if not published:
            _fail("RECOVERY_NOTHING_PUBLISHED")
        if update_tag is not None and update_tag + len(published) - 1 > 2**53 - 1:
            _fail("RECOVERY_CONFIG_INVALID")
        working = Path(replay_archive_directory).absolute()
        if working.is_relative_to(Path(archive_directory).absolute()):
            _fail("RECOVERY_PATH_UNSAFE")
        parent = _private_directory(working.parent)
        try:
            try:
                os.mkdir(working.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                _fail("RECOVERY_DESTINATION_EXISTS")
            os.fsync(parent)
        finally:
            os.close(parent)
        results = []
        with SnapshotArchive(archive_directory) as original, SnapshotArchive(working) as archive:
            archive._write(REPLAY_PENDING, _encoded({"schemaVersion": 1, "status": "pending"}))
            archive._replay_writes = True
            for index, receipt in enumerate(published):
                snapshot = original.load(
                    receipt["receiptId"], receipt["source"], receipt["profile"]
                )
                fresh_receipt = archive.store(snapshot)
                result = import_snapshot(
                    session,
                    snapshot,
                    receipt["source"],
                    update_tag=None if update_tag is None else update_tag + index,
                )
                archive.record_result(fresh_receipt.receipt_id, result)
                archive.record_health(
                    receipt["source"], receipt["profile"], result=result, snapshot=snapshot
                )
                results.append(
                    {
                        "sourceId": result.source_id,
                        "snapshotId": result.snapshot_id,
                        "originalProjectionId": receipt["projectionId"],
                        "projectionId": result.projection_id,
                    }
                )
            # Rebuild all retained source snapshots before replaying retirement.
            # The ordered journal handles A→B→C and multiple predecessors of B.
            # Pending intent is persisted first, so interruption cannot produce a
            # backup of this working archive that forgets an applied retirement.
            if transitions:
                from agent_guard_cartography.lifecycle import supersede_source

                for record in transitions:
                    transition = record["transition"]
                    archive.stage_transition(transition)
                    receipt = supersede_source(
                        session, transition, timestamp_ms=record["receipt"]["supersededAtMs"]
                    )
                    archive.finish_transition(transition, receipt)
            os.unlink(REPLAY_PENDING, dir_fd=archive._fd)
            os.fsync(archive._fd)
            archive._replay_writes = False
        return {
            "status": "complete",
            "published": len(results),
            "results": results,
            "pendingExcluded": sum(r["status"] == "pending" for r in receipts),
            "uncertainExcluded": sum(r["status"] == "idempotent" for r in receipts),
            **({"transitionsReplayed": len(transitions)} if transitions else {}),
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--archive-dir", required=True, type=Path)
    backup.add_argument("--destination", required=True, type=Path)
    backup.add_argument("--enrollment", required=True, action="append", type=Path)
    backup.add_argument("--lock-file", required=True, type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("--backup-dir", required=True, type=Path)
    restore.add_argument("--destination", required=True, type=Path)
    restore.add_argument("--lock-file", required=True, type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--backup-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            result = asdict(
                create_backup(
                    args.archive_dir,
                    args.destination,
                    [load_enrollment(path) for path in args.enrollment],
                    lock_file=args.lock_file,
                )
            )
        elif args.command == "restore":
            result = asdict(
                restore_backup(args.backup_dir, args.destination, lock_file=args.lock_file)
            )
        else:
            result = inspect_backup(args.backup_dir)["summary"]
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        RecoveryError,
        ArchiveError,
        CollectionError,
        GraphImportError,
        InventoryValidationError,
    ) as error:
        print(json.dumps({"error": error.code}), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"error": "RECOVERY_FAILED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
