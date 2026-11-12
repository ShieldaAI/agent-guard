"""Private collector backups, pending-receipt review and fresh-graph reconstruction.

Installed as the ``agent-guard-recovery`` command. Nothing here reads or restores
executor authority: a backup holds collector evidence only.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import re
import shutil
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, NoReturn, cast
from uuid import uuid4

from neo4j import Session

from agent_guard_cartography._command import (
    add_archive_arguments,
    add_neo4j_arguments,
    add_verbose_argument,
    archive_limits,
    check_archive_arguments,
    command_failed,
    ingestion_lock,
    lock_files,
    neo4j_password,
    open_driver,
    validate_neo4j_uri,
)
from agent_guard_cartography._files import (
    FileTooLargeError,
    UnsafePathError,
    open_private_directory,
    read_private_file,
)
from agent_guard_cartography._ids import (
    MAX_TIMESTAMP_SECONDS,
    PROFILES,
    SHA256_HEX,
)
from agent_guard_cartography._json import canonical_bytes, loads_strict
from agent_guard_cartography.archive import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_PENDING,
    DEFAULT_MAX_SNAPSHOTS,
    MAX_BYTES_LIMIT,
    MAX_SNAPSHOTS_LIMIT,
    REPLAY_PENDING,
    SnapshotArchive,
    timestamp,
)
from agent_guard_cartography.collector import (
    CollectorEnrollment,
    load_enrollment,
    validate_source,
)
from agent_guard_cartography.errors import AgentGuardCartographyError
from agent_guard_cartography.graph import GraphImportError, import_snapshot, source_key
from agent_guard_cartography.inventory import MAX_SNAPSHOT_BYTES
from agent_guard_cartography.lifecycle import supersede_source
from agent_guard_cartography.models import PROJECTION_LABELS
from agent_guard_cartography.shapes import (
    BackupFile,
    BackupManifest,
    BackupSource,
    ReceiptRecord,
    TransitionRecord,
)

FORMAT = "agent-guard-collector-backup"
MAX_BYTES = DEFAULT_MAX_BYTES
MAX_SNAPSHOTS = DEFAULT_MAX_SNAPSHOTS
MANIFEST_LIMIT = 8 * 1024 * 1024
MANIFEST = "backup.json"
MAX_SOURCES = 128
NAME = re.compile(
    r"(?:[a-f0-9]{64}\.(?:snapshot|receipt)\.json|(?:health|lifecycle)-[a-f0-9]{64}\.json)"
)
GUARD_LABELS = ["GuardSource", "GuardSnapshot", *PROJECTION_LABELS]


class RecoveryError(AgentGuardCartographyError, RuntimeError):
    """A backup, restore or replay failure; ``file`` names the one file that explains it."""


def _fail(code: str = "RECOVERY_INVALID", file: str | None = None) -> NoReturn:
    raise RecoveryError(code, file)


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


def _bounds(max_bytes: int, max_snapshots: int) -> None:
    if (
        type(max_bytes) is not int
        or not 1024 <= max_bytes <= MAX_BYTES_LIMIT
        or type(max_snapshots) is not int
        or not 1 <= max_snapshots <= MAX_SNAPSHOTS_LIMIT
    ):
        _fail("RECOVERY_CONFIG_INVALID")


def _sources(values: Any) -> list[BackupSource]:
    """The sources a command covers, validated, de-duplicated and in a stable order."""
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_SOURCES:
        _fail("RECOVERY_CONFIG_INVALID")
    result: list[BackupSource] = []
    seen: set[str] = set()
    for item in values:
        if isinstance(item, CollectorEnrollment):
            item = {"source": dict(item.source), "profile": item.profile}
        if type(item) is not dict or set(item) != {"source", "profile"}:
            _fail("RECOVERY_CONFIG_INVALID")
        source = dict(validate_source(item["source"]))
        if item["profile"] not in PROFILES:
            _fail("RECOVERY_CONFIG_INVALID")
        identifier = source_key(source)
        if identifier in seen:
            _fail("RECOVERY_CONFIG_INVALID")
        seen.add(identifier)
        result.append(cast(BackupSource, {"source": source, "profile": item["profile"]}))
    return sorted(result, key=lambda item: source_key(item["source"]))


def _private_directory(path: Path) -> int:
    """Open components without following symlinks; require a private final directory."""
    try:
        return open_private_directory(path)
    except UnsafePathError:
        raise RecoveryError("RECOVERY_PATH_UNSAFE") from None


def _read(descriptor: int, name: str, maximum: int) -> bytes:
    try:
        return read_private_file(name, maximum, dir_fd=descriptor)
    except UnsafePathError:
        raise RecoveryError("RECOVERY_FILE_UNSAFE") from None
    except FileTooLargeError:
        raise RecoveryError("RECOVERY_LIMIT_EXCEEDED") from None


def _write(descriptor: int, name: str, contents: bytes) -> None:
    file = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
    )
    with os.fdopen(file, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _locked(archive_directory: Path | str, lock_file: Path | str | None) -> Iterator[None]:
    """Hold the lock of an archive that must already exist.

    A mistyped path fails here, before a lock file could be left beside it.
    """
    os.close(_private_directory(Path(archive_directory)))
    with ingestion_lock(*lock_files(archive_directory, lock_file)):
        yield


def _lifecycle_sources(
    sources: list[BackupSource], transitions: Sequence[TransitionRecord], *, expand: bool
) -> list[BackupSource]:
    """Only completed transitions connected to explicitly enrolled sources extend scope."""
    if any(record["status"] != "complete" for record in transitions):
        _fail("RECOVERY_TRANSITION_PENDING")
    source_map = {source_key(item["source"]): item for item in sources}
    remaining = list(transitions)
    while remaining:
        progress = False
        for record in remaining[:]:
            transition = record["transition"]
            endpoints: dict[str, BackupSource] = {
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
            if len(source_map) > MAX_SOURCES:
                _fail("RECOVERY_LIMIT_EXCEEDED")
            remaining.remove(record)
            progress = True
        if not progress:
            _fail("RECOVERY_SCOPE_MISMATCH")
    return sorted(source_map.values(), key=lambda item: source_key(item["source"]))


def _archive_records(
    path: Path | str,
    sources: list[BackupSource],
    max_bytes: int,
    max_snapshots: int,
    *,
    backup: bool = False,
    expand: bool = False,
) -> tuple[list[BackupFile], list[ReceiptRecord], tuple[TransitionRecord, ...], list[BackupSource]]:
    """Read and verify every file of an archive (or of a backup) for the given sources."""
    with SnapshotArchive(
        path,
        max_bytes=max_bytes,
        max_snapshots=MAX_SNAPSHOTS_LIMIT if backup else max_snapshots,
        create=False,
    ) as archive:
        transitions = archive.list_transitions()
        sources = _lifecycle_sources(sources, transitions, expand=expand)
        source_map = {source_key(item["source"]): item for item in sources}
        names = [name for name in archive.entries() if not (backup and name == MANIFEST)]
        if REPLAY_PENDING in names:
            _fail("RECOVERY_REPLAY_PENDING")
        if (
            len(names) > 4 * max_snapshots
            or sum(name.endswith(".snapshot.json") for name in names) > max_snapshots
        ):
            _fail("RECOVERY_LIMIT_EXCEEDED")
        for name in names:
            # A backup is a closed set: a foreign file is named and refused, never copied.
            if NAME.fullmatch(name) is None:
                _fail("RECOVERY_FILE_UNEXPECTED", name)
        receipts: list[ReceiptRecord] = []
        files: list[BackupFile] = []
        snapshots: set[str] = set()
        sequences: set[tuple[str, int | None]] = set()
        total = 0
        for name in names:
            raw = archive.read_file(name)
            total += len(raw)
            if total > max_bytes:
                _fail("RECOVERY_LIMIT_EXCEEDED")
            files.append({"name": name, "size": len(raw), "sha256": sha256(raw).hexdigest()})
            if name.endswith(".receipt.json"):
                receipt = archive.read_receipt(name[:-13])
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


def _summary(manifest: BackupManifest, receipts: Sequence[ReceiptRecord]) -> RecoverySummary:
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


def _rename_new_directory(parent: int, source_name: str, destination_name: str) -> None:
    """Atomic publish without replacing even a concurrently created empty target.

    Supported hosts are Linux and macOS. Refuse other hosts/filesystems instead
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


def _install(
    source: Path | str,
    destination: Path | str,
    files: Sequence[BackupFile],
    manifest: BackupManifest | None = None,
) -> None:
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
            _write(stage_fd, MANIFEST, canonical_bytes(manifest))
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
    archive_directory: Path | str,
    destination: Path | str,
    enrollments: Sequence[CollectorEnrollment | Mapping[str, Any]],
    *,
    lock_file: Path | str | None = None,
    max_bytes: int = MAX_BYTES,
    max_snapshots: int = MAX_SNAPSHOTS,
) -> RecoverySummary:
    """Acquire the archive's lock and copy only enrolled schema-validated evidence."""
    _bounds(max_bytes, max_snapshots)
    sources = _sources(enrollments)
    with _locked(archive_directory, lock_file):
        files, receipts, _transitions, sources = _archive_records(
            archive_directory, sources, max_bytes, max_snapshots, expand=True
        )
        manifest: BackupManifest = {
            "format": FORMAT,
            "schemaVersion": 1,
            "backupId": uuid4().hex,
            "createdAt": timestamp(),
            "sources": sources,
            "files": files,
        }
        manifest_bytes = len(canonical_bytes(manifest))
        if (
            manifest_bytes > MANIFEST_LIMIT
            or manifest_bytes + sum(item["size"] for item in files) > MAX_BYTES_LIMIT
        ):
            _fail("RECOVERY_LIMIT_EXCEEDED")
        _install(archive_directory, destination, files, manifest)
        return _summary(manifest, receipts)


def inspect_backup(
    backup_directory: Path | str,
    *,
    max_bytes: int = MAX_BYTES,
    max_snapshots: int = MAX_SNAPSHOTS,
) -> dict[str, Any]:
    """Validate every byte before returning metadata. Hashes detect corruption, not authorship."""
    _bounds(max_bytes, max_snapshots)
    descriptor = _private_directory(Path(backup_directory))
    try:
        try:
            value = loads_strict(_read(descriptor, MANIFEST, MANIFEST_LIMIT).decode("utf-8"))
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
            or not 0 <= value["createdAt"] <= MAX_TIMESTAMP_SECONDS
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
                or not SHA256_HEX.fullmatch(entry["sha256"])
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
        min(max_bytes + MANIFEST_LIMIT, MAX_BYTES_LIMIT),
        max_snapshots,
        backup=True,
    )
    if files != value["files"]:
        _fail("RECOVERY_CONTENT_CHANGED")
    return {"manifest": value, "summary": asdict(_summary(value, receipts))}


def restore_backup(
    backup_directory: Path | str,
    destination: Path | str,
    *,
    lock_file: Path | str | None = None,
    max_bytes: int = MAX_BYTES,
    max_snapshots: int = MAX_SNAPSHOTS,
) -> RecoverySummary:
    """Restore a new archive only; never activate it or overwrite an existing directory."""
    # The destination is the archive this command creates: hold its lock, which lies
    # in its parent directory and so must never land inside the backup itself.
    target = Path(destination).absolute()
    if target.is_relative_to(Path(backup_directory).absolute()):
        _fail("RECOVERY_PATH_UNSAFE")
    os.close(_private_directory(target.parent))
    with ingestion_lock(*lock_files(destination, lock_file)):
        inspected = inspect_backup(
            backup_directory, max_bytes=max_bytes, max_snapshots=max_snapshots
        )
        _install(backup_directory, destination, inspected["manifest"]["files"])
        return RecoverySummary(**inspected["summary"])


def replay_published(
    session: Session,
    archive_directory: Path | str,
    sources: Iterable[CollectorEnrollment | Mapping[str, Any]],
    *,
    replay_archive_directory: Path | str,
    lock_file: Path | str | None = None,
    update_tag: int | None = None,
    max_bytes: int = MAX_BYTES,
    max_snapshots: int = MAX_SNAPSHOTS,
    max_pending: int = DEFAULT_MAX_PENDING,
) -> dict[str, Any]:
    """Reconstruct a fresh Guard graph and new working archive, preserving original evidence.

    Physical projection IDs are regenerated. Source/snapshot/logical entity IDs
    remain stable. Provider inventory is not backed up or replayed. Pending and
    uncertain receipts remain in the original restored archive for manual review.
    Interrupted replay requires another fresh Guard graph and working archive.
    A capture the rebuilt graph refuses as older than one already replayed is left
    out of the working archive, counted as ``supersededExcluded``; it remains in the
    original evidence.
    """
    _bounds(max_bytes, max_snapshots)
    sources = _sources(list(sources))
    if update_tag is not None and (type(update_tag) is not int or not 0 <= update_tag <= 2**53 - 1):
        _fail("RECOVERY_CONFIG_INVALID")
    with _locked(archive_directory, lock_file):
        _files, receipts, transitions, sources = _archive_records(
            archive_directory, sources, max_bytes, max_snapshots, expand=True
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
        results: list[dict[str, Any]] = []
        superseded = 0
        limits = {"max_bytes": max_bytes, "max_snapshots": max_snapshots}
        with (
            SnapshotArchive(archive_directory, create=False, **limits) as original,
            SnapshotArchive(working, max_pending=max_pending, **limits) as archive,
            archive.reconstruction(),
        ):
            for index, receipt in enumerate(published):
                snapshot = original.load(
                    receipt["receiptId"], receipt["source"], receipt["profile"]
                )
                fresh_receipt = archive.store(snapshot)
                try:
                    result = import_snapshot(
                        session,
                        snapshot,
                        receipt["source"],
                        update_tag=None if update_tag is None else update_tag + index,
                    )
                except GraphImportError as error:
                    if error.code != "GENERATED_AT_ROLLBACK":
                        raise
                    # An older capture that once replaced a newer one at the same
                    # revision: keep the newer one current. This one can never be
                    # published here, so it must not occupy the working archive's
                    # pending allowance; the original evidence still holds it.
                    archive.discard(fresh_receipt.receipt_id)
                    superseded += 1
                    continue
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
            for record in transitions:
                transition = record["transition"]
                archive.stage_transition(transition)
                completed = cast(Any, record["receipt"])
                archive.finish_transition(
                    transition,
                    supersede_source(session, transition, timestamp_ms=completed["supersededAtMs"]),
                )
        return {
            "status": "complete",
            "published": len(results),
            "results": results,
            "pendingExcluded": sum(r["status"] == "pending" for r in receipts),
            "uncertainExcluded": sum(r["status"] == "idempotent" for r in receipts),
            **({"transitionsReplayed": len(transitions)} if transitions else {}),
            **({"supersededExcluded": superseded} if superseded else {}),
        }


def _limits(args: argparse.Namespace) -> dict[str, int]:
    return {"max_bytes": args.archive_max_bytes, "max_snapshots": args.archive_max_snapshots}


def _open_existing(args: argparse.Namespace) -> SnapshotArchive:
    """The operator's archive, opened under its lock."""
    return SnapshotArchive(args.archive_dir, create=False, **archive_limits(args))


def _pending(args: argparse.Namespace) -> dict[str, Any]:
    """Unpublished receipts awaiting replay or reviewed discard; nothing is changed."""
    with _locked(args.archive_dir, args.lock_file), _open_existing(args) as archive:
        if args.enrollment:
            receipts = [
                receipt
                for enrollment in map(load_enrollment, args.enrollment)
                for receipt in archive.list_pending(enrollment.source, enrollment.profile)
            ]
        else:
            receipts = list(archive.list_pending())
        return {
            "pending": [
                {
                    "receipt_id": receipt.receipt_id,
                    "source_id": receipt.source_id,
                    "snapshot_id": receipt.snapshot_id,
                    "profile": receipt.profile,
                    "created_at": receipt.created_at,
                    "last_error": receipt.last_error,
                }
                for receipt in receipts
            ],
            "damaged": list(archive.damaged),
            "ignored": list(archive.ignored),
        }


def _discard(args: argparse.Namespace) -> dict[str, Any]:
    if not args.reviewed:
        _fail("RECOVERY_REVIEW_REQUIRED")
    with _locked(args.archive_dir, args.lock_file), _open_existing(args) as archive:
        discarded = archive.discard(args.receipt_id)
    return {
        "status": "discarded",
        "receipt_id": discarded["receiptId"],
        "state": discarded["state"],
        "source_id": discarded["sourceId"],
        "snapshot_id": discarded["snapshotId"],
    }


def _replay(args: argparse.Namespace) -> dict[str, Any]:
    validate_neo4j_uri(args.neo4j_uri)
    password = neo4j_password(args)
    sources: Sequence[CollectorEnrollment | Mapping[str, Any]]
    if args.backup_dir:
        sources = inspect_backup(args.backup_dir, **_limits(args))["manifest"]["sources"]
    else:
        sources = [load_enrollment(path) for path in args.enrollment]
    with open_driver(args, password) as driver:
        driver.verify_connectivity()
        with driver.session(database=args.neo4j_database) as session:
            return replay_published(
                session,
                args.archive_dir,
                sources,
                replay_archive_directory=args.replay_archive_dir,
                lock_file=args.lock_file,
                max_pending=args.archive_max_pending,
                **_limits(args),
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-guard-recovery", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser(
        "backup", help="Copy the enrolled sources' archived evidence into a new backup directory."
    )
    backup.add_argument("--destination", required=True, type=Path)
    backup.add_argument("--enrollment", required=True, action="append", type=Path)
    add_archive_arguments(backup)

    restore = commands.add_parser(
        "restore", help="Verify a backup and copy it into a new archive directory."
    )
    restore.add_argument("--backup-dir", required=True, type=Path)
    restore.add_argument("--destination", required=True, type=Path)
    add_archive_arguments(restore, directory="none")

    inspect = commands.add_parser(
        "inspect", help="Verify every file of a backup and print its summary."
    )
    inspect.add_argument("--backup-dir", required=True, type=Path)
    add_archive_arguments(inspect, directory="none", lock=False)

    replay = commands.add_parser(
        "replay", help="Rebuild a fresh Guard graph and working archive from restored evidence."
    )
    replay.add_argument("--replay-archive-dir", required=True, type=Path)
    scope = replay.add_mutually_exclusive_group(required=True)
    scope.add_argument("--backup-dir", type=Path, help="Use the sources in this backup.")
    scope.add_argument("--enrollment", action="append", type=Path)
    add_archive_arguments(replay)
    add_neo4j_arguments(replay)

    pending = commands.add_parser("pending", help="List receipts that were never published.")
    pending.add_argument("--enrollment", action="append", type=Path)
    add_archive_arguments(pending)

    discard = commands.add_parser(
        "discard", help="Remove one pending, unreadable or orphaned receipt after review."
    )
    discard.add_argument("--receipt-id", required=True)
    discard.add_argument(
        "--reviewed",
        action="store_true",
        help="Confirm an operator reviewed this receipt; required.",
    )
    add_archive_arguments(discard)

    for command in (backup, restore, inspect, replay, pending, discard):
        add_verbose_argument(command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    check_archive_arguments(parser, args)
    try:
        result: Any
        if args.command == "backup":
            result = asdict(
                create_backup(
                    args.archive_dir,
                    args.destination,
                    [load_enrollment(path) for path in args.enrollment],
                    lock_file=args.lock_file,
                    **_limits(args),
                )
            )
        elif args.command == "restore":
            result = asdict(
                restore_backup(
                    args.backup_dir, args.destination, lock_file=args.lock_file, **_limits(args)
                )
            )
        elif args.command == "inspect":
            result = inspect_backup(args.backup_dir, **_limits(args))["summary"]
        elif args.command == "replay":
            result = _replay(args)
        elif args.command == "pending":
            result = _pending(args)
        else:
            result = _discard(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        return command_failed(error, "RECOVERY_FAILED", args)


if __name__ == "__main__":
    raise SystemExit(main())
