"""Protected immutable snapshot files and bounded, atomic collection receipts.

The caller holds the database ingestion lock. Files are evidence/retry material;
graph publication remains authoritative for current/previous projection pointers.

One ``SnapshotArchive`` owns its directory for as long as it is open. It keeps an
in-memory index of the files it owns and of every validated receipt, built once
and updated by its own writes and removals, so that capacity checks and scans do
not re-read the directory. A file a command acts on (a receipt it loads, replays,
updates or discards, and its snapshot) is always read and verified from disk, and
pruning unlinks a file only while it is still the one that was indexed.
``refresh()`` reconciles the index with changes made outside this instance.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, NoReturn, cast
from uuid import uuid4

from agent_guard_cartography._files import (
    FileTooLargeError,
    UnsafePathError,
    is_private_file,
    open_private_directory,
    read_private_file,
)
from agent_guard_cartography._ids import MAX_TIMESTAMP_SECONDS, PROFILES, SHA256_HEX
from agent_guard_cartography._json import canonical_bytes, reject_constant, unique_object
from agent_guard_cartography.collector import CollectionError, decode_snapshot, validate_source
from agent_guard_cartography.errors import AgentGuardCartographyError, display_name
from agent_guard_cartography.graph import ImportResult, source_key
from agent_guard_cartography.inventory import MAX_SNAPSHOT_BYTES, UTC_TIMESTAMP, validate_snapshot
from agent_guard_cartography.shapes import (
    DiscardResult,
    HealthRecord,
    ReceiptRecord,
    Snapshot,
    Transition,
    TransitionReceipt,
    TransitionRecord,
)
from agent_guard_cartography.transitions import LifecycleError, transition_id, validate_transition

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_PENDING",
    "DEFAULT_MAX_SNAPSHOTS",
    "DEFAULT_RETENTION_SECONDS",
    "MAX_BYTES_LIMIT",
    "MAX_PENDING_LIMIT",
    "MAX_RETENTION_SECONDS",
    "MAX_SNAPSHOTS_LIMIT",
    "MIN_RETENTION_SECONDS",
    "PROTECTED_PER_SOURCE",
    "REPLAY_PENDING",
    "ArchiveError",
    "ArchiveReceipt",
    "PruneReport",
    "SnapshotArchive",
    "display_name",
    "required_snapshots",
    "timestamp",
]

DEFAULT_MAX_SNAPSHOTS = 4096
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOTS_LIMIT = 100_000
MAX_BYTES_LIMIT = 8 * 1024**3
DEFAULT_RETENTION_SECONDS = 7 * 24 * 60 * 60
MIN_RETENTION_SECONDS = 60 * 60
MAX_RETENTION_SECONDS = 90 * 24 * 60 * 60
# Unpublished receipts one source may hold before its new polls fail closed.
DEFAULT_MAX_PENDING = 16
MAX_PENDING_LIMIT = 1024
# Newest publications per source kept as current/previous recovery anchors.
PROTECTED_PER_SOURCE = 2
# Largest receipt, health or lifecycle file.
MAX_RECORD_BYTES = 256 * 1024
MAX_HEALTH_BYTES = 64 * 1024
MAX_TRANSITIONS = 128
MAX_SEQUENCE = 9_007_199_254_740_991

_RECEIPT_NAME = re.compile(r"([a-f0-9]{64})\.receipt\.json")
_OWNED_NAME = re.compile(
    r"[a-f0-9]{64}\.(?:snapshot|receipt)\.json|health-[a-f0-9]{64}\.json|\.tmp-[a-f0-9]{32}"
)
_SCRATCH_NAME = re.compile(r"\.tmp-[a-f0-9]{32}")
_ERROR = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_LIFECYCLE_NAME = re.compile(r"lifecycle-([a-f0-9]{64})\.json")
_LIFECYCLE_KEYS = {"schemaVersion", "transition", "transitionId", "status", "receipt"}
REPLAY_PENDING = "recovery-pending.json"
_RECEIPT_KEYS = frozenset(
    (
        "schemaVersion",
        "receiptId",
        "source",
        "sourceId",
        "profile",
        "snapshotId",
        "sha256",
        "createdAt",
        "status",
        "publishedAt",
        "publicationSequence",
        "projectionId",
        "lastError",
    )
)
_HEALTH_KEYS = frozenset(
    (
        "schemaVersion",
        "sourceId",
        "profile",
        "lastAttemptAt",
        "lastSuccessAt",
        "lastError",
        "consecutiveFailures",
        "lastSnapshotId",
        "lastSnapshotGeneratedAt",
        "lastProjectionId",
    )
)
# (inode, size, modification time, status-change time). An unchanged signature means the
# file was neither rewritten nor had its mode, owner or link count changed: those do not
# touch the modification time, but they decide whether the file may be read at all.
_Signature = tuple[int, int, int, int]
_ABSENT: _Signature = (0, 0, 0, 0)
_PAIR_NAME = re.compile(r"([a-f0-9]{64})\.(?:snapshot|receipt)\.json")


class ArchiveError(AgentGuardCartographyError, RuntimeError):
    """An archive failure; ``file`` is the basename of the one file that explains it."""


def _fail(code: str = "ARCHIVE_INVALID", file: str | None = None) -> NoReturn:
    raise ArchiveError(code, file)


def _owned(name: str) -> bool:
    """Lifecycle and recovery fences stay strict: a damaged name must never lift one."""
    return (
        name.startswith("lifecycle-")
        or name == REPLAY_PENDING
        or _OWNED_NAME.fullmatch(name) is not None
    )


def required_snapshots(sources: int, interval_seconds: int, retention_seconds: int) -> int:
    """Snapshot slots steady polling needs: every poll in the retention window plus
    the one being stored, and never fewer than the protected anchors plus one."""
    polls = -(-retention_seconds // interval_seconds)
    return sources * max(polls + 1, PROTECTED_PER_SOURCE + 1)


def _now() -> int:
    value = int(time.time())
    if value < 0 or value > MAX_TIMESTAMP_SECONDS:
        _fail("ARCHIVE_CLOCK_INVALID")
    return value


def timestamp() -> int:
    """The current time in whole seconds, as archive and backup records store it."""
    return _now()


def _receipt_id(source_id: str, snapshot_id: str) -> str:
    return sha256(canonical_bytes({"source": source_id, "snapshot": snapshot_id})).hexdigest()


def _signature(metadata: os.stat_result) -> _Signature:
    return metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _error(code: Any) -> str:
    if type(code) is not str or _ERROR.fullmatch(code) is None:
        _fail()
    return code


@dataclass(frozen=True)
class ArchiveReceipt:
    receipt_id: str
    snapshot_id: str
    source_id: str
    profile: str
    created_at: int
    content_hash: str
    status: str
    projection_id: str | None
    last_error: str | None = None


@dataclass(frozen=True)
class PruneReport:
    removed: int
    # Removed before their retention elapsed, to keep the archive inside its limits.
    pressure_removed: int
    # Unreadable files kept for operator review; never deleted automatically.
    damaged: tuple[str, ...]


class SnapshotArchive:
    def __init__(
        self,
        directory: Path | str,
        *,
        max_snapshots: int = DEFAULT_MAX_SNAPSHOTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_pending: int = DEFAULT_MAX_PENDING,
        create: bool = True,
    ) -> None:
        """Open a private archive directory; ``create`` makes it (mode 0700) if missing."""
        if (
            type(max_snapshots) is not int
            or not 1 <= max_snapshots <= MAX_SNAPSHOTS_LIMIT
            or type(max_bytes) is not int
            or not 1024 <= max_bytes <= MAX_BYTES_LIMIT
            or type(max_pending) is not int
            or not 1 <= max_pending <= MAX_PENDING_LIMIT
        ):
            _fail("ARCHIVE_CONFIG_INVALID")
        self.max_snapshots, self.max_bytes = max_snapshots, max_bytes
        self.max_pending = max_pending
        # Diagnostics for the operator: foreign files that were ignored, and
        # unreadable receipts found by the latest scan. Neither is ever trusted.
        self.ignored: tuple[str, ...] = ()
        self.damaged: tuple[str, ...] = ()
        self._fd = -1
        self._replay_writes = False
        # The index: owned files, then (once a scan needs them) validated receipts
        # and lifecycle journals. ``None`` means "read the directory again".
        self._files: dict[str, _Signature] | None = None
        self._bytes = 0
        self._receipts: dict[str, ReceiptRecord] | None = None
        self._unreadable: dict[str, str | None] = {}
        self._transitions: tuple[TransitionRecord, ...] | None = None
        try:
            self._fd = open_private_directory(directory, create=create)
            # Caller holds the ingestion lock; interrupted atomic writes are
            # unpublished scratch files and may be removed before capacity checks.
            for name in os.listdir(self._fd):
                if _SCRATCH_NAME.fullmatch(name):
                    self._metadata(name)
                    os.unlink(name, dir_fd=self._fd)
            # An archive over its limits must still open, so pruning can recover it.
            self._usage()
        except ArchiveError:
            self.close()
            raise
        except FileNotFoundError:
            self.close()
            # Only a caller that refuses to create the directory distinguishes a typo.
            code = "ARCHIVE_DIRECTORY_UNSAFE" if create else "ARCHIVE_DIRECTORY_NOT_FOUND"
            raise ArchiveError(code) from None
        except (OSError, UnsafePathError):
            self.close()
            raise ArchiveError("ARCHIVE_DIRECTORY_UNSAFE") from None

    def __enter__(self) -> SnapshotArchive:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def _open(self) -> None:
        if self._fd < 0:
            _fail("ARCHIVE_CLOSED")

    def require_recovery_complete(self) -> None:
        """Fence ordinary collection and maintenance until reconstruction completes."""
        if self._replay_writes:
            return
        try:
            self._read(REPLAY_PENDING, 1024)
        except ArchiveError as error:
            if error.code != "ARCHIVE_NOT_FOUND":
                raise
        else:
            _fail("ARCHIVE_RECOVERY_PENDING")

    def require_publishable_source(self, expected_source: Mapping[str, str]) -> None:
        """Apply the same archive fences to newly collected and replayed snapshots."""
        self.require_recovery_complete()
        source_id = source_key(validate_source(dict(expected_source)))
        if any(
            source_key(record["transition"]["predecessor"]) == source_id
            for record in self.list_transitions()
        ):
            _fail("ARCHIVE_SOURCE_SUPERSEDED")

    @contextmanager
    def reconstruction(self) -> Iterator[None]:
        """Fence a new working archive while a fresh graph is rebuilt into it.

        The marker is written first and removed only when the block completes, so an
        interrupted reconstruction leaves an archive that collection, replay, pruning
        and backup all refuse. Inside the block this archive accepts writes.
        """
        self._write(REPLAY_PENDING, canonical_bytes({"schemaVersion": 1, "status": "pending"}))
        self._replay_writes = True
        try:
            yield
            try:
                os.unlink(REPLAY_PENDING, dir_fd=self._fd)
                os.fsync(self._fd)
            except OSError:
                self._invalidate()
                raise ArchiveError("ARCHIVE_WRITE_FAILED") from None
            self._forget(REPLAY_PENDING)
        finally:
            self._replay_writes = False

    # -- files -----------------------------------------------------------------

    def _metadata(self, name: str) -> os.stat_result:
        metadata = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
        if not is_private_file(metadata):
            _fail("ARCHIVE_FILE_UNSAFE", name)
        return metadata

    def _invalidate(self) -> None:
        """Forget the index after a write whose outcome is unknown; it is rebuilt on use."""
        self._files = None
        self._receipts = None
        self._transitions = None

    def _index(self) -> dict[str, _Signature]:
        """Archive-owned entries. Foreign files are reported, never read or counted.

        Fences (lifecycle journals, the recovery marker) must be safe for anything
        to proceed. An unsafe snapshot, receipt or health file is still counted, but
        fails only the operation that reads it.
        """
        self._open()
        if self._files is not None:
            return self._files
        files: dict[str, _Signature] = {}
        foreign = []
        size = 0
        for name in os.listdir(self._fd):
            if not _owned(name):
                foreign.append(name)
                continue
            if _OWNED_NAME.fullmatch(name) is None or name.startswith(".tmp-"):
                metadata = self._metadata(name)
            else:
                try:
                    metadata = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
                except FileNotFoundError:
                    files[name] = _ABSENT
                    continue
            files[name] = _signature(metadata)
            size += metadata.st_size
        self.ignored = tuple(sorted(display_name(name) for name in foreign))
        self._files, self._bytes = files, size
        return files

    def refresh(self) -> None:
        """Reconcile the index with files changed outside this instance.

        Every owned file is examined once (``stat``, no read). Only receipts and
        lifecycle journals that were added, removed or rewritten are read again.
        """
        previous, receipts = self._files, self._receipts
        # If the directory cannot be indexed (an unsafe fence), nothing stale survives.
        self._invalidate()
        current = self._index()
        self._receipts = receipts
        if previous is None or receipts is None:
            self._receipts = None
            self._transitions = None
            return
        changed = {
            name
            for name in previous.keys() | current.keys()
            if previous.get(name) != current.get(name)
        }
        if any(name.startswith("lifecycle-") for name in changed):
            self._transitions = None
        rescan = set()
        for name in changed:
            match = _PAIR_NAME.fullmatch(name)
            if match is None:
                continue
            receipt = f"{match[1]}.receipt.json"
            # A changed snapshot matters only to an unreadable receipt: it names the owner.
            if name == receipt or receipt in self._unreadable:
                rescan.add(match[1])
        for receipt_id in rescan:
            name = f"{receipt_id}.receipt.json"
            receipts.pop(receipt_id, None)
            self._unreadable.pop(name, None)
            if name in current:
                self._scan_receipt(receipts, receipt_id)
        self.damaged = tuple(sorted(self._unreadable))

    def _record(self, name: str) -> None:
        """Index one file this instance has just written."""
        if self._files is None:
            return
        try:
            metadata = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
        except OSError:
            self._invalidate()
            return
        self._bytes += metadata.st_size - self._files.get(name, _ABSENT)[1]
        self._files[name] = _signature(metadata)
        if name.startswith("lifecycle-"):
            self._transitions = None

    def _forget(self, name: str) -> None:
        """Drop one file this instance has just removed from the index."""
        if self._files is not None:
            self._bytes -= self._files.pop(name, _ABSENT)[1]
        match = _RECEIPT_NAME.fullmatch(name)
        if match is not None:
            self._unreadable.pop(name, None)
            if self._receipts is not None:
                self._receipts.pop(match[1], None)

    def _usage(self) -> tuple[int, int, int]:
        """Committed (files, snapshots, bytes), from the index."""
        files = self._index()
        return len(files), sum(name.endswith(".snapshot.json") for name in files), self._bytes

    def _capacity(
        self, additional: int = 0, new_snapshot: bool = False, *, new_files: int = 0
    ) -> None:
        files, count, size = self._usage()
        if (
            files + new_files > 4 * self.max_snapshots
            or size + additional > self.max_bytes
            or count + new_snapshot > self.max_snapshots
        ):
            _fail("ARCHIVE_LIMIT_EXCEEDED")

    def entries(self) -> tuple[str, ...]:
        """Every name in the directory, sorted, including files the archive does not own."""
        self._open()
        return tuple(sorted(os.listdir(self._fd)))

    def read_file(self, name: str) -> bytes:
        """The verified bytes of one archive file, bounded by its kind."""
        maximum = MAX_SNAPSHOT_BYTES if name.endswith(".snapshot.json") else MAX_RECORD_BYTES
        return self._read(name, maximum)

    def _read(self, name: str, maximum: int) -> bytes:
        self._open()
        try:
            return read_private_file(name, maximum, dir_fd=self._fd)
        except UnsafePathError:
            raise ArchiveError("ARCHIVE_FILE_UNSAFE", name) from None
        except FileTooLargeError:
            raise ArchiveError("ARCHIVE_LIMIT_EXCEEDED", name) from None
        except FileNotFoundError:
            raise ArchiveError("ARCHIVE_NOT_FOUND", name) from None
        except OSError:
            raise ArchiveError("ARCHIVE_READ_FAILED", name) from None

    def _write(self, name: str, value: bytes, *, new_snapshot: bool = False) -> None:
        self._open()
        temporary = f".tmp-{uuid4().hex}"
        descriptor = -1
        try:
            new_file = False
            try:
                self._metadata(name)
            except FileNotFoundError:
                new_file = True
            # Bound the committed file count before creating scratch data.
            # Replacements keep their slot; their temporary bytes still count.
            self._capacity(len(value), new_snapshot, new_files=int(new_file))
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._fd,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
            os.fsync(self._fd)
        except OSError:
            self._invalidate()
            raise ArchiveError("ARCHIVE_WRITE_FAILED") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._fd)
            except FileNotFoundError:
                pass
        self._record(name)

    # -- receipts --------------------------------------------------------------

    def read_receipt(self, receipt_id: str) -> ReceiptRecord:
        """One receipt, read from disk and validated field by field."""
        return self._receipt(receipt_id)

    def _write_receipt(self, receipt: ReceiptRecord) -> None:
        self._write(f"{receipt['receiptId']}.receipt.json", canonical_bytes(receipt))
        if self._receipts is not None:
            self._receipts[receipt["receiptId"]] = cast(ReceiptRecord, dict(receipt))

    def _receipt(self, receipt_id: str) -> ReceiptRecord:
        if type(receipt_id) is not str or SHA256_HEX.fullmatch(receipt_id) is None:
            _fail()
        name = f"{receipt_id}.receipt.json"
        try:
            value = json.loads(self._read(name, MAX_RECORD_BYTES), object_pairs_hook=unique_object)
            if type(value) is not dict or value.keys() != _RECEIPT_KEYS:
                _fail()
            source = validate_source(value["source"])
            if (
                value["schemaVersion"] != 1
                or type(value["schemaVersion"]) is not int
                or value["receiptId"] != receipt_id
                or value["sourceId"] != source_key(source)
                or value["profile"] not in PROFILES
            ):
                _fail()
            if (
                type(value["snapshotId"]) is not str
                or not value["snapshotId"]
                or receipt_id != _receipt_id(value["sourceId"], value["snapshotId"])
            ):
                _fail()
            if (
                type(value["sha256"]) is not str
                or SHA256_HEX.fullmatch(value["sha256"]) is None
                or type(value["createdAt"]) is not int
                or not 0 <= value["createdAt"] <= MAX_TIMESTAMP_SECONDS
            ):
                _fail()
            if value["status"] not in ("pending", "published", "idempotent"):
                _fail()
            if value["publishedAt"] is not None and (
                type(value["publishedAt"]) is not int
                or not 0 <= value["publishedAt"] <= MAX_TIMESTAMP_SECONDS
            ):
                _fail()
            if value["publicationSequence"] is not None and (
                type(value["publicationSequence"]) is not int
                or not 1 <= value["publicationSequence"] <= MAX_SEQUENCE
            ):
                _fail()
            if value["projectionId"] is not None and (
                type(value["projectionId"]) is not str
                or SHA256_HEX.fullmatch(value["projectionId"]) is None
            ):
                _fail()
            if value["lastError"] is not None:
                _error(value["lastError"])
            if value["status"] == "pending" and (
                value["projectionId"] is not None or value["publishedAt"] is not None
            ):
                _fail()
            if value["status"] != "pending" and value["projectionId"] is None:
                _fail()
            if value["status"] == "published" and (
                value["publicationSequence"] is None or value["publishedAt"] is None
            ):
                _fail()
            if value["status"] != "published" and value["publicationSequence"] is not None:
                _fail()
            return value
        except ArchiveError as error:
            error.file = error.file or name
            raise
        except (ValueError, TypeError, RecursionError, CollectionError):
            raise ArchiveError("ARCHIVE_INVALID", name) from None

    @staticmethod
    def _public(value: ReceiptRecord) -> ArchiveReceipt:
        return ArchiveReceipt(
            value["receiptId"],
            value["snapshotId"],
            value["sourceId"],
            value["profile"],
            value["createdAt"],
            value["sha256"],
            value["status"],
            value["projectionId"],
            value["lastError"],
        )

    def _owner(self, receipt_id: str) -> str | None:
        """The source an unreadable receipt belongs to, proven by its intact snapshot."""
        try:
            snapshot = decode_snapshot(
                self._read(f"{receipt_id}.snapshot.json", MAX_SNAPSHOT_BYTES)
            )
            source_id = source_key(snapshot["source"])
            if _receipt_id(source_id, snapshot["snapshotId"]) == receipt_id:
                return source_id
        except (ArchiveError, CollectionError, ValueError, RecursionError):
            pass
        return None

    def _scan_receipt(self, receipts: dict[str, ReceiptRecord], receipt_id: str) -> None:
        """Read one receipt into the index, or record it as unreadable with its owner."""
        try:
            receipts[receipt_id] = self._receipt(receipt_id)
        except ArchiveError:
            self._unreadable[f"{receipt_id}.receipt.json"] = self._owner(receipt_id)

    def _scan(self) -> tuple[list[ReceiptRecord], dict[str, str | None]]:
        """Every readable receipt, plus each unreadable receipt file and its owner.

        An unreadable receipt is evidence for operator review: it is kept, named in
        diagnostics and never trusted. It blocks only the source that owns it.
        Receipts are read from disk once; later scans answer from the index.
        """
        files = self._index()
        receipts = self._receipts
        if receipts is None:
            receipts, self._unreadable = {}, {}
            for name in files:
                match = _RECEIPT_NAME.fullmatch(name)
                if match is not None:
                    self._scan_receipt(receipts, match[1])
            self._receipts = receipts
        self.damaged = tuple(sorted(self._unreadable))
        return list(receipts.values()), dict(self._unreadable)

    def _source_receipts(self, source_id: str) -> list[ReceiptRecord]:
        """One source's readable receipts; its own unreadable receipt fails it alone."""
        receipts, damaged = self._scan()
        for name, owner in sorted(damaged.items()):
            if owner == source_id:
                _fail("ARCHIVE_INVALID", name)
        return [value for value in receipts if value["sourceId"] == source_id]

    # -- lifecycle journals ----------------------------------------------------

    @staticmethod
    def _transition_receipt(transition: Transition, receipt: Any) -> TransitionReceipt:
        expected = {
            "schemaVersion": 1,
            "transitionId": transition_id(transition),
            "predecessorSourceId": source_key(transition["predecessor"]),
            "successorSourceId": source_key(transition["successor"]),
            "profile": transition["profile"],
        }
        if (
            type(receipt) is not dict
            or receipt.keys() != {*expected, "supersededAtMs"}
            or type(receipt.get("schemaVersion")) is not int
            or any(receipt.get(key) != value for key, value in expected.items())
            or type(receipt.get("supersededAtMs")) is not int
            or not 0 <= receipt["supersededAtMs"] <= MAX_TIMESTAMP_SECONDS * 1000 + 999
        ):
            _fail("ARCHIVE_TRANSITION_INVALID")
        return cast(TransitionReceipt, {**expected, "supersededAtMs": receipt["supersededAtMs"]})

    def _transition_record(self, name: str) -> TransitionRecord:
        match = _LIFECYCLE_NAME.fullmatch(name)
        if match is None:
            _fail("ARCHIVE_TRANSITION_INVALID", name)
        try:
            record = json.loads(
                self._read(name, MAX_RECORD_BYTES).decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
            if (
                type(record) is not dict
                or record.keys() != _LIFECYCLE_KEYS
                or type(record["schemaVersion"]) is not int
                or record["schemaVersion"] != 1
                or record["status"] not in ("pending", "complete")
            ):
                _fail("ARCHIVE_TRANSITION_INVALID")
            transition = validate_transition(record["transition"])
            if match[1] != source_key(transition["predecessor"]) or record[
                "transitionId"
            ] != transition_id(transition):
                _fail("ARCHIVE_TRANSITION_INVALID")
            if record["status"] == "pending":
                if record["receipt"] is not None:
                    _fail("ARCHIVE_TRANSITION_INVALID")
            else:
                record["receipt"] = self._transition_receipt(transition, record["receipt"])
            record["transition"] = transition
            return record
        except ArchiveError as error:
            error.file = error.file or display_name(name)
            raise
        except (
            ValueError,
            TypeError,
            UnicodeError,
            RecursionError,
            CollectionError,
            LifecycleError,
        ):
            raise ArchiveError("ARCHIVE_TRANSITION_INVALID", name) from None

    @staticmethod
    def _ordered_transitions(records: list[TransitionRecord]) -> tuple[TransitionRecord, ...]:
        """A bounded acyclic replacement graph, allowing explicit predecessor fan-in."""
        by_predecessor: dict[str, TransitionRecord] = {}
        incoming: dict[str, int] = {}
        profiles: dict[str, str] = {}
        for record in records:
            transition = record["transition"]
            before, after = (source_key(transition[key]) for key in ("predecessor", "successor"))
            if before in by_predecessor:
                _fail("ARCHIVE_TRANSITION_CONFLICT")
            by_predecessor[before] = record
            incoming[after] = incoming.get(after, 0) + 1
            for source in (before, after):
                if source in profiles and profiles[source] != transition["profile"]:
                    _fail("ARCHIVE_TRANSITION_CONFLICT")
                profiles[source] = transition["profile"]
        if len(profiles) > MAX_TRANSITIONS:
            _fail("ARCHIVE_LIMIT_EXCEEDED")
        ordered = []
        ready = sorted(set(profiles) - set(incoming))
        while ready:
            current = ready.pop(0)
            if current not in by_predecessor:
                continue
            record = by_predecessor[current]
            ordered.append(record)
            after = source_key(record["transition"]["successor"])
            incoming[after] -= 1
            if not incoming[after]:
                ready.append(after)
                ready.sort()
        if len(ordered) != len(records):
            _fail("ARCHIVE_TRANSITION_CONFLICT")
        return tuple(ordered)

    def list_transitions(self) -> tuple[TransitionRecord, ...]:
        """Validated private lifecycle evidence, including pending intents.

        Journals are read once and again only after one is written or ``refresh()``
        finds one changed; the returned records must not be modified.
        """
        self._capacity()
        if self._transitions is None:
            names = [name for name in self._index() if name.startswith("lifecycle-")]
            if len(names) > MAX_TRANSITIONS:
                _fail("ARCHIVE_LIMIT_EXCEEDED")
            self._transitions = self._ordered_transitions(
                [self._transition_record(name) for name in names]
            )
        return self._transitions

    def require_transition_evidence(
        self, value: object, *, projection_ids: Mapping[str, str] | None = None
    ) -> dict[str, ArchiveReceipt]:
        """Require recoverable published anchors before committing a host transition."""
        self.require_recovery_complete()
        transition = validate_transition(value)
        sources = {
            source_key(transition[key]): transition[key] for key in ("predecessor", "successor")
        }
        if projection_ids is not None and (
            type(projection_ids) is not dict
            or projection_ids.keys() != sources.keys()
            or any(
                type(identifier) is not str or SHA256_HEX.fullmatch(identifier) is None
                for identifier in projection_ids.values()
            )
        ):
            _fail("ARCHIVE_TRANSITION_INVALID")
        self._capacity()
        selected: dict[str, ReceiptRecord] = {}
        for name in os.listdir(self._fd):
            match = _RECEIPT_NAME.fullmatch(name)
            if match is None:
                continue
            record = self._receipt(match[1])
            source = sources.get(record["sourceId"])
            if (
                source is None
                or record["profile"] != transition["profile"]
                or record["status"] != "published"
            ):
                continue
            self.load(record["receiptId"], source, transition["profile"])
            if (
                projection_ids is not None
                and projection_ids[record["sourceId"]] != record["projectionId"]
            ):
                continue
            previous = selected.get(record["sourceId"])
            if previous is None or record["publicationSequence"] > previous["publicationSequence"]:
                selected[record["sourceId"]] = record
        if selected.keys() != sources.keys():
            _fail("ARCHIVE_TRANSITION_EVIDENCE_MISSING")
        return {identifier: self._public(record) for identifier, record in selected.items()}

    def stage_transition(self, value: object) -> TransitionRecord:
        """Durably fence predecessor collection before mutating its graph source."""
        self.require_recovery_complete()
        transition = validate_transition(value)
        records = list(self.list_transitions())
        predecessor = source_key(transition["predecessor"])
        for record in records:
            if source_key(record["transition"]["predecessor"]) == predecessor:
                if record["transition"] != transition:
                    _fail("ARCHIVE_TRANSITION_CONFLICT")
                return record
        if any(record["status"] == "pending" for record in records):
            _fail("ARCHIVE_TRANSITION_PENDING")
        record: TransitionRecord = {
            "schemaVersion": 1,
            "transition": transition,
            "transitionId": transition_id(transition),
            "status": "pending",
            "receipt": None,
        }
        self._ordered_transitions([*records, record])
        self._write(f"lifecycle-{predecessor}.json", canonical_bytes(record))
        return record

    def finish_transition(self, value: object, receipt: object) -> TransitionRecord:
        """Complete only an existing exact intent after the graph receipt is durable."""
        transition = validate_transition(value)
        checked = self._transition_receipt(transition, receipt)
        predecessor = source_key(transition["predecessor"])
        records = self.list_transitions()
        existing = next(
            (
                record
                for record in records
                if source_key(record["transition"]["predecessor"]) == predecessor
            ),
            None,
        )
        if existing is None:
            _fail("ARCHIVE_TRANSITION_NOT_STAGED")
        if existing["transition"] != transition or (
            existing["status"] == "complete" and existing["receipt"] != checked
        ):
            _fail("ARCHIVE_TRANSITION_CONFLICT")
        if existing["status"] == "complete":
            return existing
        record: TransitionRecord = {**existing, "status": "complete", "receipt": checked}
        self._write(f"lifecycle-{predecessor}.json", canonical_bytes(record))
        return record

    # -- snapshots and their receipts ------------------------------------------

    def store(self, snapshot: Mapping[str, Any]) -> ArchiveReceipt:
        """Write a validated snapshot and its pending receipt before any graph import."""
        snapshot = validate_snapshot(snapshot)
        self.require_publishable_source(snapshot["source"])
        contents = canonical_bytes(snapshot)
        source_id = source_key(snapshot["source"])
        receipt_id = _receipt_id(source_id, snapshot["snapshotId"])
        digest = sha256(contents).hexdigest()
        try:
            existing = self._receipt(receipt_id)
        except ArchiveError as error:
            if error.code != "ARCHIVE_NOT_FOUND":
                raise
        else:
            if existing["sha256"] != digest or existing["profile"] != snapshot["profile"]:
                _fail("ARCHIVE_SNAPSHOT_CONFLICT")
            self.load(receipt_id, snapshot["source"], snapshot["profile"])
            return self._public(existing)
        # A source the graph keeps rejecting must not fill the quota every source shares.
        pending = sum(value["status"] == "pending" for value in self._source_receipts(source_id))
        if pending >= self.max_pending:
            _fail("ARCHIVE_PENDING_LIMIT_EXCEEDED")
        receipt: ReceiptRecord = {
            "schemaVersion": 1,
            "receiptId": receipt_id,
            "source": snapshot["source"],
            "sourceId": source_id,
            "profile": snapshot["profile"],
            "snapshotId": snapshot["snapshotId"],
            "sha256": digest,
            "createdAt": _now(),
            "status": "pending",
            "publishedAt": None,
            "publicationSequence": None,
            "projectionId": None,
            "lastError": None,
        }
        receipt_contents = canonical_bytes(receipt)
        filename = f"{receipt_id}.snapshot.json"
        try:
            orphan = self._read(filename, MAX_SNAPSHOT_BYTES)
        except ArchiveError as error:
            if error.code != "ARCHIVE_NOT_FOUND":
                raise
            # A predictable quota failure must not strand a snapshot without
            # its receipt. Actual interrupted writes still use exact-content retry.
            self._capacity(len(contents) + len(receipt_contents), True, new_files=2)
            self._write(filename, contents, new_snapshot=True)
        else:
            if orphan != contents:
                _fail("ARCHIVE_SNAPSHOT_CONFLICT")
        self._write_receipt(receipt)
        return self._public(receipt)

    def load(
        self,
        receipt_id: str,
        expected_source: Mapping[str, str],
        expected_profile: str | None = None,
    ) -> Snapshot:
        """The archived snapshot of one receipt, verified against its hash and scope."""
        receipt = self._receipt(receipt_id)
        if receipt["source"] != dict(expected_source) or (
            expected_profile is not None and receipt["profile"] != expected_profile
        ):
            _fail("ARCHIVE_SCOPE_MISMATCH")
        name = f"{receipt_id}.snapshot.json"
        contents = self._read(name, MAX_SNAPSHOT_BYTES)
        if sha256(contents).hexdigest() != receipt["sha256"]:
            _fail("ARCHIVE_CONTENT_CONFLICT", name)
        try:
            snapshot = decode_snapshot(contents)
        except CollectionError:
            raise ArchiveError("ARCHIVE_INVALID", name) from None
        if (
            snapshot["source"] != receipt["source"]
            or snapshot["profile"] != receipt["profile"]
            or snapshot["snapshotId"] != receipt["snapshotId"]
        ):
            _fail("ARCHIVE_CONTENT_CONFLICT", name)
        return snapshot

    def record_result(self, receipt_id: str, result: ImportResult) -> ArchiveReceipt:
        """Record the graph's outcome for one receipt: published or already known."""
        receipt = self._receipt(receipt_id)
        if (
            not isinstance(result, ImportResult)
            or result.source_id != receipt["sourceId"]
            or result.snapshot_id != receipt["snapshotId"]
            or SHA256_HEX.fullmatch(result.projection_id) is None
            or type(result.published) is not bool
            or type(result.idempotent) is not bool
            or result.published == result.idempotent
        ):
            _fail()
        if receipt["projectionId"] not in (None, result.projection_id):
            _fail("ARCHIVE_PUBLICATION_CONFLICT")
        receipt["projectionId"] = result.projection_id
        if result.published:
            receipt["status"] = "published"
            if receipt["publishedAt"] is None:
                receipt["publishedAt"] = _now()
                receipt["publicationSequence"] = 1 + max(
                    (
                        value["publicationSequence"] or 0
                        for value in self._source_receipts(receipt["sourceId"])
                    ),
                    default=0,
                )
                if receipt["publicationSequence"] > MAX_SEQUENCE:
                    _fail("ARCHIVE_LIMIT_EXCEEDED")
        elif receipt["status"] == "pending":
            # Could be current or historical after recovery. Kept: retention never
            # prunes it, and only a reviewed discard removes it.
            receipt["status"] = "idempotent"
        receipt["lastError"] = None
        self._write_receipt(receipt)
        return self._public(receipt)

    def record_failure(self, receipt_id: str, error_code: str) -> None:
        """Keep a receipt pending and note why its publication failed."""
        receipt = self._receipt(receipt_id)
        receipt["lastError"] = _error(error_code)
        self._write_receipt(receipt)

    def list_pending(
        self, expected_source: Mapping[str, str] | None = None, profile: str | None = None
    ) -> tuple[ArchiveReceipt, ...]:
        """Unpublished receipts for one enrolled source, or for every source."""
        if expected_source is None:
            receipts, _damaged = self._scan()
        else:
            receipts = [
                value
                for value in self._source_receipts(
                    source_key(validate_source(dict(expected_source)))
                )
                if value["source"] == dict(expected_source) and value["profile"] == profile
            ]
        return tuple(
            self._public(value)
            for value in sorted(receipts, key=lambda item: (item["createdAt"], item["receiptId"]))
            if value["status"] == "pending"
        )

    def discard(self, receipt_id: str) -> DiscardResult:
        """Operator-reviewed removal of one pending, uncertain, invalid or orphaned record.

        A published receipt is a recovery anchor: retention prunes it, and this
        refuses it. An already-known (idempotent) receipt is never pruned, so this is
        the one way to remove it. A receipt that is unsafe, too large or cannot be
        read is not known to be damaged: its error is raised and the file is kept.
        The caller confirms the review.
        """
        self.require_recovery_complete()
        if type(receipt_id) is not str or SHA256_HEX.fullmatch(receipt_id) is None:
            _fail()
        receipt_name, snapshot_name = f"{receipt_id}.receipt.json", f"{receipt_id}.snapshot.json"
        # Read the directory itself: this acts on the files as they are now.
        names = set(self.entries())
        if receipt_name not in names and snapshot_name not in names:
            _fail("ARCHIVE_NOT_FOUND", receipt_name)
        state: Any = "orphan"
        source_id: str | None = None
        snapshot_id: str | None = None
        if receipt_name in names:
            try:
                receipt = self._receipt(receipt_id)
            except ArchiveError as error:
                # Wrong permissions or a failed read say nothing about the content:
                # the receipt may be a valid anchor once the file is repaired.
                if error.code != "ARCHIVE_INVALID":
                    raise
                state, source_id = "damaged", self._owner(receipt_id)
            else:
                if receipt["status"] == "published":
                    _fail("ARCHIVE_DISCARD_REFUSED", receipt_name)
                state = "pending" if receipt["status"] == "pending" else "uncertain"
                source_id, snapshot_id = receipt["sourceId"], receipt["snapshotId"]
        try:
            # Snapshot first: an interruption leaves a receipt that can be discarded again.
            for name in (snapshot_name, receipt_name):
                try:
                    os.unlink(name, dir_fd=self._fd)
                except FileNotFoundError:
                    pass
                self._forget(name)
            os.fsync(self._fd)
        except OSError:
            self._invalidate()
            raise ArchiveError("ARCHIVE_WRITE_FAILED") from None
        self.damaged = tuple(sorted(self._unreadable))
        return {
            "receiptId": receipt_id,
            "state": state,
            "sourceId": source_id,
            "snapshotId": snapshot_id,
        }

    def _reconcile(self, receipt_id: str) -> None:
        """Index one receipt and its snapshot again, as they are on disk now."""
        if self._files is None:
            return
        receipt = f"{receipt_id}.receipt.json"
        for name in (f"{receipt_id}.snapshot.json", receipt):
            try:
                metadata = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            except FileNotFoundError:
                self._forget(name)
                continue
            except OSError:
                self._invalidate()
                return
            self._bytes += metadata.st_size - self._files.get(name, _ABSENT)[1]
            self._files[name] = _signature(metadata)
        self._unreadable.pop(receipt, None)
        if self._receipts is not None:
            self._receipts.pop(receipt_id, None)
            if receipt in self._files:
                self._scan_receipt(self._receipts, receipt_id)

    def _remove(self, receipt_id: str) -> tuple[int, int, int]:
        """Unlink one validated receipt and its snapshot; (files, snapshots, bytes) freed.

        The decision to remove them was made from the index. Both files must still be
        the ones that were indexed: one that was rewritten, damaged, re-moded, added
        or removed since is never deleted on a stale record. It is indexed again
        instead, and ``ARCHIVE_FILE_CHANGED`` names it.
        """
        indexed = self._index()
        present = []
        freed = [0, 0, 0]
        try:
            for name in (f"{receipt_id}.snapshot.json", f"{receipt_id}.receipt.json"):
                try:
                    metadata = self._metadata(name)
                except FileNotFoundError:
                    # A previous pruning attempt may have stopped between the two
                    # unlinks: then the index never held this file either.
                    if name in indexed:
                        self._reconcile(receipt_id)
                        _fail("ARCHIVE_FILE_CHANGED", name)
                    continue
                if indexed.get(name) != _signature(metadata):
                    self._reconcile(receipt_id)
                    _fail("ARCHIVE_FILE_CHANGED", name)
                present.append((name, metadata.st_size))
            for name, size in present:
                os.unlink(name, dir_fd=self._fd)
                self._forget(name)
                freed = [freed[0] + 1, freed[1] + name.endswith(".snapshot.json"), freed[2] + size]
        except OSError:
            self._invalidate()
            raise ArchiveError("ARCHIVE_WRITE_FAILED") from None
        return freed[0], freed[1], freed[2]

    def maintain(
        self,
        *,
        now: int | None = None,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        protected_projection_ids: Iterable[str] = (),
        reserve_snapshots: int = 0,
        reserve_bytes: int = 0,
    ) -> PruneReport:
        """Prune by age, then oldest-first for room; only published receipts are removed.

        Published receipts expire after the retention period. The newest two
        publications per source and every protected graph projection always stay,
        as do pending and already-known (idempotent) receipts, whose outcome nothing
        here can confirm. When the archive cannot hold ``reserve_*`` more, the oldest
        unprotected publications go early instead of every source failing.
        """
        if any(
            type(value) is not int or value < 0
            for value in (retention_seconds, reserve_snapshots, reserve_bytes)
        ):
            _fail("ARCHIVE_CONFIG_INVALID")
        now = _now() if now is None else now
        if type(now) is not int or now < 0:
            _fail("ARCHIVE_CONFIG_INVALID")
        self.require_recovery_complete()
        receipts, damaged = self._scan()
        unreadable = set(damaged)
        groups: dict[str, list[ReceiptRecord]] = {}
        for receipt in receipts:
            if receipt["status"] == "published":
                groups.setdefault(receipt["sourceId"], []).append(receipt)
        protected_projections = frozenset(protected_projection_ids)
        protected = {
            value["receiptId"]
            for values in groups.values()
            for value in sorted(values, key=lambda item: item["publicationSequence"], reverse=True)[
                :PROTECTED_PER_SOURCE
            ]
        }
        candidates = sorted(
            (
                receipt
                for receipt in receipts
                if receipt["status"] == "published"
                and receipt["receiptId"] not in protected
                and receipt["projectionId"] not in protected_projections
            ),
            key=lambda item: (
                item["createdAt"],
                item["publicationSequence"] or 0,
                item["receiptId"],
            ),
        )
        files, count, size = self._usage()
        removed = early = 0
        try:
            for receipt in candidates:
                expired = now - receipt["createdAt"] >= retention_seconds
                crowded = (
                    count + reserve_snapshots > self.max_snapshots
                    or size + reserve_bytes > self.max_bytes
                    or files + 2 * reserve_snapshots > 4 * self.max_snapshots
                )
                if not expired and not crowded:
                    break
                try:
                    freed = self._remove(receipt["receiptId"])
                except ArchiveError as error:
                    if error.code == "ARCHIVE_FILE_CHANGED":
                        # Changed since it was indexed: kept, and judged again from
                        # disk by the next scan. It is reported only if now unreadable.
                        files, count, size = self._usage()
                        continue
                    if error.code != "ARCHIVE_FILE_UNSAFE":
                        raise
                    # Kept and reported; an unsafe file is never unlinked on trust.
                    if error.file is not None:
                        unreadable.add(error.file)
                    continue
                files, count, size = files - freed[0], count - freed[1], size - freed[2]
                removed, early = removed + 1, early + (not expired)
        finally:
            if removed:
                os.fsync(self._fd)
        self.damaged = tuple(sorted(unreadable | set(self._unreadable)))
        return PruneReport(removed, early, self.damaged)

    def prune(
        self,
        *,
        now: int | None = None,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        protected_projection_ids: Iterable[str] = (),
    ) -> int:
        """Age-based pruning only; see ``maintain``."""
        return self.maintain(
            now=now,
            retention_seconds=retention_seconds,
            protected_projection_ids=protected_projection_ids,
        ).removed

    def record_health(
        self,
        expected_source: Mapping[str, str],
        profile: str,
        *,
        error_code: str | None = None,
        result: ImportResult | None = None,
        snapshot: Mapping[str, Any] | None = None,
    ) -> HealthRecord:
        """Record one attempt for a source: either its error code or its import result."""
        source = dict(validate_source(dict(expected_source)))
        identifier = source_key(source)
        if profile not in PROFILES or (error_code is None) == (result is None):
            _fail()
        filename = f"health-{identifier}.json"
        previous = self.read_health(source, profile)
        health: HealthRecord = {
            "schemaVersion": 1,
            "sourceId": identifier,
            "profile": profile,
            "lastAttemptAt": _now(),
            "lastSuccessAt": previous["lastSuccessAt"] if previous else None,
            "lastError": _error(error_code) if error_code is not None else None,
            "consecutiveFailures": min(
                (previous["consecutiveFailures"] if previous else 0) + 1, 1_000_000_000
            )
            if error_code is not None
            else 0,
            "lastSnapshotId": previous["lastSnapshotId"] if previous else None,
            "lastSnapshotGeneratedAt": previous["lastSnapshotGeneratedAt"] if previous else None,
            "lastProjectionId": previous["lastProjectionId"] if previous else None,
        }
        if result is not None:
            if (
                not isinstance(result, ImportResult)
                or result.source_id != identifier
                or not SHA256_HEX.fullmatch(result.projection_id)
            ):
                _fail()
            health["lastSnapshotGeneratedAt"] = None
            if snapshot is not None:
                checked = validate_snapshot(snapshot)
                if (
                    checked["source"] != source
                    or checked["profile"] != profile
                    or checked["snapshotId"] != result.snapshot_id
                ):
                    _fail()
                health["lastSnapshotGeneratedAt"] = checked["generatedAt"]
            health["lastSuccessAt"] = health["lastAttemptAt"]
            health["lastSnapshotId"] = result.snapshot_id
            health["lastProjectionId"] = result.projection_id
        self._write(filename, canonical_bytes(health))
        return health

    def read_health(self, expected_source: Mapping[str, str], profile: str) -> HealthRecord | None:
        """The health record of one source, or ``None`` before its first attempt."""
        identifier = source_key(dict(validate_source(dict(expected_source))))
        try:
            return self._health(identifier, profile)
        except ArchiveError as error:
            error.file = error.file or f"health-{identifier}.json"
            raise

    def _health(self, identifier: str, profile: str) -> HealthRecord | None:
        try:
            value = json.loads(
                self._read(f"health-{identifier}.json", MAX_HEALTH_BYTES),
                object_pairs_hook=unique_object,
            )
        except ArchiveError as error:
            if error.code == "ARCHIVE_NOT_FOUND":
                return None
            raise
        except (ValueError, UnicodeError, RecursionError):
            raise ArchiveError("ARCHIVE_INVALID") from None
        if (
            type(value) is not dict
            or value.keys() != _HEALTH_KEYS
            or value["sourceId"] != identifier
            or value["profile"] != profile
            or value["schemaVersion"] != 1
            or type(value["schemaVersion"]) is not int
        ):
            _fail("ARCHIVE_SCOPE_MISMATCH")
        if (
            type(value["lastAttemptAt"]) is not int
            or value["lastAttemptAt"] < 0
            or type(value["consecutiveFailures"]) is not int
            or not 0 <= value["consecutiveFailures"] <= 1_000_000_000
        ):
            _fail()
        if value["lastSuccessAt"] is not None and (
            type(value["lastSuccessAt"]) is not int or value["lastSuccessAt"] < 0
        ):
            _fail()
        if value["lastSnapshotId"] is not None and (
            type(value["lastSnapshotId"]) is not str
            or not value["lastSnapshotId"]
            or len(value["lastSnapshotId"]) > 4096
        ):
            _fail()
        if value["lastProjectionId"] is not None and (
            type(value["lastProjectionId"]) is not str
            or SHA256_HEX.fullmatch(value["lastProjectionId"]) is None
        ):
            _fail()
        if value["lastSnapshotGeneratedAt"] is not None:
            if (
                type(value["lastSnapshotGeneratedAt"]) is not str
                or UTC_TIMESTAMP.fullmatch(value["lastSnapshotGeneratedAt"]) is None
            ):
                _fail()
            try:
                datetime.fromisoformat(value["lastSnapshotGeneratedAt"])
            except ValueError:
                raise ArchiveError("ARCHIVE_INVALID") from None
        if value["lastError"] is not None:
            _error(value["lastError"])
        return value
