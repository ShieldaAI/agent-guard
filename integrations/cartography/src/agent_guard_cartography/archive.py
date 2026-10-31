"""Protected immutable snapshot files and bounded, atomic collection receipts.

The caller holds the database ingestion lock. Files are evidence/retry material;
graph publication remains authoritative for current/previous projection pointers.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from agent_guard_cartography.collector import CollectionError, _pairs, _source, decode_snapshot
from agent_guard_cartography.graph import ImportResult, source_key
from agent_guard_cartography.inventory import MAX_SNAPSHOT_BYTES, UTC_TIMESTAMP, validate_snapshot

_ID = re.compile(r"[a-f0-9]{64}")
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


class ArchiveError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str = "ARCHIVE_INVALID") -> None:
    raise ArchiveError(code)


def _encoded(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _now() -> int:
    value = int(time.time())
    if value < 0 or value > 253_402_300_799:
        _fail("ARCHIVE_CLOCK_INVALID")
    return value


def _receipt_id(source_id: str, snapshot_id: str) -> str:
    return sha256(_encoded({"source": source_id, "snapshot": snapshot_id})).hexdigest()


def _error(code: str) -> str:
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


class SnapshotArchive:
    def __init__(
        self,
        directory: Path | str,
        *,
        max_snapshots: int = 4096,
        max_bytes: int = 256 * 1024 * 1024,
    ):
        if (
            type(max_snapshots) is not int
            or not 1 <= max_snapshots <= 100_000
            or type(max_bytes) is not int
            or not 1024 <= max_bytes <= 8 * 1024**3
        ):
            _fail("ARCHIVE_CONFIG_INVALID")
        self.max_snapshots, self.max_bytes = max_snapshots, max_bytes
        self._fd = -1
        self._replay_writes = False
        path = Path(directory).absolute()
        if ".." in path.parts:
            _fail("ARCHIVE_DIRECTORY_UNSAFE")
        descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for index, part in enumerate(path.parts[1:]):
                final = index == len(path.parts) - 2
                if final:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                next_descriptor = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                _fail("ARCHIVE_DIRECTORY_UNSAFE")
            self._fd, descriptor = descriptor, -1
            # Caller holds the ingestion lock; interrupted atomic writes are
            # unpublished scratch files and may be removed before capacity checks.
            for name in os.listdir(self._fd):
                if re.fullmatch(r"\.tmp-[a-f0-9]{32}", name):
                    self._metadata(name)
                    os.unlink(name, dir_fd=self._fd)
            self._capacity()
        except ArchiveError:
            self.close()
            raise
        except OSError:
            self.close()
            raise ArchiveError("ARCHIVE_DIRECTORY_UNSAFE") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def __enter__(self) -> SnapshotArchive:
        return self

    def __exit__(self, *_args) -> None:
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
        source_id = source_key(_source(dict(expected_source)))
        if any(
            source_key(record["transition"]["predecessor"]) == source_id
            for record in self.list_transitions()
        ):
            _fail("ARCHIVE_SOURCE_SUPERSEDED")

    def _metadata(self, name: str):
        metadata = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            _fail("ARCHIVE_FILE_UNSAFE")
        return metadata

    def _capacity(
        self, additional: int = 0, new_snapshot: bool = False, *, new_files: int = 0
    ) -> None:
        self._open()
        names = os.listdir(self._fd)
        if len(names) + new_files > 4 * self.max_snapshots:
            _fail("ARCHIVE_LIMIT_EXCEEDED")
        size = sum(self._metadata(name).st_size for name in names)
        count = sum(name.endswith(".snapshot.json") for name in names)
        if size + additional > self.max_bytes or count + new_snapshot > self.max_snapshots:
            _fail("ARCHIVE_LIMIT_EXCEEDED")

    def _read(self, name: str, maximum: int) -> bytes:
        self._open()
        descriptor = -1
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o077
            ):
                _fail("ARCHIVE_FILE_UNSAFE")
            if metadata.st_size > maximum:
                _fail("ARCHIVE_LIMIT_EXCEEDED")
            result = bytearray()
            while len(result) <= maximum:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
            if len(result) > maximum:
                _fail("ARCHIVE_LIMIT_EXCEEDED")
            return bytes(result)
        except FileNotFoundError:
            raise ArchiveError("ARCHIVE_NOT_FOUND") from None
        except OSError:
            raise ArchiveError("ARCHIVE_READ_FAILED") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

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
            raise ArchiveError("ARCHIVE_WRITE_FAILED") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._fd)
            except FileNotFoundError:
                pass

    def _receipt(self, receipt_id: str) -> dict:
        if type(receipt_id) is not str or _ID.fullmatch(receipt_id) is None:
            _fail()
        try:
            value = json.loads(
                self._read(f"{receipt_id}.receipt.json", 256 * 1024), object_pairs_hook=_pairs
            )
            if type(value) is not dict or value.keys() != _RECEIPT_KEYS:
                _fail()
            source = _source(value["source"])
            if (
                value["schemaVersion"] != 1
                or type(value["schemaVersion"]) is not int
                or value["receiptId"] != receipt_id
                or value["sourceId"] != source_key(source)
                or value["profile"] not in ("core", "host", "host-mcp")
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
                or _ID.fullmatch(value["sha256"]) is None
                or type(value["createdAt"]) is not int
                or not 0 <= value["createdAt"] <= 253_402_300_799
            ):
                _fail()
            if value["status"] not in ("pending", "published", "idempotent"):
                _fail()
            if value["publishedAt"] is not None and (
                type(value["publishedAt"]) is not int
                or not 0 <= value["publishedAt"] <= 253_402_300_799
            ):
                _fail()
            if value["publicationSequence"] is not None and (
                type(value["publicationSequence"]) is not int
                or not 1 <= value["publicationSequence"] <= 9_007_199_254_740_991
            ):
                _fail()
            if value["projectionId"] is not None and (
                type(value["projectionId"]) is not str
                or _ID.fullmatch(value["projectionId"]) is None
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
        except (ValueError, TypeError, CollectionError):
            raise ArchiveError("ARCHIVE_INVALID") from None

    @staticmethod
    def _public(value: dict) -> ArchiveReceipt:
        return ArchiveReceipt(
            value["receiptId"],
            value["snapshotId"],
            value["sourceId"],
            value["profile"],
            value["createdAt"],
            value["sha256"],
            value["status"],
            value["projectionId"],
        )

    @staticmethod
    def _transition_value(value: dict) -> dict:
        # Lifecycle orchestration uses this archive; keep validation imports lazy.
        from agent_guard_cartography.lifecycle import validate_transition

        return validate_transition(value)

    @staticmethod
    def _transition_receipt(transition: dict, receipt: dict) -> dict:
        from agent_guard_cartography.lifecycle import transition_id

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
            or not 0 <= receipt["supersededAtMs"] <= 253_402_300_799_999
        ):
            _fail("ARCHIVE_TRANSITION_INVALID")
        return {**expected, "supersededAtMs": receipt["supersededAtMs"]}

    def _transition_record(self, name: str) -> dict:
        from agent_guard_cartography.lifecycle import LifecycleError, transition_id

        match = _LIFECYCLE_NAME.fullmatch(name)
        if match is None:
            _fail("ARCHIVE_TRANSITION_INVALID")
        try:
            record = json.loads(
                self._read(name, 256 * 1024).decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=lambda _value: _fail("ARCHIVE_TRANSITION_INVALID"),
            )
            if (
                type(record) is not dict
                or record.keys() != _LIFECYCLE_KEYS
                or type(record["schemaVersion"]) is not int
                or record["schemaVersion"] != 1
                or record["status"] not in ("pending", "complete")
            ):
                _fail("ARCHIVE_TRANSITION_INVALID")
            transition = self._transition_value(record["transition"])
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
        except (
            ValueError,
            TypeError,
            UnicodeError,
            RecursionError,
            CollectionError,
            LifecycleError,
        ):
            raise ArchiveError("ARCHIVE_TRANSITION_INVALID") from None

    @staticmethod
    def _ordered_transitions(records: list[dict]) -> tuple[dict, ...]:
        """A bounded acyclic replacement graph, allowing explicit predecessor fan-in."""
        by_predecessor, incoming, profiles = {}, {}, {}
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
        if len(profiles) > 128:
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

    def list_transitions(self) -> tuple[dict, ...]:
        """Read and validate private lifecycle evidence, including pending intents."""
        self._capacity()
        names = [name for name in os.listdir(self._fd) if name.startswith("lifecycle-")]
        if len(names) > 128:
            _fail("ARCHIVE_LIMIT_EXCEEDED")
        return self._ordered_transitions([self._transition_record(name) for name in names])

    def require_transition_evidence(
        self, value: dict, *, projection_ids: Mapping[str, str] | None = None
    ) -> dict[str, ArchiveReceipt]:
        """Require recoverable published anchors before committing a host transition."""
        self.require_recovery_complete()
        transition = self._transition_value(value)
        sources = {
            source_key(transition[key]): transition[key] for key in ("predecessor", "successor")
        }
        if projection_ids is not None and (
            type(projection_ids) is not dict
            or projection_ids.keys() != sources.keys()
            or any(
                type(identifier) is not str or _ID.fullmatch(identifier) is None
                for identifier in projection_ids.values()
            )
        ):
            _fail("ARCHIVE_TRANSITION_INVALID")
        self._capacity()
        selected = {}
        for name in os.listdir(self._fd):
            if re.fullmatch(r"[a-f0-9]{64}\.receipt\.json", name) is None:
                continue
            record = self._receipt(name[:-13])
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

    def stage_transition(self, value: dict) -> dict:
        """Durably fence predecessor collection before mutating its graph source."""
        from agent_guard_cartography.lifecycle import transition_id

        self.require_recovery_complete()
        transition = self._transition_value(value)
        records = list(self.list_transitions())
        predecessor = source_key(transition["predecessor"])
        for record in records:
            if source_key(record["transition"]["predecessor"]) == predecessor:
                if record["transition"] != transition:
                    _fail("ARCHIVE_TRANSITION_CONFLICT")
                return record
        if any(record["status"] == "pending" for record in records):
            _fail("ARCHIVE_TRANSITION_PENDING")
        record = {
            "schemaVersion": 1,
            "transition": transition,
            "transitionId": transition_id(transition),
            "status": "pending",
            "receipt": None,
        }
        self._ordered_transitions([*records, record])
        self._write(f"lifecycle-{predecessor}.json", _encoded(record))
        return record

    def finish_transition(self, value: dict, receipt: dict) -> dict:
        """Complete only an existing exact intent after the graph receipt is durable."""
        transition = self._transition_value(value)
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
        record = {**existing, "status": "complete", "receipt": checked}
        self._write(f"lifecycle-{predecessor}.json", _encoded(record))
        return record

    def store(self, snapshot: dict) -> ArchiveReceipt:
        snapshot = validate_snapshot(snapshot)
        self.require_publishable_source(snapshot["source"])
        contents = _encoded(snapshot)
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
        receipt = {
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
        receipt_contents = _encoded(receipt)
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
        self._write(f"{receipt_id}.receipt.json", receipt_contents)
        return self._public(receipt)

    def load(
        self,
        receipt_id: str,
        expected_source: Mapping[str, str],
        expected_profile: str | None = None,
    ) -> dict:
        receipt = self._receipt(receipt_id)
        if receipt["source"] != dict(expected_source) or (
            expected_profile is not None and receipt["profile"] != expected_profile
        ):
            _fail("ARCHIVE_SCOPE_MISMATCH")
        contents = self._read(f"{receipt_id}.snapshot.json", MAX_SNAPSHOT_BYTES)
        if sha256(contents).hexdigest() != receipt["sha256"]:
            _fail("ARCHIVE_CONTENT_CONFLICT")
        try:
            snapshot = decode_snapshot(contents)
        except CollectionError:
            raise ArchiveError("ARCHIVE_INVALID") from None
        if (
            snapshot["source"] != receipt["source"]
            or snapshot["profile"] != receipt["profile"]
            or snapshot["snapshotId"] != receipt["snapshotId"]
        ):
            _fail("ARCHIVE_CONTENT_CONFLICT")
        return snapshot

    def record_result(self, receipt_id: str, result: ImportResult) -> ArchiveReceipt:
        receipt = self._receipt(receipt_id)
        if (
            not isinstance(result, ImportResult)
            or result.source_id != receipt["sourceId"]
            or result.snapshot_id != receipt["snapshotId"]
            or _ID.fullmatch(result.projection_id) is None
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
                previous = [
                    self._receipt(name[:-13])
                    for name in os.listdir(self._fd)
                    if re.fullmatch(r"[a-f0-9]{64}\.receipt\.json", name)
                ]
                receipt["publicationSequence"] = 1 + max(
                    (
                        value["publicationSequence"] or 0
                        for value in previous
                        if value["sourceId"] == receipt["sourceId"]
                    ),
                    default=0,
                )
                if receipt["publicationSequence"] > 9_007_199_254_740_991:
                    _fail("ARCHIVE_LIMIT_EXCEEDED")
        elif receipt["status"] == "pending":
            # Could be current or historical after recovery. Keep conservatively
            # until explicit protection/retention reconciliation is available.
            receipt["status"] = "idempotent"
        receipt["lastError"] = None
        self._write(f"{receipt_id}.receipt.json", _encoded(receipt))
        return self._public(receipt)

    def record_failure(self, receipt_id: str, error_code: str) -> None:
        receipt = self._receipt(receipt_id)
        receipt["lastError"] = _error(error_code)
        self._write(f"{receipt_id}.receipt.json", _encoded(receipt))

    def list_pending(
        self, expected_source: Mapping[str, str], profile: str
    ) -> tuple[ArchiveReceipt, ...]:
        self._capacity()
        values = [
            self._receipt(name[:-13])
            for name in os.listdir(self._fd)
            if re.fullmatch(r"[a-f0-9]{64}\.receipt\.json", name)
        ]
        return tuple(
            self._public(value)
            for value in sorted(values, key=lambda item: (item["createdAt"], item["receiptId"]))
            if value["source"] == dict(expected_source)
            and value["profile"] == profile
            and value["status"] == "pending"
        )

    def prune(
        self,
        *,
        now: int | None = None,
        retention_seconds: int = 7 * 24 * 60 * 60,
        protected_projection_ids: tuple[str, ...] = (),
    ) -> int:
        """Retain pending/uncertain receipts and the latest two actual publications."""
        if type(retention_seconds) is not int or retention_seconds < 0:
            _fail("ARCHIVE_CONFIG_INVALID")
        now = _now() if now is None else now
        if type(now) is not int or now < 0:
            _fail("ARCHIVE_CONFIG_INVALID")
        self.require_recovery_complete()
        self._capacity()
        receipts = [
            self._receipt(name[:-13])
            for name in os.listdir(self._fd)
            if re.fullmatch(r"[a-f0-9]{64}\.receipt\.json", name)
        ]
        groups: dict[str, list[dict]] = {}
        for receipt in receipts:
            if receipt["status"] == "published":
                groups.setdefault(receipt["sourceId"], []).append(receipt)
        protected = {
            value["receiptId"]
            for values in groups.values()
            for value in sorted(values, key=lambda item: item["publicationSequence"], reverse=True)[
                :2
            ]
        }
        removed = 0
        for receipt in receipts:
            if (
                receipt["status"] != "published"
                or receipt["receiptId"] in protected
                or receipt["projectionId"] in protected_projection_ids
                or now - receipt["createdAt"] < retention_seconds
            ):
                continue
            try:
                try:
                    self._metadata(f"{receipt['receiptId']}.snapshot.json")
                    os.unlink(f"{receipt['receiptId']}.snapshot.json", dir_fd=self._fd)
                except FileNotFoundError:
                    # A previous pruning attempt may have stopped between the
                    # two unlinks. This receipt is still eligible and unprotected.
                    pass
                os.unlink(f"{receipt['receiptId']}.receipt.json", dir_fd=self._fd)
            except OSError:
                raise ArchiveError("ARCHIVE_WRITE_FAILED") from None
            removed += 1
        if removed:
            os.fsync(self._fd)
        return removed

    def record_health(
        self,
        expected_source: Mapping[str, str],
        profile: str,
        *,
        error_code: str | None = None,
        result: ImportResult | None = None,
        snapshot: dict | None = None,
    ) -> dict:
        source = dict(_source(dict(expected_source)))
        identifier = source_key(source)
        if profile not in ("core", "host", "host-mcp") or (error_code is None) == (result is None):
            _fail()
        filename = f"health-{identifier}.json"
        previous = self.read_health(source, profile)
        health = {
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
                or not _ID.fullmatch(result.projection_id)
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
            health.update(
                lastSuccessAt=health["lastAttemptAt"],
                lastSnapshotId=result.snapshot_id,
                lastProjectionId=result.projection_id,
            )
        self._write(filename, _encoded(health))
        return health

    def read_health(self, expected_source: Mapping[str, str], profile: str) -> dict | None:
        identifier = source_key(dict(_source(dict(expected_source))))
        try:
            value = json.loads(
                self._read(f"health-{identifier}.json", 64 * 1024), object_pairs_hook=_pairs
            )
        except ArchiveError as error:
            if error.code == "ARCHIVE_NOT_FOUND":
                return None
            raise
        except (ValueError, UnicodeError):
            raise ArchiveError("ARCHIVE_INVALID") from None
        if (
            type(value) is not dict
            or set(value)
            != {
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
            }
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
            or _ID.fullmatch(value["lastProjectionId"]) is None
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
