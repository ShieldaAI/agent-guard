"""Explicit host-approved source supersession; no inference from absent enrollments."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from hashlib import sha256
from pathlib import Path

from neo4j import GraphDatabase, unit_of_work

from agent_guard_cartography.graph import GraphImportError, _lock_source, source_key
from agent_guard_cartography.input_files import read_regular_file

MAX_TRANSITION_BYTES = 256 * 1024
SOURCE_FIELDS = frozenset(
    ("companyId", "sourceId", "tenantId", "enrollmentGeneration", "inventoryInstanceId")
)
PROFILES = ("core", "host", "host-mcp")
MAX_TIMESTAMP_MS = 253_402_300_799_999


class LifecycleError(RuntimeError):
    """Stable safe diagnostics, excluding host configuration and database details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str = "SOURCE_TRANSITION_INVALID") -> None:
    raise LifecycleError(code)


def _source(value: object) -> dict:
    if type(value) is not dict or value.keys() != SOURCE_FIELDS:
        _fail()
    result = {}
    for key in sorted(SOURCE_FIELDS):
        item = value[key]
        if (
            type(item) is not str
            or not any(character != "\ufeff" and not character.isspace() for character in item)
            or len(item) > 4096
            or "\x00" in item
            or any(0xD800 <= ord(char) <= 0xDFFF for char in item)
        ):
            _fail()
        result[key] = item
    return result


def validate_transition(value: object) -> dict:
    """Detach a closed explicit predecessor/successor transition within one installation."""
    if (
        type(value) is not dict
        or value.keys() != {"schemaVersion", "predecessor", "successor", "profile"}
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
        or type(value["profile"]) is not str
        or value["profile"] not in PROFILES
    ):
        _fail()
    before, after = _source(value["predecessor"]), _source(value["successor"])
    if any(before[key] != after[key] for key in ("companyId", "sourceId", "tenantId")):
        _fail("SOURCE_TRANSITION_SCOPE_MISMATCH")
    if before["enrollmentGeneration"] == after["enrollmentGeneration"]:
        _fail()
    result = {
        "schemaVersion": 1,
        "predecessor": before,
        "successor": after,
        "profile": value["profile"],
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_TRANSITION_BYTES:
        _fail()
    return result


def transition_id(value: object) -> str:
    transition = validate_transition(value)
    return sha256(
        json.dumps(transition, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _timestamp(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TIMESTAMP_MS:
        _fail()
    return value


def _matches_source(node: dict, source: dict) -> bool:
    return all(
        node.get(property_name) == source[field]
        for field, property_name in (
            ("companyId", "company_id"),
            ("sourceId", "native_source_id"),
            ("tenantId", "tenant_id"),
            ("enrollmentGeneration", "enrollment_generation"),
            ("inventoryInstanceId", "inventory_instance_id"),
        )
    )


def _ready(tx, identifier: str, node: dict, profile: str) -> None:
    current = node.get("current_snapshot_id")
    if type(current) is not str or not current:
        _fail("SOURCE_TRANSITION_NOT_READY")
    row = tx.run(
        "MATCH (p:GuardSnapshot {id:$id,source_id:$source,status:'published'}) RETURN p",
        id=current,
        source=identifier,
    ).single()
    if row is None:
        _fail("SOURCE_TRANSITION_NOT_READY")
    snapshot = row["p"]
    if snapshot.get("profile", "core") != profile or snapshot.get("tenant_id") != node.get(
        "tenant_id"
    ):
        _fail("SOURCE_TRANSITION_PROFILE_MISMATCH")
    # A published projection is a completed importer transaction; also require
    # its mandatory coverage, rather than treating a damaged marker as ready.
    try:
        encoded = snapshot.get("coverage_json")
        if type(encoded) is not str or len(encoded) > 16_384:
            _fail("SOURCE_TRANSITION_NOT_READY")
        coverage = json.loads(encoded)
        required = ("tasks", "tools") if profile == "core" else ("tasks", "tools", "manifest")
        if type(coverage) is not dict or any(
            type(coverage.get(key)) is not dict or coverage[key].get("status") != "complete"
            for key in required
        ):
            _fail("SOURCE_TRANSITION_NOT_READY")
    except (ValueError, TypeError, RecursionError):
        _fail("SOURCE_TRANSITION_NOT_READY")


def _receipt(transition: dict, identifier: str, timestamp: int) -> dict:
    return {
        "schemaVersion": 1,
        "transitionId": identifier,
        "predecessorSourceId": source_key(transition["predecessor"]),
        "successorSourceId": source_key(transition["successor"]),
        "profile": transition["profile"],
        "supersededAtMs": timestamp,
    }


@unit_of_work(timeout=30)
def _inspect(tx, transition: dict, identifier: str, lock: bool = False) -> dict | None:
    predecessor, successor = (source_key(transition[key]) for key in ("predecessor", "successor"))
    nodes = {}
    # Shared sorted lock order also serializes publication and opposing transitions.
    for source_id in sorted((predecessor, successor)):
        try:
            if lock:
                nodes[source_id] = _lock_source(tx, source_id)
            else:
                row = tx.run("MATCH (s:GuardSource {id:$id}) RETURN s", id=source_id).single()
                if row is None:
                    _fail("SOURCE_TRANSITION_SOURCE_MISSING")
                nodes[source_id] = dict(row["s"])
        except GraphImportError as error:
            if error.code == "SOURCE_MISSING":
                _fail("SOURCE_TRANSITION_SOURCE_MISSING")
            raise
    before, after = nodes[predecessor], nodes[successor]
    for key, node in (("predecessor", before), ("successor", after)):
        if not _matches_source(node, transition[key]):
            _fail("SOURCE_TRANSITION_SCOPE_MISMATCH")
        if node.get("profile", "core") != transition["profile"]:
            _fail("SOURCE_TRANSITION_PROFILE_MISMATCH")
    if before.get("lifecycle_status") == "superseded":
        if (
            before.get("lifecycle_operation_id") != identifier
            or before.get("superseded_by") != successor
        ):
            _fail("SOURCE_TRANSITION_CONFLICT")
        # Recover a graph-committed / archive-pending operation even if later
        # transitions or retention have advanced. This never reactivates a source.
        return _receipt(transition, identifier, _timestamp(before.get("superseded_at_ms")))
    if before.get("lifecycle_status") not in (None, "active"):
        _fail("SOURCE_LIFECYCLE_INVALID")
    if after.get("lifecycle_status") == "superseded":
        _fail("SOURCE_TRANSITION_CONFLICT")
    if after.get("lifecycle_status") not in (None, "active"):
        _fail("SOURCE_LIFECYCLE_INVALID")
    _ready(tx, predecessor, before, transition["profile"])
    _ready(tx, successor, after, transition["profile"])
    return None


@unit_of_work(timeout=30)
def _supersede(tx, transition: dict, identifier: str, timestamp: int) -> dict:
    existing = _inspect(tx, transition, identifier, lock=True)
    if existing is not None:
        return existing
    else:
        tx.run(
            "MATCH (s:GuardSource {id:$id}) "
            "SET s.lifecycle_status='superseded',s.superseded_by=$successor,"
            "s.lifecycle_operation_id=$operation,s.superseded_at_ms=$timestamp,"
            "s.superseded_current_snapshot_id=s.current_snapshot_id,"
            "s.superseded_previous_snapshot_id=s.previous_snapshot_id "
            "REMOVE s.current_snapshot_id,s.previous_snapshot_id",
            id=source_key(transition["predecessor"]),
            successor=source_key(transition["successor"]),
            operation=identifier,
            timestamp=timestamp,
        ).consume()
    return _receipt(transition, identifier, timestamp)


def preflight_transition(session, transition: object) -> dict | None:
    """Validate readiness before persisting intent; the mutation transaction rechecks it."""
    checked = validate_transition(transition)
    return session.execute_read(_inspect, checked, transition_id(checked))


def _transition_projection_ids(session, transition: dict) -> dict:
    identifiers = {source_key(transition[key]) for key in ("predecessor", "successor")}
    rows = list(
        session.run(
            "MATCH (s:GuardSource) WHERE s.id IN $ids "
            "RETURN s.id AS id,coalesce(s.current_snapshot_id,s.superseded_current_snapshot_id) AS projection "
            "LIMIT 3",
            ids=sorted(identifiers),
        )
    )
    result = {row["id"]: row["projection"] for row in rows}
    if (
        len(rows) != 2
        or set(result) != identifiers
        or any(type(value) is not str or len(value) != 64 for value in result.values())
    ):
        _fail("SOURCE_TRANSITION_NOT_READY")
    return result


def supersede_source(session, transition: object, *, timestamp_ms: int | None = None) -> dict:
    """Supersede an exact source after its approved replacement is fully published.

    The host must hold the shared ingestion lock and persist a pending archive
    transition before calling this API. The CLI performs that durable protocol.
    """
    checked = validate_transition(transition)
    timestamp = _timestamp(int(time.time() * 1000) if timestamp_ms is None else timestamp_ms)
    return session.execute_write(_supersede, checked, transition_id(checked), timestamp)


def load_transition(path: Path | str) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                _fail()
            value[key] = item
        return value

    try:
        contents = read_regular_file(path, MAX_TRANSITION_BYTES + 1)
        if len(contents) > MAX_TRANSITION_BYTES:
            _fail()
        return validate_transition(json.loads(contents.decode("utf-8"), object_pairs_hook=pairs))
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        raise LifecycleError("SOURCE_TRANSITION_INVALID") from None


def main(argv=None) -> int:
    # Lazy imports keep archive validation and graph publication acyclic.
    from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
    from agent_guard_cartography.cli import _validate_uri, ingestion_lock

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transition", required=True, type=Path)
    parser.add_argument("--archive-dir", required=True, type=Path)
    parser.add_argument("--archive-max-snapshots", type=int, default=4096)
    parser.add_argument("--archive-max-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--neo4j-uri", required=True)
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-database", default="neo4j")
    parser.add_argument("--neo4j-password-env-var", default="NEO4J_PASSWORD")
    parser.add_argument("--lock-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        transition = load_transition(args.transition)
        _validate_uri(args.neo4j_uri)
        password = os.environ.get(args.neo4j_password_env_var)
        if not password:
            raise GraphImportError("NEO4J_PASSWORD_REQUIRED")
        with (
            ingestion_lock(args.lock_file),
            SnapshotArchive(
                args.archive_dir,
                max_snapshots=args.archive_max_snapshots,
                max_bytes=args.archive_max_bytes,
            ) as archive,
            GraphDatabase.driver(
                args.neo4j_uri,
                auth=(args.neo4j_user, password),
                connection_timeout=10,
                connection_acquisition_timeout=10,
                max_transaction_retry_time=0,
                notifications_min_severity="OFF",
            ) as driver,
            driver.session(database=args.neo4j_database) as session,
        ):
            preflight_transition(session, transition)
            archive.require_transition_evidence(
                transition, projection_ids=_transition_projection_ids(session, transition)
            )
            archive.stage_transition(transition)
            result = supersede_source(session, transition)
            archive.finish_transition(transition, result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (LifecycleError, GraphImportError, ArchiveError) as error:
        print(json.dumps({"error": error.code}), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"error": "SOURCE_TRANSITION_FAILED"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
