"""Explicit host-approved source supersession; no inference from absent enrollments."""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

from neo4j import unit_of_work

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
from agent_guard_cartography._ids import MAX_TIMESTAMP_SECONDS
from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.graph import GraphImportError, _lock_source, source_key
from agent_guard_cartography.shapes import Transition, TransitionReceipt
from agent_guard_cartography.transitions import (
    MAX_TRANSITION_BYTES,
    LifecycleError,
    load_transition,
    transition_id,
    validate_transition,
)

__all__ = [
    "MAX_TRANSITION_BYTES",
    "LifecycleError",
    "load_transition",
    "main",
    "preflight_transition",
    "supersede_source",
    "transition_id",
    "validate_transition",
]

MAX_TIMESTAMP_MS = MAX_TIMESTAMP_SECONDS * 1000 + 999


def _fail(code: str = "SOURCE_TRANSITION_INVALID") -> NoReturn:
    raise LifecycleError(code)


def _timestamp(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TIMESTAMP_MS:
        _fail()
    return value


def _matches_source(node: Mapping[str, Any], source: Mapping[str, str]) -> bool:
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


def _ready(tx: Any, identifier: str, node: Mapping[str, Any], profile: str) -> None:
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
    # Every published projection records its profile; none was written without one.
    if snapshot.get("profile") != profile or snapshot.get("tenant_id") != node.get("tenant_id"):
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


def _receipt(transition: Transition, identifier: str, timestamp: int) -> TransitionReceipt:
    return {
        "schemaVersion": 1,
        "transitionId": identifier,
        "predecessorSourceId": source_key(transition["predecessor"]),
        "successorSourceId": source_key(transition["successor"]),
        "profile": transition["profile"],
        "supersededAtMs": timestamp,
    }


@unit_of_work(timeout=30)
def _inspect(
    tx: Any, transition: Transition, identifier: str, lock: bool = False
) -> TransitionReceipt | None:
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
        if node.get("profile") != transition["profile"]:
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
def _supersede(
    tx: Any, transition: Transition, identifier: str, timestamp: int
) -> TransitionReceipt:
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


def preflight_transition(session: Any, transition: object) -> TransitionReceipt | None:
    """Validate readiness before persisting intent; the mutation transaction rechecks it."""
    checked = validate_transition(transition)
    return session.execute_read(_inspect, checked, transition_id(checked))


def _transition_projection_ids(session: Any, transition: Transition) -> dict[str, str]:
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


def supersede_source(
    session: Any, transition: object, *, timestamp_ms: int | None = None
) -> TransitionReceipt:
    """Supersede an exact source after its approved replacement is fully published.

    The host must hold the shared ingestion lock and persist a pending archive
    transition before calling this API. The CLI performs that durable protocol.
    """
    checked = validate_transition(transition)
    timestamp = _timestamp(int(time.time() * 1000) if timestamp_ms is None else timestamp_ms)
    return session.execute_write(_supersede, checked, transition_id(checked), timestamp)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-guard-source-lifecycle", description=__doc__)
    parser.add_argument(
        "--transition",
        required=True,
        type=Path,
        help="Trusted JSON file naming the exact predecessor, successor and profile.",
    )
    add_archive_arguments(parser, create=True)
    add_neo4j_arguments(parser)
    add_verbose_argument(parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    check_archive_arguments(parser, args)
    try:
        transition = load_transition(args.transition)
        validate_neo4j_uri(args.neo4j_uri)
        password = neo4j_password(args)
        if not args.create and not args.archive_dir.is_dir():
            # A mistyped path must fail, not become a new empty archive or leave a lock file.
            raise ArchiveError("ARCHIVE_DIRECTORY_NOT_FOUND")
        with (
            ingestion_lock(*lock_files(args.archive_dir, args.lock_file)),
            SnapshotArchive(
                args.archive_dir, create=args.create, **archive_limits(args)
            ) as archive,
            open_driver(args, password, retry_seconds=0) as driver,
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
    except Exception as error:
        return command_failed(error, "SOURCE_TRANSITION_FAILED", args)


if __name__ == "__main__":
    raise SystemExit(main())
