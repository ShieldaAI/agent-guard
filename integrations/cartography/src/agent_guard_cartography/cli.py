"""The collector command: explicit file imports and single-worker observer collection."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cartography.config import Config
from cartography.sync import Sync
from neo4j import Driver, Session

from agent_guard_cartography._command import (
    add_archive_arguments,
    add_neo4j_arguments,
    add_verbose_argument,
    archive_limits,
    check_archive_arguments,
    command_failed,
    failure_code,
    infrastructure_code,
    ingestion_lock,
    lock_files,
    log_exception,
    neo4j_password,
    open_driver,
    report_failure,
    sigterm_as_interrupt,
    validate_neo4j_uri,
    warn,
)
from agent_guard_cartography._ids import SHA256_HEX
from agent_guard_cartography._json import unique_object
from agent_guard_cartography.archive import (
    MAX_RECORD_BYTES,
    PROTECTED_PER_SOURCE,
    ArchiveError,
    SnapshotArchive,
    required_snapshots,
)
from agent_guard_cartography.aws_capture import capture_aws
from agent_guard_cartography.aws_config import (
    AwsCollectionError,
    AwsEnrollment,
    collection_id,
    load_aws_enrollment,
)
from agent_guard_cartography.aws_graph import publish_aws_capture
from agent_guard_cartography.cloud import CloudJoinError, CloudScope, validate_cloud_scope
from agent_guard_cartography.collector import CollectionError, CollectorEnrollment, load_enrollment
from agent_guard_cartography.graph import (
    GraphImportError,
    ImportResult,
    import_snapshot,
    source_key,
)
from agent_guard_cartography.input_files import read_regular_file
from agent_guard_cartography.inventory import load_snapshot, validate_snapshot
from agent_guard_cartography.publish import (
    collect_and_publish,
    prune_archive,
    publish_receipt,
    retire_obsolete,
    retire_superseded,
)

_AWS_CODE = re.compile(r"AWS_[A-Z_]{1,56}")
# Company and tenant: the scope a cloud allowlist or AWS enrollment applies to.
_Scope = tuple[str, str]


@contextmanager
def _model_diagnostics() -> Iterator[None]:
    """Our deliberately external schemas need no repeated upstream advisory per poll."""

    class ExternalSchemaNotice(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return not (
                record.msg
                == "The schema %s does not start with 'cartography.models.'. "
                "This may indicate that the schema is not part of the official cartography models."
                and isinstance(record.args, tuple)
                and len(record.args) == 1
                and isinstance(record.args[0], str)
                and (
                    record.args[0] == "agent_guard_cartography.models"
                    or record.args[0].startswith("agent_guard_cartography.models.")
                )
            )

    class StageFailureTraceback(logging.Filter):
        """A rejected import is reported once, by its code; not as an upstream traceback."""

        def filter(self, record: logging.LogRecord) -> bool:
            return record.msg != "Unhandled exception during sync stage '%s'"

    logger = logging.getLogger("cartography.graph.querybuilder")
    stages = logging.getLogger("cartography.sync")
    notice, rejection = ExternalSchemaNotice(), StageFailureTraceback()
    logger.addFilter(notice)
    stages.addFilter(rejection)
    try:
        yield
    finally:
        logger.removeFilter(notice)
        stages.removeFilter(rejection)


def build_sync(
    snapshot: Mapping[str, Any],
    expected_source: Mapping[str, str],
    on_result: Callable[[ImportResult], None] | None = None,
    *,
    cloud_scope: CloudScope | None = None,
) -> Sync:
    """Register exactly one stage; never discover/run provider collectors."""
    snapshot = validate_snapshot(snapshot)
    expected_source = dict(expected_source)
    if snapshot["source"] != expected_source:
        raise GraphImportError("SOURCE_SCOPE_MISMATCH")

    def start_agent_guard_ingestion(session: Session, config: Config) -> None:
        result = import_snapshot(
            session,
            snapshot,
            expected_source,
            update_tag=config.update_tag,
            cloud_scope=cloud_scope,
        )
        if on_result is not None:
            on_result(result)

    sync = Sync()
    sync.add_stage("agent_guard", start_agent_guard_ingestion)
    return sync


def _expected_source(path: Path) -> dict[str, Any]:
    """A small trusted JSON object: the expected source, or a cloud scope."""
    try:
        content = read_regular_file(path, 16_385)
        if len(content) > 16_384:
            raise ValueError()
        value = json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except FileNotFoundError:
        raise GraphImportError("SOURCE_CONFIG_NOT_FOUND") from None
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise GraphImportError("SOURCE_CONFIG_INVALID") from None


def _secret_values(
    args: argparse.Namespace,
    enrollments: Sequence[CollectorEnrollment],
    aws_enrollment: AwsEnrollment | None,
) -> list[str]:
    """Current credential values, so ``--verbose`` can never print one."""
    names = [args.neo4j_password_env_var, *(item.token_env for item in enrollments)]
    if aws_enrollment is not None:
        names += [
            aws_enrollment.access_key_id_env,
            aws_enrollment.secret_access_key_env,
            aws_enrollment.session_token_env,
        ]
    return [value for name in names if (value := os.environ.get(name))]


def _check_sizing(args: argparse.Namespace, sources: int) -> None:
    """Refuse an archive that can never hold its sources; warn once when history is cut."""
    if args.archive_max_snapshots < sources * (PROTECTED_PER_SOURCE + 1):
        raise ArchiveError("ARCHIVE_SIZING_INVALID")
    if not args.watch:
        return
    required = required_snapshots(sources, args.interval_seconds, args.archive_retention_seconds)
    if required > args.archive_max_snapshots:
        # Collection continues: the oldest published snapshots are pruned early.
        warn(
            "ARCHIVE_SIZING_INSUFFICIENT",
            sources=sources,
            interval_seconds=args.interval_seconds,
            retention_seconds=args.archive_retention_seconds,
            required_snapshots=required,
            max_snapshots=args.archive_max_snapshots,
        )


class _Cycle:
    """What one pass over the enrolled sources produced."""

    def __init__(self) -> None:
        # 0 complete; 1 an unexpected source failure; 2 a failure with a known code.
        self.failed = 0
        # Published snapshots removed before their retention elapsed, to make room.
        self.pruned_early = 0

    def fail(self, level: int) -> None:
        self.failed = max(self.failed, level)


def _collect_aws(
    driver: Driver,
    args: argparse.Namespace,
    aws_enrollment: AwsEnrollment,
    explain: Callable[[BaseException], None],
) -> int:
    """Capture and publish the enrolled AWS account once; returns the failure level."""
    try:
        capture = capture_aws(aws_enrollment)
        with driver.session(database=args.neo4j_database) as session:
            publish_aws_capture(session, aws_enrollment, capture)
        policy_summary = {}
        if aws_enrollment.include_iam_policy_evidence:
            evidence = capture["policyEvidence"]
            policy_summary["policy_evidence"] = {
                "status": "complete",
                "assessment": "unknown",
                "candidate_edges": len(evidence["edges"]),
                "unresolved_principals": sum(
                    row["status"] != "mapped" for row in evidence["principals"]
                ),
            }
        print(
            json.dumps(
                {
                    "kind": "aws_collection",
                    "status": "complete",
                    "collection_id": collection_id(aws_enrollment),
                    "captured_at": capture["capturedAt"],
                    "counts": {name: len(capture[name]) for name in ("roles", "users", "buckets")},
                    **policy_summary,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 0
    except Exception as error:
        code = (
            error.code
            if isinstance(error, AwsCollectionError)
            and isinstance(error.code, str)
            and _AWS_CODE.fullmatch(error.code)
            else infrastructure_code(error) or "AWS_COLLECTION_FAILED"
        )
        report_failure(code, kind="aws_collection", collection_id=collection_id(aws_enrollment))
        explain(error)
        return 2


def _collect_source(
    driver: Driver,
    args: argparse.Namespace,
    archive: SnapshotArchive,
    enrollment: CollectorEnrollment,
    scope: CloudScope | None,
    cycle: _Cycle,
    explain: Callable[[BaseException], None],
) -> None:
    """Collect (or replay) one source, publish it, then run its maintenance."""
    try:
        with driver.session(database=args.neo4j_database) as session:
            if args.replay_receipt:
                result = publish_receipt(
                    session, enrollment, archive, args.replay_receipt, cloud_scope=scope
                )
            else:
                # Reclaim old files before store, and make room for this poll,
                # so a full archive recovers instead of failing every source.
                cycle.pruned_early += prune_archive(
                    session,
                    archive,
                    retention_seconds=args.archive_retention_seconds,
                    reserve_snapshots=1,
                    # The snapshot about to be stored, and the receipt beside it.
                    reserve_bytes=enrollment.max_response_bytes + MAX_RECORD_BYTES,
                ).pressure_removed
                token = os.environ.get(enrollment.token_env, "")
                result = collect_and_publish(session, enrollment, token, archive, cloud_scope=scope)
            summary = {**result.summary(), "maintenance": "complete"}
            try:
                retire_obsolete(
                    session,
                    result.import_result.source_id,
                    minimum_retention_seconds=args.retention_seconds,
                )
                cycle.pruned_early += prune_archive(
                    session, archive, retention_seconds=args.archive_retention_seconds
                ).pressure_removed
            except Exception as error:
                # Publication already committed; maintenance is retried next
                # cycle, but its failure is reported and fails the run.
                code = failure_code(error, "MAINTENANCE_FAILED")
                summary.update(maintenance="unavailable", maintenance_code=code)
                report_failure(
                    code,
                    operation="maintenance",
                    source_id=source_key(enrollment.source),
                    error=error,
                )
                explain(error)
                cycle.fail(2)
        print(json.dumps(summary, sort_keys=True), flush=True)
    except Exception as error:
        code = failure_code(error, "COLLECTION_FAILED")
        context: dict[str, Any] = {"source_id": source_key(enrollment.source), "error": error}
        receipt_id = getattr(error, "receipt_id", None)
        if type(receipt_id) is str and SHA256_HEX.fullmatch(receipt_id):
            # The retained receipt: replay it, or review and discard it.
            context["receipt_id"] = receipt_id
        report_failure(code, **context)
        explain(error)
        cycle.fail(1 if code == "COLLECTION_FAILED" else 2)


def _retire_superseded(
    driver: Driver,
    args: argparse.Namespace,
    archive: SnapshotArchive,
    cycle: _Cycle,
    explain: Callable[[BaseException], None],
) -> None:
    """Retire projections of superseded sources once their grace period has passed."""
    # Retired generations are no longer in the active enrollment queue.
    # Their durable journal keeps grace-period cleanup discoverable.
    try:
        with driver.session(database=args.neo4j_database) as session:
            retired = retire_superseded(
                session,
                archive,
                minimum_retention_seconds=args.retention_seconds,
            )
        if retired:
            print(
                json.dumps(
                    {"status": "complete", "operation": "source_retirement", "retired": retired}
                ),
                flush=True,
            )
    except Exception as error:
        report_failure(
            failure_code(error, "SOURCE_RETIREMENT_FAILED"),
            operation="source_retirement",
            error=error,
        )
        explain(error)
        cycle.fail(2)


def _collect_sources(
    driver: Driver,
    args: argparse.Namespace,
    enrollments: Sequence[CollectorEnrollment],
    cloud_scopes: Mapping[_Scope, CloudScope],
    aws_enrollment: AwsEnrollment | None = None,
) -> int:
    """One bounded serial queue; one failing enrollment does not suppress other sources."""

    def explain(error: BaseException) -> None:
        if args.verbose:
            log_exception(
                error, verbose=True, secrets=_secret_values(args, enrollments, aws_enrollment)
            )

    with SnapshotArchive(args.archive_dir, **archive_limits(args)) as archive:
        # An interrupted reconstruction is not an active collector archive.
        # Reject before AWS observation/publication, pruning or source replay.
        archive.require_recovery_complete()
        next_aws = 0.0
        ignored: tuple[str, ...] = ()
        first = True
        while True:
            started = time.monotonic()
            cycle = _Cycle()
            if not first:
                # Notice files added, removed or rewritten by anything else since the
                # previous cycle; within a cycle the archive answers from its index.
                try:
                    archive.refresh()
                except ArchiveError as error:
                    report_failure(error.code, operation="archive", error=error)
                    explain(error)
                    cycle.fail(2)
            first = False
            if aws_enrollment is not None and started >= next_aws:
                try:
                    cycle.fail(_collect_aws(driver, args, aws_enrollment, explain))
                finally:
                    # Never retry a failed account in a hot loop or catch up missed periods.
                    next_aws = time.monotonic() + args.aws_interval_seconds
            for enrollment in enrollments:
                scope = cloud_scopes.get(
                    (enrollment.source["companyId"], enrollment.source["tenantId"])
                )
                _collect_source(driver, args, archive, enrollment, scope, cycle, explain)
            _retire_superseded(driver, args, archive, cycle, explain)
            if cycle.pruned_early:
                warn(
                    "ARCHIVE_RETENTION_SHORTENED",
                    operation="archive_prune",
                    removed=cycle.pruned_early,
                )
            # Unreadable receipts stay for review. Each fails only the source that owns
            # it, but every one is named and fails the run until it is reconciled.
            for name in archive.damaged[:16]:
                report_failure("ARCHIVE_FILE_DAMAGED", operation="archive", file=name)
            if archive.damaged:
                cycle.fail(2)
            if archive.ignored != ignored:
                ignored = archive.ignored
                if ignored:
                    warn(
                        "ARCHIVE_FILE_IGNORED",
                        operation="archive",
                        files=list(ignored[:16]),
                        count=len(ignored),
                    )
            if not args.watch:
                return cycle.failed
            time.sleep(max(0, args.interval_seconds - (time.monotonic() - started)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-guard-cartography",
        description="Collect enrolled Agent Guard executors, or import one inventory file, "
        "into Neo4j as immutable snapshots.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--enrollment",
        type=Path,
        action="append",
        help="Trusted observer enrollment JSON; repeat for serial collection.",
    )
    mode.add_argument(
        "--snapshot", type=Path, help="Import one complete inventory file instead of collecting."
    )
    parser.add_argument(
        "--expected-source",
        type=Path,
        help="With --snapshot: trusted JSON file containing the exact enrolled source object.",
    )
    parser.add_argument(
        "--cloud-scope",
        type=Path,
        action="append",
        help="Explicit company/tenant AWS account allowlist JSON.",
    )
    parser.add_argument(
        "--replay-receipt",
        help="Retry one protected archive receipt instead of fetching the observer.",
    )
    parser.add_argument(
        "--watch", action="store_true", help="Keep the ingestion lock and collect repeatedly."
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=300,
        help="With --watch: seconds between collection cycles, 1..3600 (default 300).",
    )
    parser.add_argument(
        "--aws-enrollment",
        type=Path,
        help="Explicit private single-account AWS metadata enrollment; shares this worker's lock.",
    )
    parser.add_argument(
        "--aws-interval-seconds",
        type=int,
        help="AWS refresh interval from completion, 60..86400 seconds (default 3600).",
    )
    parser.add_argument(
        "--retention-seconds",
        type=int,
        default=3600,
        help="Minimum graph projection age before scoped retirement (at least 60 seconds).",
    )
    add_archive_arguments(parser, directory="optional")
    add_neo4j_arguments(parser)
    add_verbose_argument(parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.aws_enrollment and (not args.enrollment or args.replay_receipt):
        parser.error("AWS collection requires observer enrollments and cannot replay receipts")
    if args.aws_interval_seconds is not None and not args.aws_enrollment:
        parser.error("--aws-interval-seconds requires --aws-enrollment")
    args.aws_interval_seconds = (
        args.aws_interval_seconds if args.aws_interval_seconds is not None else 3600
    )
    if not 60 <= args.aws_interval_seconds <= 86400:
        parser.error("AWS interval must be 60..86400 seconds")
    if args.snapshot and (
        not args.expected_source or args.archive_dir or args.replay_receipt or args.watch
    ):
        parser.error(
            "File import requires --expected-source and does not accept observer-only options"
        )
    if args.enrollment and (args.expected_source or not args.archive_dir):
        parser.error(
            "Observer collection requires --archive-dir and uses the source in --enrollment"
        )
    if len(args.enrollment or []) > 128 or len(args.cloud_scope or []) > 128:
        parser.error("At most 128 enrollments and cloud scopes are supported")
    if args.replay_receipt and len(args.enrollment or []) != 1:
        parser.error("Receipt replay requires exactly one enrollment")
    if args.replay_receipt and args.watch:
        parser.error("--replay-receipt and --watch cannot be combined")
    if not 1 <= args.interval_seconds <= 3600 or not 60 <= args.retention_seconds <= 2_592_000:
        parser.error("Interval must be 1..3600 and retention 60..2592000 seconds")
    check_archive_arguments(parser, args)
    with sigterm_as_interrupt() as terminated:
        return _run(args, terminated)


def _cloud_scopes(paths: Sequence[Path]) -> dict[_Scope, CloudScope]:
    """Each allowlist file, keyed by its company and tenant; one file per scope."""
    scopes: dict[_Scope, CloudScope] = {}
    for path in paths:
        scope = validate_cloud_scope(_expected_source(path))
        key = (scope.company_id, scope.tenant_id)
        if key in scopes:
            raise CloudJoinError("CLOUD_CONFIG_INVALID")
        scopes[key] = scope
    return scopes


def _check_enrollments(
    args: argparse.Namespace,
    enrollments: Sequence[CollectorEnrollment],
    cloud_scopes: Mapping[_Scope, CloudScope],
    aws_enrollment: AwsEnrollment | None,
) -> None:
    """Sources are distinct, the archive can hold them, and every scope is enrolled."""
    if len({source_key(enrollment.source) for enrollment in enrollments}) != len(enrollments):
        raise CollectionError("COLLECTOR_CONFIG_INVALID")
    if not args.replay_receipt:
        _check_sizing(args, len(enrollments))
    enrolled_scopes = {(item.source["companyId"], item.source["tenantId"]) for item in enrollments}
    if set(cloud_scopes) - enrolled_scopes:
        raise CloudJoinError("CLOUD_SCOPE_MISMATCH")
    if aws_enrollment is not None:
        key = (aws_enrollment.company_id, aws_enrollment.tenant_id)
        scope = cloud_scopes.get(key)
        if (
            key not in enrolled_scopes
            or scope is None
            or (aws_enrollment.partition, aws_enrollment.account_id) not in scope.accounts
        ):
            raise AwsCollectionError("AWS_SCOPE_MISMATCH")


def _run(args: argparse.Namespace, terminated: list[int]) -> int:
    try:
        validate_neo4j_uri(args.neo4j_uri)
        password = neo4j_password(args)
        enrollments = [load_enrollment(path) for path in args.enrollment or []]
        aws_enrollment = load_aws_enrollment(args.aws_enrollment) if args.aws_enrollment else None
        cloud_scopes = _cloud_scopes(args.cloud_scope or [])
        results: list[ImportResult] = []
        if enrollments:
            _check_enrollments(args, enrollments, cloud_scopes, aws_enrollment)
        else:
            snapshot = load_snapshot(args.snapshot)
            expected_source = _expected_source(args.expected_source)
            key = (snapshot["source"]["companyId"], snapshot["source"]["tenantId"])
            if set(cloud_scopes) - {key}:
                raise CloudJoinError("CLOUD_SCOPE_MISMATCH")
            sync = build_sync(
                snapshot, expected_source, results.append, cloud_scope=cloud_scopes.get(key)
            )
        config = Config(
            neo4j_uri=args.neo4j_uri,
            neo4j_database=args.neo4j_database,
            update_tag=int(time.time()),
        )
        with (
            _model_diagnostics(),
            # The archive's own lock, so every command on this archive excludes this one.
            ingestion_lock(*lock_files(args.archive_dir if enrollments else None, args.lock_file)),
            open_driver(args, password) as driver,
        ):
            driver.verify_connectivity()
            if enrollments:
                return _collect_sources(driver, args, enrollments, cloud_scopes, aws_enrollment)
            status = sync.run(driver, config)
            if status != 0 or len(results) != 1:
                raise GraphImportError("SYNC_INCOMPLETE")
            print(json.dumps(asdict(results[0]), sort_keys=True))
        return 0
    except KeyboardInterrupt:
        # Ctrl-C or SIGTERM is how an operator stops --watch: a clean stop. An interrupted
        # one-shot collection is not a success; 130/143 are the conventional statuses.
        if args.watch:
            return 0
        report_failure("TERMINATED" if terminated else "INTERRUPTED")
        return 143 if terminated else 130
    except Exception as error:
        return command_failed(error, "IMPORT_FAILED", args)


if __name__ == "__main__":
    sys.exit(main())
