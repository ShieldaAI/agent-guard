"""Explicit file imports and single-worker observer collection for Cartography."""

import argparse
import ipaddress
import json
import logging
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from cartography.config import Config
from cartography.sync import Sync
from neo4j import GraphDatabase

from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.aws_capture import capture_aws
from agent_guard_cartography.aws_config import (
    AwsCollectionError,
    collection_id,
    load_aws_enrollment,
)
from agent_guard_cartography.aws_graph import publish_aws_capture
from agent_guard_cartography.cloud import CloudJoinError, CloudScope, validate_cloud_scope
from agent_guard_cartography.collector import CollectionError, load_enrollment
from agent_guard_cartography.graph import (
    GraphImportError,
    ImportResult,
    import_snapshot,
    source_key,
)
from agent_guard_cartography.input_files import read_regular_file
from agent_guard_cartography.inventory import (
    InventoryValidationError,
    load_snapshot,
    validate_snapshot,
)
from agent_guard_cartography.publish import (
    collect_and_publish,
    prune_archive,
    publish_receipt,
    retire_obsolete,
    retire_superseded,
)


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

    logger = logging.getLogger("cartography.graph.querybuilder")
    notice = ExternalSchemaNotice()
    logger.addFilter(notice)
    try:
        yield
    finally:
        logger.removeFilter(notice)


def build_sync(
    snapshot: dict,
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

    def start_agent_guard_ingestion(session, config) -> None:
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


@contextmanager
def ingestion_lock(path: Path) -> Iterator[None]:
    """One worker on one host/volume. This is deliberately not a distributed lease."""
    try:
        import fcntl
    except ImportError:
        raise GraphImportError("PROCESS_LOCK_UNSUPPORTED") from None
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise GraphImportError("PROCESS_LOCK_UNSAFE")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise GraphImportError("INGESTION_ALREADY_RUNNING") from None
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        # Do not unlink the file: another worker might have opened this inode.
        os.close(descriptor)


def _expected_source(path: Path) -> dict:
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    try:
        content = read_regular_file(path, 16_385)
        if len(content) > 16_384:
            raise ValueError()
        value = json.loads(content.decode("utf-8"), object_pairs_hook=object_pairs)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise GraphImportError("SOURCE_CONFIG_INVALID") from None


def _validate_uri(value: str) -> None:
    try:
        uri = urlsplit(value)
        if (
            uri.scheme not in ("bolt", "bolt+s", "neo4j+s")
            or not uri.hostname
            or uri.username is not None
            or uri.password is not None
            or uri.path
            or uri.query
            or uri.fragment
        ):
            raise ValueError()
        if uri.port is not None and not 1 <= uri.port <= 65535:
            raise ValueError()
        # Routing discovery can advertise remote plaintext peers even from a
        # loopback seed. Plaintext therefore uses direct literal-loopback Bolt.
        if uri.scheme == "bolt":
            if not ipaddress.ip_address(uri.hostname).is_loopback:
                raise ValueError()
    except ValueError:
        raise GraphImportError("NEO4J_URI_INVALID") from None


def _collect_sources(driver, args, enrollments, cloud_scopes, aws_enrollment=None) -> int:
    """One bounded serial queue; one failing enrollment does not suppress other sources."""
    with SnapshotArchive(
        args.archive_dir, max_snapshots=args.archive_max_snapshots, max_bytes=args.archive_max_bytes
    ) as archive:
        # An interrupted reconstruction is not an active collector archive.
        # Reject before AWS observation/publication, pruning or source replay.
        archive.require_recovery_complete()
        next_aws = 0.0
        while True:
            started = time.monotonic()
            failed = 0
            if aws_enrollment is not None and started >= next_aws:
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
                                "counts": {
                                    name: len(capture[name])
                                    for name in ("roles", "users", "buckets")
                                },
                                **policy_summary,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                except Exception as error:
                    code = (
                        error.code
                        if isinstance(error, AwsCollectionError)
                        and isinstance(error.code, str)
                        and re.fullmatch(r"AWS_[A-Z_]{1,56}", error.code)
                        else "AWS_COLLECTION_FAILED"
                    )
                    print(
                        json.dumps(
                            {
                                "kind": "aws_collection",
                                "status": "failed",
                                "collection_id": collection_id(aws_enrollment),
                                "code": code,
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                        flush=True,
                    )
                    failed = 2
                finally:
                    # Never retry a failed account in a hot loop or catch up missed periods.
                    next_aws = time.monotonic() + args.aws_interval_seconds
            for enrollment in enrollments:
                scope = cloud_scopes.get(
                    (enrollment.source["companyId"], enrollment.source["tenantId"])
                )
                try:
                    with driver.session(database=args.neo4j_database) as session:
                        if args.replay_receipt:
                            result = publish_receipt(
                                session, enrollment, archive, args.replay_receipt, cloud_scope=scope
                            )
                        else:
                            # Reclaim eligible old files before store, so a full archive can recover.
                            prune_archive(session, archive)
                            token = os.environ.get(enrollment.token_env, "")
                            result = collect_and_publish(
                                session, enrollment, token, archive, cloud_scope=scope
                            )
                        maintenance = "complete"
                        try:
                            retire_obsolete(
                                session,
                                result.import_result.source_id,
                                minimum_retention_seconds=args.retention_seconds,
                            )
                            prune_archive(session, archive)
                        except Exception:
                            # Publication already committed; retry maintenance next cycle.
                            maintenance = "unavailable"
                    print(
                        json.dumps(
                            {**result.summary(), "maintenance": maintenance}, sort_keys=True
                        ),
                        flush=True,
                    )
                except (
                    InventoryValidationError,
                    GraphImportError,
                    CollectionError,
                    ArchiveError,
                    CloudJoinError,
                ) as error:
                    print(
                        json.dumps(
                            {
                                "status": "failed",
                                "source_id": source_key(enrollment.source),
                                "code": error.code,
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                        flush=True,
                    )
                    failed = 2
                except Exception:
                    print(
                        json.dumps(
                            {
                                "status": "failed",
                                "source_id": source_key(enrollment.source),
                                "code": "COLLECTION_FAILED",
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                        flush=True,
                    )
                    failed = 1
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
                            {
                                "status": "complete",
                                "operation": "source_retirement",
                                "retired": retired,
                            }
                        ),
                        flush=True,
                    )
            except Exception:
                print(
                    json.dumps(
                        {
                            "status": "unavailable",
                            "operation": "source_retirement",
                            "code": "SOURCE_RETIREMENT_FAILED",
                        }
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                failed = max(failed, 2)
            if not args.watch:
                return failed
            time.sleep(max(0, args.interval_seconds - (time.monotonic() - started)))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import a complete inventory file or collect an enrolled observer into Cartography."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", type=Path)
    mode.add_argument(
        "--enrollment",
        type=Path,
        action="append",
        help="Trusted observer enrollment JSON; repeat for serial collection.",
    )
    parser.add_argument(
        "--expected-source",
        type=Path,
        help="Trusted JSON file containing the exact enrolled source object.",
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        help="Private persistent directory required for observer collection.",
    )
    parser.add_argument("--archive-max-snapshots", type=int, default=4096)
    parser.add_argument("--archive-max-bytes", type=int, default=256 * 1024 * 1024)
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
    parser.add_argument("--interval-seconds", type=int, default=300)
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
    parser.add_argument("--neo4j-uri", required=True)
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-database", default="neo4j")
    parser.add_argument("--neo4j-password-env-var", default="NEO4J_PASSWORD")
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=Path(".agent-guard-cartography.lock"),
        help="Shared persistent lock path for every worker targeting this database.",
    )
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
    try:
        _validate_uri(args.neo4j_uri)
        password = os.environ.get(args.neo4j_password_env_var)
        if not password:
            raise GraphImportError("NEO4J_PASSWORD_REQUIRED")
        enrollments = [load_enrollment(path) for path in args.enrollment or []]
        aws_enrollment = load_aws_enrollment(args.aws_enrollment) if args.aws_enrollment else None
        cloud_scopes = {}
        for path in args.cloud_scope or []:
            scope = validate_cloud_scope(_expected_source(path))
            key = (scope.company_id, scope.tenant_id)
            if key in cloud_scopes:
                raise CloudJoinError("CLOUD_CONFIG_INVALID")
            cloud_scopes[key] = scope
        if enrollments:
            if len({source_key(enrollment.source) for enrollment in enrollments}) != len(
                enrollments
            ):
                raise CollectionError("COLLECTOR_CONFIG_INVALID")
            enrolled_scopes = {
                (item.source["companyId"], item.source["tenantId"]) for item in enrollments
            }
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
        else:
            snapshot = load_snapshot(args.snapshot)
            expected_source = _expected_source(args.expected_source)
            key = (snapshot["source"]["companyId"], snapshot["source"]["tenantId"])
            if set(cloud_scopes) - {key}:
                raise CloudJoinError("CLOUD_SCOPE_MISMATCH")
            results: list[ImportResult] = []
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
            ingestion_lock(args.lock_file),
            GraphDatabase.driver(
                args.neo4j_uri,
                auth=(args.neo4j_user, password),
                connection_timeout=10,
                connection_acquisition_timeout=10,
                max_transaction_retry_time=10,
                notifications_min_severity="OFF",
            ) as driver,
        ):
            driver.verify_connectivity()
            if enrollments:
                return _collect_sources(driver, args, enrollments, cloud_scopes, aws_enrollment)
            else:
                status = sync.run(driver, config)
                if status != 0 or len(results) != 1:
                    raise GraphImportError("SYNC_INCOMPLETE")
                print(json.dumps(asdict(results[0]), sort_keys=True))
        return 0
    except (
        InventoryValidationError,
        GraphImportError,
        CollectionError,
        ArchiveError,
        CloudJoinError,
        AwsCollectionError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("IMPORT_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
