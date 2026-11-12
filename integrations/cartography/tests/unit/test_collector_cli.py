"""Collector command diagnostics, archive sizing, per-source isolation and shutdown."""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import neo4j
import pytest
from neo4j import exceptions as neo4j_errors

from agent_guard_cartography import cli, publish
from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.collector import validate_enrollment
from agent_guard_cartography.graph import GraphImportError, ImportResult, source_key

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "alpha-v1.json"
PASSWORD = "database-secret-canary"


class Driver:
    def __init__(self, verify=None):
        self.verify = verify

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def verify_connectivity(self):
        if self.verify is not None:
            raise self.verify

    @contextmanager
    def session(self, **_kwargs):
        yield object()


def lines(text):
    return [json.loads(line) for line in text.splitlines()]


@pytest.fixture
def collector(tmp_path, monkeypatch):
    """A real archive behind the collection loop; the observer and graph are stand-ins."""
    base = json.loads(FIXTURE.read_text())
    polls = {"count": 0}
    state = SimpleNamespace(import_error=None, maintenance_error=None)

    def enrollment(name):
        return validate_enrollment(
            {
                "source": {**base["source"], "sourceId": name},
                "profile": "core",
                "endpoint": "http://127.0.0.1:8181/v1/inventory/snapshot",
                "tokenEnv": "TEST_COLLECTOR_TOKEN",
            }
        )

    def snapshot(name, snapshot_id):
        value = deepcopy(base)
        value["source"]["sourceId"] = name
        value["snapshotId"] = snapshot_id
        return value

    def collect(enrolled, _token):
        polls["count"] += 1
        return snapshot(enrolled.source["sourceId"], f"poll-{polls['count']}")

    def imported(_session, value, expected_source, **_kwargs):
        if state.import_error is not None:
            raise state.import_error
        return ImportResult(
            source_key(expected_source), f"{polls['count']:064x}", value["snapshotId"], True, False
        )

    def retire(*_args, **_kwargs):
        if state.maintenance_error is not None:
            raise state.maintenance_error
        return 0

    monkeypatch.setenv("NEO4J_PASSWORD", PASSWORD)
    monkeypatch.setenv("TEST_COLLECTOR_TOKEN", "agi_v1." + "a" * 43)
    monkeypatch.setattr(publish, "collect_snapshot", collect)
    monkeypatch.setattr(publish, "import_snapshot", imported)
    monkeypatch.setattr(cli, "prune_archive", lambda _s, archive, **o: archive.maintain(**o))
    monkeypatch.setattr(cli, "retire_obsolete", retire)
    monkeypatch.setattr(cli, "retire_superseded", lambda *_args, **_kwargs: 0)
    args = SimpleNamespace(
        archive_dir=tmp_path / "archive",
        archive_max_snapshots=4096,
        archive_max_bytes=256 * 1024**2,
        archive_max_pending=16,
        archive_retention_seconds=604800,
        neo4j_database="neo4j",
        neo4j_password_env_var="NEO4J_PASSWORD",
        replay_receipt=None,
        retention_seconds=3600,
        interval_seconds=300,
        watch=False,
        verbose=False,
    )
    return SimpleNamespace(
        args=args, enrollment=enrollment, snapshot=snapshot, state=state, folder=args.archive_dir
    )


def test_rejected_publication_names_the_retained_receipt(collector, capsys):
    collector.state.import_error = GraphImportError("PUBLICATION_CONFLICT")
    enrolled = collector.enrollment("one")
    assert cli._collect_sources(Driver(), collector.args, [enrolled], {}) == 2
    output = capsys.readouterr()
    (failure,) = lines(output.err)
    with SnapshotArchive(collector.folder) as archive:
        (pending,) = archive.list_pending(enrolled.source, "core")
    assert failure == {
        "status": "failed",
        "code": "PUBLICATION_CONFLICT",
        "source_id": source_key(enrolled.source),
        "receipt_id": pending.receipt_id,
    }
    assert pending.last_error == "PUBLICATION_CONFLICT" and not output.out


@pytest.mark.parametrize("code", ["GENERATED_AT_ROLLBACK", "REVISION_ROLLBACK"])
def test_a_source_whose_clock_stepped_back_recovers_without_an_operator(collector, capsys, code):
    # Every poll is older than the published view: an executor clock stepped back.
    collector.state.import_error = GraphImportError(code)
    enrolled = collector.enrollment("one")
    for _poll in range(collector.args.archive_max_pending + 4):
        assert cli._collect_sources(Driver(), collector.args, [enrolled], {}) == 2
    output = capsys.readouterr()
    # Each rejection is reported with its own code; there is no receipt to replay.
    assert lines(output.err) == [
        {"status": "failed", "code": code, "source_id": source_key(enrolled.source)}
    ] * (collector.args.archive_max_pending + 4)
    assert not output.out and not list(collector.folder.glob("*.snapshot.json"))
    with SnapshotArchive(collector.folder) as archive:
        assert archive.list_pending() == ()
        health = archive.read_health(enrolled.source, "core")
        assert health["lastError"] == code and health["consecutiveFailures"] == 20
    # The clock caught up: the next poll publishes, with no discard in between.
    collector.state.import_error = None
    assert cli._collect_sources(Driver(), collector.args, [enrolled], {}) == 0
    (complete,) = lines(capsys.readouterr().out)
    assert complete["status"] == "complete"


def test_source_at_its_pending_cap_fails_closed_while_others_continue(collector, capsys):
    collector.args.archive_max_pending = 2
    broken, healthy = collector.enrollment("broken"), collector.enrollment("healthy")
    with SnapshotArchive(collector.folder) as archive:
        for index in range(2):
            archive.store(collector.snapshot("broken", f"rejected-{index}"))
    assert cli._collect_sources(Driver(), collector.args, [broken, healthy], {}) == 2
    output = capsys.readouterr()
    (failure,) = lines(output.err)
    assert failure["code"] == "ARCHIVE_PENDING_LIMIT_EXCEEDED"
    assert failure["source_id"] == source_key(broken.source)
    (complete,) = lines(output.out)
    assert complete["status"] == "complete" and complete["maintenance"] == "complete"
    assert len(list(collector.folder.glob("*.snapshot.json"))) == 3


def test_unreadable_and_foreign_files_are_isolated_named_and_reported(collector, capsys):
    broken, healthy = collector.enrollment("broken"), collector.enrollment("healthy")
    with SnapshotArchive(collector.folder) as archive:
        stored = archive.store(collector.snapshot("broken", "earlier"))
    name = f"{stored.receipt_id}.receipt.json"
    (collector.folder / name).write_text('{"schemaVersion":1,')
    stray = collector.folder / ".DS_Store"
    stray.write_bytes(b"finder-private-canary")
    stray.chmod(0o644)
    assert cli._collect_sources(Driver(), collector.args, [broken, healthy], {}) == 2
    output = capsys.readouterr()
    (complete,) = lines(output.out)
    assert complete["import_result"]["source_id"] == source_key(healthy.source)
    failure, damaged, ignored = lines(output.err)
    assert failure == {
        "status": "failed",
        "code": "ARCHIVE_INVALID",
        "source_id": source_key(broken.source),
        "file": name,
    }
    assert damaged == {
        "status": "failed",
        "code": "ARCHIVE_FILE_DAMAGED",
        "operation": "archive",
        "file": name,
    }
    assert ignored["code"] == "ARCHIVE_FILE_IGNORED" and ignored["files"] == [".DS_Store"]
    assert ignored["status"] == "warning" and "canary" not in output.out + output.err
    assert (collector.folder / name).exists() and stray.exists()


def test_full_archive_prunes_early_with_a_warning_instead_of_failing(collector, capsys):
    collector.args.archive_max_snapshots = 3
    enrolled = collector.enrollment("one")
    for _ in range(6):
        assert cli._collect_sources(Driver(), collector.args, [enrolled], {}) == 0
    output = capsys.readouterr()
    assert [row["status"] for row in lines(output.out)] == ["complete"] * 6
    warnings = lines(output.err)
    assert warnings and {row["code"] for row in warnings} == {"ARCHIVE_RETENTION_SHORTENED"}
    assert len(list(collector.folder.glob("*.snapshot.json"))) == 3


@pytest.mark.parametrize(
    "error,code,status",
    [
        (neo4j_errors.ServiceUnavailable("private-host-canary"), "NEO4J_UNAVAILABLE", 2),
        (neo4j_errors.AuthError("private-user-canary"), "NEO4J_AUTH_FAILED", 2),
        (PermissionError("private-path-canary"), "PATH_PERMISSION_DENIED", 2),
        (RuntimeError("private-detail-canary"), "COLLECTION_FAILED", 1),
    ],
)
def test_unexpected_collection_failures_get_specific_safe_codes(
    collector, capsys, error, code, status
):
    collector.state.import_error = error
    enrolled = collector.enrollment("one")
    assert cli._collect_sources(Driver(), collector.args, [enrolled], {}) == status
    output = capsys.readouterr()
    (failure,) = lines(output.err)
    assert failure["code"] == code and failure["status"] == "failed"
    assert "canary" not in output.out + output.err


@pytest.mark.parametrize("verbose", [False, True])
def test_maintenance_failure_is_visible_in_output_and_exit_status(collector, capsys, verbose):
    collector.args.verbose = verbose
    collector.state.maintenance_error = neo4j_errors.ServiceUnavailable(
        f"lost connection as {PASSWORD} to private-host"
    )
    enrolled = collector.enrollment("one")
    assert cli._collect_sources(Driver(), collector.args, [enrolled], {}) == 2
    output = capsys.readouterr()
    (summary,) = lines(output.out)
    assert summary["status"] == "complete" and summary["maintenance"] == "unavailable"
    assert summary["maintenance_code"] == "NEO4J_UNAVAILABLE"
    failure, *detail = lines(output.err)
    assert failure == {
        "status": "failed",
        "code": "NEO4J_UNAVAILABLE",
        "operation": "maintenance",
        "source_id": source_key(enrolled.source),
    }
    assert PASSWORD not in output.out + output.err
    if verbose:
        assert detail == [
            {
                "status": "debug",
                "exception": "ServiceUnavailable",
                "message": "lost connection as [REDACTED] to private-host",
            }
        ]
    else:
        assert not detail and "private-host" not in output.err


def test_failure_codes_trust_only_this_package_and_known_infrastructure():
    assert cli.failure_code(ArchiveError("ARCHIVE_INVALID"), "X") == "ARCHIVE_INVALID"
    assert cli.failure_code(ArchiveError("not a safe code"), "X") == "X"
    # A database error's own code attribute is server text, never echoed.
    assert cli.failure_code(neo4j_errors.ClientError("private"), "X") == "NEO4J_QUERY_FAILED"
    assert cli.failure_code(neo4j_errors.Forbidden("private"), "X") == "NEO4J_FORBIDDEN"
    assert cli.failure_code(FileNotFoundError("private"), "X") == "PATH_NOT_FOUND"
    assert cli.failure_code(KeyError("private"), "X") == "X"


@pytest.fixture
def command(tmp_path, monkeypatch):
    source = json.loads(FIXTURE.read_text())["source"]
    enrollment = tmp_path / "observer.json"
    enrollment.write_text(
        json.dumps(
            {
                "source": source,
                "profile": "core",
                "endpoint": "http://127.0.0.1:8181/v1/inventory/snapshot",
                "tokenEnv": "TEST_COLLECTOR_TOKEN",
            }
        )
    )
    events = []

    def collect(*_args, **_kwargs):
        events.append("collect")
        return SimpleNamespace(
            import_result=SimpleNamespace(source_id="a" * 64),
            summary=lambda: {"status": "complete", "source_id": "a" * 64},
        )

    state = SimpleNamespace(verify=None)
    monkeypatch.setenv("NEO4J_PASSWORD", PASSWORD)
    monkeypatch.setenv("TEST_COLLECTOR_TOKEN", "agi_v1." + "a" * 43)
    monkeypatch.setattr(neo4j.GraphDatabase, "driver", lambda *_a, **_k: Driver(state.verify))
    monkeypatch.setattr(cli, "collect_and_publish", collect)
    monkeypatch.setattr(cli, "prune_archive", lambda _s, archive, **o: archive.maintain(**o))
    monkeypatch.setattr(cli, "retire_obsolete", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(cli, "retire_superseded", lambda *_args, **_kwargs: 0)
    lock = tmp_path / "ingestion.lock"
    arguments = [
        "--enrollment",
        str(enrollment),
        "--archive-dir",
        str(tmp_path / "archive"),
        "--neo4j-uri",
        "bolt://127.0.0.1:7687",
        "--lock-file",
        str(lock),
    ]
    return SimpleNamespace(
        arguments=arguments, events=events, state=state, lock=lock, enrollment=enrollment
    )


def replaced(arguments, option, value):
    arguments = list(arguments)
    arguments[arguments.index(option) + 1] = str(value)
    return arguments


def test_startup_failures_are_distinguishable_and_share_one_json_shape(command, tmp_path, capsys):
    cases = [
        (
            replaced(command.arguments, "--enrollment", tmp_path / "missing-canary.json"),
            "COLLECTOR_ENROLLMENT_NOT_FOUND",
        ),
        (
            replaced(command.arguments, "--lock-file", tmp_path / "missing-canary" / "lock"),
            "PROCESS_LOCK_PATH_INVALID",
        ),
        ([*command.arguments, "--archive-max-snapshots", "2"], "ARCHIVE_SIZING_INVALID"),
        ([*command.arguments, "--archive-max-bytes", "1"], "ARCHIVE_CONFIG_INVALID"),
    ]
    for arguments, code in cases:
        assert cli.main(arguments) == 2
        output = capsys.readouterr()
        assert json.loads(output.err) == {"status": "failed", "code": code}
        assert not output.out and "canary" not in output.err
    assert command.events == []


@pytest.mark.parametrize("verbose", [False, True])
def test_unreachable_or_unauthenticated_database_is_not_a_generic_failure(command, capsys, verbose):
    arguments = [*command.arguments, *(["--verbose"] if verbose else [])]
    for error, code in (
        (neo4j_errors.ServiceUnavailable(f"refused for {PASSWORD}"), "NEO4J_UNAVAILABLE"),
        (neo4j_errors.AuthError("unauthorized"), "NEO4J_AUTH_FAILED"),
    ):
        command.state.verify = error
        assert cli.main(arguments) == 2
        failure, *detail = lines(capsys.readouterr().err)
        assert failure == {"status": "failed", "code": code}
        assert len(detail) == verbose and PASSWORD not in json.dumps(detail)
        if verbose:
            assert detail[0]["exception"] == type(error).__name__
    assert command.events == []


@pytest.mark.parametrize("value", ["3599", "7776001"])
def test_archive_retention_is_bounded_before_any_work(command, value):
    with pytest.raises(SystemExit) as error:
        cli.main([*command.arguments, "--archive-retention-seconds", value])
    assert error.value.code == 2 and command.events == []


def test_archive_retention_flag_reaches_pruning(command, monkeypatch):
    seen = []

    def prune(_session, archive, **options):
        seen.append(options)
        return archive.maintain(**options)

    monkeypatch.setattr(cli, "prune_archive", prune)
    assert cli.main([*command.arguments, "--archive-retention-seconds", "86400"]) == 0
    assert [options["retention_seconds"] for options in seen] == [86400, 86400]
    assert seen[0]["reserve_snapshots"] == 1 and seen[0]["reserve_bytes"] > 8 * 1024**2


def test_startup_warns_once_when_polling_cannot_fit_the_archive(capsys):
    def args(**values):
        return SimpleNamespace(
            archive_max_snapshots=4096,
            archive_retention_seconds=604800,
            interval_seconds=300,
            watch=True,
            **values,
        )

    cli._check_sizing(args(), 2)
    assert capsys.readouterr().err == ""
    cli._check_sizing(args(), 3)
    assert json.loads(capsys.readouterr().err) == {
        "status": "warning",
        "code": "ARCHIVE_SIZING_INSUFFICIENT",
        "sources": 3,
        "interval_seconds": 300,
        "retention_seconds": 604800,
        "required_snapshots": 6051,
        "max_snapshots": 4096,
    }
    with pytest.raises(ArchiveError, match="^ARCHIVE_SIZING_INVALID$"):
        cli._check_sizing(args(), 1366)


@pytest.mark.parametrize("watch", [True, False])
def test_sigterm_stops_like_ctrl_c_and_releases_the_lock(command, monkeypatch, capsys, watch):
    def unhandled(*_args):
        pytest.fail("the collector did not handle SIGTERM")

    previous = signal.signal(signal.SIGTERM, unhandled)
    wait = time.sleep

    def terminate(*_args, **_kwargs):
        os.kill(os.getpid(), signal.SIGTERM)
        for _ in range(500):
            wait(0.01)
        pytest.fail("SIGTERM was not delivered")

    try:
        if watch:
            monkeypatch.setattr(cli.time, "sleep", terminate)
        else:
            monkeypatch.setattr(cli, "collect_and_publish", terminate)
        status = cli.main([*command.arguments, *(["--watch"] if watch else [])])
        assert signal.getsignal(signal.SIGTERM) is unhandled
    finally:
        signal.signal(signal.SIGTERM, previous)
    output = capsys.readouterr()
    if watch:
        assert status == 0 and command.events == ["collect"]
    else:
        assert status == 143
        assert json.loads(output.err) == {"status": "failed", "code": "TERMINATED"}
    # The finally blocks ran: another worker can take the lock immediately.
    with cli.ingestion_lock(command.lock):
        pass


def test_rejected_file_import_is_not_logged_as_an_upstream_traceback():
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("cartography.sync")
    handler = Capture()
    logger.addHandler(handler)
    try:
        with cli._model_diagnostics():
            try:
                raise GraphImportError("REVISION_ROLLBACK")
            except GraphImportError:
                logger.exception("Unhandled exception during sync stage '%s'", "agent_guard")
            logger.warning("Sync interrupted during stage '%s'.", "agent_guard")
        assert records == ["Sync interrupted during stage 'agent_guard'."]
        logger.error("Unhandled exception during sync stage '%s'", "agent_guard")
        assert len(records) == 2
    finally:
        logger.removeHandler(handler)


def test_watch_reconciles_the_archive_with_outside_changes_once_per_cycle(
    collector, monkeypatch, capsys
):
    enrolled = collector.enrollment("one")
    collector.args.watch = True
    collector.args.interval_seconds = 1
    refreshed = []
    refresh = SnapshotArchive.refresh
    monkeypatch.setattr(
        SnapshotArchive, "refresh", lambda archive: refreshed.append(True) or refresh(archive)
    )
    cycles = []

    def between_cycles(_seconds):
        cycles.append(True)
        if len(cycles) == 1:
            # Something other than the collector drops a file into the archive.
            (collector.folder / ".DS_Store").write_bytes(b"finder-private-canary")
        elif len(cycles) == 3:
            raise KeyboardInterrupt()

    monkeypatch.setattr(cli.time, "sleep", between_cycles)
    with pytest.raises(KeyboardInterrupt):
        cli._collect_sources(Driver(), collector.args, [enrolled], {})
    output = capsys.readouterr()
    # Not before the first cycle (the archive was just opened), then once per cycle.
    assert len(cycles) == 3 and len(refreshed) == 2
    (ignored,) = lines(output.err)
    assert ignored["code"] == "ARCHIVE_FILE_IGNORED" and ignored["files"] == [".DS_Store"]
    assert [line["status"] for line in lines(output.out)] == ["complete"] * 3
