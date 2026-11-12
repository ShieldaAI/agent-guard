"""Every command shares one archive/lock option group, one error base and one failure shape."""

import inspect
import json
import os
from pathlib import Path

import pytest

from agent_guard_cartography import _command, aws_capture, cli, graph, lifecycle, pilot_recovery
from agent_guard_cartography._command import (
    DEFAULT_LOCK_FILE,
    archive_lock_file,
    ingestion_lock,
    lock_files,
    report_failure,
)
from agent_guard_cartography.archive import ArchiveError, SnapshotArchive
from agent_guard_cartography.aws_config import AwsCollectionError
from agent_guard_cartography.cloud import CloudJoinError
from agent_guard_cartography.collector import CollectionError
from agent_guard_cartography.errors import AgentGuardCartographyError
from agent_guard_cartography.graph import GraphImportError
from agent_guard_cartography.inventory import InventoryValidationError
from agent_guard_cartography.lifecycle import LifecycleError
from agent_guard_cartography.pilot_recovery import RecoveryError
from agent_guard_cartography.reference_report import ReportError

LIMITS = {
    "archive_max_snapshots": 4096,
    "archive_max_bytes": 256 * 1024 * 1024,
    "archive_retention_seconds": 7 * 24 * 60 * 60,
    "archive_max_pending": 16,
}
NEO4J = ["--neo4j-uri", "bolt://127.0.0.1:7687"]
# Each command line that opens an archive, with only its own required options.
ARCHIVE_COMMANDS = {
    "collector": lambda: cli._parser().parse_args(
        ["--enrollment", "e.json", "--archive-dir", "archive", *NEO4J]
    ),
    "lifecycle": lambda: lifecycle._parser().parse_args(
        ["--transition", "t.json", "--archive-dir", "archive", *NEO4J]
    ),
    "backup": lambda: pilot_recovery._parser().parse_args(
        ["backup", "--archive-dir", "archive", "--destination", "d", "--enrollment", "e.json"]
    ),
    "replay": lambda: pilot_recovery._parser().parse_args(
        ["replay", "--archive-dir", "archive", "--replay-archive-dir", "w", "--backup-dir", "b"]
        + NEO4J
    ),
    "pending": lambda: pilot_recovery._parser().parse_args(["pending", "--archive-dir", "archive"]),
    "discard": lambda: pilot_recovery._parser().parse_args(
        ["discard", "--archive-dir", "archive", "--receipt-id", "a" * 64]
    ),
}


@pytest.mark.parametrize("command", sorted(ARCHIVE_COMMANDS))
def test_every_archive_command_has_the_same_options_and_defaults(command):
    args = vars(ARCHIVE_COMMANDS[command]())
    assert {name: args[name] for name in LIMITS} == LIMITS
    assert str(args["archive_dir"]) == "archive"
    # No lock option is needed: the lock is derived from the archive directory.
    assert args["lock_file"] is None and args["verbose"] is False
    assert lock_files(args["archive_dir"], args["lock_file"]) == (Path.cwd() / "archive.lock",)


def test_commands_without_an_archive_directory_still_share_the_limits_and_lock():
    restore = vars(
        pilot_recovery._parser().parse_args(["restore", "--backup-dir", "b", "--destination", "d"])
    )
    inspected = vars(pilot_recovery._parser().parse_args(["inspect", "--backup-dir", "b"]))
    for args in (restore, inspected):
        assert {name: args[name] for name in LIMITS} == LIMITS and "archive_dir" not in args
    # A restore locks the archive it creates: the file beside its destination.
    assert restore["lock_file"] is None
    assert lock_files(restore["destination"], None) == (Path.cwd() / "d.lock",)
    # Inspecting a backup changes nothing and takes no lock.
    assert "lock_file" not in inspected


def test_the_lock_is_derived_from_the_archive_not_the_working_directory(tmp_path, monkeypatch):
    archive = tmp_path / "state" / "archive"
    (tmp_path / "state").mkdir()
    (tmp_path / "elsewhere").mkdir()
    expected = tmp_path / "state" / "archive.lock"
    monkeypatch.chdir(tmp_path / "state")
    for spelling in ("archive", "archive/", "./archive", archive, f"{archive}/"):
        assert archive_lock_file(spelling) == expected
    monkeypatch.chdir(tmp_path / "elsewhere")
    assert archive_lock_file(archive) == expected
    # ".." is refused, as the archive refuses it, never resolved to some other directory.
    for unusable in ("/", "../state/archive", archive / ".."):
        with pytest.raises(GraphImportError, match="^PROCESS_LOCK_PATH_INVALID$"):
            archive_lock_file(unusable)
    # --lock-file adds a lock and never replaces the archive's own.
    assert lock_files(archive, tmp_path / "shared.lock") == (expected, tmp_path / "shared.lock")
    # Only a command with neither (a file import) uses the working-directory file.
    assert lock_files(None) == (DEFAULT_LOCK_FILE,)
    assert lock_files(None, tmp_path / "shared.lock") == (tmp_path / "shared.lock",)


def test_two_commands_on_one_archive_exclude_each_other_from_any_directory(
    tmp_path, monkeypatch, capsys
):
    archive = tmp_path / "state" / "archive"
    for name in ("state", "service", "operator"):
        (tmp_path / name).mkdir()
    with SnapshotArchive(archive):
        pass
    pending = ["pending", "--archive-dir", str(archive)]
    monkeypatch.chdir(tmp_path / "service")
    # The collector holds its archive's lock, with or without a --lock-file of its own.
    for collector in (lock_files(archive), lock_files(archive, tmp_path / "service" / "own.lock")):
        with ingestion_lock(*collector):
            monkeypatch.chdir(tmp_path / "operator")
            # An operator elsewhere who passes nothing, or a different --lock-file.
            for extra in ([], ["--lock-file", str(tmp_path / "operator" / "other.lock")]):
                assert pilot_recovery.main([*pending, *extra]) == 2
                assert json.loads(capsys.readouterr().err) == {
                    "status": "failed",
                    "code": "INGESTION_ALREADY_RUNNING",
                }
            monkeypatch.chdir(tmp_path / "service")
        monkeypatch.chdir(tmp_path / "operator")
        assert pilot_recovery.main(pending) == 0
        assert json.loads(capsys.readouterr().out)["pending"] == []
        monkeypatch.chdir(tmp_path / "service")
    # The lock lies beside the archive, never in it or in a working directory.
    assert (tmp_path / "state" / "archive.lock").is_file()
    assert os.listdir(archive) == []
    assert not list(tmp_path.rglob(".agent-guard-cartography.lock"))


def test_one_file_named_twice_is_locked_once_and_a_failed_lock_releases_the_rest(tmp_path):
    first, second = tmp_path / "first.lock", tmp_path / "second.lock"
    with ingestion_lock(first, tmp_path / "." / "first.lock", second):
        with pytest.raises(GraphImportError, match="^INGESTION_ALREADY_RUNNING$"):
            with ingestion_lock(tmp_path / "third.lock", second):
                pytest.fail("the second lock is held")
        # The lock taken before the refused one was released again.
        with ingestion_lock(tmp_path / "third.lock"):
            pass
    with ingestion_lock(second, first):
        pass
    with pytest.raises(GraphImportError, match="^PROCESS_LOCK_PATH_INVALID$"):
        with ingestion_lock():
            pytest.fail("no lock was named")


def test_only_the_lifecycle_command_offers_to_create_a_missing_archive():
    assert vars(ARCHIVE_COMMANDS["lifecycle"]())["create"] is False
    assert all(
        "create" not in vars(build())
        for name, build in ARCHIVE_COMMANDS.items()
        if name != "lifecycle"
    )


@pytest.mark.parametrize(
    "option,value", [("--archive-max-pending", "0"), ("--archive-max-pending", "1025")]
)
def test_shared_limits_are_checked_by_every_command(option, value, capsys):
    with pytest.raises(SystemExit):
        pilot_recovery.main(["pending", "--archive-dir", "archive", option, value])
    assert "Pending receipts per source must be 1..1024" in capsys.readouterr().err


@pytest.mark.parametrize(
    "error_type,builtin",
    [
        (ArchiveError, RuntimeError),
        (AwsCollectionError, RuntimeError),
        (CloudJoinError, ValueError),
        (CollectionError, RuntimeError),
        (GraphImportError, RuntimeError),
        (InventoryValidationError, ValueError),
        (LifecycleError, RuntimeError),
        (RecoveryError, RuntimeError),
        (ReportError, RuntimeError),
    ],
)
def test_every_error_has_one_base_and_keeps_its_builtin_type(error_type, builtin):
    error = error_type("EXAMPLE_CODE")
    assert isinstance(error, AgentGuardCartographyError) and isinstance(error, builtin)
    assert error.code == str(error) == "EXAMPLE_CODE" and error.file is None
    assert error.args == ("EXAMPLE_CODE",)
    assert _command.failure_code(error, "DEFAULT") == "EXAMPLE_CODE"


def test_a_failure_names_the_file_of_any_package_error_but_never_its_path(capsys):
    report_failure("RECOVERY_FILE_UNEXPECTED", error=RecoveryError("X", "/private/dir/.DS_Store\n"))
    assert json.loads(capsys.readouterr().err) == {
        "status": "failed",
        "code": "RECOVERY_FILE_UNEXPECTED",
        "file": "?private?dir?.DS_Store?",
    }
    foreign = RuntimeError("not ours")
    foreign.file = "/private/path"
    report_failure("RECOVERY_FAILED", error=foreign)
    assert json.loads(capsys.readouterr().err) == {"status": "failed", "code": "RECOVERY_FAILED"}


def test_test_seams_are_private_hooks_not_parameters():
    assert "_after_load" not in inspect.signature(graph.import_snapshot).parameters
    assert graph._after_load_hook is None
    assert list(inspect.signature(aws_capture._run_worker).parameters) == [
        "enrollment",
        "credentials",
    ]
    # The real worker is this module, isolated: -I ignores PYTHON* variables and user site.
    assert aws_capture._worker_command()[1:] == [
        "-I",
        "-m",
        "agent_guard_cartography.aws_capture",
        "--worker",
    ]
