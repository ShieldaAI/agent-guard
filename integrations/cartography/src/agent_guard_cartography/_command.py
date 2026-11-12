"""What every command shares: archive, lock and Neo4j options, the lock, failure output.

The collector, lifecycle and recovery commands import this module rather than each
other, so they accept the same options with the same defaults and report failures
in the same shape.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import stat
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Any, Literal
from urllib.parse import urlsplit

from neo4j import Driver, GraphDatabase
from neo4j import exceptions as neo4j_errors

from agent_guard_cartography.archive import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_PENDING,
    DEFAULT_MAX_SNAPSHOTS,
    DEFAULT_RETENTION_SECONDS,
    MAX_PENDING_LIMIT,
    MAX_RETENTION_SECONDS,
    MIN_RETENTION_SECONDS,
)
from agent_guard_cartography.errors import AgentGuardCartographyError
from agent_guard_cartography.graph import GraphImportError

# The lock of a command that names neither an archive nor --lock-file (a file import):
# the working-directory file every release has used. Commands with an archive lock
# the file beside it instead; see ``lock_files``.
DEFAULT_LOCK_FILE = Path(".agent-guard-cartography.lock")
_SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def add_archive_arguments(
    parser: argparse.ArgumentParser,
    *,
    directory: Literal["required", "optional", "none"] = "required",
    lock: bool = True,
    create: bool = False,
) -> None:
    """The one archive and lock option group, with the same defaults for every command.

    ``directory`` says whether this command opens an archive named by ``--archive-dir``;
    ``lock`` whether it takes the ingestion lock; ``create`` adds ``--create`` for a
    command that otherwise requires the archive directory to exist.
    """
    group = parser.add_argument_group("archive and lock")
    if directory != "none":
        group.add_argument(
            "--archive-dir",
            type=Path,
            required=directory == "required",
            help="Private (mode 0700) directory of archived snapshots and receipts.",
        )
    if create:
        group.add_argument(
            "--create",
            action="store_true",
            help="Create --archive-dir when it is missing instead of failing.",
        )
    if lock:
        group.add_argument(
            "--lock-file",
            type=Path,
            help="An additional lock file to hold, shared by commands that write the same "
            "database. A command always locks <archive directory>.lock beside its archive; "
            f"a file import, which has no archive, locks this file or else {DEFAULT_LOCK_FILE} "
            "in the working directory.",
        )
    group.add_argument(
        "--archive-max-snapshots",
        type=int,
        default=DEFAULT_MAX_SNAPSHOTS,
        help="Snapshot limit, 1..100000 (default 4096).",
    )
    group.add_argument(
        "--archive-max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="Byte limit, 1024..8589934592 (default 268435456).",
    )
    group.add_argument(
        "--archive-retention-seconds",
        type=int,
        default=DEFAULT_RETENTION_SECONDS,
        help="Age at which collection prunes published snapshots beyond the newest two "
        "per source, 3600..7776000 (default 604800). Only collection prunes.",
    )
    group.add_argument(
        "--archive-max-pending",
        type=int,
        default=DEFAULT_MAX_PENDING,
        help="Unpublished receipts one source may hold before its new snapshots are "
        "refused, 1..1024 (default 16).",
    )


def check_archive_arguments(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not MIN_RETENTION_SECONDS <= args.archive_retention_seconds <= MAX_RETENTION_SECONDS:
        parser.error("Archive retention must be 3600..7776000 seconds")
    if not 1 <= args.archive_max_pending <= MAX_PENDING_LIMIT:
        parser.error("Pending receipts per source must be 1..1024")


def archive_limits(args: argparse.Namespace) -> dict[str, int]:
    """``SnapshotArchive`` keyword arguments from the shared options."""
    return {
        "max_snapshots": args.archive_max_snapshots,
        "max_bytes": args.archive_max_bytes,
        "max_pending": args.archive_max_pending,
    }


def add_neo4j_arguments(parser: argparse.ArgumentParser) -> None:
    """The Neo4j connection options; the password is only ever named, never passed."""
    group = parser.add_argument_group("Neo4j")
    group.add_argument(
        "--neo4j-uri",
        required=True,
        help="bolt+s:// or neo4j+s://, or bolt:// to a literal loopback address.",
    )
    group.add_argument("--neo4j-user", default="neo4j")
    group.add_argument("--neo4j-database", default="neo4j")
    group.add_argument(
        "--neo4j-password-env-var",
        default="NEO4J_PASSWORD",
        help="Environment variable that holds the password (default NEO4J_PASSWORD).",
    )


def add_verbose_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Also log each failure's exception type and message to stderr (no credentials).",
    )


def validate_neo4j_uri(value: str) -> None:
    """Verified TLS, or plaintext Bolt to a literal loopback address; nothing else."""
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


def neo4j_password(args: argparse.Namespace) -> str:
    """The password from the named environment variable; never from an argument."""
    password = os.environ.get(args.neo4j_password_env_var)
    if not password:
        raise GraphImportError("NEO4J_PASSWORD_REQUIRED")
    return password


def open_driver(args: argparse.Namespace, password: str, *, retry_seconds: int = 10) -> Driver:
    """A bounded driver for the validated URI; the caller closes it."""
    return GraphDatabase.driver(
        args.neo4j_uri,
        auth=(args.neo4j_user, password),
        connection_timeout=10,
        connection_acquisition_timeout=10,
        max_transaction_retry_time=retry_seconds,
        notifications_min_severity="OFF",
    )


def archive_lock_file(directory: Path | str) -> Path:
    """The lock that belongs to one archive: ``<directory>.lock`` beside the directory.

    It is derived from the archive's absolute location alone, so two commands that
    name the same archive take the same lock whatever their working directories or
    other options. The archive rejects symlinked and ``..`` path components, so one
    archive has one such path.
    """
    path = Path(directory).absolute()
    if not path.name or ".." in path.parts:
        raise GraphImportError("PROCESS_LOCK_PATH_INVALID")
    return path.with_name(f"{path.name}.lock")


def lock_files(
    archive_dir: Path | str | None, lock_file: Path | str | None = None
) -> tuple[Path, ...]:
    """Every lock one command holds: its archive's own lock, then ``--lock-file`` if given.

    ``--lock-file`` adds a lock; it never replaces the archive's. A command with no
    archive (a file import) and no ``--lock-file`` locks ``DEFAULT_LOCK_FILE``.
    """
    paths = []
    if archive_dir is not None:
        paths.append(archive_lock_file(archive_dir))
    if lock_file is not None:
        paths.append(Path(lock_file))
    return tuple(paths) or (DEFAULT_LOCK_FILE,)


def _open_lock(path: Path | str) -> tuple[int, os.stat_result]:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        # Missing parent directory, a symlink, a directory or no permission.
        raise GraphImportError("PROCESS_LOCK_PATH_INVALID") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise GraphImportError("PROCESS_LOCK_UNSAFE")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def ingestion_lock(*paths: Path | str) -> Iterator[None]:
    """One worker on one host/volume per lock file. This is deliberately not a distributed lease.

    Every named file is locked, in order, or the command does not start; a file named
    twice is locked once.
    """
    try:
        import fcntl
    except ImportError:
        raise GraphImportError("PROCESS_LOCK_UNSUPPORTED") from None
    if not paths:
        raise GraphImportError("PROCESS_LOCK_PATH_INVALID")
    held: dict[tuple[int, int], int] = {}
    try:
        for path in paths:
            descriptor, metadata = _open_lock(path)
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in held:
                os.close(descriptor)
                continue
            held[identity] = descriptor
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GraphImportError("INGESTION_ALREADY_RUNNING") from None
        yield
    finally:
        for descriptor in reversed(list(held.values())):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                # Do not unlink the file: another worker might have opened this inode.
                os.close(descriptor)


@contextmanager
def sigterm_as_interrupt() -> Iterator[list[int]]:
    """Stop on SIGTERM as on Ctrl-C, so locks, the archive and the AWS worker are released."""
    received: list[int] = []

    def handler(signum: int, _frame: FrameType | None) -> None:
        received.append(signum)
        raise KeyboardInterrupt()

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:
        # Not the main thread: the embedding host owns signal handling.
        yield received
        return
    try:
        yield received
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL if previous is None else previous)


def infrastructure_code(error: BaseException) -> str | None:
    """Stable codes for database and filesystem failures; never their messages."""
    if isinstance(error, neo4j_errors.AuthError):
        return "NEO4J_AUTH_FAILED"
    if isinstance(error, neo4j_errors.Forbidden):
        return "NEO4J_FORBIDDEN"
    if isinstance(
        error,
        (
            neo4j_errors.ServiceUnavailable,
            neo4j_errors.SessionExpired,
            neo4j_errors.ConnectionPoolError,
            neo4j_errors.DatabaseUnavailable,
        ),
    ):
        return "NEO4J_UNAVAILABLE"
    if isinstance(error, neo4j_errors.ConfigurationError):
        return "NEO4J_CONFIG_INVALID"
    if isinstance(error, neo4j_errors.Neo4jError):
        if error.code == "Neo.ClientError.Database.DatabaseNotFound":
            return "NEO4J_DATABASE_NOT_FOUND"
        if isinstance(error, neo4j_errors.TransientError):
            return "NEO4J_TRANSIENT_FAILURE"
        return "NEO4J_QUERY_FAILED"
    if isinstance(error, neo4j_errors.DriverError):
        return "NEO4J_DRIVER_FAILED"
    if isinstance(error, FileNotFoundError):
        return "PATH_NOT_FOUND"
    if isinstance(error, PermissionError):
        return "PATH_PERMISSION_DENIED"
    return None


def failure_code(
    error: BaseException,
    default: str,
    coded: tuple[type, ...] = (AgentGuardCartographyError,),
) -> str:
    """This package's own stable code, a known infrastructure code, or ``default``."""
    code = getattr(error, "code", None)
    if isinstance(error, coded) and type(code) is str and _SAFE_CODE.fullmatch(code):
        return code
    return infrastructure_code(error) or default


def report_failure(code: str, **context: Any) -> None:
    """The one error shape every command writes to stderr: status, code, safe context."""
    error = context.pop("error", None)
    file = getattr(error, "file", None)
    if isinstance(error, AgentGuardCartographyError) and file:
        # The basename of the one file that explains the failure; never its contents.
        context["file"] = file
    print(
        json.dumps({**context, "status": "failed", "code": code}, sort_keys=True),
        file=sys.stderr,
        flush=True,
    )


def warn(code: str, **context: Any) -> None:
    """A condition the operator should know about that does not change the exit status."""
    print(
        json.dumps({**context, "status": "warning", "code": code}, sort_keys=True),
        file=sys.stderr,
        flush=True,
    )


def log_exception(error: BaseException, *, verbose: bool, secrets: Sequence[str] = ()) -> None:
    """``--verbose`` detail: exception type and one bounded line, credentials redacted."""
    if not verbose:
        return
    message = " ".join(str(error).split())
    for secret in secrets:
        if secret:
            message = message.replace(secret, "[REDACTED]")
    print(
        json.dumps(
            {"status": "debug", "exception": type(error).__name__, "message": message[:500]},
            sort_keys=True,
        ),
        file=sys.stderr,
        flush=True,
    )


def command_failed(error: BaseException, default: str, args: argparse.Namespace) -> int:
    """Report one command failure; exit status 2 for a known code, 1 for ``default``."""
    code = failure_code(error, default)
    report_failure(code, error=error)
    log_exception(
        error,
        verbose=args.verbose,
        secrets=[os.environ.get(getattr(args, "neo4j_password_env_var", "")) or ""],
    )
    return 1 if code == default else 2
