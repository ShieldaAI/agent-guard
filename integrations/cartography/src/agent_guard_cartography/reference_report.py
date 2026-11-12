"""Minimized, private, bounded operational differences; never an execution audit log.

Installed as the ``agent-guard-map-report`` command. It asks the Agent Map service
what changed between a source's previous and current snapshot and stores only counts.
"""

from __future__ import annotations

import argparse
import fcntl
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from agent_guard_cartography import _http
from agent_guard_cartography._command import (
    add_verbose_argument,
    failure_code,
    log_exception,
    report_failure,
)
from agent_guard_cartography._files import UnsafePathError, is_private_file, open_private_directory
from agent_guard_cartography._ids import SHA256_HEX
from agent_guard_cartography._json import loads_strict
from agent_guard_cartography.errors import AgentGuardCartographyError

LABELS = frozenset(
    [
        "GuardAgent",
        "GuardOwner",
        "GuardCredentialReference",
        "GuardDeployment",
        "GuardDirectAccess",
        "GuardTask",
        "GuardPrincipal",
        "GuardGrant",
        "GuardTool",
        "GuardResource",
        "GuardResourceBinding",
        "GuardExecutionBinding",
        "GuardExternalResource",
        "GuardExternalIdentity",
        "GuardMcpConnection",
        "GuardMcpOperation",
    ]
)
# Every operation the Agent Map service defines (MAP_OPERATIONS, exported by
# packages/agent-map/src/service.ts); a unit test keeps the two lists identical.
MAP_OPERATIONS = (
    "list_agents",
    "get_agent_access",
    "explain_access",
    "find_agents_with_access",
    "get_changes",
    "get_inventory_health",
    "list_owners",
    "list_resources",
    "get_resource_access",
    "get_agent_inventory",
    "list_undeclared_activity",
    "list_unclaimed_identities",
)
OPERATIONS = frozenset(MAP_OPERATIONS)
MAX_RESPONSE = 2 * 1024 * 1024
NAME = re.compile(r"report-(\d{13})-([a-f0-9]{32})\.json")
_TIMEOUT = 10.0
_WORKERS = threading.BoundedSemaphore(4)
_STORE = ".store.json"
_MAX_FILES = 10_000
_MAX_BYTES = 16 * 1024 * 1024
_MAX_FILE = 16_384


class ReportError(AgentGuardCartographyError, RuntimeError):
    """A report failure; the code never contains the endpoint, token or response."""


_remaining = _http.remaining


def _connect(
    address: tuple[str, int],
    _timeout: float | None,
    source_address: tuple[str, int] | None,
    *,
    deadline: float,
    cancelled: threading.Event,
    sockets: list[socket.socket],
) -> socket.socket:
    # libc DNS cannot be cancelled. Its worker slot remains occupied until it
    # returns, and the following check prevents a late connection or credential send.
    answers = socket.getaddrinfo(address[0], address[1], type=socket.SOCK_STREAM)
    _remaining(deadline, cancelled)
    if not answers or len(answers) > 32:
        raise ValueError()
    for family, kind, protocol, _canonical, target in answers:
        _remaining(deadline, cancelled)
        current = socket.socket(family, kind, protocol)
        sockets.append(current)
        try:
            current.settimeout(_remaining(deadline, cancelled))
            if source_address:
                current.bind(source_address)
            current.connect(target)
            _remaining(deadline, cancelled)
            return current
        except OSError:
            current.close()
    raise OSError()


def _fetch_reference(
    parsed: SplitResult,
    token: str,
    operation: str,
    body: bytes,
    deadline: float,
    cancelled: threading.Event,
    sockets: list[socket.socket],
) -> dict[str, Any]:
    class DeadlineTLSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            # Register the TLS socket before its handshake can block. Closing the
            # pre-wrap socket after wrap_socket() would not interrupt the wrapper.
            raw = self._create_connection((self.host, self.port), self.timeout, self.source_address)
            try:
                self.sock = self._context.wrap_socket(
                    raw, server_hostname=self.host, do_handshake_on_connect=False
                )
                sockets.append(self.sock)
                self.sock.settimeout(_remaining(deadline, cancelled))
                self.sock.do_handshake()
                _remaining(deadline, cancelled)
            except BaseException:
                raw.close()
                if self.sock:
                    self.sock.close()
                raise

    connection = (
        DeadlineTLSConnection(
            parsed.hostname, parsed.port, timeout=_TIMEOUT, context=ssl.create_default_context()
        )
        if parsed.scheme == "https"
        else http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=_TIMEOUT)
    )
    connection._create_connection = lambda address, timeout, source_address: _connect(
        address, timeout, source_address, deadline=deadline, cancelled=cancelled, sockets=sockets
    )
    connection.response_class = _http.deadline_response_class(deadline)
    try:
        connection.connect()
        sockets.append(connection.sock)  # Include the TLS wrapper for cancellation.
        connection.sock.settimeout(_remaining(deadline, cancelled))
        content = _http.post_json(
            connection,
            parsed.path,
            token,
            body,
            deadline=deadline,
            cancelled=cancelled,
            maximum=MAX_RESPONSE,
        )
        _remaining(deadline, cancelled)
        value = loads_strict(content.decode("utf-8"))
        if (
            type(value) is not dict
            or value.get("operation") != operation
            or type(value.get("data")) is not dict
        ):
            raise ValueError()
        _remaining(deadline, cancelled)
        return value
    finally:
        connection.close()


def query_reference(
    endpoint: str, token: str, operation: str, args: dict[str, Any]
) -> dict[str, Any]:
    """Fixed authenticated POST with a whole-request deadline and four worker slots."""
    try:
        if (
            type(endpoint) is not str
            or len(endpoint) > 4096
            or not endpoint.isascii()
            or any(ord(char) <= 32 or ord(char) >= 127 or char in "\\%" for char in endpoint)
        ):
            raise ValueError()
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/query"
            or operation not in OPERATIONS
            or type(token) is not str
            or not re.fullmatch(r"agm_v1\.[A-Za-z0-9_-]{43}", token)
            or type(args) is not dict
        ):
            raise ValueError()
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
            if not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", parsed.hostname
            ) or any(
                not part or part.startswith("-") or part.endswith("-") or len(part) > 63
                for part in parsed.hostname.split(".")
            ):
                raise ValueError() from None
        if parsed.scheme == "http" and (address is None or not address.is_loopback):
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        body = json.dumps({"operation": operation, "args": args}, allow_nan=False).encode()
        if len(body) > 32768:
            raise ValueError()
    except Exception:
        raise ReportError("REFERENCE_QUERY_FAILED") from None
    deadline = time.monotonic() + _TIMEOUT

    def work(cancelled: threading.Event, sockets: list[socket.socket]) -> dict[str, Any]:
        return _fetch_reference(parsed, token, operation, body, deadline, cancelled, sockets)

    try:
        return _http.run_bounded(
            work, deadline=deadline, slots=_WORKERS, thread_name="agent-map-reference"
        )
    except _http.WorkerBusy:
        raise ReportError("REFERENCE_QUERY_BUSY") from None
    except Exception:
        raise ReportError("REFERENCE_QUERY_FAILED") from None


def minimize_changes(response: dict[str, Any], source_id: str) -> dict[str, Any]:
    """Reduce a ``get_changes`` response to counts per label; reject anything partial."""
    try:
        data = response["data"]
        if (
            response["operation"] != "get_changes"
            or data["sourceId"] != source_id
            or not SHA256_HEX.fullmatch(source_id)
            or type(data["coverageGap"]) is not bool
            or data.get("changeSummaryScope", "retained") != "retained"
        ):
            raise ValueError()

        def projection(receipt: dict[str, Any] | None) -> str | None:
            if receipt is None:
                return None
            value = receipt["projectionId"]
            if not SHA256_HEX.fullmatch(value):
                raise ValueError()
            return value

        counts: dict[str, dict[str, int]] = {}
        for kind in ["added", "removed", "changed"]:
            values = data["changes"][kind]
            if not isinstance(values, list) or len(values) > 2000:
                raise ValueError()
            counts[kind] = {}
            for value in values:
                label = value["label"]
                if label not in LABELS:
                    raise ValueError()
                counts[kind][label] = counts[kind].get(label, 0) + 1
        # This client requests the unpaged retained summary. Reject page-scoped
        # or inconsistent responses rather than silently persisting partial counts.
        if "total" in data and (
            type(data["total"]) is not int
            or data["total"] != sum(sum(labels.values()) for labels in counts.values())
        ):
            raise ValueError()
        return {
            "schemaVersion": 1,
            "kind": "agent-map-difference",
            "sourceId": source_id,
            "recordedAt": datetime.now(UTC).isoformat(),
            "fromProjection": projection(data["from"]),
            "toProjection": projection(data["to"]),
            "coverageGap": data["coverageGap"],
            "counts": counts,
        }
    except Exception:
        raise ReportError("REFERENCE_REPORT_INVALID") from None


def _encode(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _validate_metadata(value: os.stat_result, *, links: tuple[int, ...] = (1,)) -> os.stat_result:
    if not is_private_file(value, links=links) or value.st_size > _MAX_FILE:
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
    return value


def _metadata(fd: int, name: str, *, links: tuple[int, ...] = (1,)) -> os.stat_result:
    return _validate_metadata(os.stat(name, dir_fd=fd, follow_symlinks=False), links=links)


def _read(fd: int, name: str, *, links: tuple[int, ...] = (1,)) -> Any:
    expected = _metadata(fd, name, links=links)
    # The checked path can change before open. Never block on a replacement FIFO,
    # and validate permissions/links again on the descriptor that supplies bytes.
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        current = _validate_metadata(os.fstat(descriptor), links=links)
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(_MAX_FILE + 1)
        if len(content) > _MAX_FILE:
            raise ReportError("REFERENCE_REPORT_LIMIT_EXCEEDED")
        return loads_strict(content.decode("utf-8"))
    finally:
        os.close(descriptor)


def _validate_record(value: Any, store_id: str, name: str) -> dict[str, Any]:
    match = NAME.fullmatch(name)
    if (
        not match
        or type(value) is not dict
        or set(value)
        != {
            "schemaVersion",
            "kind",
            "sourceId",
            "recordedAt",
            "fromProjection",
            "toProjection",
            "coverageGap",
            "counts",
            "storeId",
            "reportId",
        }
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
        or value["kind"] != "agent-map-difference"
        or value["storeId"] != store_id
        or value["reportId"] != match[2]
        or type(value["coverageGap"]) is not bool
    ):
        raise ValueError()
    for field in ("sourceId", "toProjection"):
        if type(value[field]) is not str or not SHA256_HEX.fullmatch(value[field]):
            raise ValueError()
    if value["fromProjection"] is not None and (
        type(value["fromProjection"]) is not str
        or not SHA256_HEX.fullmatch(value["fromProjection"])
    ):
        raise ValueError()
    recorded = datetime.fromisoformat(value["recordedAt"])
    if recorded.tzinfo != UTC or int(recorded.timestamp() * 1000) != int(match[1]):
        raise ValueError()
    if type(value["counts"]) is not dict or set(value["counts"]) != {"added", "removed", "changed"}:
        raise ValueError()
    for counts in value["counts"].values():
        if (
            type(counts) is not dict
            or set(counts) - LABELS
            or any(type(number) is not int or not 1 <= number <= 2000 for number in counts.values())
            or sum(counts.values()) > 2000
        ):
            raise ValueError()
    return value


def _publish(fd: int, temporary: str, name: str) -> None:
    try:
        os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    except FileExistsError:
        first, second = _metadata(fd, temporary, links=(2,)), _metadata(fd, name, links=(2,))
        if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE") from None
    os.fsync(fd)
    os.unlink(temporary, dir_fd=fd)
    os.fsync(fd)


def _write(fd: int, name: str, data: bytes) -> None:
    descriptor = os.open(
        name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=fd
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    except BaseException:
        # This process created this exact inode; cleanup never targets a found file.
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
            os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(descriptor)


def _open_directory(directory: Path | str) -> tuple[Path, int]:
    """Open (creating if needed) the private report directory and lock it."""
    if not hasattr(os, "getuid"):
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
    try:
        descriptor = open_private_directory(directory, create=True)
    except UnsafePathError:
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE") from None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return Path(directory).absolute(), descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _prepare_store(fd: int) -> str:
    """The ID of this directory's report store, creating its marker in an empty directory."""
    names = os.listdir(fd)
    if _STORE not in names:
        if names:
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
        marker = {"schemaVersion": 1, "kind": "agent-map-report-store", "storeId": uuid.uuid4().hex}
        temporary = ".initialize-" + uuid.uuid4().hex
        _write(fd, temporary, _encode(marker))
        _publish(fd, temporary, _STORE)
    marker = _read(fd, _STORE)
    if (
        type(marker) is not dict
        or set(marker) != {"schemaVersion", "kind", "storeId"}
        or type(marker["schemaVersion"]) is not int
        or marker["schemaVersion"] != 1
        or marker["kind"] != "agent-map-report-store"
        or type(marker["storeId"]) is not str
        or not re.fullmatch(r"[a-f0-9]{32}", marker["storeId"])
    ):
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
    return marker["storeId"]


def _inspect(
    fd: int, store_id: str
) -> tuple[int, list[tuple[str, dict[str, Any], os.stat_result]]]:
    """Finish interrupted publications; return total bytes and every valid report."""
    names = os.listdir(fd)
    if len(names) > _MAX_FILES:
        raise ReportError("REFERENCE_REPORT_LIMIT_EXCEEDED")
    for name in names:
        if not name.startswith(f".pending-{store_id}-"):
            continue
        published = name.removeprefix(f".pending-{store_id}-")
        _metadata(fd, name, links=(1, 2))
        if NAME.fullmatch(published) is None:
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
        try:
            _validate_record(_read(fd, name, links=(1, 2)), store_id, published)
        except (ValueError, TypeError, KeyError, UnicodeError):
            # A crash midway through writing is never a published report. Preserve
            # unverified bytes instead of deleting a file on filename evidence.
            continue
        _publish(fd, name, published)
    total, reports = 0, []
    for name in os.listdir(fd):
        metadata = _metadata(fd, name)
        total += metadata.st_size
        if name == _STORE:
            continue
        if name.startswith(f".pending-{store_id}-"):
            continue
        try:
            value = _validate_record(_read(fd, name), store_id, name)
        except Exception:
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE") from None
        reports.append((name, value, metadata))
    if total > _MAX_BYTES:
        raise ReportError("REFERENCE_REPORT_LIMIT_EXCEEDED")
    return total, reports


def write_report(
    endpoint: str, token: str, source_id: str, directory: Path, *, retention_days: int = 30
) -> Path:
    """Persist only minimized counts, with explicit store ownership and atomic publication."""
    if (
        type(retention_days) is not int
        or not 1 <= retention_days <= 30
        or type(source_id) is not str
        or SHA256_HEX.fullmatch(source_id) is None
    ):
        raise ReportError("REFERENCE_REPORT_CONFIG_INVALID")
    value = minimize_changes(
        query_reference(endpoint, token, "get_changes", {"sourceId": source_id}), source_id
    )
    descriptor = -1
    try:
        directory, descriptor = _open_directory(directory)
        store_id = _prepare_store(descriptor)
        total, reports = _inspect(descriptor, store_id)
        cutoff = int((time.time() - retention_days * 86400) * 1000)
        for name, previous, metadata in reports:
            if int(datetime.fromisoformat(previous["recordedAt"]).timestamp() * 1000) < cutoff:
                current = _metadata(descriptor, name)
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
                os.unlink(name, dir_fd=descriptor)
                total -= metadata.st_size
        report_id = uuid.uuid4().hex
        recorded = int(datetime.fromisoformat(value["recordedAt"]).timestamp() * 1000)
        name = f"report-{recorded:013d}-{report_id}.json"
        value.update({"storeId": store_id, "reportId": report_id})
        _validate_record(value, store_id, name)
        data = _encode(value)
        if (
            len(data) > _MAX_FILE
            or total + len(data) > _MAX_BYTES
            or len(os.listdir(descriptor)) + 1 > _MAX_FILES
        ):
            raise ReportError("REFERENCE_REPORT_LIMIT_EXCEEDED")
        temporary = f".pending-{store_id}-{name}"
        _write(descriptor, temporary, data)
        _publish(descriptor, temporary, name)
        return directory / name
    except ReportError:
        raise
    except Exception:
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-guard-map-report", description=__doc__)
    parser.add_argument(
        "--endpoint",
        required=True,
        help="The Agent Map service's /v1/query URL (HTTPS, or HTTP to a literal loopback address).",
    )
    parser.add_argument(
        "--token-env",
        required=True,
        help="Environment variable that holds the agm_v1 reader token.",
    )
    parser.add_argument(
        "--source-id", required=True, help="The 64-hex source ID the collector prints."
    )
    parser.add_argument(
        "--directory",
        type=Path,
        required=True,
        help="Private (mode 0700) directory used only for these reports.",
    )
    add_verbose_argument(parser)
    args = parser.parse_args(argv)
    token = os.environ.get(args.token_env, "")
    try:
        path = write_report(args.endpoint, token, args.source_id, args.directory)
        print(json.dumps({"status": "complete", "report": path.name}))
        return 0
    except Exception as error:
        # The same shape and exit statuses as the other commands: 2 for a known code.
        code = failure_code(error, "REFERENCE_REPORT_FAILED")
        report_failure(code, error=error)
        log_exception(error, verbose=args.verbose, secrets=[token])
        return 1 if code == "REFERENCE_REPORT_FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
