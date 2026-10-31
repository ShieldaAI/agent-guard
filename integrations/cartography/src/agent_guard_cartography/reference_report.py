"""Minimized, private, bounded operational differences; never an execution audit log."""

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
import stat
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import urlsplit

from agent_guard_cartography.collector import _pairs, _response_type

LABELS = frozenset(
    [
        "GuardAgent",
        "GuardDeployment",
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
OPERATIONS = frozenset(
    [
        "list_agents",
        "get_agent_access",
        "explain_access",
        "find_agents_with_access",
        "get_changes",
        "get_inventory_health",
    ]
)
MAX_RESPONSE = 2 * 1024 * 1024
NAME = re.compile(r"report-(\d{13})-([a-f0-9]{32})\.json")
_TIMEOUT = 10.0
_WORKERS = threading.BoundedSemaphore(4)
_STORE = ".store.json"
_MAX_FILES = 10_000
_MAX_BYTES = 16 * 1024 * 1024
_MAX_FILE = 16_384


class ReportError(RuntimeError):
    pass


def _remaining(deadline, cancelled):
    remaining = deadline - time.monotonic()
    if cancelled.is_set() or remaining <= 0:
        raise TimeoutError()
    return remaining


def _connect(address, timeout, source_address, *, deadline, cancelled, sockets):
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


def _fetch_reference(parsed, token, operation, body, deadline, cancelled, sockets):
    class DeadlineTLSConnection(http.client.HTTPSConnection):
        def connect(self):
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
    connection.response_class = _response_type(deadline)
    try:
        connection.connect()
        sockets.append(connection.sock)  # Include the TLS wrapper for cancellation.
        connection.sock.settimeout(_remaining(deadline, cancelled))
        connection.request(
            "POST",
            parsed.path,
            body,
            {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        lengths = response.headers.get_all("content-length", [])
        types = response.headers.get_all("content-type", [])
        if (
            response.status != 200
            or len(lengths) != 1
            or re.fullmatch(r"[0-9]{1,8}", lengths[0]) is None
            or not 0 < int(lengths[0]) <= MAX_RESPONSE
            or len(types) != 1
            or not re.fullmatch(r"application/json(?:\s*;\s*charset=utf-8)?", types[0], re.I)
            or response.headers.get_all("content-encoding")
            or response.headers.get_all("transfer-encoding")
        ):
            raise ValueError()
        chunks, size = [], 0
        while size < int(lengths[0]):
            _remaining(deadline, cancelled)
            chunk = response.read1(min(65536, int(lengths[0]) - size))
            if not chunk:
                raise ValueError()
            chunks.append(chunk)
            size += len(chunk)
        _remaining(deadline, cancelled)
        value = json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
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


def query_reference(endpoint: str, token: str, operation: str, args: dict) -> dict:
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
    if not _WORKERS.acquire(blocking=False):
        raise ReportError("REFERENCE_QUERY_BUSY")
    deadline, cancelled, sockets, result = (
        time.monotonic() + _TIMEOUT,
        threading.Event(),
        [],
        Queue(maxsize=1),
    )

    def worker():
        try:
            result.put(
                (
                    _fetch_reference(parsed, token, operation, body, deadline, cancelled, sockets),
                    True,
                )
            )
        except Exception:
            result.put((None, False))
        finally:
            _WORKERS.release()

    thread = threading.Thread(target=worker, name="agent-map-reference", daemon=True)
    try:
        thread.start()
    except Exception:
        _WORKERS.release()
        raise ReportError("REFERENCE_QUERY_FAILED") from None
    try:
        value, ok = result.get(timeout=max(0, deadline - time.monotonic()))
        if not ok or time.monotonic() >= deadline:
            raise ReportError("REFERENCE_QUERY_FAILED")
        return value
    except Empty:
        raise ReportError("REFERENCE_QUERY_FAILED") from None
    finally:
        cancelled.set()
        for current in tuple(sockets):
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            current.close()


def minimize_changes(response: dict, source_id: str) -> dict:
    try:
        data = response["data"]
        if (
            response["operation"] != "get_changes"
            or data["sourceId"] != source_id
            or not re.fullmatch(r"[a-f0-9]{64}", source_id)
            or type(data["coverageGap"]) is not bool
        ):
            raise ValueError()

        def projection(receipt):
            if receipt is None:
                return None
            value = receipt["projectionId"]
            if not re.fullmatch(r"[a-f0-9]{64}", value):
                raise ValueError()
            return value

        counts = {}
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


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _validate_metadata(value, *, links=(1,)):
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink not in links
        or value.st_uid != os.getuid()
        or value.st_mode & 0o077
        or value.st_size > _MAX_FILE
    ):
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
    return value


def _metadata(fd, name, *, links=(1,)):
    return _validate_metadata(os.stat(name, dir_fd=fd, follow_symlinks=False), links=links)


def _read(fd, name, *, links=(1,)):
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
        return json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    finally:
        os.close(descriptor)


def _validate_record(value, store_id, name):
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
        if type(value[field]) is not str or not re.fullmatch(r"[a-f0-9]{64}", value[field]):
            raise ValueError()
    if value["fromProjection"] is not None and (
        type(value["fromProjection"]) is not str
        or not re.fullmatch(r"[a-f0-9]{64}", value["fromProjection"])
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


def _publish(fd, temporary, name):
    try:
        os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    except FileExistsError:
        first, second = _metadata(fd, temporary, links=(2,)), _metadata(fd, name, links=(2,))
        if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE") from None
    os.fsync(fd)
    os.unlink(temporary, dir_fd=fd)
    os.fsync(fd)


def _write(fd, name, data):
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


def _open_directory(directory):
    directory = Path(directory).absolute()
    if ".." in directory.parts or not hasattr(os, "getuid"):
        raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
    descriptor = os.open(directory.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(directory.parts[1:]):
            if index == len(directory.parts) - 2:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ReportError("REFERENCE_REPORT_DIRECTORY_UNSAFE")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return directory, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _prepare_store(fd):
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


def _inspect(fd, store_id):
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
        or re.fullmatch(r"[a-f0-9]{64}", source_id) is None
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-env", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        token = os.environ.get(args.token_env, "")
        path = write_report(args.endpoint, token, args.source_id, args.directory)
        print(json.dumps({"status": "complete", "report": path.name}))
        return 0
    except Exception:
        print("REFERENCE_REPORT_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
