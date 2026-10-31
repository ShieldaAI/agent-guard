"""Bounded, credential-scoped observer collection; no provider discovery or graph writes."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from agent_guard_cartography.input_files import read_regular_file
from agent_guard_cartography.inventory import (
    MAX_SNAPSHOT_BYTES,
    validate_snapshot,
)

SOURCE_FIELDS = frozenset(
    ("companyId", "sourceId", "enrollmentGeneration", "inventoryInstanceId", "tenantId")
)
TOKEN = re.compile(r"agi_v1\.[A-Za-z0-9_-]{43}")
_WORKERS = threading.BoundedSemaphore(4)


class CollectionError(RuntimeError):
    """Stable diagnostics; response bodies, endpoint details and tokens never enter errors."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str = "COLLECTOR_CONFIG_INVALID") -> None:
    raise CollectionError(code)


def _identifier(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > 4096
        or not any(character != "\ufeff" and not character.isspace() for character in value)
        or "\x00" in value
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        _fail()
    return value


def _source(value: Any) -> Mapping[str, str]:
    if type(value) is not dict or value.keys() != SOURCE_FIELDS:
        _fail()
    return MappingProxyType({key: _identifier(value[key]) for key in sorted(SOURCE_FIELDS)})


def _endpoint(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > 4096
        or not value.isascii()
        or any(ord(character) <= 32 or ord(character) >= 127 for character in value)
        or "\\" in value
        or "%" in value
    ):
        _fail()
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/inventory/snapshot"
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)
        ):
            _fail()
        hostname = parsed.hostname
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname):
                _fail()
            if any(
                not label or label.startswith("-") or label.endswith("-") or len(label) > 63
                for label in hostname.split(".")
            ):
                _fail()
        # A literal loopback address avoids DNS changes on the cleartext path.
        if parsed.scheme == "http" and (address is None or not address.is_loopback):
            _fail()
    except ValueError:
        raise CollectionError("COLLECTOR_CONFIG_INVALID") from None
    return value


@dataclass(frozen=True)
class CollectorEnrollment:
    source: Mapping[str, str]
    profile: str
    endpoint: str
    token_env: str
    timeout_seconds: float = 10.0
    max_response_bytes: int = MAX_SNAPSHOT_BYTES

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _source(dict(self.source)))
        _endpoint(self.endpoint)
        if self.profile not in ("core", "host", "host-mcp"):
            _fail()
        if type(self.token_env) is not str or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]{0,127}", self.token_env
        ):
            _fail()
        if type(self.timeout_seconds) not in (float, int) or not 0.05 <= self.timeout_seconds <= 60:
            _fail()
        if (
            type(self.max_response_bytes) is not int
            or not 128 <= self.max_response_bytes <= MAX_SNAPSHOT_BYTES
        ):
            _fail()


def validate_enrollment(value: Any) -> CollectorEnrollment:
    """Detach trusted configuration; credentials are named, never embedded."""
    if (
        type(value) is not dict
        or not {"source", "profile", "endpoint", "tokenEnv"}.issubset(value)
        or set(value)
        - {"source", "profile", "endpoint", "tokenEnv", "timeoutSeconds", "maxResponseBytes"}
    ):
        _fail()
    return CollectorEnrollment(
        _source(value["source"]),
        value["profile"],
        _endpoint(value["endpoint"]),
        value["tokenEnv"],
        value.get("timeoutSeconds", 10.0),
        value.get("maxResponseBytes", MAX_SNAPSHOT_BYTES),
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError()


def load_enrollment(path: Path | str) -> CollectorEnrollment:
    try:
        contents = read_regular_file(path, 131_073)
        if len(contents) > 131_072:
            _fail()
        value = json.loads(
            contents.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        return validate_enrollment(value)
    except CollectionError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        raise CollectionError("COLLECTOR_CONFIG_INVALID") from None


def decode_snapshot(contents: bytes) -> dict:
    """Strict JSON decoding shared with protected replay; duplicate members are invalid."""
    if type(contents) is not bytes or len(contents) > MAX_SNAPSHOT_BYTES:
        _fail("COLLECTOR_RESPONSE_TOO_LARGE")
    try:
        value = json.loads(
            contents.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        return validate_snapshot(value)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise CollectionError("COLLECTOR_SNAPSHOT_INVALID") from None


class _DeadlineReader:
    def __init__(self, stream, sock: socket.socket, deadline: float):
        self.stream, self.sock, self.deadline = stream, sock, deadline
        self.header_bytes = 0
        self.headers = True

    def _timeout(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.sock.settimeout(remaining)

    def readline(self, size: int = -1) -> bytes:
        self._timeout()
        if self.headers:
            size = min(8193 - self.header_bytes, size) if size >= 0 else 8193 - self.header_bytes
            if size <= 0:
                _fail("COLLECTOR_RESPONSE_INVALID")
        result = self.stream.readline(size)
        if self.headers:
            self.header_bytes += len(result)
            if self.header_bytes > 8192:
                _fail("COLLECTOR_RESPONSE_INVALID")
        return result

    def read(self, size: int = -1) -> bytes:
        self._timeout()
        return self.stream.read(size)

    def read1(self, size: int = -1) -> bytes:
        self._timeout()
        return self.stream.read1(size)

    def close(self) -> None:
        self.stream.close()

    def flush(self) -> None:
        self.stream.flush()


def _response_type(deadline: float):
    class BoundedResponse(http.client.HTTPResponse):
        def __init__(self, sock, *args, **kwargs):
            super().__init__(sock, *args, **kwargs)
            self.fp = _DeadlineReader(self.fp, sock, deadline)

        def begin(self) -> None:
            super().begin()
            self.fp.headers = False

    return BoundedResponse


def _fetch(
    enrollment: CollectorEnrollment,
    token: str,
    deadline: float,
    cancelled: threading.Event,
    live_socket: list[socket.socket],
) -> bytes:
    parsed = urlsplit(enrollment.endpoint)
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port,
            timeout=enrollment.timeout_seconds,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port, timeout=enrollment.timeout_seconds
        )
    connection.response_class = _response_type(deadline)
    try:
        # DNS may not respect socket timeouts. The outer bounded worker returns
        # on deadline; a late resolver can never send credentials afterwards.
        connection.connect()
        live_socket.append(connection.sock)
        if cancelled.is_set() or time.monotonic() >= deadline:
            raise TimeoutError()
        connection.sock.settimeout(deadline - time.monotonic())
        body = json.dumps({"tenantId": enrollment.source["tenantId"]}, separators=(",", ":"))
        connection.request(
            "POST",
            parsed.path,
            body=body.encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            _fail("COLLECTOR_HTTP_REJECTED")
        headers = response.headers
        lengths = headers.get_all("Content-Length", [])
        types = headers.get_all("Content-Type", [])
        if (
            len(lengths) != 1
            or re.fullmatch(r"[0-9]{1,8}", lengths[0]) is None
            or len(types) != 1
            or re.fullmatch(r"application/json(?:\s*;\s*charset=utf-8)?", types[0], re.I) is None
            or headers.get_all("Transfer-Encoding")
            or headers.get_all("Content-Encoding") not in (None, ["identity"])
        ):
            _fail("COLLECTOR_RESPONSE_INVALID")
        length = int(lengths[0])
        if length > enrollment.max_response_bytes:
            _fail("COLLECTOR_RESPONSE_TOO_LARGE")
        chunks = []
        count = 0
        while count < length:
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise TimeoutError()
            chunk = response.read1(min(65_536, length - count))
            if not chunk:
                _fail("COLLECTOR_RESPONSE_INVALID")
            chunks.append(chunk)
            count += len(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError()
        return b"".join(chunks)
    finally:
        connection.close()


def collect_snapshot(enrollment: CollectorEnrollment, token: str) -> dict:
    """Collect one complete scope. Bounded worker slots also cap stuck DNS lookups."""
    if not isinstance(enrollment, CollectorEnrollment):
        _fail()
    if type(token) is not str or TOKEN.fullmatch(token) is None:
        _fail("COLLECTOR_CREDENTIAL_INVALID")
    if not _WORKERS.acquire(blocking=False):
        _fail("COLLECTOR_BUSY")
    deadline = time.monotonic() + enrollment.timeout_seconds
    cancelled = threading.Event()
    live_socket: list[socket.socket] = []
    result: Queue = Queue(maxsize=1)

    def worker() -> None:
        try:
            contents = _fetch(enrollment, token, deadline, cancelled, live_socket)
            value = decode_snapshot(contents)
            if value["source"] != dict(enrollment.source) or value["profile"] != enrollment.profile:
                _fail("COLLECTOR_SCOPE_MISMATCH")
            result.put((value, None))
        except CollectionError as error:
            result.put((None, error.code))
        except TimeoutError:
            result.put((None, "COLLECTOR_TIMEOUT"))
        except Exception:
            result.put((None, "COLLECTOR_UNAVAILABLE"))
        finally:
            _WORKERS.release()

    thread = threading.Thread(target=worker, name="agent-guard-observer", daemon=True)
    try:
        thread.start()
    except Exception:
        _WORKERS.release()
        raise CollectionError("COLLECTOR_UNAVAILABLE") from None
    try:
        value, code = result.get(timeout=max(0, deadline - time.monotonic()))
    except Empty:
        cancelled.set()
        if live_socket:
            try:
                live_socket[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        raise CollectionError("COLLECTOR_TIMEOUT") from None
    if time.monotonic() >= deadline:
        cancelled.set()
        _fail("COLLECTOR_TIMEOUT")
    if code is not None:
        raise CollectionError(code)
    return value
