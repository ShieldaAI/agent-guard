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
from types import MappingProxyType
from typing import Any, NoReturn
from urllib.parse import urlsplit

from agent_guard_cartography import _http
from agent_guard_cartography._ids import PROFILES, SOURCE_FIELDS, is_identifier, source_identity
from agent_guard_cartography._json import loads_strict
from agent_guard_cartography.errors import AgentGuardCartographyError
from agent_guard_cartography.input_files import read_regular_file
from agent_guard_cartography.inventory import (
    MAX_SNAPSHOT_BYTES,
    validate_snapshot,
)
from agent_guard_cartography.shapes import Snapshot

__all__ = [
    "SOURCE_FIELDS",
    "TOKEN",
    "CollectionError",
    "CollectorEnrollment",
    "collect_snapshot",
    "decode_snapshot",
    "load_enrollment",
    "validate_enrollment",
    "validate_source",
]

TOKEN = re.compile(r"agi_v1\.[A-Za-z0-9_-]{43}")
_WORKERS = threading.BoundedSemaphore(4)


class CollectionError(AgentGuardCartographyError, RuntimeError):
    """Stable diagnostics; response bodies, endpoint details and tokens never enter errors."""


def _fail(code: str = "COLLECTOR_CONFIG_INVALID") -> NoReturn:
    raise CollectionError(code)


def _identifier(value: Any) -> str:
    if not is_identifier(value):
        _fail()
    return value


def validate_source(value: Any) -> Mapping[str, str]:
    """The exact five-field source identity as a read-only mapping."""
    source = source_identity(value)
    if source is None:
        _fail()
    return MappingProxyType(source)


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
        object.__setattr__(self, "source", validate_source(dict(self.source)))
        _endpoint(self.endpoint)
        if self.profile not in PROFILES:
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
        validate_source(value["source"]),
        value["profile"],
        _endpoint(value["endpoint"]),
        value["tokenEnv"],
        value.get("timeoutSeconds", 10.0),
        value.get("maxResponseBytes", MAX_SNAPSHOT_BYTES),
    )


def load_enrollment(path: Path | str) -> CollectorEnrollment:
    try:
        contents = read_regular_file(path, 131_073)
        if len(contents) > 131_072:
            _fail()
        return validate_enrollment(loads_strict(contents.decode("utf-8")))
    except CollectionError:
        raise
    except FileNotFoundError:
        raise CollectionError("COLLECTOR_ENROLLMENT_NOT_FOUND") from None
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        raise CollectionError("COLLECTOR_CONFIG_INVALID") from None


def decode_snapshot(contents: bytes) -> Snapshot:
    """Strict JSON decoding shared with protected replay; duplicate members are invalid."""
    if type(contents) is not bytes or len(contents) > MAX_SNAPSHOT_BYTES:
        _fail("COLLECTOR_RESPONSE_TOO_LARGE")
    try:
        return validate_snapshot(loads_strict(contents.decode("utf-8")))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise CollectionError("COLLECTOR_SNAPSHOT_INVALID") from None


def _fetch(
    enrollment: CollectorEnrollment,
    token: str,
    deadline: float,
    cancelled: threading.Event,
    live_socket: list[socket.socket],
) -> bytes:
    parsed = urlsplit(enrollment.endpoint)
    connection: http.client.HTTPConnection
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
    connection.response_class = _http.deadline_response_class(deadline)
    try:
        # DNS may not respect socket timeouts. The outer bounded worker returns
        # on deadline; a late resolver can never send credentials afterwards.
        connection.connect()
        live_socket.append(connection.sock)
        connection.sock.settimeout(_http.remaining(deadline, cancelled))
        body = json.dumps({"tenantId": enrollment.source["tenantId"]}, separators=(",", ":"))
        return _http.post_json(
            connection,
            parsed.path,
            token,
            body.encode(),
            deadline=deadline,
            cancelled=cancelled,
            maximum=enrollment.max_response_bytes,
            allow_identity_encoding=True,
        )
    except _http.ResponseRejected:
        _fail("COLLECTOR_HTTP_REJECTED")
    except _http.ResponseInvalid:
        _fail("COLLECTOR_RESPONSE_INVALID")
    except _http.ResponseTooLarge:
        _fail("COLLECTOR_RESPONSE_TOO_LARGE")
    finally:
        connection.close()


def collect_snapshot(enrollment: CollectorEnrollment, token: str) -> Snapshot:
    """Collect one complete scope. Bounded worker slots also cap stuck DNS lookups."""
    if not isinstance(enrollment, CollectorEnrollment):
        _fail()
    if type(token) is not str or TOKEN.fullmatch(token) is None:
        _fail("COLLECTOR_CREDENTIAL_INVALID")
    deadline = time.monotonic() + enrollment.timeout_seconds

    def work(cancelled: threading.Event, sockets: list[socket.socket]) -> Snapshot:
        value = decode_snapshot(_fetch(enrollment, token, deadline, cancelled, sockets))
        if value["source"] != dict(enrollment.source) or value["profile"] != enrollment.profile:
            _fail("COLLECTOR_SCOPE_MISMATCH")
        return value

    try:
        return _http.run_bounded(
            work, deadline=deadline, slots=_WORKERS, thread_name="agent-guard-observer"
        )
    except _http.WorkerBusy:
        raise CollectionError("COLLECTOR_BUSY") from None
    except CollectionError as error:
        raise CollectionError(error.code) from None
    except TimeoutError:
        raise CollectionError("COLLECTOR_TIMEOUT") from None
    except Exception:
        raise CollectionError("COLLECTOR_UNAVAILABLE") from None
