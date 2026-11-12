"""One deadline-bounded JSON POST exchange, shared by the observer and report clients.

The caller builds and connects its own ``http.client`` connection; this module
bounds the response headers and body, and runs the whole request in a worker slot
so that an uncancellable DNS lookup cannot outlive the caller's deadline.
"""

from __future__ import annotations

import http.client
import re
import socket
import threading
import time
from collections.abc import Callable
from queue import Empty, Queue
from typing import Any, cast

MAX_HEADER_BYTES = 8192
_LENGTH = re.compile(r"[0-9]{1,8}")
_JSON_TYPE = re.compile(r"application/json(?:\s*;\s*charset=utf-8)?", re.I)


class ResponseRejected(Exception):
    """The server answered with a status other than 200."""


class ResponseInvalid(Exception):
    """The response is not one complete, length-delimited, uncompressed JSON body."""


class ResponseTooLarge(Exception):
    """The declared body is longer than the caller accepts."""


class WorkerBusy(Exception):
    """Every worker slot is occupied, possibly by a lookup that cannot be cancelled."""


class WorkerUnavailable(Exception):
    """The worker thread could not be started."""


def remaining(deadline: float, cancelled: threading.Event) -> float:
    """Seconds left before ``deadline``; ``TimeoutError`` once cancelled or elapsed."""
    left = deadline - time.monotonic()
    if cancelled.is_set() or left <= 0:
        raise TimeoutError()
    return left


class _DeadlineReader:
    """A response stream whose every read is bounded by the whole-request deadline."""

    def __init__(self, stream: Any, sock: socket.socket, deadline: float) -> None:
        self.stream, self.sock, self.deadline = stream, sock, deadline
        self.header_bytes = 0
        self.headers = True

    def _timeout(self) -> None:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        self.sock.settimeout(left)

    def readline(self, size: int = -1) -> bytes:
        self._timeout()
        if self.headers:
            limit = MAX_HEADER_BYTES + 1 - self.header_bytes
            size = min(limit, size) if size >= 0 else limit
            if size <= 0:
                raise ResponseInvalid()
        result = self.stream.readline(size)
        if self.headers:
            self.header_bytes += len(result)
            if self.header_bytes > MAX_HEADER_BYTES:
                raise ResponseInvalid()
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


def deadline_response_class(deadline: float) -> type[http.client.HTTPResponse]:
    """An ``HTTPResponse`` type that caps header bytes and applies ``deadline`` to reads."""

    class BoundedResponse(http.client.HTTPResponse):
        def __init__(self, sock: socket.socket, *args: Any, **kwargs: Any) -> None:
            super().__init__(sock, *args, **kwargs)
            self.fp = _DeadlineReader(self.fp, sock, deadline)

        def begin(self) -> None:
            super().begin()
            self.fp.headers = False

    return BoundedResponse


def post_json(
    connection: http.client.HTTPConnection,
    path: str,
    token: str,
    body: bytes,
    *,
    deadline: float,
    cancelled: threading.Event,
    maximum: int,
    allow_identity_encoding: bool = False,
) -> bytes:
    """Send one bearer-authenticated JSON POST on a connected socket; return the body.

    Requires status 200, exactly one ``Content-Length`` and JSON ``Content-Type``,
    and no transfer or content coding (``identity`` only when allowed). Redirects
    are never followed. The connection stays open; the caller closes it.
    """
    connection.request(
        "POST",
        path,
        body=body,
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
        raise ResponseRejected()
    headers = response.headers
    lengths = headers.get_all("Content-Length", [])
    types = headers.get_all("Content-Type", [])
    encodings = headers.get_all("Content-Encoding")
    if (
        len(lengths) != 1
        or _LENGTH.fullmatch(lengths[0]) is None
        or len(types) != 1
        or _JSON_TYPE.fullmatch(types[0]) is None
        or headers.get_all("Transfer-Encoding")
        or (encodings is not None and not (allow_identity_encoding and encodings == ["identity"]))
    ):
        raise ResponseInvalid()
    length = int(lengths[0])
    if length > maximum:
        raise ResponseTooLarge()
    chunks = []
    count = 0
    while count < length:
        remaining(deadline, cancelled)
        chunk = response.read1(min(65_536, length - count))
        if not chunk:
            raise ResponseInvalid()
        chunks.append(chunk)
        count += len(chunk)
    if time.monotonic() >= deadline:
        raise TimeoutError()
    return b"".join(chunks)


def run_bounded[T](
    work: Callable[[threading.Event, list[socket.socket]], T],
    *,
    deadline: float,
    slots: threading.BoundedSemaphore,
    thread_name: str,
) -> T:
    """Run ``work(cancelled, sockets)`` in a daemon worker and wait until ``deadline``.

    ``work`` appends every socket it opens to ``sockets`` and checks ``cancelled``
    before sending credentials. On return, timeout or failure the worker is cancelled
    and its sockets are shut down and closed, so a late DNS answer cannot send anything.
    Raises ``WorkerBusy``, ``WorkerUnavailable``, ``TimeoutError`` or the worker's error.
    """
    if not slots.acquire(blocking=False):
        raise WorkerBusy()
    cancelled = threading.Event()
    sockets: list[socket.socket] = []
    result: Queue[tuple[T | None, BaseException | None]] = Queue(maxsize=1)

    def worker() -> None:
        try:
            result.put((work(cancelled, sockets), None))
        except Exception as error:
            result.put((None, error))
        finally:
            slots.release()

    thread = threading.Thread(target=worker, name=thread_name, daemon=True)
    try:
        thread.start()
    except Exception:
        slots.release()
        raise WorkerUnavailable() from None
    try:
        try:
            value, error = result.get(timeout=max(0, deadline - time.monotonic()))
        except Empty:
            raise TimeoutError() from None
        if time.monotonic() >= deadline:
            raise TimeoutError()
        if error is not None:
            raise error
        return cast(T, value)
    finally:
        cancelled.set()
        for current in tuple(sockets):
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            current.close()
