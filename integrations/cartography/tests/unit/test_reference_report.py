"""Bounded reference transport and private, explicitly owned minimized reports."""

import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from agent_guard_cartography import reference_report as report
from agent_guard_cartography.reference_report import ReportError, query_reference, write_report

TOKEN = "agm_v1." + "a" * 43
SOURCE = "a" * 64


def difference():
    return {
        "operation": "get_changes",
        "observedAt": "2026-10-30T00:00:00Z",
        "data": {
            "sourceId": SOURCE,
            "from": {"projectionId": "b" * 64},
            "to": {"projectionId": "c" * 64},
            "coverageGap": False,
            "changes": {
                "added": [
                    {"label": "GuardTask", "entityId": "private-entity", "name": "private-name"}
                ],
                "changed": [],
                "removed": [],
            },
            "private": "private-body",
        },
    }


def wire(body, status="200 OK", headers=None):
    headers = headers or [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    return (
        f"HTTP/1.1 {status}\r\n" + "".join(f"{key}: {value}\r\n" for key, value in headers) + "\r\n"
    ).encode() + body


@contextmanager
def endpoint(reply):
    received = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            try:
                line = self.rfile.readline()
                if not line:
                    return
                headers = {}
                while field := self.rfile.readline():
                    if field == b"\r\n":
                        break
                    name, value = field.decode().split(":", 1)
                    headers[name.lower()] = value.strip()
                body = self.rfile.read(int(headers.get("content-length", "0")))
                received.append((line, headers, body))
                if callable(reply):
                    reply(self.request)
                else:
                    self.request.sendall(reply)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with Server(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}/v1/query", received
        finally:
            server.shutdown()
            thread.join(timeout=1)


def test_query_fixed_post_no_proxy_and_minimized_private_report(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://private-proxy.invalid:1")
    with endpoint(wire(json.dumps(difference()).encode())) as (url, received):
        path = write_report(url, TOKEN, SOURCE, tmp_path / "reports")
    assert len(received) == 1
    line, headers, body = received[0]
    assert line == b"POST /v1/query HTTP/1.1\r\n"
    assert headers["authorization"] == "Bearer " + TOKEN
    assert headers["accept-encoding"] == "identity"
    assert json.loads(body) == {"operation": "get_changes", "args": {"sourceId": SOURCE}}
    value = json.loads(path.read_text())
    assert value["counts"] == {"added": {"GuardTask": 1}, "removed": {}, "changed": {}}
    for text in [TOKEN, "private-name", "private-entity", "private-body", "Authorization"]:
        assert text not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert value["storeId"] == json.loads((path.parent / ".store.json").read_text())["storeId"]


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/v1/query",
        "http://example.com/v1/query",
        "https://user:secret@example.com/v1/query",
        "https://example.com/v1/query?secret=x",
        "https://example.com/v1/query#x",
        "https://example.com:0/v1/query",
        "https://example.com/%76%31/query",
        "https://example.com/v1/query\n",
        "https://bad_host/v1/query",
        "https://example..com/v1/query",
    ],
)
def test_bad_endpoint_fails_before_transport(url, monkeypatch):
    monkeypatch.setattr(report, "_fetch_reference", lambda *args: pytest.fail("opened transport"))
    with pytest.raises(ReportError, match="^REFERENCE_QUERY_FAILED$"):
        query_reference(url, TOKEN, "get_changes", {})


@pytest.mark.parametrize(
    "operation,token,args",
    [
        ("execute", TOKEN, {}),
        ("get_changes", "task-secret", {}),
        ("get_changes", TOKEN, []),
        ("get_changes", TOKEN, {"large": "x" * 32768}),
        ("get_changes", TOKEN, {"invalid": float("nan")}),
    ],
)
def test_bad_request_never_dispatches(operation, token, args, monkeypatch):
    monkeypatch.setattr(report, "_fetch_reference", lambda *args: pytest.fail("opened transport"))
    with pytest.raises(ReportError, match="^REFERENCE_QUERY_FAILED$"):
        query_reference("http://127.0.0.1/v1/query", token, operation, args)


@pytest.mark.parametrize(
    "reply",
    [
        wire(b'{"operation":"get_changes","operation":"get_changes","data":{}}'),
        wire(b'{"operation":"get_changes","data":{"x":1,"\\u0078":2}}'),
        wire(b"\xff"),
        wire(b"[]"),
        wire(b'{"operation":"wrong","data":{}}'),
        wire(b"{}", status="302 Redirect", headers=[("Location", "https://private.invalid/")]),
        wire(
            b"{}",
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Content-Length", "2"),
            ],
        ),
        wire(
            b"{}",
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
            ],
        ),
        wire(
            b"{}",
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Transfer-Encoding", "chunked"),
            ],
        ),
        wire(
            b"{}",
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Content-Encoding", "gzip"),
            ],
        ),
        wire(b"{}", headers=[("Content-Type", "application/json"), ("Content-Length", "2097153")]),
        wire(b"{}", headers=[("Content-Type", "application/json"), ("Content-Length", "100")]),
    ],
)
def test_ambiguous_or_incomplete_responses_are_rejected(reply):
    with endpoint(reply) as (url, received):
        with pytest.raises(ReportError, match="^REFERENCE_QUERY_FAILED$"):
            query_reference(url, TOKEN, "get_changes", {})
        assert len(received) == 1


def test_stalled_dns_is_bounded_and_cannot_connect_or_send_later(monkeypatch):
    monkeypatch.setattr(report, "_TIMEOUT", 0.04)
    monkeypatch.setattr(report, "_WORKERS", threading.BoundedSemaphore(4))
    release = threading.Event()
    finished = threading.Event()
    connections = []

    def resolve(*args, **kwargs):
        release.wait(2)
        finished.set()
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 1))]

    monkeypatch.setattr(report.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(report.socket, "socket", lambda *args: connections.append(args))
    started = time.monotonic()
    try:
        for _ in range(4):
            with pytest.raises(ReportError, match="^REFERENCE_QUERY_FAILED$"):
                query_reference("https://host.invalid/v1/query", TOKEN, "get_changes", {})
        with pytest.raises(ReportError, match="^REFERENCE_QUERY_BUSY$"):
            query_reference("https://host.invalid/v1/query", TOKEN, "get_changes", {})
        assert time.monotonic() - started < 0.8
    finally:
        release.set()
    assert finished.wait(1)
    deadline = time.monotonic() + 1
    while (
        any(thread.name == "agent-map-reference" for thread in threading.enumerate())
        and time.monotonic() < deadline
    ):
        time.sleep(0.005)
    assert connections == []
    assert not any(thread.name == "agent-map-reference" for thread in threading.enumerate())


def test_slow_response_stops_at_absolute_deadline_and_closes_socket(monkeypatch):
    monkeypatch.setattr(report, "_TIMEOUT", 0.06)
    closed = threading.Event()

    def slow(sock):
        sock.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"
        )
        if sock.recv(1) == b"":
            closed.set()

    with endpoint(slow) as (url, _received):
        started = time.monotonic()
        with pytest.raises(ReportError, match="^REFERENCE_QUERY_FAILED$"):
            query_reference(url, TOKEN, "get_changes", {})
        assert time.monotonic() - started < 0.6
        assert closed.wait(1)


def test_stalled_tls_handshake_is_cancelled_before_credentials_are_sent(monkeypatch):
    monkeypatch.setattr(report, "_TIMEOUT", 0.06)
    closed = threading.Event()
    received = bytearray()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            try:
                while data := self.request.recv(4096):
                    received.extend(data)
                closed.set()
            except OSError:
                pass

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            url = f"https://127.0.0.1:{server.server_address[1]}/v1/query"
            started = time.monotonic()
            with pytest.raises(ReportError, match="^REFERENCE_QUERY_FAILED$"):
                query_reference(url, TOKEN, "get_changes", {})
            assert time.monotonic() - started < 0.6
            assert closed.wait(1)
            assert TOKEN.encode() not in received
        finally:
            server.shutdown()
            thread.join(timeout=1)


@pytest.fixture
def fake_query(monkeypatch):
    monkeypatch.setattr(report, "query_reference", lambda *_args: difference())


def old_report(path):
    value = json.loads(path.read_text())
    value["recordedAt"] = (datetime.now(UTC) - timedelta(days=31)).isoformat()
    stamp = int(datetime.fromisoformat(value["recordedAt"]).timestamp() * 1000)
    destination = path.with_name(f"report-{stamp:013d}-{value['reportId']}.json")
    path.rename(destination)
    destination.write_text(json.dumps(value))
    return destination


def test_prunes_only_valid_owned_reports_and_preserves_lookalike_foreign_files(
    tmp_path, fake_query
):
    directory = tmp_path / "reports"
    first = write_report("endpoint", TOKEN, SOURCE, directory)
    old = old_report(first)
    current = write_report("endpoint", TOKEN, SOURCE, directory)
    assert not old.exists()
    foreign = directory / ("report-0000000000000-" + "f" * 32 + ".json")
    foreign.write_text('{"foreign":"keep-me"}')
    foreign.chmod(0o600)
    with pytest.raises(ReportError, match="REFERENCE_REPORT_DIRECTORY_UNSAFE"):
        write_report("endpoint", TOKEN, SOURCE, directory)
    assert foreign.read_text() == '{"foreign":"keep-me"}'
    assert current.exists()


def test_foreign_store_identity_and_extra_fields_are_not_deleted(tmp_path, fake_query):
    for change in [{"storeId": "f" * 32}, {"private": "do-not-delete"}]:
        directory = tmp_path / str(len(list(tmp_path.iterdir())))
        path = old_report(write_report("endpoint", TOKEN, SOURCE, directory))
        value = json.loads(path.read_text())
        value.update(change)
        path.write_text(json.dumps(value))
        with pytest.raises(ReportError, match="REFERENCE_REPORT_DIRECTORY_UNSAFE"):
            write_report("endpoint", TOKEN, SOURCE, directory)
        assert path.exists()


def test_complete_interrupted_report_recovers_atomically_and_partial_bytes_are_preserved(
    tmp_path, fake_query, monkeypatch
):
    directory = tmp_path / "reports"
    write_report("endpoint", TOKEN, SOURCE, directory)
    publish = report._publish
    monkeypatch.setattr(
        report, "_publish", lambda *_args: (_ for _ in ()).throw(OSError("interrupted"))
    )
    with pytest.raises(ReportError):
        write_report("endpoint", TOKEN, SOURCE, directory)
    pending = list(directory.glob(".pending-*.json"))
    assert len(pending) == 1
    marker = json.loads((directory / ".store.json").read_text())
    partial = directory / (
        f".pending-{marker['storeId']}-report-0000000000000-" + "d" * 32 + ".json"
    )
    partial.write_bytes(b'{"unfinished":')
    partial.chmod(0o600)
    monkeypatch.setattr(report, "_publish", publish)
    write_report("endpoint", TOKEN, SOURCE, directory)
    assert not pending[0].exists()
    assert len(list(directory.glob("report-*.json"))) == 3
    assert partial.read_bytes() == b'{"unfinished":'


def test_no_overwrite_and_hardlink_public_or_symlink_files_fail_closed(tmp_path, fake_query):
    directory = tmp_path / "reports"
    path = write_report("endpoint", TOKEN, SOURCE, directory)
    original = path.read_bytes()
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            report._write(descriptor, path.name, b"overwrite")
    finally:
        os.close(descriptor)
    assert path.read_bytes() == original
    path.chmod(0o644)
    with pytest.raises(ReportError):
        write_report("endpoint", TOKEN, SOURCE, directory)
    path.chmod(0o600)
    os.link(path, directory / "hardlink")
    with pytest.raises(ReportError):
        write_report("endpoint", TOKEN, SOURCE, directory)
    assert path.read_bytes() == original


def test_recovery_finishes_an_interrupted_link_without_overwriting(tmp_path, fake_query):
    directory = tmp_path / "reports"
    path = write_report("endpoint", TOKEN, SOURCE, directory)
    value = json.loads(path.read_text())
    temporary = directory / f".pending-{value['storeId']}-{path.name}"
    os.link(path, temporary)
    assert path.stat().st_nlink == 2
    write_report("endpoint", TOKEN, SOURCE, directory)
    assert not temporary.exists()
    assert path.stat().st_nlink == 1
    assert json.loads(path.read_text()) == value


def test_report_store_never_follows_directory_or_report_symlinks(tmp_path, fake_query):
    directory = tmp_path / "reports"
    path = write_report("endpoint", TOKEN, SOURCE, directory)
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ReportError, match="REFERENCE_REPORT_DIRECTORY_UNSAFE"):
        write_report("endpoint", TOKEN, SOURCE, alias)
    original = path.read_bytes()
    path.unlink()
    target = tmp_path / "foreign"
    target.write_bytes(original)
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(ReportError, match="REFERENCE_REPORT_DIRECTORY_UNSAFE"):
        write_report("endpoint", TOKEN, SOURCE, directory)
    assert target.read_bytes() == original


def test_report_read_rejects_fifo_replacement_without_blocking(tmp_path):
    # A subprocess deadline makes regression of this boundary a bounded failure.
    probe = """
import os
import sys
from pathlib import Path
from agent_guard_cartography import reference_report as report

path = Path(sys.argv[1]) / "record.json"
path.write_text("{}")
path.chmod(0o600)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
original = report._metadata
def replaced(*args, **kwargs):
    checked = original(*args, **kwargs)
    path.unlink()
    os.mkfifo(path, mode=0o600)
    return checked
report._metadata = replaced
try:
    try:
        report._read(directory, path.name)
    except report.ReportError as error:
        assert str(error) == "REFERENCE_REPORT_DIRECTORY_UNSAFE"
    else:
        raise AssertionError("replacement FIFO accepted")
finally:
    os.close(directory)
"""
    result = subprocess.run(
        [sys.executable, "-c", probe, str(tmp_path)], capture_output=True, text=True, timeout=3
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("change", ["permissions", "hardlink"])
def test_report_read_rechecks_same_inode_safety_and_closes_descriptor(
    tmp_path, monkeypatch, change
):
    path = tmp_path / "record.json"
    path.write_text("{}")
    path.chmod(0o600)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    metadata, original_open, opened = report._metadata, os.open, []

    def changed(*args, **kwargs):
        checked = metadata(*args, **kwargs)
        if change == "permissions":
            path.chmod(0o644)
        else:
            os.link(path, tmp_path / "foreign-link")
        return checked

    def tracked_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(report, "_metadata", changed)
    monkeypatch.setattr(report.os, "open", tracked_open)
    try:
        with pytest.raises(ReportError, match="REFERENCE_REPORT_DIRECTORY_UNSAFE"):
            report._read(directory, path.name)
        assert len(opened) == 1
        with pytest.raises(OSError):
            os.fstat(opened[0])
    finally:
        os.close(directory)


def test_invalid_source_never_dispatches_or_creates_a_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(report, "query_reference", lambda *_args: pytest.fail("queried"))
    with pytest.raises(ReportError, match="REFERENCE_REPORT_CONFIG_INVALID"):
        write_report("endpoint", TOKEN, "private-not-source-id", tmp_path / "reports")
    assert not (tmp_path / "reports").exists()


@pytest.mark.parametrize("days", [0, 31, True, 1.5])
def test_retention_bound_validation_before_query(days, monkeypatch, tmp_path):
    monkeypatch.setattr(report, "query_reference", lambda *_args: pytest.fail("queried"))
    with pytest.raises(ReportError, match="REFERENCE_REPORT_CONFIG_INVALID"):
        write_report("endpoint", TOKEN, SOURCE, tmp_path / "reports", retention_days=days)


def test_cumulative_file_and_byte_caps_fail_without_overwrite(tmp_path, fake_query, monkeypatch):
    directory = tmp_path / "reports"
    existing = write_report("endpoint", TOKEN, SOURCE, directory)
    monkeypatch.setattr(report, "_MAX_FILES", 2)
    with pytest.raises(ReportError, match="REFERENCE_REPORT_LIMIT_EXCEEDED"):
        write_report("endpoint", TOKEN, SOURCE, directory)
    monkeypatch.setattr(report, "_MAX_FILES", 10000)
    monkeypatch.setattr(report, "_MAX_BYTES", 200)
    with pytest.raises(ReportError, match="REFERENCE_REPORT_LIMIT_EXCEEDED"):
        write_report("endpoint", TOKEN, SOURCE, directory)
    assert existing.exists()
