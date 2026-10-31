"""Real loopback HTTP checks for bounded, scoped observer collection."""

import json
import socketserver
import ssl
import threading
import time
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from agent_guard_cartography import collector
from agent_guard_cartography.collector import (
    CollectionError,
    collect_snapshot,
    load_enrollment,
    validate_enrollment,
)

TOKEN = "agi_v1." + "a" * 43
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "alpha-v1.json"


@pytest.fixture
def snapshot():
    return json.loads(FIXTURE.read_text())


def enrollment(snapshot, endpoint, **extra):
    return validate_enrollment(
        {
            "source": snapshot["source"],
            "profile": snapshot["profile"],
            "endpoint": endpoint,
            "tokenEnv": "GUARD_OBSERVER_TOKEN",
            **extra,
        }
    )


def response(body, *, status="200 OK", headers=None):
    fields = (
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        if headers is None
        else headers
    )
    return (
        f"HTTP/1.1 {status}\r\n" + "".join(f"{key}: {value}\r\n" for key, value in fields) + "\r\n"
    ).encode() + body


@contextmanager
def observer(reply):
    received = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(2)
                request = self.rfile.readline()
                if not request:
                    return
                headers = {}
                while line := self.rfile.readline():
                    if line == b"\r\n":
                        break
                    name, value = line.decode().split(":", 1)
                    headers[name.lower()] = value.strip()
                body = self.rfile.read(int(headers.get("content-length", "0")))
                received.append((request, headers, body))
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
        worker = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        worker.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}/v1/inventory/snapshot", received
        finally:
            server.shutdown()
            worker.join(timeout=1)


def test_collects_exact_scoped_post_without_proxy_or_cookie_state(snapshot, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://private-proxy.invalid:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy.invalid:1")
    with observer(response(json.dumps(snapshot).encode())) as (url, requests):
        configured = enrollment(snapshot, url)
        assert collect_snapshot(configured, TOKEN) == snapshot
        assert len(requests) == 1
        request, headers, body = requests[0]
        assert request == b"POST /v1/inventory/snapshot HTTP/1.1\r\n"
        assert headers["authorization"] == f"Bearer {TOKEN}"
        assert headers["accept-encoding"] == "identity"
        assert headers["connection"] == "close"
        assert "cookie" not in headers
        assert json.loads(body) == {"tenantId": snapshot["source"]["tenantId"]}


def test_enrollment_is_detached_and_immutable(snapshot):
    value = enrollment(snapshot, "http://127.0.0.1:8080/v1/inventory/snapshot")
    snapshot["source"]["tenantId"] = "changed"
    assert value.source["tenantId"] != "changed"
    with pytest.raises(TypeError):
        value.source["tenantId"] = "changed"
    with pytest.raises(FrozenInstanceError):
        value.endpoint = "https://changed.invalid/v1/inventory/snapshot"


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost/v1/inventory/snapshot",
        "http://example.com/v1/inventory/snapshot",
        "http://169.254.169.254/v1/inventory/snapshot",
        "file:///v1/inventory/snapshot",
        "https://user:secret@example.com/v1/inventory/snapshot",
        "https://example.com/v1/inventory/snapshot?token=secret",
        "https://example.com/v1/inventory/snapshot#secret",
        "https://example.com/other",
        "https://example.com:0/v1/inventory/snapshot",
        "https://example.com:99999/v1/inventory/snapshot",
        "https://example.com/v1/inventory/snapshot\n",
        "https://exa_mple.com/v1/inventory/snapshot",
        "https://example..com/v1/inventory/snapshot",
        "https://%65xample.com/v1/inventory/snapshot",
    ],
)
def test_endpoint_config_rejects_unsafe_ambiguity_without_values(snapshot, endpoint):
    with pytest.raises(CollectionError) as error:
        enrollment(snapshot, endpoint)
    assert str(error.value) == "COLLECTOR_CONFIG_INVALID"
    assert "secret" not in repr(error.value)


@pytest.mark.parametrize(
    "change",
    [
        {"profile": "full"},
        {"tokenEnv": "TOKEN;unsafe"},
        {"token": TOKEN},
        {"timeoutSeconds": True},
        {"timeoutSeconds": 0},
        {"timeoutSeconds": 61},
        {"timeoutSeconds": float("nan")},
        {"maxResponseBytes": 8 * 1024 * 1024 + 1},
        {"source": {}},
        {"source": {"tenantId": "only"}},
    ],
)
def test_enrollment_rejects_extra_or_invalid_configuration(snapshot, change):
    value = {
        "source": snapshot["source"],
        "profile": "core",
        "tokenEnv": "TOKEN",
        "endpoint": "http://127.0.0.1/v1/inventory/snapshot",
        **change,
    }
    with pytest.raises(CollectionError, match="COLLECTOR_CONFIG_INVALID"):
        validate_enrollment(value)


@pytest.mark.parametrize("blank", ["\ufeff", " \ufeff\t", "\ufeff\x1c\ufeff\x85\ufeff\n"])
def test_enrollment_rejects_bom_only_source_identifiers(snapshot, blank):
    base = enrollment(snapshot, "http://127.0.0.1/v1/inventory/snapshot")
    for field in snapshot["source"]:
        source = {**snapshot["source"], field: blank}
        with pytest.raises(CollectionError, match="^COLLECTOR_CONFIG_INVALID$"):
            enrollment(snapshot, base.endpoint, source=source)
        with pytest.raises(CollectionError, match="^COLLECTOR_CONFIG_INVALID$"):
            replace(base, source=source)


def test_enrollment_preserves_nonblank_bom_source_identifiers(snapshot):
    source = {key: f"\ufeff \n{value}\ufeff\x85" for key, value in snapshot["source"].items()}
    value = enrollment(snapshot, "http://127.0.0.1/v1/inventory/snapshot", source=source)
    assert dict(value.source) == source
    assert replace(value).source == source


def test_enrollment_file_rejects_duplicates_and_size(snapshot, tmp_path):
    path = tmp_path / "source.json"
    path.write_text('{"profile":"core","profile":"host"}')
    with pytest.raises(CollectionError, match="COLLECTOR_CONFIG_INVALID"):
        load_enrollment(path)
    path.write_bytes(b" " * 131_073)
    with pytest.raises(CollectionError, match="COLLECTOR_CONFIG_INVALID"):
        load_enrollment(path)
    path.write_text(
        json.dumps(
            {
                "source": snapshot["source"],
                "profile": "core",
                "tokenEnv": "TOKEN",
                "endpoint": "http://127.0.0.1/v1/inventory/snapshot",
            }
        )
    )
    assert load_enrollment(path).source == snapshot["source"]


@pytest.mark.parametrize("token", ["", "task-secret", "agi_v1.short", "agi_v1." + "a" * 43 + "\n"])
def test_invalid_credential_never_opens_transport(snapshot, token, monkeypatch):
    monkeypatch.setattr(collector, "_fetch", lambda *args: pytest.fail("transport opened"))
    with pytest.raises(CollectionError, match="COLLECTOR_CREDENTIAL_INVALID"):
        collect_snapshot(enrollment(snapshot, "http://127.0.0.1/v1/inventory/snapshot"), token)


@pytest.mark.parametrize(
    "status",
    [
        "301 Moved",
        "302 Found",
        "307 Redirect",
        "401 Unauthorized",
        "403 Forbidden",
        "429 Limited",
        "503 Unavailable",
    ],
)
def test_http_rejections_never_follow_redirect_or_echo_body(snapshot, status):
    body = b'{"token":"private-response-canary"}'
    with observer(
        response(
            body,
            status=status,
            headers=[("Location", "https://attacker.invalid/"), ("Content-Length", str(len(body)))],
        )
    ) as (url, requests):
        with pytest.raises(CollectionError) as error:
            collect_snapshot(enrollment(snapshot, url), TOKEN)
        assert str(error.value) == "COLLECTOR_HTTP_REJECTED"
        assert "private" not in repr(error.value)
        assert len(requests) == 1


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Type", "text/html"), ("Content-Length", "2")],
        [("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Length", "2")],
        [
            ("Content-Type", "application/json"),
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
        ],
        [("Content-Type", "application/json"), ("Transfer-Encoding", "chunked")],
        [
            ("Content-Type", "application/json"),
            ("Content-Length", "2"),
            ("Content-Encoding", "gzip"),
        ],
        [("Content-Type", "application/json"), ("Content-Length", "-2")],
        [("Content-Type", "application/json")],
        [("X-Large", "a" * 8200), ("Content-Type", "application/json"), ("Content-Length", "2")],
    ],
)
def test_response_framing_and_headers_are_bounded(snapshot, headers):
    with observer(response(b"{}", headers=headers)) as (url, _):
        with pytest.raises(CollectionError, match="COLLECTOR_RESPONSE_INVALID"):
            collect_snapshot(enrollment(snapshot, url), TOKEN)


def test_oversized_and_truncated_responses_fail_closed(snapshot):
    with observer(
        response(
            b"{}", headers=[("Content-Type", "application/json"), ("Content-Length", "8388609")]
        )
    ) as (url, _):
        with pytest.raises(CollectionError, match="COLLECTOR_RESPONSE_TOO_LARGE"):
            collect_snapshot(enrollment(snapshot, url), TOKEN)
    with observer(
        response(b"{}", headers=[("Content-Type", "application/json"), ("Content-Length", "100")])
    ) as (url, _):
        with pytest.raises(CollectionError, match="COLLECTOR_RESPONSE_INVALID"):
            collect_snapshot(enrollment(snapshot, url), TOKEN)
    with observer(response(json.dumps(snapshot).encode())) as (url, _):
        with pytest.raises(CollectionError, match="COLLECTOR_RESPONSE_TOO_LARGE"):
            collect_snapshot(enrollment(snapshot, url, maxResponseBytes=128), TOKEN)


@pytest.mark.parametrize(
    "body",
    [
        b'{"profile":"core","profile":"host"}',
        b"{}",
        b"NaN",
        b"\xff",
        b'{"schemaVersion":99,"password":"private-canary"}',
    ],
)
def test_invalid_json_and_contract_are_redacted(snapshot, body):
    with observer(response(body)) as (url, _):
        with pytest.raises(CollectionError) as error:
            collect_snapshot(enrollment(snapshot, url), TOKEN)
        assert str(error.value) == "COLLECTOR_SNAPSHOT_INVALID"
        assert "private" not in repr(error.value)


@pytest.mark.parametrize("change", ["source", "profile"])
def test_closed_snapshot_must_match_enrolled_source_and_profile(snapshot, change):
    with observer(response(json.dumps(snapshot).encode())) as (url, _):
        config = {
            "source": dict(snapshot["source"]),
            "profile": "core",
            "tokenEnv": "TOKEN",
            "endpoint": url,
        }
        if change == "source":
            config["source"]["inventoryInstanceId"] = "other-ledger"
        else:
            config["profile"] = "host"
        with pytest.raises(CollectionError, match="COLLECTOR_SCOPE_MISMATCH"):
            collect_snapshot(validate_enrollment(config), TOKEN)


def test_slow_drip_header_cannot_extend_absolute_deadline(snapshot):
    def drip(sock):
        for byte in b"HTTP/1.1 200 OK\r\n":
            sock.sendall(bytes([byte]))
            time.sleep(0.02)

    with observer(drip) as (url, _):
        started = time.monotonic()
        with pytest.raises(CollectionError, match="COLLECTOR_TIMEOUT"):
            collect_snapshot(enrollment(snapshot, url, timeoutSeconds=0.05), TOKEN)
        assert time.monotonic() - started < 0.5


def test_blocked_dns_has_bounded_workers_and_never_sends_credentials_after_timeout(
    snapshot, monkeypatch
):
    release = threading.Event()
    completed = threading.Event()
    opened = []
    actual = collector.http.client.HTTPConnection.connect

    def blocked_connect(self):
        opened.append(True)
        release.wait(2)
        actual(self)
        completed.set()

    monkeypatch.setattr(collector.http.client.HTTPConnection, "connect", blocked_connect)
    with observer(response(json.dumps(snapshot).encode())) as (url, requests):
        with pytest.raises(CollectionError, match="COLLECTOR_TIMEOUT"):
            collect_snapshot(enrollment(snapshot, url, timeoutSeconds=0.05), TOKEN)
        release.set()
        assert completed.wait(1)
        time.sleep(0.02)
        assert opened and not requests


def test_tls_context_verifies_certificate_and_hostname(snapshot, monkeypatch):
    inspected = []

    class SecureConnection:
        def __init__(self, host, port, timeout, context):
            inspected.append((host, context.verify_mode, context.check_hostname))

        def connect(self):
            raise ssl.SSLCertVerificationError("private-certificate-canary")

        def close(self):
            pass

    monkeypatch.setattr(collector.http.client, "HTTPSConnection", SecureConnection)
    with pytest.raises(CollectionError) as error:
        collect_snapshot(
            enrollment(snapshot, "https://observer.example/v1/inventory/snapshot"), TOKEN
        )
    assert str(error.value) == "COLLECTOR_UNAVAILABLE"
    assert inspected == [("observer.example", ssl.CERT_REQUIRED, True)]


def test_busy_collector_is_bounded(snapshot):
    acquired = []
    try:
        while collector._WORKERS.acquire(blocking=False):
            acquired.append(True)
        with pytest.raises(CollectionError, match="COLLECTOR_BUSY"):
            collect_snapshot(enrollment(snapshot, "http://127.0.0.1/v1/inventory/snapshot"), TOKEN)
    finally:
        for _ in acquired:
            collector._WORKERS.release()
