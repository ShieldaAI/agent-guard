"""Exercise readiness deadlines against local sockets without starting Docker."""

import importlib.util
import socket
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import ServiceUnavailable

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "test-disposable-neo4j.py"
spec = importlib.util.spec_from_file_location("disposable_neo4j_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_silent_bolt_peer_cannot_consume_the_default_sixty_second_acquisition_deadline():
    release = threading.Event()
    handshake = bytearray()
    failures = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        uri = f"bolt://127.0.0.1:{listener.getsockname()[1]}"

        def silent_peer():
            try:
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(5)
                    while len(handshake) < 20:
                        chunk = connection.recv(20 - len(handshake))
                        if not chunk:
                            return
                        handshake.extend(chunk)
                    # A finite fallback also makes the old implementation fail
                    # promptly instead of hanging the test for sixty seconds.
                    release.wait(5)
            except (OSError, TimeoutError) as exc:
                failures.append(exc)

        peer = threading.Thread(target=silent_peer, daemon=True)
        peer.start()
        started = time.monotonic()
        try:
            with pytest.raises(RuntimeError, match="did not become ready"):
                # One attempt is enough: the peer accepts TCP but never sends
                # the Bolt handshake response. No database or auth is involved.
                runner.wait_ready(uri, "unused-test-password", None, timeout=1)
            elapsed = time.monotonic() - started
            assert elapsed < 4, f"Silent Bolt handshake exceeded its attempt bound: {elapsed:.2f}s"
        finally:
            release.set()
            peer.join(timeout=2)
        assert not peer.is_alive()
        assert not failures
        assert len(handshake) == 20 and handshake[:4] == b"\x60\x60\xb0\x17"


def test_readiness_retries_connectivity_then_requires_a_successful_database_query(monkeypatch):
    driver = MagicMock()
    driver.__enter__.return_value = driver
    driver.verify_connectivity.side_effect = [ServiceUnavailable("still starting"), None]
    session = driver.session.return_value.__enter__.return_value
    monkeypatch.setattr(runner.GraphDatabase, "driver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(runner.time, "sleep", lambda _duration: None)

    runner.wait_ready("bolt://127.0.0.1:1", "unused-test-password", None, timeout=1)

    assert driver.verify_connectivity.call_count == 2
    driver.session.assert_called_once_with(database="neo4j")
    session.run.assert_called_once_with("RETURN 1 AS ready")
    session.run.return_value.consume.assert_called_once_with()
    driver.__exit__.assert_called_once()
