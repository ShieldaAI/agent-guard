"""Preserve the full random token across the pinned admin CLI's option boundary."""

import base64
import importlib.util
import string
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "test-disposable-neo4j.py"
spec = importlib.util.spec_from_file_location("neo4j_password_fixture", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_every_urlsafe_leading_character_is_retained_after_a_nonoption_prefix(monkeypatch, capsys):
    calls = []
    for first in string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_":
        suffix = first + "A" * 42

        def random_token(size, suffix=suffix):
            calls.append(size)
            return suffix

        monkeypatch.setattr(runner.secrets, "token_urlsafe", random_token)
        password = runner.neo4j_initial_password()
        assert password == "guard-" + suffix
        assert len(password) == 49
        assert not password.startswith("-")
        assert "/" not in password
    assert calls == [32] * 64
    assert capsys.readouterr() == ("", "")


def test_password_generation_does_not_cache_or_retry_random_tokens(monkeypatch):
    suffixes = ["-" + "A" * 42, "_" + "B" * 42]
    calls = []

    def random_token(size):
        calls.append(size)
        return suffixes[len(calls) - 1]

    monkeypatch.setattr(runner.secrets, "token_urlsafe", random_token)
    assert runner.neo4j_initial_password() == "guard-" + suffixes[0]
    assert runner.neo4j_initial_password() == "guard-" + suffixes[1]
    assert calls == [32, 32]


def test_entropy_source_failure_propagates_without_fallback_or_disclosure(monkeypatch, capsys):
    error = RuntimeError("private entropy-source message")
    calls = []

    def unavailable(size):
        calls.append(size)
        raise error

    monkeypatch.setattr(runner.secrets, "token_urlsafe", unavailable)
    with pytest.raises(RuntimeError) as failed:
        runner.neo4j_initial_password()
    assert failed.value is error
    assert calls == [32]
    assert capsys.readouterr() == ("", "")


def test_real_generator_keeps_all_32_random_bytes_without_exposing_the_value(capsys):
    password = runner.neo4j_initial_password()
    assert password.startswith("guard-")
    suffix = password.removeprefix("guard-")
    assert len(suffix) == 43
    assert set(suffix) <= set(string.ascii_letters + string.digits + "-_")
    assert len(base64.urlsafe_b64decode(suffix + "=")) == 32
    assert capsys.readouterr() == ("", "")
