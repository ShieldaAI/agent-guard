"""Public local JSON inputs remain bounded even when a path names a FIFO."""

import importlib
import json
import os
import select
import subprocess
import sys
from pathlib import Path

import pytest

from agent_guard_cartography.cli import _expected_source
from agent_guard_cartography.graph import GraphImportError

READERS = (
    ("inventory", "load_snapshot", "InventoryValidationError", "INVENTORY_READ_FAILED"),
    ("collector", "load_enrollment", "CollectionError", "COLLECTOR_CONFIG_INVALID"),
    ("cli", "_expected_source", "GraphImportError", "SOURCE_CONFIG_INVALID"),
    ("lifecycle", "load_transition", "LifecycleError", "SOURCE_TRANSITION_INVALID"),
)


@pytest.mark.parametrize("module_name,function,error_type,error_code", READERS)
def test_local_json_readers_without_nonblocking_support_fail_before_open(
    tmp_path, monkeypatch, module_name, function, error_type, error_code
):
    module = importlib.import_module(f"agent_guard_cartography.{module_name}")
    reader = getattr(module, function)
    expected_error = getattr(module, error_type)
    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)

    def unexpected_open(*_args, **_kwargs):
        pytest.fail("unsupported nonblocking reads must not open input files")

    monkeypatch.setattr(os, "open", unexpected_open)
    with pytest.raises(expected_error, match=f"^{error_code}$"):
        reader(tmp_path / "private-path-canary.json")


@pytest.mark.parametrize("module_name,function,error_type,error_code", READERS)
def test_local_json_readers_reject_fifo_without_waiting_for_a_writer(
    tmp_path, module_name, function, error_type, error_code
):
    path = tmp_path / "private-path-canary.json"
    os.mkfifo(path, 0o600)
    script = """
import importlib
import json
import sys
from pathlib import Path

reader = getattr(importlib.import_module(sys.argv[1]), sys.argv[2])
print("ready", flush=True)
try:
    reader(Path(sys.argv[3]))
except Exception as error:
    print(json.dumps([type(error).__name__, str(error)]), flush=True)
else:
    print("accepted", flush=True)
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            f"agent_guard_cartography.{module_name}",
            function,
            str(path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        # Separate import time from the operation's deadline. A regression must
        # fail in the parent rather than leave a blocked test worker behind.
        assert select.select([process.stdout], [], [], 10)[0], "reader did not initialize"
        assert process.stdout.readline().strip() == b"ready"
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            pytest.fail("local JSON reader blocked on a FIFO with no writer")
        assert process.returncode == 0 and stderr == b""
        assert json.loads(stdout) == [error_type, error_code]
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


@pytest.mark.parametrize("module_name,function,_error_type,_error_code", READERS)
@pytest.mark.parametrize("symlink", [False, True])
def test_local_json_readers_preserve_regular_files_and_symlinks(
    tmp_path, module_name, function, _error_type, _error_code, symlink
):
    snapshot = json.loads((Path(__file__).parents[1] / "fixtures" / "alpha-v1.json").read_text())
    values = {
        "inventory": snapshot,
        "collector": {
            "source": snapshot["source"],
            "profile": "core",
            "endpoint": "http://127.0.0.1/v1/inventory/snapshot",
            "tokenEnv": "TOKEN",
        },
        "cli": snapshot["source"],
        "lifecycle": {
            "schemaVersion": 1,
            "predecessor": snapshot["source"],
            "successor": {**snapshot["source"], "enrollmentGeneration": "replacement"},
            "profile": "core",
        },
    }
    value = values[module_name]
    regular = tmp_path / "input.json"
    regular.write_text(json.dumps(value))
    path = regular
    if symlink:
        path = tmp_path / "alias.json"
        path.symlink_to(regular)
    reader = getattr(importlib.import_module(f"agent_guard_cartography.{module_name}"), function)
    result = reader(path)
    if module_name == "collector":
        assert dict(result.source) == value["source"]
        assert result.profile == value["profile"]
    else:
        assert result == value


@pytest.mark.parametrize(
    "contents",
    [b"{}" + b" " * 16_383, b'{"key":1,"key":2}', b"[]", b"\xff", b"{"],
)
def test_source_and_cloud_scope_files_keep_json_and_size_rejections(tmp_path, contents):
    path = tmp_path / "private-path-canary.json"
    path.write_bytes(contents)
    with pytest.raises(GraphImportError, match="^SOURCE_CONFIG_INVALID$"):
        _expected_source(path)


def test_source_and_cloud_scope_file_accepts_exact_size_limit(tmp_path):
    path = tmp_path / "input.json"
    path.write_bytes(b"{}" + b" " * 16_382)
    assert _expected_source(path) == {}
