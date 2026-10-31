"""Validate real observer HTTP snapshots through the independently enforced contract."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_guard_cartography.graph import build_rows, source_key
from agent_guard_cartography.inventory import validate_snapshot

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "observe-executor.mjs"


@pytest.fixture(scope="module")
def observer_receipts():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/index.js").is_file():
        pytest.fail("Observer contract tests require Node >=22.13 and npm run build at repo root")
    result = subprocess.run(
        [node, str(FIXTURE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("name", ["observed", "empty"])
def test_observer_http_output_is_a_complete_consumer_snapshot(observer_receipts, name):
    receipt = observer_receipts[name]
    assert receipt["status"] == 200
    assert receipt["cacheControl"] == "no-store"
    assert int(receipt["contentLength"]) == receipt["byteLength"]
    snapshot = validate_snapshot(receipt["body"])
    rows = build_rows(snapshot, "observer-contract-projection", source_key(snapshot["source"]))
    assert len(rows["GuardTask"]) == len(snapshot["tasks"])
    assert all(row["assessment"] == "unknown" for row in rows["GuardGrant"])
    assert snapshot["coverage"]["tasks"]["status"] == "complete"
    assert snapshot["coverage"]["tools"]["status"] == "complete"


def test_observation_preserves_inventory_identity_and_authority_revision(observer_receipts):
    direct, observed, after = (
        observer_receipts["direct"],
        observer_receipts["observed"]["body"],
        observer_receipts["after"],
    )
    assert direct["source"] == observed["source"] == after["source"]
    assert direct["ledgerRevision"] == observed["ledgerRevision"] == after["ledgerRevision"]
    assert direct["policyEpoch"] == observed["policyEpoch"] == after["policyEpoch"]
    assert direct["tasks"] == observed["tasks"] == after["tasks"]
    assert direct["tools"] == observed["tools"] == after["tools"]
    assert len({snapshot["snapshotId"] for snapshot in (direct, observed, after)}) == 3
    assert {task["id"] for task in observed["tasks"]} == {"alpha-task"}
    task = observed["tasks"][0]
    assert task["grants"][0]["resources"][0].startswith("opaque:")
    assert task["allowedRecipients"][0].startswith("opaque:")
    assert observer_receipts["empty"]["body"]["tasks"] == []
    assert observer_receipts["empty"]["body"]["tools"] == []


@pytest.mark.parametrize(
    ("name", "status", "code"),
    [
        ("forbidden", 403, "INVENTORY_SCOPE_DENIED"),
        ("taskCredential", 401, "UNAUTHENTICATED"),
        ("unknownCredential", 401, "UNAUTHENTICATED"),
        ("filtered", 400, "REQUEST_INVALID"),
        ("limited", 413, "INVENTORY_RESPONSE_TOO_LARGE"),
    ],
)
def test_failed_observation_returns_only_a_bounded_error(observer_receipts, name, status, code):
    receipt = observer_receipts[name]
    assert receipt["status"] == status
    assert receipt["body"] == {"error": code}
    assert receipt["cacheControl"] == "no-store"
    assert int(receipt["contentLength"]) == receipt["byteLength"]
    assert receipt["byteLength"] <= 128
