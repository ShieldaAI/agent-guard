"""Exercise the real TypeScript exporter through the independently validated contract."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_guard_cartography.graph import build_rows, source_key
from agent_guard_cartography.inventory import InventoryValidationError, validate_snapshot

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "export-executor.mjs"


@pytest.fixture(scope="module")
def executor_snapshots():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/index.js").is_file():
        pytest.fail("Executor contract tests require Node >=22.13 and npm run build at repo root")
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


@pytest.mark.parametrize("name", ["live", "repeated", "revoked", "reopened", "empty"])
def test_executor_snapshots_validate_with_independent_consumer(executor_snapshots, name):
    snapshot = validate_snapshot(executor_snapshots[name])
    rows = build_rows(snapshot, "contract-projection", source_key(snapshot["source"]))
    assert len(rows["GuardTask"]) == len(snapshot["tasks"])
    assert all(row["assessment"] == "unknown" for row in rows["GuardGrant"])


@pytest.mark.parametrize(
    "source_id", ["\u0085", "\u001c", "\u001d", "\u001e", "\u001f", " \u0085\t"]
)
def test_unicode_whitespace_is_rejected_by_both_languages(executor_snapshots, source_id):
    # The Node fixture independently asserts these source IDs fail during construction.
    live = executor_snapshots["live"]
    candidate = {**live, "source": {**live["source"], "sourceId": source_id}}
    with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
        validate_snapshot(candidate)


def test_executor_snapshot_semantics_survive_contract_boundary(executor_snapshots):
    live, repeated, revoked, reopened, empty = (
        executor_snapshots[name] for name in ("live", "repeated", "revoked", "reopened", "empty")
    )
    tasks = {task["id"]: task for task in live["tasks"]}
    assert set(tasks) == {"root", "child", "handoff"}
    assert tasks["child"]["parentTaskId"] == "root"
    assert tasks["child"]["sourceTaskId"] is None
    assert tasks["handoff"]["parentTaskId"] is None
    assert tasks["handoff"]["sourceTaskId"] == "child"
    assert tasks["handoff"]["principalId"] != tasks["root"]["principalId"]
    assert {task["familyId"] for task in tasks.values()} == {"root"}
    assert all(task["sensitive"] for task in tasks.values())
    assert tasks["root"]["budget"]["deadline"] == 100000.5
    grants = {grant["tool"]: grant["resources"] for grant in tasks["root"]["grants"]}
    assert len(tasks["root"]["grants"]) == 2
    assert len(grants["records.read"]) == len(set(grants["records.read"])) == 2
    assert grants["future.tool"] == ["*"]
    assert len(tasks["root"]["allowedRecipients"]) == 1
    assert len(live["tools"]) == 1
    tool = live["tools"][0]
    assert tool["name"] == "records.read"
    assert tool["registered"] is True
    assert tool["approved"] is True
    assert tool["requiresApproval"] is True
    assert tool["controlPlane"] is False
    assert tool["maxCost"] == 2
    assert live["source"] == repeated["source"] == revoked["source"] == reopened["source"]
    assert len({item["snapshotId"] for item in executor_snapshots.values()}) == 5
    assert live["ledgerRevision"] == repeated["ledgerRevision"]
    assert live["policyEpoch"] == repeated["policyEpoch"]
    assert live["tasks"] == repeated["tasks"]
    assert live["tools"] == repeated["tools"]
    assert revoked["ledgerRevision"] > live["ledgerRevision"]
    assert next(task for task in revoked["tasks"] if task["id"] == "root")["revoked"] is True
    assert reopened["ledgerRevision"] > revoked["ledgerRevision"]
    assert reopened["policyEpoch"] > revoked["policyEpoch"]
    assert reopened["tools"][0]["registered"] is False
    assert reopened["tools"][0]["approved"] is False
    for flag in ("requiresApproval", "controlPlane", "maxCost"):
        assert reopened["tools"][0][flag] is None
    assert empty["source"]["tenantId"] == "empty"
    assert empty["tasks"] == empty["tools"] == []
    assert empty["coverage"]["tasks"]["status"] == "complete"
    assert empty["coverage"]["tools"]["status"] == "complete"
