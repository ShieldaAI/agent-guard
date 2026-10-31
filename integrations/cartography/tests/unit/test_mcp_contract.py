"""Validate actual managed MCP/executor/HTTP receipts with the independent consumer."""

from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.graph import build_rows, source_key
from agent_guard_cartography.inventory import (
    InventoryValidationError,
    validate_mcp_inventory,
    validate_snapshot,
)

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mcp-executor.mjs"


@pytest.fixture(scope="module")
def mcp_receipts():
    node = shutil.which("node")
    if node is None or any(
        not (ROOT / f"packages/{package}/dist/index.js").is_file()
        for package in ("executor", "mcp")
    ):
        pytest.fail("MCP contract tests require Node >=22.13 and npm run build at repo root")
    result = subprocess.run(
        [node, str(FIXTURE)], cwd=ROOT, capture_output=True, text=True, check=False, timeout=30
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    ("name", "state", "metadata_state", "metadata_revision", "operations"),
    [
        ("ready", "ready", "current", 1, 1),
        ("quarantined", "quarantined", "stale", 1, 0),
        ("refreshed", "ready", "current", 2, 1),
        ("removed", "ready", "current", 3, 0),
        ("closed", "closed", "stale", 3, 0),
    ],
)
def test_actual_mcp_lifecycle_passes_consumer_schema_and_graph_projection(
    mcp_receipts, name, state, metadata_state, metadata_revision, operations
):
    snapshot = validate_snapshot(mcp_receipts[name])
    assert snapshot["profile"] == "host-mcp"
    (record,) = snapshot["mcp"]["connections"]
    assert record["status"] == "observed"
    inventory = validate_mcp_inventory(record["inventory"])
    assert inventory["state"] == state
    assert inventory["metadataState"] == metadata_state
    assert inventory["metadataRevision"] == metadata_revision
    assert len(inventory["operations"]) == operations
    assert snapshot["coverage"]["mcp"] == {
        "status": "complete",
        "observedAt": snapshot["mcp"]["observedAt"],
    }
    rows = build_rows(snapshot, f"actual-mcp-{name}", source_key(snapshot["source"]))
    (connection,) = rows["GuardMcpConnection"]
    (execution,) = rows["GuardExecutionBinding"]
    assert connection["state"] == state
    assert connection["metadata_state"] == metadata_state
    assert connection["metadata_revision"] == metadata_revision
    assert execution["connection_node_id"] == connection["id"]
    assert len(rows["GuardMcpOperation"]) == operations
    for operation in rows["GuardMcpOperation"]:
        assert connection["operation_node_ids"] == [operation["id"]]
        assert operation["tool_node_id"] in {tool["id"] for tool in rows["GuardTool"]}
        assert operation["evidence_kind"] == "observed"
        assert operation["assessment"] == "unknown"
        assert "approved" not in operation
    assert all(grant["assessment"] == "unknown" for grant in rows["GuardGrant"])


def test_actual_inventory_preserves_authority_and_only_changes_lifecycle_revisions(mcp_receipts):
    standalone = validate_mcp_inventory(mcp_receipts["standalone"])
    ready = mcp_receipts["ready"]
    first = ready["mcp"]["connections"][0]["inventory"]
    assert {key: value for key, value in standalone.items() if key != "observedAt"} == {
        key: value for key, value in first.items() if key != "observedAt"
    }
    for receipt in [ready, mcp_receipts["observedMcp"]["body"], mcp_receipts["after"]]:
        for field in ("source", "tasks", "tools", "ledgerRevision", "policyEpoch"):
            assert receipt[field] == mcp_receipts["core"][field]
    observations = [
        mcp_receipts[name]["mcp"]["connections"][0]["inventory"]
        for name in ("ready", "quarantined", "refreshed", "removed", "closed")
    ]
    assert len({value["sessionId"] for value in observations}) == 1
    assert len({value["identity"]["transportRef"] for value in observations}) == 1
    for previous, current in zip(observations, observations[1:], strict=False):
        assert current["revision"] > previous["revision"]
        assert current["authorizationEpoch"] > previous["authorizationEpoch"]
    assert (
        observations[0]["operations"][0]["fingerprint"]
        != observations[2]["operations"][0]["fingerprint"]
    )
    assert mcp_receipts["ready"]["tools"][0]["approved"] is True
    assert mcp_receipts["refreshed"]["tools"][0]["approved"] is False
    assert all(value == 0 for value in mcp_receipts["observationCallbacks"].values())
    serialized = json.dumps(mcp_receipts)
    for secret in ("private-", "transportIdentity", "remoteName", "inputSchema"):
        assert secret not in serialized


def test_actual_missing_source_is_explicitly_unavailable_with_no_stale_operations(mcp_receipts):
    snapshot = validate_snapshot(mcp_receipts["missing"])
    assert snapshot["coverage"]["mcp"]["status"] == "unavailable"
    assert snapshot["mcp"]["connections"] == [
        {"connectionId": "documents-mcp", "status": "unavailable", "reason": "missing"}
    ]
    rows = build_rows(snapshot, "actual-mcp-missing", source_key(snapshot["source"]))
    (connection,) = rows["GuardMcpConnection"]
    assert connection["capture_status"] == "unavailable"
    assert connection["unavailable_reason"] == "missing"
    assert connection["state"] is None
    assert connection["metadata_revision"] is None
    assert connection["session_id"] is None
    assert not rows["GuardMcpOperation"]


def test_actual_observer_mcp_profile_is_credential_scoped_and_bounded(mcp_receipts):
    receipt = mcp_receipts["observedMcp"]
    assert receipt["status"] == 200
    assert receipt["cacheControl"] == "no-store"
    assert int(receipt["contentLength"]) == receipt["byteLength"]
    observed = validate_snapshot(receipt["body"])
    assert observed["profile"] == "host-mcp"
    assert observed["mcp"]["connections"][0]["inventory"]["state"] == "ready"
    assert observed["source"]["tenantId"] == "alpha"
    core = mcp_receipts["observedCore"]
    assert core["status"] == 200
    assert validate_snapshot(core["body"])["profile"] == "core"
    assert core["body"]["coverage"]["mcp"] == {"status": "not_collected"}
    assert "mcp" not in core["body"] and "manifest" not in core["body"]
    assert mcp_receipts["forbidden"]["status"] == 403
    assert mcp_receipts["forbidden"]["body"] == {"error": "INVENTORY_SCOPE_DENIED"}
    assert mcp_receipts["override"]["status"] == 400
    assert mcp_receipts["override"]["body"] == {"error": "REQUEST_INVALID"}


@pytest.mark.parametrize(
    "mutation",
    [
        lambda snapshot: snapshot["mcp"]["connections"][0]["inventory"].update(
            descriptor="private-descriptor-canary"
        ),
        lambda snapshot: snapshot["mcp"]["connections"][0]["inventory"]["identity"].update(
            transportIdentity="https://private-credential-canary@example.test"
        ),
        lambda snapshot: snapshot["mcp"]["connections"][0]["inventory"]["identity"].update(
            tenantId="beta"
        ),
        lambda snapshot: snapshot["mcp"]["connections"][0]["inventory"]["operations"][0].update(
            fingerprint="0" * 64
        ),
        lambda snapshot: snapshot["mcp"]["connections"][0]["inventory"].update(
            state="quarantined", metadataState="stale"
        ),
        lambda snapshot: snapshot["mcp"]["connections"][0].update(connectionId="unbound"),
        lambda snapshot: snapshot["coverage"]["mcp"].update(status="unavailable"),
        lambda snapshot: snapshot["manifest"]["executionBindings"][0].update(connectionId=None),
    ],
)
def test_consumer_rejects_tampered_actual_mcp_observations(mcp_receipts, mutation):
    snapshot = deepcopy(mcp_receipts["ready"])
    mutation(snapshot)
    with pytest.raises(InventoryValidationError) as error:
        validate_snapshot(snapshot)
    assert str(error.value) == error.value.code
    assert "private" not in str(error.value)
