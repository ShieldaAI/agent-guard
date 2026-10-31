"""Independent validation of actual executor composition and observer host profiles."""

from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.graph import build_rows, source_key
from agent_guard_cartography.inventory import InventoryValidationError, validate_snapshot

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "manifest-executor.mjs"


@pytest.fixture(scope="module")
def manifest_receipts():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/index.js").is_file():
        pytest.fail("Manifest contract tests require Node >=22.13 and npm run build at repo root")
    result = subprocess.run(
        [node, str(FIXTURE)], cwd=ROOT, capture_output=True, text=True, check=False, timeout=30
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("name", ["composed", "observedHost"])
def test_actual_host_composition_passes_independent_schema_and_graph_projection(
    manifest_receipts, name
):
    value = manifest_receipts[name]
    if name == "observedHost":
        assert value["status"] == 200
        assert value["cacheControl"] == "no-store"
        assert int(value["contentLength"]) == value["byteLength"]
        value = value["body"]
    snapshot = validate_snapshot(value)
    assert snapshot["profile"] == "host"
    manifest = snapshot["manifest"]
    assert manifest["source"] == snapshot["source"]
    assert manifest["evidenceKind"] == "host_asserted"
    assert snapshot["coverage"]["manifest"] == {
        "status": "complete",
        "observedAt": manifest["observedAt"],
    }
    rows = build_rows(snapshot, "host-contract-projection", source_key(snapshot["source"]))
    assert len(rows["GuardTask"]) == 3
    assert len(rows["GuardAgent"]) == len(rows["GuardDeployment"]) == 2
    assert len(rows["GuardResourceBinding"]) == len(rows["GuardExternalResource"]) == 2
    assert len(rows["GuardExecutionBinding"]) == 2
    assert len(rows["GuardExternalIdentity"]) == 1
    assert all(row["assessment"] == "unknown" for row in rows["GuardGrant"])


def test_host_composition_preserves_authority_and_independent_capture_evidence(manifest_receipts):
    core, composed, after = (manifest_receipts[name] for name in ("core", "composed", "after"))
    observed = manifest_receipts["observedHost"]["body"]
    assert core["source"] == composed["source"] == observed["source"] == after["source"]
    for field in ("tasks", "tools", "ledgerRevision", "policyEpoch"):
        assert core[field] == composed[field] == observed[field] == after[field]
    assert core["coverage"]["tasks"] == composed["coverage"]["tasks"]
    assert core["coverage"]["tools"] == composed["coverage"]["tools"]
    assert composed["coverage"]["manifest"]["observedAt"] == "2026-10-30T00:00:00Z"
    assert composed["manifest"] == manifest_receipts["validated"] == observed["manifest"]
    assert len({item["snapshotId"] for item in (core, composed, observed, after)}) == 4
    assert "unassigned" in {task["id"] for task in composed["tasks"]}
    assert "unassigned" not in {
        binding["taskId"] for binding in composed["manifest"]["taskBindings"]
    }
    assert all(
        binding["resourceRef"].startswith("opaque:")
        for binding in composed["manifest"]["resourceBindings"]
    )


def test_host_profile_is_selected_by_credential_without_widening_scope(manifest_receipts):
    core = manifest_receipts["observedCore"]
    assert core["status"] == 200
    assert validate_snapshot(core["body"])["profile"] == "core"
    assert "manifest" not in core["body"]
    assert core["body"]["coverage"]["manifest"] == {"status": "not_collected"}
    assert manifest_receipts["forbidden"]["status"] == 403
    assert manifest_receipts["forbidden"]["body"] == {"error": "INVENTORY_SCOPE_DENIED"}
    assert manifest_receipts["override"]["status"] == 400
    assert manifest_receipts["override"]["body"] == {"error": "REQUEST_INVALID"}
    assert {failure["label"] for failure in manifest_receipts["failures"]} == {
        "extra-field",
        "wrong-source",
        "wrong-account",
        "wildcard-binding",
        "raw-alias",
        "poisoned-core",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda snapshot: snapshot["manifest"].update(token="private-canary"),
        lambda snapshot: snapshot["manifest"]["source"].update(tenantId="beta"),
        lambda snapshot: snapshot["manifest"]["resourceBindings"][0].update(resourceRef="*"),
        lambda snapshot: snapshot["manifest"]["resourceBindings"][0].update(
            resourceRef="raw-alias"
        ),
        lambda snapshot: snapshot["manifest"]["resourceBindings"][0]["target"].update(
            kind="bucket"
        ),
        lambda snapshot: snapshot["manifest"]["executionBindings"][0]["identity"].update(
            accountId="999988887777"
        ),
        lambda snapshot: snapshot["manifest"]["executionBindings"][1].update(
            identity=snapshot["manifest"]["executionBindings"][0]["identity"]
        ),
        lambda snapshot: snapshot["coverage"]["manifest"].update(observedAt="2026-10-30T00:00:01Z"),
    ],
)
def test_consumer_independently_rejects_tampered_host_bindings(manifest_receipts, mutation):
    candidate = deepcopy(manifest_receipts["composed"])
    mutation(candidate)
    with pytest.raises(InventoryValidationError) as error:
        validate_snapshot(candidate)
    assert str(error.value) == error.value.code
    assert "private" not in str(error.value)
