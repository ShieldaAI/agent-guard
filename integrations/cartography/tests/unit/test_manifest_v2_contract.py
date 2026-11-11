"""Actual v2 executor/observer output is independently validated by Python."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from agent_guard_cartography.graph import build_rows, source_key
from agent_guard_cartography.inventory import InventoryValidationError, validate_snapshot

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).parents[1] / "fixtures" / "manifest-executor.mjs"


@pytest.fixture(scope="module")
def v2_receipts():
    node = shutil.which("node")
    assert node is not None and (ROOT / "packages/executor/dist/index.js").is_file()
    result = subprocess.run(
        [node, str(FIXTURE), "--v2"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_actual_v2_composition_observer_and_python_projection_have_no_authority_effect(v2_receipts):
    core, after = v2_receipts["core"], v2_receipts["after"]
    for value in [v2_receipts["composed"], v2_receipts["observedHost"]["body"]]:
        snapshot = validate_snapshot(value)
        assert snapshot["manifest"]["schemaVersion"] == 2
        for field in ("tasks", "tools", "ledgerRevision", "policyEpoch"):
            assert core[field] == snapshot[field] == after[field]
        rows = build_rows(snapshot, "projection", source_key(snapshot["source"]))
        assert len(rows["GuardOwner"]) == len(rows["GuardCredentialReference"]) == 2
        assert all(row["assessment"] == "unknown" for row in rows["GuardGrant"])
        assert any(
            row["provider"] == "host" and row["arn"] is None
            for row in rows["GuardExternalResource"]
        )
        assert (
            snapshot["coverage"]["manifest"]["observedAt"]
            != snapshot["coverage"]["tasks"]["observedAt"]
        )
    assert "private-" not in json.dumps(v2_receipts)
    assert v2_receipts["observedCore"]["body"]["profile"] == "core"
    assert v2_receipts["forbidden"]["status"] == 403
    assert v2_receipts["override"]["status"] == 400


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m["credentialReferences"][0].update(token="private-canary"),
        lambda m: m["credentialReferences"][0].update(id="opaque:" + "A" * 64),
        lambda m: m["deployments"][0].update(credentialReferenceIds=["opaque:" + "9" * 64]),
        lambda m: m["agents"][0].update(ownerId="missing"),
        lambda m: m["resourceBindings"][1].update(dependsOn=["prefix-binding"]),
    ],
)
def test_python_rejects_tampered_actual_v2_export(v2_receipts, mutation):
    value = deepcopy(v2_receipts["composed"])
    mutation(value["manifest"])
    with pytest.raises(InventoryValidationError) as error:
        validate_snapshot(value)
    assert "private-canary" not in str(error.value)


def test_public_company_cartography_example_validates_and_projects_without_effects():
    result = subprocess.run(
        [shutil.which("node"), str(ROOT / "examples/agent-cartography.mjs")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    snapshot = validate_snapshot(json.loads(result.stdout))
    assert snapshot["manifest"]["schemaVersion"] == 2
    assert all(
        task["usage"]["calls"] == 0 and task["usage"]["spent"] == 0 for task in snapshot["tasks"]
    )
    rows = build_rows(snapshot, "example", source_key(snapshot["source"]))
    assert len(rows["GuardOwner"]) == len(rows["GuardCredentialReference"]) == 1
    assert rows["GuardExternalResource"][0]["provider"] == "host"
    assert "private-company-database-selector" not in result.stdout
