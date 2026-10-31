"""Strict AWS tokens use identical end-of-input semantics in Python and JavaScript."""

from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from test_manifest import host_snapshot
from test_mcp_inventory import inventory, mcp_snapshot

from agent_guard_cartography.inventory import (
    InventoryValidationError,
    validate_manifest,
    validate_mcp_inventory,
    validate_snapshot,
)

ROOT = Path(__file__).resolve().parents[4]
SCHEMAS = {
    "manifest": "agent-guard-inventory-manifest-v1.schema.json",
    "snapshot": "agent-guard-inventory-v1.schema.json",
    "mcp": "agent-guard-mcp-inventory-v1.schema.json",
}


def candidate(case):
    snapshot = host_snapshot()
    manifest = snapshot["manifest"]
    if case == "resource-account":
        manifest["resourceBindings"][0]["target"]["accountId"] += "\n"
    elif case == "identity-account":
        manifest["executionBindings"][0]["identity"]["accountId"] += "\n"
    elif case == "action":
        manifest["resourceBindings"][0]["actions"][0] += "\n"
    elif case == "region":
        manifest["resourceBindings"][0]["target"]["region"] = "us-east-1\n"
    elif case == "resource-arn-bom":
        manifest["resourceBindings"][0]["target"]["arn"] += "\ufeffx"
    elif case == "identity-arn-bom":
        manifest["executionBindings"][0]["identity"]["arn"] += "\ufeffx"
    elif case == "regional-resource-and-identifier":
        # Region/action tokens are strict; ordinary nonblank identifiers may
        # contain or end with newlines and must not be narrowed by this fix.
        manifest["agents"][0]["name"] = "Research\nAgent\n"
        binding = manifest["resourceBindings"][0]
        binding["target"].update(
            region="us-east-1",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-example",
            kind="resource",
        )
        binding["actions"] = ["ec2:DescribeInstances"]
    elif case != "valid":
        raise AssertionError(case)
    return snapshot


def validator(kind):
    # Deliberately use plain JSON Schema validation without application-specific
    # ARN/action checks or format extras. The portable pattern itself must hold.
    return Draft202012Validator(json.loads((ROOT / "schemas" / SCHEMAS[kind]).read_text()))


@pytest.mark.parametrize("kind", ["manifest", "snapshot"])
@pytest.mark.parametrize(
    "case",
    [
        "resource-account",
        "identity-account",
        "action",
        "region",
        "resource-arn-bom",
        "identity-arn-bom",
    ],
)
def test_schema_and_consumer_reject_malformed_aws_tokens(kind, case):
    snapshot = candidate(case)
    value = snapshot["manifest"] if kind == "manifest" else snapshot
    assert not validator(kind).is_valid(value)
    with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
        (validate_manifest if kind == "manifest" else validate_snapshot)(value)


@pytest.mark.parametrize("kind", ["manifest", "snapshot"])
@pytest.mark.parametrize("case", ["valid", "regional-resource-and-identifier"])
def test_valid_tokens_and_multiline_identifiers_remain_supported(kind, case):
    snapshot = candidate(case)
    value = snapshot["manifest"] if kind == "manifest" else snapshot
    assert validator(kind).is_valid(value)
    assert (validate_manifest if kind == "manifest" else validate_snapshot)(value) == value


def test_actual_javascript_and_python_manifest_validation_agree_on_token_boundaries():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/inventory-manifest.js").is_file():
        pytest.fail("Manifest contract tests require Node >=22.13 and npm run build at repo root")
    names = [
        "resource-account",
        "identity-account",
        "action",
        "region",
        "resource-arn-bom",
        "identity-arn-bom",
        "valid",
        "regional-resource-and-identifier",
    ]
    snapshots = [candidate(name) for name in names]
    script = """
import { readFileSync } from 'node:fs';
import { validateInventoryManifest, composeInventorySnapshot }
  from './packages/executor/dist/inventory-manifest.js';
const accepted = operation => {
  try { operation(); return true; }
  catch (error) {
    if (error.code !== 'INVENTORY_MANIFEST_INVALID') throw error;
    return false;
  }
};
const result = JSON.parse(readFileSync(0, 'utf8')).map(snapshot => {
  const { manifest, ...base } = snapshot;
  const core = { ...base, profile: 'core', coverage: {
    ...base.coverage, manifest: { status: 'not_collected' },
  } };
  return [accepted(() => validateInventoryManifest(manifest)),
    accepted(() => composeInventorySnapshot(core, manifest))];
});
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(snapshots),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)
    for name, snapshot, javascript in zip(names, snapshots, actual, strict=True):
        expected = name in {"valid", "regional-resource-and-identifier"}
        assert javascript == [expected, expected]
        try:
            validate_snapshot(deepcopy(snapshot))
        except InventoryValidationError:
            assert not expected
        else:
            assert expected


@pytest.mark.parametrize("kind", ["manifest", "snapshot", "mcp"])
def test_identifier_whitespace_matches_actual_javascript_in_all_profiles(kind):
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/inventory-mcp.js").is_file():
        pytest.fail("Inventory contract tests require Node >=22.13 and npm run build at repo root")
    cases = [
        ("\ufeff", False),
        (" \n\ufeff\x1c\x85", False),
        ("\x1c", False),
        ("\x85", False),
        ("agent\n", True),
        ("\ufeffagent\ufeff", True),
    ]
    values = []
    for text, _accepted in cases:
        if kind == "manifest":
            value = host_snapshot()["manifest"]
            value["agents"][0]["name"] = text
        elif kind == "snapshot":
            value = json.loads(
                (ROOT / "integrations/cartography/tests/fixtures/alpha-v1.json").read_text()
            )
            value["source"]["sourceId"] = text
        else:
            value = inventory(mcp_snapshot())
            value["identity"]["serverId"] = text
        values.append(value)
    script = """
import { readFileSync } from 'node:fs';
import { validateInventoryManifest, composeInventorySnapshot }
  from './packages/executor/dist/inventory-manifest.js';
import { validateMcpConnectionInventory } from './packages/executor/dist/inventory-mcp.js';
const { kind, values } = JSON.parse(readFileSync(0, 'utf8'));
const errorCodes = { manifest: 'INVENTORY_MANIFEST_INVALID',
  snapshot: 'INVENTORY_SNAPSHOT_INVALID', mcp: 'INVENTORY_MCP_INVALID' };
const result = values.map(value => {
  try {
    if (kind === 'manifest') validateInventoryManifest(value);
    else if (kind === 'mcp') validateMcpConnectionInventory(value);
    else composeInventorySnapshot(value, { schemaVersion: 1, evidenceKind: 'host_asserted',
      source: value.source, manifestId: 'whitespace-check', revision: 1,
      observedAt: value.generatedAt, agents: [], deployments: [], taskBindings: [],
      resourceBindings: [], executionBindings: [] });
    return true;
  } catch (error) {
    if (error.code !== errorCodes[kind]) throw error;
    return false;
  }
});
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps({"kind": kind, "values": values}),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    expected = [accepted for _text, accepted in cases]
    assert json.loads(result.stdout) == expected
    public = {
        "manifest": validate_manifest,
        "snapshot": validate_snapshot,
        "mcp": validate_mcp_inventory,
    }[kind]
    for value, accepted in zip(values, expected, strict=True):
        assert validator(kind).is_valid(value) == accepted
        if accepted:
            assert public(value) == value
        else:
            with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
                public(value)


def test_canonical_strict_token_patterns_are_portable_to_javascript():
    node = shutil.which("node")
    if node is None:
        pytest.fail("Inventory contract tests require Node >=22.13")
    checks = []
    for filename in SCHEMAS.values():
        definitions = json.loads((ROOT / "schemas" / filename).read_text())["$defs"]
        patterns = [
            (
                definitions["identifier"]["pattern"],
                [("\ufeff", False), ("\x85", False), ("a\n", True)],
            )
        ]
        if "awsReference" in definitions:
            for reference in ("awsReference", "awsResourceReference"):
                patterns.append(
                    (
                        definitions[reference]["properties"]["accountId"]["pattern"],
                        [("123456789012", True), ("123456789012\n", False)],
                    )
                )
                arn = (
                    "arn:aws:iam::123456789012:role/reporter"
                    if reference == "awsReference"
                    else "arn:aws:s3:::reports/item"
                )
                patterns.append(
                    (
                        definitions[reference]["properties"]["arn"]["pattern"],
                        [(arn, True), (arn + "\ufeffx", False)],
                    )
                )
            patterns.extend(
                [
                    (
                        definitions["awsResourceReference"]["properties"]["region"]["pattern"],
                        [("", True), ("us-east-1", True), ("us-east-1\n", False)],
                    ),
                    (
                        definitions["awsAction"]["pattern"],
                        [("s3:GetObject", True), ("s3:GetObject\n", False)],
                    ),
                ]
            )
        for pattern, cases in patterns:
            checks.extend([pattern, value, expected] for value, expected in cases)
    script = """
import { readFileSync } from 'node:fs';
const values = JSON.parse(readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(values.map(([pattern, value]) => new RegExp(pattern).test(value))));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(checks),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [expected for _pattern, _value, expected in checks]


def test_core_fingerprint_boundaries_match_actual_javascript():
    node = shutil.which("node")
    if node is None or not (ROOT / "packages/executor/dist/inventory-manifest.js").is_file():
        pytest.fail("Inventory contract tests require Node >=22.13 and npm run build at repo root")
    cases = [("a" * 64, True), ("a" * 64 + "\n", False), ("a" * 63, False), ("a" * 65, False)]
    snapshots = []
    for fingerprint, accepted in cases:
        snapshot = json.loads(
            (ROOT / "integrations/cartography/tests/fixtures/alpha-v1.json").read_text()
        )
        snapshot["tools"][0]["fingerprint"] = fingerprint
        snapshots.append(snapshot)
        assert validator("snapshot").is_valid(snapshot) == accepted
        if accepted:
            assert validate_snapshot(snapshot) == snapshot
        else:
            with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
                validate_snapshot(snapshot)
    script = """
import { readFileSync } from 'node:fs';
import { composeInventorySnapshot } from './packages/executor/dist/inventory-manifest.js';
const values = JSON.parse(readFileSync(0, 'utf8'));
const result = values.map(value => {
  try {
    composeInventorySnapshot(value, { schemaVersion: 1, evidenceKind: 'host_asserted',
      source: value.source, manifestId: 'fingerprint-check', revision: 1,
      observedAt: value.generatedAt, agents: [], deployments: [], taskBindings: [],
      resourceBindings: [], executionBindings: [] });
    return true;
  } catch (error) {
    if (error.code !== 'INVENTORY_SNAPSHOT_INVALID') throw error;
    return false;
  }
});
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(snapshots),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [accepted for _fingerprint, accepted in cases]


@pytest.mark.parametrize("kind", ["manifest", "snapshot", "mcp"])
def test_timestamp_patterns_match_javascript_without_optional_format_checkers(kind):
    node = shutil.which("node")
    if node is None:
        pytest.fail("Inventory contract tests require Node >=22.13")
    cases = [
        ("2026-10-30T00:00:00Z", True),
        ("2026-10-30T00:00:00.1Z", True),
        ("2026-10-30T00:00:00.123456Z", True),
        ("2026-10-30T00:00:00.1234567Z", False),
        ("2026-10-30T00:00:00Z\n", False),
        ("٢٠٢٦-١٠-٣٠T٠٠:٠٠:٠٠Z", False),
        ("2026-10-30T00:00:00.١Z", False),
    ]
    public = {
        "manifest": validate_manifest,
        "snapshot": validate_snapshot,
        "mcp": validate_mcp_inventory,
    }[kind]
    for timestamp, accepted in cases:
        if kind == "manifest":
            value = host_snapshot()["manifest"]
            value["observedAt"] = timestamp
        elif kind == "snapshot":
            value = json.loads(
                (ROOT / "integrations/cartography/tests/fixtures/alpha-v1.json").read_text()
            )
            value["generatedAt"] = timestamp
        else:
            value = inventory(mcp_snapshot())
            value["observedAt"] = timestamp
        assert validator(kind).is_valid(value) == accepted
        if accepted:
            assert public(value) == value
        else:
            with pytest.raises(InventoryValidationError, match="^INVENTORY_SCHEMA_INVALID$"):
                public(value)
    definition = json.loads((ROOT / "schemas" / SCHEMAS[kind]).read_text())["$defs"]["timestamp"]
    script = """
import { readFileSync } from 'node:fs';
const { pattern, values } = JSON.parse(readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(values.map(value => new RegExp(pattern).test(value))));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(
            {"pattern": definition["pattern"], "values": [value for value, _ in cases]}
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [accepted for _value, accepted in cases]
