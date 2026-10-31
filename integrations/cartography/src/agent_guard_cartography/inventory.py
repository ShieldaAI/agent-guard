"""Validate bounded, single-tenant Agent Guard core, host and MCP inventory profiles.

Validation checks the transport contract and structural consistency. It does not
evaluate grants, invoke tool implementations, or decide whether an action is allowed.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from agent_guard_cartography.input_files import read_regular_file

MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_VALUES = 200_000
MAX_MCP_CONNECTION_BYTES = 2 * 1024 * 1024
MAX_MCP_OPERATIONS = 10_000
MAX_JSON_DEPTH = 32
MAX_JSON_VALUES = 500_000
MAX_RESOURCE_SELECTORS = 100_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
SCHEMA_FILENAME = "agent-guard-inventory-v1.schema.json"
MANIFEST_SCHEMA_FILENAME = "agent-guard-inventory-manifest-v1.schema.json"
MCP_SCHEMA_FILENAME = "agent-guard-mcp-inventory-v1.schema.json"
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


class InventoryValidationError(ValueError):
    """A stable error code that never contains imported values or file paths."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise InventoryValidationError(code)


@lru_cache(maxsize=3)
def _validator(filename: str = SCHEMA_FILENAME) -> Draft202012Validator:
    # Editable installs can expose both source modules and an older packaged
    # schema. Prefer the canonical schema only in this exact repository layout.
    # Installed wheels always use their bundled resource, independent of cwd.
    module_path = Path(__file__).resolve()
    expected_suffix = (
        "integrations",
        "cartography",
        "src",
        "agent_guard_cartography",
        "inventory.py",
    )
    if module_path.parts[-5:] == expected_suffix:
        canonical = module_path.parents[4] / "schemas" / filename
        try:
            schema_text = canonical.read_text(encoding="utf-8")
        except OSError:
            raise InventoryValidationError("INVENTORY_SCHEMA_UNAVAILABLE") from None
    else:
        packaged = resources.files("agent_guard_cartography").joinpath("schemas", filename)
        try:
            schema_text = packaged.read_text(encoding="utf-8")
        except OSError:
            raise InventoryValidationError("INVENTORY_SCHEMA_UNAVAILABLE") from None
    schema = json.loads(schema_text)
    Draft202012Validator.check_schema(schema)
    formats = FormatChecker()

    @formats.checks("date-time", raises=(ValueError, OverflowError))
    def utc_timestamp(value: Any) -> bool:
        # jsonschema's RFC3339 support otherwise depends on an optional extra.
        if not isinstance(value, str):
            return True
        if UTC_TIMESTAMP.fullmatch(value) is None:
            return False
        datetime.fromisoformat(value)
        return True

    return Draft202012Validator(schema, format_checker=formats)


def _check_json_shape(
    value: Any, maximum_bytes: int = MAX_SNAPSHOT_BYTES, maximum_values: int = MAX_JSON_VALUES
) -> None:
    """Bound depth/work before serialization; reject non-JSON Python values."""
    count = 0
    text_bytes = 0
    active: set[int] = set()

    def check_text(text: str) -> None:
        nonlocal text_bytes
        if len(text) > maximum_bytes:
            _fail("INVENTORY_LIMIT_EXCEEDED")
        try:
            text_bytes += len(text.encode("utf-8"))
        except UnicodeError:
            raise InventoryValidationError("INVENTORY_JSON_INVALID") from None
        if text_bytes > maximum_bytes:
            _fail("INVENTORY_LIMIT_EXCEEDED")

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > maximum_values or depth > MAX_JSON_DEPTH:
            _fail("INVENTORY_LIMIT_EXCEEDED")
        if type(item) is str:
            check_text(item)
            return
        if type(item) is int and abs(item) > MAX_SAFE_INTEGER:
            _fail("INVENTORY_SCHEMA_INVALID")
        if type(item) in (int, float, bool) or item is None:
            return
        if type(item) not in (dict, list):
            _fail("INVENTORY_JSON_INVALID")
        identity = id(item)
        if identity in active:
            _fail("INVENTORY_JSON_INVALID")
        active.add(identity)
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    _fail("INVENTORY_JSON_INVALID")
                check_text(key)
                visit(child, depth + 1)
        else:
            for child in item:
                visit(child, depth + 1)
        active.remove(identity)

    visit(value, 0)


def _unique_records(records: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        identifier = record[key]
        if identifier in result:
            _fail("INVENTORY_DUPLICATE_ID")
        result[identifier] = record
    return result


def _check_graph(snapshot: dict[str, Any]) -> None:
    tasks = _unique_records(snapshot["tasks"], "id")
    _unique_records(snapshot["tools"], "name")
    tenant = snapshot["source"]["tenantId"]
    selectors = 0
    family_sensitivity: dict[str, bool] = {}

    for task in tasks.values():
        if task["tenantId"] != tenant:
            _fail("INVENTORY_TENANT_MISMATCH")
        family = task["familyId"]
        if family in family_sensitivity and family_sensitivity[family] != task["sensitive"]:
            _fail("INVENTORY_FAMILY_INVALID")
        family_sensitivity[family] = task["sensitive"]
        granted_tools: set[str] = set()
        for grant in task["grants"]:
            if grant["tool"] in granted_tools:
                _fail("INVENTORY_DUPLICATE_GRANT")
            granted_tools.add(grant["tool"])
            selectors += len(grant["resources"])
            if selectors > MAX_RESOURCE_SELECTORS:
                _fail("INVENTORY_LIMIT_EXCEEDED")

        for field in ("parentTaskId", "sourceTaskId"):
            related_id = task[field]
            if related_id is None:
                continue
            if related_id not in tasks:
                _fail("INVENTORY_REFERENCE_INVALID")
            related = tasks[related_id]
            if related["familyId"] != family:
                _fail("INVENTORY_FAMILY_INVALID")
            if field == "parentTaskId" and related["principalId"] != task["principalId"]:
                _fail("INVENTORY_PRINCIPAL_INVALID")

    # Parent and provenance are different relationships, but their union must
    # remain acyclic: both reference tasks that already existed at creation.
    state: dict[str, int] = {}
    for task_id in tasks:
        if state.get(task_id) == 2:
            continue
        stack = [(task_id, False)]
        while stack:
            current, exiting = stack.pop()
            if exiting:
                state[current] = 2
                continue
            if state.get(current) == 1:
                _fail("INVENTORY_REFERENCE_CYCLE")
            if state.get(current) == 2:
                continue
            state[current] = 1
            stack.append((current, True))
            for field in ("parentTaskId", "sourceTaskId"):
                related_id = tasks[current][field]
                if related_id is not None:
                    stack.append((related_id, False))


def _detached_json(value: Any, maximum_bytes: int, maximum_values: int) -> Any:
    _check_json_shape(value, maximum_bytes, maximum_values)
    try:
        serialized = json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise InventoryValidationError("INVENTORY_JSON_INVALID") from None
    if len(serialized) > maximum_bytes:
        _fail("INVENTORY_LIMIT_EXCEEDED")
    return json.loads(serialized)


def _aws_reference(value: dict, *, identity: bool = False) -> tuple[str, str]:
    arn = value["arn"]
    if re.search(r"[\s\x1c-\x1f\x85\ufeff*?]", arn):
        _fail("INVENTORY_MANIFEST_ARN_INVALID")
    match = re.fullmatch(
        r"arn:(aws|aws-cn|aws-us-gov):([a-z0-9][a-z0-9-]*):([^:]*):([^:]*):(.+)", arn
    )
    if match is None:
        _fail("INVENTORY_MANIFEST_ARN_INVALID")
    partition, service, region, account, resource = match.groups()
    if partition != value["partition"] or region != value["region"]:
        _fail("INVENTORY_MANIFEST_ARN_INVALID")
    if service == "s3":
        if region or account:
            _fail("INVENTORY_MANIFEST_ARN_INVALID")
    elif account != value["accountId"]:
        _fail("INVENTORY_MANIFEST_ARN_INVALID")
    if identity:
        iam = (
            service == "iam"
            and not region
            and re.fullmatch(r"(?:role|user)/(?:[^/]+/)*[^/]+", resource)
        )
        sts = (
            service == "sts" and not region and re.fullmatch(r"assumed-role/[^/]+/[^/]+", resource)
        )
        if not (iam or sts):
            _fail("INVENTORY_MANIFEST_ARN_INVALID")
    return service, resource


def _check_manifest(manifest: dict) -> None:
    agents = _unique_records(manifest["agents"], "id")
    deployments = _unique_records(manifest["deployments"], "id")
    _unique_records(manifest["taskBindings"], "taskId")
    _unique_records(manifest["resourceBindings"], "id")
    _unique_records(manifest["executionBindings"], "id")
    for deployment in deployments.values():
        if deployment["agentId"] not in agents:
            _fail("INVENTORY_MANIFEST_REFERENCE_INVALID")
    for binding in manifest["taskBindings"]:
        if binding["deploymentId"] not in deployments:
            _fail("INVENTORY_MANIFEST_REFERENCE_INVALID")
    resources = set()
    for binding in manifest["resourceBindings"]:
        pair = (binding["tool"], binding["resourceRef"])
        if pair in resources or binding["resourceRef"] == "*":
            _fail("INVENTORY_MANIFEST_BINDING_INVALID")
        resources.add(pair)
        service, resource = _aws_reference(binding["target"])
        kind = binding["target"]["kind"]
        if service == "s3":
            bucket, separator, key = resource.partition("/")
            valid = bool(bucket) and (
                (kind == "bucket" and not separator and binding["scope"] == "exact")
                or (kind == "object" and bool(key) and binding["scope"] == "exact")
                or (
                    kind == "prefix"
                    and bool(key)
                    and key.endswith("/")
                    and binding["scope"] == "prefix"
                )
            )
        else:
            valid = kind == "resource" and binding["scope"] == "exact"
        if not valid or any(action.split(":", 1)[0] != service for action in binding["actions"]):
            _fail("INVENTORY_MANIFEST_BINDING_INVALID")
    executions = set()
    for binding in manifest["executionBindings"]:
        pair = (binding["deploymentId"], binding["tool"])
        if pair in executions or binding["deploymentId"] not in deployments:
            _fail("INVENTORY_MANIFEST_BINDING_INVALID")
        executions.add(pair)
        if binding["identitySelection"] == "static":
            if binding["identity"] is None:
                _fail("INVENTORY_MANIFEST_BINDING_INVALID")
            _aws_reference(binding["identity"], identity=True)
        elif binding["identity"] is not None:
            _fail("INVENTORY_MANIFEST_BINDING_INVALID")


def validate_manifest(value: Any) -> dict[str, Any]:
    """Validate host assertions without interpreting them as runtime authority."""
    manifest = _detached_json(value, MAX_MANIFEST_BYTES, MAX_MANIFEST_VALUES)
    if next(_validator(MANIFEST_SCHEMA_FILENAME).iter_errors(manifest), None) is not None:
        _fail("INVENTORY_SCHEMA_INVALID")
    _check_manifest(manifest)
    return manifest


def _check_manifest_snapshot(snapshot: dict) -> None:
    manifest = validate_manifest(snapshot["manifest"])
    if manifest["source"] != snapshot["source"]:
        _fail("INVENTORY_MANIFEST_SOURCE_MISMATCH")
    if snapshot["coverage"]["manifest"]["observedAt"] != manifest["observedAt"]:
        _fail("INVENTORY_MANIFEST_COVERAGE_INVALID")
    tasks = {task["id"] for task in snapshot["tasks"]}
    tools = {tool["name"] for tool in snapshot["tools"]}
    resources = set()
    for task in snapshot["tasks"]:
        for grant in task["grants"]:
            tools.add(grant["tool"])
            resources.update((grant["tool"], resource) for resource in grant["resources"])
    if any(binding["taskId"] not in tasks for binding in manifest["taskBindings"]):
        _fail("INVENTORY_MANIFEST_REFERENCE_INVALID")
    for binding in manifest["resourceBindings"]:
        if (binding["tool"], binding["resourceRef"]) not in resources:
            _fail("INVENTORY_MANIFEST_REFERENCE_INVALID")
    if any(binding["tool"] not in tools for binding in manifest["executionBindings"]):
        _fail("INVENTORY_MANIFEST_REFERENCE_INVALID")


def validate_mcp_inventory(value: Any) -> dict[str, Any]:
    """Validate detached, descriptor-free MCP observations without granting authority."""
    inventory = _detached_json(value, MAX_MCP_CONNECTION_BYTES, MAX_JSON_VALUES)
    if next(_validator(MCP_SCHEMA_FILENAME).iter_errors(inventory), None) is not None:
        _fail("INVENTORY_SCHEMA_INVALID")
    _unique_records(inventory["operations"], "name")
    return inventory


def _check_mcp_snapshot(snapshot: dict) -> None:
    mcp = snapshot["mcp"]
    records = _unique_records(mcp["connections"], "connectionId")
    expected: dict[str, set[str]] = {}
    for binding in snapshot["manifest"]["executionBindings"]:
        if binding["connectionId"] is not None:
            expected.setdefault(binding["connectionId"], set()).add(binding["tool"])
    if set(records) != set(expected):
        _fail("INVENTORY_MCP_REFERENCE_INVALID")
    tools = {tool["name"]: tool for tool in snapshot["tools"]}
    observed = 0
    operations = 0
    for connection_id, record in records.items():
        if record["status"] != "observed":
            continue
        inventory = validate_mcp_inventory(record["inventory"])
        if inventory["identity"]["tenantId"] != snapshot["source"]["tenantId"]:
            _fail("INVENTORY_MCP_SCOPE_MISMATCH")
        observed += 1
        operations += len(inventory["operations"])
        if operations > MAX_MCP_OPERATIONS:
            _fail("INVENTORY_LIMIT_EXCEEDED")
        for operation in inventory["operations"]:
            tool = tools.get(operation["name"])
            if operation["name"] not in expected[connection_id]:
                _fail("INVENTORY_MCP_REFERENCE_INVALID")
            if (
                tool is None
                or not tool["registered"]
                or tool["fingerprint"] != operation["fingerprint"]
            ):
                _fail("INVENTORY_MCP_REGISTRATION_MISMATCH")
    status = "complete" if observed == len(records) else "partial" if observed else "unavailable"
    if snapshot["coverage"]["mcp"] != {"status": status, "observedAt": mcp["observedAt"]}:
        _fail("INVENTORY_MCP_COVERAGE_INVALID")


def validate_snapshot(value: Any) -> dict[str, Any]:
    """Validate an inventory and return a detached JSON copy.

    The schema permits grants to unregistered tools: a grant does not establish
    that a corresponding implementation exists. Consumers must keep that state
    unknown instead of manufacturing tool metadata or a denial.
    """
    snapshot = _detached_json(value, MAX_SNAPSHOT_BYTES, MAX_JSON_VALUES)
    # Do not include jsonschema's exception text: it quotes imported properties,
    # which may contain secrets even though the schema refuses to accept them.
    if next(_validator().iter_errors(snapshot), None) is not None:
        _fail("INVENTORY_SCHEMA_INVALID")
    _check_graph(snapshot)
    if snapshot["profile"] in ("host", "host-mcp"):
        _check_manifest_snapshot(snapshot)
    if snapshot["profile"] == "host-mcp":
        _check_mcp_snapshot(snapshot)
    return snapshot


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("INVENTORY_DUPLICATE_KEY")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    _fail("INVENTORY_JSON_INVALID")


def load_snapshot(path: str | Path) -> dict[str, Any]:
    """Read at most 8 MiB and validate before any importer can write graph data."""
    try:
        contents = read_regular_file(path, MAX_SNAPSHOT_BYTES + 1)
    except OSError:
        raise InventoryValidationError("INVENTORY_READ_FAILED") from None
    if len(contents) > MAX_SNAPSHOT_BYTES:
        _fail("INVENTORY_LIMIT_EXCEEDED")
    try:
        value = json.loads(
            contents.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, InventoryValidationError):
            raise
        raise InventoryValidationError("INVENTORY_JSON_INVALID") from None
    return validate_snapshot(value)
