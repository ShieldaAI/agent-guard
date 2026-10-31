"""File-backed compatibility spike: versioned projections and atomic publication.

The caller owns the Neo4j session and must serialize collection in deployment.
CAS publication additionally prevents an older in-flight import from replacing
a newer view. None of these operations grants execution authority.
"""

import json
import time
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Any
from uuid import uuid4

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from neo4j import Session, unit_of_work

from agent_guard_cartography.cloud import (
    CloudJoinError,
    CloudScope,
    check_cloud_scope,
    collect_cloud,
    publish_cloud,
    unavailable_cloud,
    validate_cloud_scope,
)
from agent_guard_cartography.inventory import validate_snapshot
from agent_guard_cartography.models import PROJECTION_LABELS, SCHEMAS

MAX_MCP_CONNECTION_RECEIPTS = 128
MAX_MCP_RETIRED_SESSIONS = 64
MAX_MCP_WATERMARK_BYTES = 1024 * 1024


class GraphImportError(RuntimeError):
    """Stable error codes deliberately omit imported values and credentials."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ImportResult:
    source_id: str
    projection_id: str
    snapshot_id: str
    published: bool
    idempotent: bool


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _key(*parts: Any) -> str:
    return sha256(_canonical(parts).encode()).hexdigest()


def source_key(source: Mapping[str, str]) -> str:
    """Canonical scope key; caller configuration must match the entire source."""
    return _key("source", dict(source))


def _authority_hash(snapshot: dict) -> str:
    """A ledger revision cannot describe two different core authority states."""
    tasks = deepcopy(snapshot["tasks"])
    for task in tasks:
        task["allowedRecipients"].sort()
        task["grants"].sort(key=lambda grant: grant["tool"])
        for grant in task["grants"]:
            grant["resources"].sort()
    return _key(
        snapshot["policyEpoch"],
        sorted(tasks, key=lambda task: task["id"]),
        sorted(snapshot["tools"], key=lambda tool: tool["name"]),
    )


def _manifest_hash(manifest: dict) -> str:
    """Manifest revisions are independent of ledger revisions and capture times."""
    normalized = deepcopy(manifest)
    normalized.pop("observedAt")
    for field in ("agents", "deployments", "resourceBindings", "executionBindings"):
        normalized[field].sort(key=lambda item: item["id"])
    normalized["taskBindings"].sort(key=lambda item: item["taskId"])
    for binding in normalized["resourceBindings"]:
        binding["actions"].sort()
    return _key(normalized)


def _manifest_properties(snapshot: dict) -> dict:
    manifest = snapshot.get("manifest")
    if manifest is None:
        return {}
    return {
        "manifest_id": manifest["manifestId"],
        "manifest_revision": manifest["revision"],
        "manifest_hash": _manifest_hash(manifest),
        "manifest_observed_at": manifest["observedAt"],
    }


def _mcp_properties(snapshot: dict) -> dict:
    if snapshot["profile"] != "host-mcp":
        return {}
    observations = {}
    manifest_hash = _manifest_hash(snapshot["manifest"])
    for record in snapshot["mcp"]["connections"]:
        connection = _key(record["connectionId"])
        if record["status"] == "unavailable":
            observations[connection] = None
            continue
        inventory = record["inventory"]
        lifecycle = {
            key: value
            for key, value in inventory.items()
            if key not in ("observedAt", "operations")
        }
        observations[connection] = {
            # Fixed-length hashes bound durable replay receipts even when host
            # identifiers are large. These receipts are never projected as authority.
            "session": _key(inventory["sessionId"]),
            "revision": inventory["revision"],
            "authorization_epoch": inventory["authorizationEpoch"],
            "metadata_revision": inventory["metadataRevision"],
            "lifecycle_hash": _key(lifecycle),
            "operations_hash": _key(sorted(inventory["operations"], key=lambda item: item["name"])),
            "manifest_hash": manifest_hash,
        }
    return {"mcp_observations_json": _canonical(observations)}


def _next_mcp_watermarks(current: Mapping, candidate: Mapping) -> str | None:
    """Keep bounded replay receipts independently of current capture availability."""
    if candidate["profile"] != "host-mcp":
        return None
    watermarks = json.loads(current.get("mcp_watermarks_json", "{}"))
    observations = json.loads(candidate["mcp_observations_json"])
    if len(set(watermarks) | set(observations)) > MAX_MCP_CONNECTION_RECEIPTS:
        raise GraphImportError("MCP_ENROLLMENT_ROTATION_REQUIRED")
    for connection, observation in observations.items():
        previous = watermarks.setdefault(connection, {"session": None, "retired": []})
        if observation is None:
            continue
        retired = list(previous["retired"])
        if observation["session"] in retired:
            raise GraphImportError("MCP_SESSION_REPLAY")
        if previous["session"] == observation["session"]:
            for field in ("revision", "authorization_epoch", "metadata_revision"):
                if observation[field] < previous[field]:
                    raise GraphImportError("MCP_REVISION_ROLLBACK")
            if observation["revision"] == previous["revision"]:
                if observation["lifecycle_hash"] != previous["lifecycle_hash"]:
                    raise GraphImportError("MCP_REVISION_CONTENT_CONFLICT")
                if (
                    observation["manifest_hash"] == previous["manifest_hash"]
                    and observation["operations_hash"] != previous["operations_hash"]
                ):
                    raise GraphImportError("MCP_REVISION_CONTENT_CONFLICT")
        elif previous["session"] is not None:
            if len(retired) >= MAX_MCP_RETIRED_SESSIONS:
                raise GraphImportError("MCP_ENROLLMENT_ROTATION_REQUIRED")
            retired.append(previous["session"])
        watermarks[connection] = {**observation, "retired": retired}
    serialized = _canonical(watermarks)
    if len(serialized.encode()) > MAX_MCP_WATERMARK_BYTES:
        raise GraphImportError("MCP_ENROLLMENT_ROTATION_REQUIRED")
    return serialized


def _check_component_versions(current: Mapping, candidate: Mapping) -> None:
    profile = current.get("profile")
    # Existing pre-manifest published sources used the core profile implicitly.
    if profile is None and current.get("current_snapshot_id") is not None:
        profile = "core"
    if profile is not None and profile != candidate["profile"]:
        raise GraphImportError("PROFILE_CONFLICT")
    if candidate["profile"] not in ("host", "host-mcp"):
        return
    if current.get("manifest_id") not in (None, candidate["manifest_id"]):
        raise GraphImportError("MANIFEST_ID_CONFLICT")
    if candidate["manifest_revision"] < current.get("manifest_revision", -1):
        raise GraphImportError("MANIFEST_REVISION_ROLLBACK")
    if candidate["manifest_revision"] == current.get("manifest_revision") and candidate[
        "manifest_hash"
    ] != current.get("manifest_hash"):
        raise GraphImportError("MANIFEST_CONTENT_CONFLICT")


def ensure_constraints(session: Session) -> None:
    for label in ("GuardSource", "GuardSnapshot", *PROJECTION_LABELS):
        # Labels are a static module allowlist, never input strings.
        session.run(
            f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.id IS UNIQUE"
        ).consume()


def build_rows(snapshot: dict, projection_id: str, scoped_source_id: str) -> dict[str, list[dict]]:
    """Project only known schema fields; selectors and identities remain local."""
    rows: dict[str, dict[str, dict]] = {label: {} for label in PROJECTION_LABELS}
    tenant_id = snapshot["source"]["tenantId"]
    manifest = snapshot.get("manifest")
    assignments = (
        {binding["taskId"]: binding["deploymentId"] for binding in manifest["taskBindings"]}
        if manifest
        else {}
    )

    def make(label: str, native: Any, **properties: Any) -> dict:
        logical_id = _key(scoped_source_id, label, native)
        item = {
            "id": _key(projection_id, logical_id),
            "entity_id": logical_id,
            "projection_id": projection_id,
            "source_id": scoped_source_id,
            "tenant_id": tenant_id,
            **properties,
        }
        rows[label][item["id"]] = item
        return item

    def node_id(label: str, native: Any) -> str:
        return _key(projection_id, _key(scoped_source_id, label, native))

    known_tools = {tool["name"]: tool for tool in snapshot["tools"]}
    tool_names = set(known_tools)
    tool_names.update(grant["tool"] for task in snapshot["tasks"] for grant in task["grants"])
    for name in sorted(tool_names):
        tool = known_tools.get(name)
        make(
            "GuardTool",
            name,
            name=name,
            known_metadata=tool is not None,
            fingerprint=tool["fingerprint"] if tool else None,
            revision=tool["revision"] if tool else None,
            registered=tool["registered"] if tool else None,
            approved=tool["approved"] if tool else None,
            requires_approval=tool["requiresApproval"] if tool else None,
            control_plane=tool["controlPlane"] if tool else None,
            max_cost=tool["maxCost"] if tool else None,
        )

    for task in snapshot["tasks"]:
        principal = make("GuardPrincipal", task["principalId"], principal_id=task["principalId"])
        grants = []
        for grant in task["grants"]:
            resource_nodes = []
            for resource in sorted(grant["resources"]):
                resource_nodes.append(
                    make(
                        "GuardResource",
                        [grant["tool"], resource],
                        resource_id=resource,
                        tool=grant["tool"],
                        selector_kind="wildcard" if resource == "*" else "exact",
                    )["id"]
                )
            grant_node = make(
                "GuardGrant",
                [task["id"], grant["tool"]],
                task_id=task["id"],
                tool=grant["tool"],
                resources=sorted(grant["resources"]),
                tool_node_id=node_id("GuardTool", grant["tool"]),
                resource_node_ids=resource_nodes,
                evidence_kind="declared",
                assessment="unknown",
            )
            grants.append(grant_node["id"])
        make(
            "GuardTask",
            task["id"],
            task_id=task["id"],
            principal_id=task["principalId"],
            principal_node_id=principal["id"],
            deployment_node_id=node_id("GuardDeployment", assignments[task["id"]])
            if task["id"] in assignments
            else None,
            family_id=task["familyId"],
            parent_node_id=node_id("GuardTask", task["parentTaskId"])
            if task["parentTaskId"]
            else None,
            source_task_node_id=node_id("GuardTask", task["sourceTaskId"])
            if task["sourceTaskId"]
            else None,
            grant_node_ids=grants,
            revoked=task["revoked"],
            sensitive=task["sensitive"],
            allowed_recipients=task["allowedRecipients"],
            allow_control_plane=task["allowControlPlane"],
            max_calls=task["budget"]["maxCalls"],
            max_concurrent=task["budget"]["maxConcurrent"],
            max_cost=task["budget"]["maxCost"],
            deadline=task["budget"]["deadline"],
            **task["usage"],
        )
    if manifest:
        evidence = {
            "evidence_kind": "host_asserted",
            "manifest_id": manifest["manifestId"],
            "manifest_revision": manifest["revision"],
            "manifest_observed_at": manifest["observedAt"],
            "assessment": "unknown",
        }

        def external(label: str, value: dict) -> dict:
            # Keep account, partition, kind and exact ARN in identity. Host ownership
            # assertions never merge into provider nodes or imply IAM permission.
            return make(
                label,
                value,
                provider=value["provider"],
                partition=value["partition"],
                account_id=value["accountId"],
                region=value["region"],
                arn=value["arn"],
                **({"kind": value["kind"]} if "kind" in value else {}),
                **evidence,
            )

        for agent in manifest["agents"]:
            make(
                "GuardAgent",
                agent["id"],
                agent_id=agent["id"],
                name=agent["name"],
                owner_id=agent["ownerId"],
                team_id=agent["teamId"],
                **evidence,
            )
        for deployment in manifest["deployments"]:
            make(
                "GuardDeployment",
                deployment["id"],
                deployment_id=deployment["id"],
                environment=deployment["environment"],
                agent_node_id=node_id("GuardAgent", deployment["agentId"]),
                **evidence,
            )
        for binding in manifest["resourceBindings"]:
            target = external("GuardExternalResource", binding["target"])
            make(
                "GuardResourceBinding",
                binding["id"],
                binding_id=binding["id"],
                tool=binding["tool"],
                resource_ref=binding["resourceRef"],
                actions=sorted(binding["actions"]),
                scope=binding["scope"],
                resource_node_id=node_id(
                    "GuardResource", [binding["tool"], binding["resourceRef"]]
                ),
                external_resource_node_id=target["id"],
                **evidence,
            )
        for binding in manifest["executionBindings"]:
            identity = (
                external("GuardExternalIdentity", binding["identity"])
                if binding["identity"]
                else None
            )
            make(
                "GuardExecutionBinding",
                binding["id"],
                binding_id=binding["id"],
                tool=binding["tool"],
                connection_id=binding["connectionId"],
                identity_selection=binding["identitySelection"],
                deployment_node_id=node_id("GuardDeployment", binding["deploymentId"]),
                tool_node_id=node_id("GuardTool", binding["tool"]),
                identity_node_id=identity["id"] if identity else None,
                connection_node_id=node_id("GuardMcpConnection", binding["connectionId"])
                if snapshot["profile"] == "host-mcp" and binding["connectionId"] is not None
                else None,
                **evidence,
            )
    if snapshot["profile"] == "host-mcp":
        for connection in snapshot["mcp"]["connections"]:
            inventory = connection.get("inventory", {})
            identity = inventory.get("identity", {})
            operation_ids = []
            for operation in inventory.get("operations", []):
                operation_ids.append(
                    make(
                        "GuardMcpOperation",
                        [connection["connectionId"], operation["name"], operation["kind"]],
                        connection_id=connection["connectionId"],
                        name=operation["name"],
                        kind=operation["kind"],
                        fingerprint=operation["fingerprint"],
                        tool_node_id=node_id("GuardTool", operation["name"]),
                        evidence_kind="observed",
                        assessment="unknown",
                    )["id"]
                )
            make(
                "GuardMcpConnection",
                connection["connectionId"],
                connection_id=connection["connectionId"],
                capture_status=connection["status"],
                unavailable_reason=connection.get("reason"),
                capture_observed_at=snapshot["mcp"]["observedAt"],
                server_id=identity.get("serverId"),
                transport_ref=identity.get("transportRef"),
                principal_id=identity.get("principalId"),
                session_id=inventory.get("sessionId"),
                revision=inventory.get("revision"),
                authorization_epoch=inventory.get("authorizationEpoch"),
                metadata_revision=inventory.get("metadataRevision"),
                state=inventory.get("state"),
                metadata_state=inventory.get("metadataState"),
                observed_at=inventory.get("observedAt"),
                operation_node_ids=operation_ids,
                evidence_kind="observed" if inventory else "unavailable",
                assessment="unknown",
            )
    return {label: list(items.values()) for label, items in rows.items()}


def _lock_source(tx: Any, source_id: str) -> dict:
    row = tx.run(
        "MATCH (s:GuardSource {id:$id}) SET s.lock_revision=coalesce(s.lock_revision,0)+1 RETURN s",
        id=source_id,
    ).single()
    if row is None:
        raise GraphImportError("SOURCE_MISSING")
    return dict(row["s"])


def _check_source_lifecycle(source: Mapping) -> None:
    if source.get("lifecycle_status") == "superseded":
        raise GraphImportError("SOURCE_SUPERSEDED")
    if source.get("lifecycle_status") not in (None, "active"):
        raise GraphImportError("SOURCE_LIFECYCLE_INVALID")


def _begin(
    tx: Any,
    snapshot: dict,
    source_id: str,
    projection_id: str,
    content_hash: str,
    authority_hash: str,
    update_tag: int,
) -> tuple[str | None, ImportResult | None]:
    source = snapshot["source"]
    tx.run(
        "MERGE (s:GuardSource {id:$id}) ON CREATE SET s += $properties",
        id=source_id,
        properties={
            "company_id": source["companyId"],
            "native_source_id": source["sourceId"],
            "enrollment_generation": source["enrollmentGeneration"],
            "inventory_instance_id": source["inventoryInstanceId"],
            "tenant_id": source["tenantId"],
            "profile": snapshot["profile"],
        },
    ).consume()
    current = _lock_source(tx, source_id)
    # Supersession is a durable replay fence, including already-known receipts.
    _check_source_lifecycle(current)
    component = {
        "profile": snapshot["profile"],
        **_manifest_properties(snapshot),
        **_mcp_properties(snapshot),
    }
    receipts = list(
        tx.run(
            "MATCH (p:GuardSnapshot {source_id:$source_id,snapshot_id:$snapshot_id}) "
            "RETURN p.id AS id,p.content_hash AS hash,p.status AS status",
            source_id=source_id,
            snapshot_id=snapshot["snapshotId"],
        )
    )
    if any(row["hash"] != content_hash for row in receipts):
        raise GraphImportError("SNAPSHOT_ID_CONFLICT")
    published = next((row for row in receipts if row["status"] in ("published", "retired")), None)
    if published is not None:
        return None, ImportResult(source_id, published["id"], snapshot["snapshotId"], False, True)
    _check_component_versions(current, component)
    _next_mcp_watermarks(current, component)
    if snapshot["ledgerRevision"] < current.get("ledger_revision", -1):
        raise GraphImportError("REVISION_ROLLBACK")
    if snapshot["policyEpoch"] < current.get("policy_epoch", -1):
        raise GraphImportError("POLICY_EPOCH_ROLLBACK")
    if snapshot["ledgerRevision"] == current.get(
        "ledger_revision"
    ) and authority_hash != current.get("authority_hash"):
        raise GraphImportError("REVISION_CONTENT_CONFLICT")
    tx.run(
        "MATCH (s:GuardSource {id:$source_id}) "
        "CREATE (p:GuardSnapshot {id:$id}) SET p += $properties "
        "CREATE (p)-[:G_FROM_SOURCE]->(s)",
        source_id=source_id,
        id=projection_id,
        properties={
            "source_id": source_id,
            "snapshot_id": snapshot["snapshotId"],
            "content_hash": content_hash,
            "authority_hash": authority_hash,
            "status": "staging",
            "update_tag": update_tag,
            "ledger_revision": snapshot["ledgerRevision"],
            "policy_epoch": snapshot["policyEpoch"],
            "generated_at": snapshot["generatedAt"],
            "created_at_ms": int(time.time() * 1000),
            "coverage_json": _canonical(snapshot["coverage"]),
            "tenant_id": source["tenantId"],
            **component,
        },
    ).consume()
    return current.get("current_snapshot_id"), None


@unit_of_work(timeout=30)
def _publish(
    tx: Any,
    source_id: str,
    projection_id: str,
    expected_current: str | None,
    counts: Mapping[str, int],
    edges: Mapping[str, tuple[str, str, list[dict]]],
    cloud_capture: dict | None = None,
) -> None:
    source = _lock_source(tx, source_id)
    _check_source_lifecycle(source)
    if source.get("current_snapshot_id") != expected_current:
        raise GraphImportError("PUBLICATION_CONFLICT")
    row = tx.run(
        "MATCH (p:GuardSnapshot {id:$id,source_id:$source,status:'staging'}) RETURN p",
        id=projection_id,
        source=source_id,
    ).single()
    if row is None:
        raise GraphImportError("PROJECTION_NOT_STAGING")
    projection = row["p"]
    _check_component_versions(source, projection)
    mcp_watermarks = _next_mcp_watermarks(source, projection)
    if projection["ledger_revision"] < source.get("ledger_revision", -1):
        raise GraphImportError("REVISION_ROLLBACK")
    for label, expected in counts.items():
        actual = tx.run(
            f"MATCH (n:{label})-[:G_IN_SNAPSHOT]->(p:GuardSnapshot {{id:$id}}) "
            "WHERE n.source_id=$source AND n.projection_id=$id "
            "RETURN count(n) AS count,count(DISTINCT n) AS distinct_count",
            id=projection_id,
            source=source_id,
        ).single()
        # A duplicate membership must not compensate for another missing node.
        if actual["count"] != expected or actual["distinct_count"] != expected:
            raise GraphImportError("PROJECTION_COUNT_MISMATCH")
    for rel, (source_label, target_label, pairs) in edges.items():
        # Every expected endpoint pair must be present, and the total edge count
        # must equal the number of unique expected pairs. Together these require
        # exactly one edge per pair; duplicates cannot hide missing endpoints.
        actual = tx.run(
            f"MATCH (n:{source_label})-[r:{rel}]->() "
            "WHERE n.projection_id=$id RETURN count(r) AS count",
            id=projection_id,
        ).single()["count"]
        matched = tx.run(
            "UNWIND $pairs AS pair "
            f"MATCH (n:{source_label} {{id:pair.source}})-[r:{rel}]->"
            f"(m:{target_label} {{id:pair.target}}) "
            "WHERE n.projection_id=$id AND n.source_id=$source "
            "RETURN count(DISTINCT pair) AS count",
            pairs=pairs,
            id=projection_id,
            source=source_id,
        ).single()["count"]
        if actual != len(pairs) or matched != len(pairs):
            raise GraphImportError("PROJECTION_RELATIONSHIP_MISMATCH")
    publish_cloud(tx, source_id, projection_id, cloud_capture)
    tx.run(
        "MATCH (s:GuardSource {id:$source}),(p:GuardSnapshot {id:$projection}) "
        "SET s.previous_snapshot_id=s.current_snapshot_id,s.current_snapshot_id=p.id, "
        "s.ledger_revision=p.ledger_revision,s.policy_epoch=p.policy_epoch, "
        "s.authority_hash=p.authority_hash, "
        "s.profile=p.profile,s.manifest_id=p.manifest_id,s.manifest_revision=p.manifest_revision, "
        "s.manifest_hash=p.manifest_hash,s.manifest_observed_at=p.manifest_observed_at, "
        "s.mcp_watermarks_json=$mcp_watermarks, "
        "p.status='published',p.published_at_ms=$now",
        source=source_id,
        projection=projection_id,
        now=int(time.time() * 1000),
        mcp_watermarks=mcp_watermarks,
    ).consume()


def import_snapshot(
    session: Session,
    snapshot: dict,
    expected_source: Mapping[str, str],
    *,
    update_tag: int | None = None,
    after_load: Callable[[], None] | None = None,
    cloud_scope: CloudScope | dict | None = None,
) -> ImportResult:
    """Import one complete core, host or host-mcp snapshot with mandatory source scope.

    ``after_load`` is a host-side fault-injection hook for this compatibility
    spike. It runs before validation/publication and is never snapshot input.
    """
    snapshot = validate_snapshot(snapshot)
    if dict(expected_source) != snapshot["source"]:
        raise GraphImportError("SOURCE_SCOPE_MISMATCH")
    if cloud_scope is not None:
        cloud_scope = validate_cloud_scope(cloud_scope)
        check_cloud_scope(cloud_scope, snapshot["source"])
    tag = int(time.time()) if update_tag is None else update_tag
    if type(tag) is not int or not 0 <= tag <= 2**53 - 1:
        raise GraphImportError("UPDATE_TAG_INVALID")
    source_id = source_key(expected_source)
    projection_id = _key(source_id, snapshot["snapshotId"], str(uuid4()))
    content_hash = sha256(_canonical(snapshot).encode()).hexdigest()
    rows = build_rows(snapshot, projection_id, source_id)
    cloud_capture = collect_cloud(session, rows, cloud_scope) if cloud_scope is not None else None
    ensure_constraints(session)
    previous, duplicate = session.execute_write(
        _begin, snapshot, source_id, projection_id, content_hash, _authority_hash(snapshot), tag
    )
    if duplicate is not None:
        return duplicate
    edges: dict[str, tuple[str, str, list[dict]]] = {}
    for relation, source_label, target_label, field in (
        ("G_ACTS_AS", "GuardTask", "GuardPrincipal", "principal_node_id"),
        ("G_HAS_GRANT", "GuardTask", "GuardGrant", "grant_node_ids"),
        ("G_FOR_TOOL", "GuardGrant", "GuardTool", "tool_node_id"),
        ("G_TARGETS", "GuardGrant", "GuardResource", "resource_node_ids"),
        ("G_DELEGATED_FROM", "GuardTask", "GuardTask", "parent_node_id"),
        ("G_DERIVED_FROM", "GuardTask", "GuardTask", "source_task_node_id"),
        ("G_ASSIGNED_TO", "GuardTask", "GuardDeployment", "deployment_node_id"),
        ("G_INSTANCE_OF", "GuardDeployment", "GuardAgent", "agent_node_id"),
        ("G_BINDS_SELECTOR", "GuardResourceBinding", "GuardResource", "resource_node_id"),
        ("G_MAPS_TO", "GuardResourceBinding", "GuardExternalResource", "external_resource_node_id"),
        ("G_EXECUTES_FOR", "GuardExecutionBinding", "GuardDeployment", "deployment_node_id"),
        ("G_EXECUTES_TOOL", "GuardExecutionBinding", "GuardTool", "tool_node_id"),
        ("G_USES_IDENTITY", "GuardExecutionBinding", "GuardExternalIdentity", "identity_node_id"),
        ("G_VIA_CONNECTION", "GuardExecutionBinding", "GuardMcpConnection", "connection_node_id"),
        ("G_EXPOSES_OPERATION", "GuardMcpConnection", "GuardMcpOperation", "operation_node_ids"),
        ("G_OPERATION_TOOL", "GuardMcpOperation", "GuardTool", "tool_node_id"),
    ):
        pairs = []
        for item in rows[source_label]:
            targets = item[field] if isinstance(item[field], list) else [item[field]]
            pairs.extend(
                {"source": item["id"], "target": target}
                for target in set(targets)
                if target is not None
            )
        edges[relation] = (source_label, target_label, pairs)
    try:
        # First create all endpoints. A second pass creates relationships, so
        # parent ordering in a snapshot cannot silently drop delegation links.
        for label, schema in SCHEMAS.items():
            load(
                session,
                replace(schema, other_relationships=None),
                rows[label],
                lastupdated=tag,
                GuardSnapshotId=projection_id,
            )
        for label, schema in SCHEMAS.items():
            if schema.other_relationships is not None:
                load(session, schema, rows[label], lastupdated=tag, GuardSnapshotId=projection_id)
        cleanup_projection_rows(session, projection_id, tag)
        if after_load is not None:
            after_load()
        publication = (
            source_id,
            projection_id,
            previous,
            {label: len(items) for label, items in rows.items()},
            edges,
        )
        try:
            session.execute_write(_publish, *publication, cloud_capture)
        except CloudJoinError as error:
            if error.code != "CLOUD_RECHECK_UNAVAILABLE" or cloud_capture is None:
                raise
            # The first publication transaction rolled back. Retry once with
            # no provider reads/links and the same CAS, preserving fresh core
            # evidence while making the optional component unavailable.
            session.execute_write(_publish, *publication, unavailable_cloud(cloud_capture))
    except BaseException:
        # Best effort only. A committed publication must never be relabeled by
        # response/retry uncertainty; staging/failed data remain unpublished.
        try:
            session.run(
                "MATCH (p:GuardSnapshot {id:$id}) WHERE p.status IN ['staging','cleaning'] "
                "SET p.status='failed'",
                id=projection_id,
            ).consume()
        except Exception:
            pass
        raise
    return ImportResult(source_id, projection_id, snapshot["snapshotId"], True, False)


def _claim_cleanup(tx: Any, projection_id: str, statuses: tuple[str, ...]) -> tuple[str, int]:
    row = tx.run("MATCH (p:GuardSnapshot {id:$id}) RETURN p", id=projection_id).single()
    if row is None:
        raise GraphImportError("PROJECTION_MISSING")
    projection = dict(row["p"])
    source = _lock_source(tx, projection["source_id"])
    # Read the mutable status again after acquiring the source lock; another
    # publication/cleanup may have committed while this transaction waited.
    projection = dict(
        tx.run("MATCH (p:GuardSnapshot {id:$id}) RETURN p", id=projection_id).single()["p"]
    )
    if projection_id in (source.get("current_snapshot_id"), source.get("previous_snapshot_id")):
        raise GraphImportError("PROJECTION_PROTECTED")
    if projection["status"] not in statuses:
        raise GraphImportError("PROJECTION_NOT_STAGING")
    tx.run("MATCH (p:GuardSnapshot {id:$id}) SET p.status='cleaning'", id=projection_id).consume()
    return projection["source_id"], projection["update_tag"]


def cleanup_projection_rows(session: Session, projection_id: str, update_tag: int) -> None:
    """Exercise Cartography cleanup only inside an unpublished generation."""
    session.execute_write(_claim_cleanup, projection_id, ("staging",))
    try:
        for schema in SCHEMAS.values():
            GraphJob.from_node_schema(
                schema,
                {"UPDATE_TAG": update_tag, "GuardSnapshotId": projection_id},
                cascade_delete=False,
            ).run(session)
    except BaseException:
        session.run(
            "MATCH (p:GuardSnapshot {id:$id}) SET p.status='failed'", id=projection_id
        ).consume()
        raise
    session.run(
        "MATCH (p:GuardSnapshot {id:$id,status:'cleaning'}) SET p.status='staging'",
        id=projection_id,
    ).consume()


def cleanup_staging(session: Session, projection_id: str) -> None:
    """Discard a failed or staging generation, preserving its import receipt."""
    _, update_tag = session.execute_write(
        _claim_cleanup, projection_id, ("staging", "failed", "cleaning")
    )
    try:
        for schema in SCHEMAS.values():
            GraphJob.from_node_schema(
                schema,
                {"UPDATE_TAG": update_tag + 1, "GuardSnapshotId": projection_id},
                cascade_delete=False,
            ).run(session)
    except BaseException:
        try:
            session.run(
                "MATCH (p:GuardSnapshot {id:$id,status:'cleaning'}) SET p.status='failed'",
                id=projection_id,
            ).consume()
        except Exception:
            pass
        raise
    session.run(
        "MATCH (p:GuardSnapshot {id:$id,status:'cleaning'}) SET p.status='discarded'",
        id=projection_id,
    ).consume()


def retire_projection(
    session: Session, projection_id: str, *, minimum_retention_seconds: int = 60
) -> None:
    """Retire old published rows; active source current/previous views are protected.

    The default is a configurable grace period, not a guarantee for external
    readers. A future query service must coordinate its cursor lifetime.
    Tests may explicitly select zero because no user-facing cursors exist.
    """
    if type(minimum_retention_seconds) is not int or minimum_retention_seconds < 0:
        raise GraphImportError("RETENTION_INVALID")

    def retire(tx: Any) -> None:
        row = tx.run("MATCH (p:GuardSnapshot {id:$id}) RETURN p", id=projection_id).single()
        if row is None:
            raise GraphImportError("PROJECTION_MISSING")
        projection = dict(row["p"])
        source = _lock_source(tx, projection["source_id"])
        projection = dict(
            tx.run("MATCH (p:GuardSnapshot {id:$id}) RETURN p", id=projection_id).single()["p"]
        )
        superseded = source.get("lifecycle_status") == "superseded"
        if source.get("lifecycle_status") not in (None, "active", "superseded"):
            raise GraphImportError("SOURCE_LIFECYCLE_INVALID")
        if not superseded and projection_id in (
            source.get("current_snapshot_id"),
            source.get("previous_snapshot_id"),
        ):
            raise GraphImportError("PROJECTION_PROTECTED")
        if projection["status"] != "published":
            raise GraphImportError("PROJECTION_NOT_PUBLISHED")
        retained_since = projection["published_at_ms"]
        if superseded:
            stamp = source.get("superseded_at_ms")
            if type(stamp) is not int or not 0 <= stamp <= 253_402_300_799_999:
                raise GraphImportError("SOURCE_LIFECYCLE_INVALID")
            retained_since = max(retained_since, stamp)
        if int(time.time() * 1000) - retained_since < minimum_retention_seconds * 1000:
            raise GraphImportError("PROJECTION_RETENTION")
        for label in PROJECTION_LABELS:
            # Static labels + exact membership protect shared provider nodes,
            # even when they have a relationship to a retired Guard entity.
            tx.run(
                f"MATCH (n:{label})-[:G_IN_SNAPSHOT]->(p:GuardSnapshot {{id:$id}}) "
                "WHERE n.projection_id=$id AND n.source_id=$source DETACH DELETE n",
                id=projection_id,
                source=projection["source_id"],
            ).consume()
        tx.run(
            "MATCH (p:GuardSnapshot {id:$id}) SET p.status='retired'", id=projection_id
        ).consume()

    session.execute_write(retire)
