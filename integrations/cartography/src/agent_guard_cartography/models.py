"""Cartography 0.144.0 schemas for immutable core, host and MCP inventory projections.

Every entity belongs to exactly one GuardSnapshot. Cloud-provider labels are
deliberately absent: local resource selectors are not cloud permissions.
"""

from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties, CartographyNodeSchema
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    OtherRelationships,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class GuardRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class GuardRelationship(CartographyRelSchema):
    target_node_label: str = "GuardSnapshot"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("GuardSnapshotId", set_in_kwargs=True)}
    )
    direction: LinkDirection = LinkDirection.OUTWARD
    rel_label: str = "G_IN_SNAPSHOT"
    properties: GuardRelProperties = GuardRelProperties()


def relationship(label: str, target: str, field: str, *, many: bool = False) -> GuardRelationship:
    return GuardRelationship(
        target_node_label=target,
        target_node_matcher=make_target_node_matcher({"id": PropertyRef(field, one_to_many=many)}),
        rel_label=label,
    )


@dataclass(frozen=True)
class GuardProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    entity_id: PropertyRef = PropertyRef("entity_id")
    projection_id: PropertyRef = PropertyRef("projection_id", extra_index=True)
    source_id: PropertyRef = PropertyRef("source_id")
    tenant_id: PropertyRef = PropertyRef("tenant_id")


@dataclass(frozen=True)
class PrincipalProperties(GuardProperties):
    principal_id: PropertyRef = PropertyRef("principal_id")


@dataclass(frozen=True)
class ToolProperties(GuardProperties):
    name: PropertyRef = PropertyRef("name")
    fingerprint: PropertyRef = PropertyRef("fingerprint")
    revision: PropertyRef = PropertyRef("revision")
    registered: PropertyRef = PropertyRef("registered")
    approved: PropertyRef = PropertyRef("approved")
    known_metadata: PropertyRef = PropertyRef("known_metadata")
    requires_approval: PropertyRef = PropertyRef("requires_approval")
    control_plane: PropertyRef = PropertyRef("control_plane")
    max_cost: PropertyRef = PropertyRef("max_cost")


@dataclass(frozen=True)
class ResourceProperties(GuardProperties):
    resource_id: PropertyRef = PropertyRef("resource_id")
    tool: PropertyRef = PropertyRef("tool")
    selector_kind: PropertyRef = PropertyRef("selector_kind")


@dataclass(frozen=True)
class GrantProperties(GuardProperties):
    task_id: PropertyRef = PropertyRef("task_id")
    tool: PropertyRef = PropertyRef("tool")
    resources: PropertyRef = PropertyRef("resources")
    evidence_kind: PropertyRef = PropertyRef("evidence_kind")
    assessment: PropertyRef = PropertyRef("assessment")


@dataclass(frozen=True)
class TaskProperties(GuardProperties):
    task_id: PropertyRef = PropertyRef("task_id")
    principal_id: PropertyRef = PropertyRef("principal_id")
    family_id: PropertyRef = PropertyRef("family_id")
    revoked: PropertyRef = PropertyRef("revoked")
    sensitive: PropertyRef = PropertyRef("sensitive")
    allowed_recipients: PropertyRef = PropertyRef("allowed_recipients")
    allow_control_plane: PropertyRef = PropertyRef("allow_control_plane")
    max_calls: PropertyRef = PropertyRef("max_calls")
    max_concurrent: PropertyRef = PropertyRef("max_concurrent")
    max_cost: PropertyRef = PropertyRef("max_cost")
    deadline: PropertyRef = PropertyRef("deadline")
    calls: PropertyRef = PropertyRef("calls")
    concurrent: PropertyRef = PropertyRef("concurrent")
    spent: PropertyRef = PropertyRef("spent")
    reserved: PropertyRef = PropertyRef("reserved")


@dataclass(frozen=True)
class HostProperties(GuardProperties):
    evidence_kind: PropertyRef = PropertyRef("evidence_kind")
    manifest_id: PropertyRef = PropertyRef("manifest_id")
    manifest_revision: PropertyRef = PropertyRef("manifest_revision")
    manifest_observed_at: PropertyRef = PropertyRef("manifest_observed_at")
    assessment: PropertyRef = PropertyRef("assessment")


@dataclass(frozen=True)
class AgentProperties(HostProperties):
    agent_id: PropertyRef = PropertyRef("agent_id")
    name: PropertyRef = PropertyRef("name")
    owner_id: PropertyRef = PropertyRef("owner_id")
    team_id: PropertyRef = PropertyRef("team_id")


@dataclass(frozen=True)
class DeploymentProperties(HostProperties):
    deployment_id: PropertyRef = PropertyRef("deployment_id")
    environment: PropertyRef = PropertyRef("environment")


@dataclass(frozen=True)
class ExternalIdentityProperties(HostProperties):
    provider: PropertyRef = PropertyRef("provider")
    partition: PropertyRef = PropertyRef("partition")
    account_id: PropertyRef = PropertyRef("account_id")
    region: PropertyRef = PropertyRef("region")
    arn: PropertyRef = PropertyRef("arn")


@dataclass(frozen=True)
class ExternalResourceProperties(ExternalIdentityProperties):
    kind: PropertyRef = PropertyRef("kind")


@dataclass(frozen=True)
class ResourceBindingProperties(HostProperties):
    binding_id: PropertyRef = PropertyRef("binding_id")
    tool: PropertyRef = PropertyRef("tool")
    resource_ref: PropertyRef = PropertyRef("resource_ref")
    actions: PropertyRef = PropertyRef("actions")
    scope: PropertyRef = PropertyRef("scope")


@dataclass(frozen=True)
class ExecutionBindingProperties(HostProperties):
    binding_id: PropertyRef = PropertyRef("binding_id")
    tool: PropertyRef = PropertyRef("tool")
    connection_id: PropertyRef = PropertyRef("connection_id")
    identity_selection: PropertyRef = PropertyRef("identity_selection")


@dataclass(frozen=True)
class McpConnectionProperties(GuardProperties):
    connection_id: PropertyRef = PropertyRef("connection_id")
    capture_status: PropertyRef = PropertyRef("capture_status")
    unavailable_reason: PropertyRef = PropertyRef("unavailable_reason")
    capture_observed_at: PropertyRef = PropertyRef("capture_observed_at")
    server_id: PropertyRef = PropertyRef("server_id")
    transport_ref: PropertyRef = PropertyRef("transport_ref")
    principal_id: PropertyRef = PropertyRef("principal_id")
    session_id: PropertyRef = PropertyRef("session_id")
    revision: PropertyRef = PropertyRef("revision")
    authorization_epoch: PropertyRef = PropertyRef("authorization_epoch")
    metadata_revision: PropertyRef = PropertyRef("metadata_revision")
    state: PropertyRef = PropertyRef("state")
    metadata_state: PropertyRef = PropertyRef("metadata_state")
    observed_at: PropertyRef = PropertyRef("observed_at")
    evidence_kind: PropertyRef = PropertyRef("evidence_kind")
    assessment: PropertyRef = PropertyRef("assessment")


@dataclass(frozen=True)
class McpOperationProperties(GuardProperties):
    connection_id: PropertyRef = PropertyRef("connection_id")
    name: PropertyRef = PropertyRef("name")
    kind: PropertyRef = PropertyRef("kind")
    fingerprint: PropertyRef = PropertyRef("fingerprint")
    evidence_kind: PropertyRef = PropertyRef("evidence_kind")
    assessment: PropertyRef = PropertyRef("assessment")


@dataclass(frozen=True)
class GuardSchema(CartographyNodeSchema):
    label: str = "GuardPrincipal"
    properties: CartographyNodeProperties = PrincipalProperties()
    sub_resource_relationship: GuardRelationship = GuardRelationship()
    other_relationships: OtherRelationships | None = None
    scoped_cleanup: bool = True


SCHEMAS: dict[str, GuardSchema] = {
    "GuardPrincipal": GuardSchema(),
    "GuardTool": GuardSchema(label="GuardTool", properties=ToolProperties()),
    "GuardResource": GuardSchema(label="GuardResource", properties=ResourceProperties()),
    "GuardGrant": GuardSchema(
        label="GuardGrant",
        properties=GrantProperties(),
        other_relationships=OtherRelationships(
            [
                relationship("G_FOR_TOOL", "GuardTool", "tool_node_id"),
                relationship("G_TARGETS", "GuardResource", "resource_node_ids", many=True),
            ]
        ),
    ),
    "GuardTask": GuardSchema(
        label="GuardTask",
        properties=TaskProperties(),
        other_relationships=OtherRelationships(
            [
                relationship("G_ACTS_AS", "GuardPrincipal", "principal_node_id"),
                relationship("G_DELEGATED_FROM", "GuardTask", "parent_node_id"),
                relationship("G_DERIVED_FROM", "GuardTask", "source_task_node_id"),
                relationship("G_HAS_GRANT", "GuardGrant", "grant_node_ids", many=True),
                relationship("G_ASSIGNED_TO", "GuardDeployment", "deployment_node_id"),
            ]
        ),
    ),
    "GuardAgent": GuardSchema(label="GuardAgent", properties=AgentProperties()),
    "GuardDeployment": GuardSchema(
        label="GuardDeployment",
        properties=DeploymentProperties(),
        other_relationships=OtherRelationships(
            [
                relationship("G_INSTANCE_OF", "GuardAgent", "agent_node_id"),
            ]
        ),
    ),
    "GuardExternalResource": GuardSchema(
        label="GuardExternalResource", properties=ExternalResourceProperties()
    ),
    "GuardExternalIdentity": GuardSchema(
        label="GuardExternalIdentity", properties=ExternalIdentityProperties()
    ),
    "GuardResourceBinding": GuardSchema(
        label="GuardResourceBinding",
        properties=ResourceBindingProperties(),
        other_relationships=OtherRelationships(
            [
                relationship("G_BINDS_SELECTOR", "GuardResource", "resource_node_id"),
                relationship("G_MAPS_TO", "GuardExternalResource", "external_resource_node_id"),
            ]
        ),
    ),
    "GuardExecutionBinding": GuardSchema(
        label="GuardExecutionBinding",
        properties=ExecutionBindingProperties(),
        other_relationships=OtherRelationships(
            [
                relationship("G_EXECUTES_FOR", "GuardDeployment", "deployment_node_id"),
                relationship("G_EXECUTES_TOOL", "GuardTool", "tool_node_id"),
                relationship("G_USES_IDENTITY", "GuardExternalIdentity", "identity_node_id"),
                relationship("G_VIA_CONNECTION", "GuardMcpConnection", "connection_node_id"),
            ]
        ),
    ),
    "GuardMcpConnection": GuardSchema(
        label="GuardMcpConnection",
        properties=McpConnectionProperties(),
        other_relationships=OtherRelationships(
            [
                relationship(
                    "G_EXPOSES_OPERATION", "GuardMcpOperation", "operation_node_ids", many=True
                )
            ]
        ),
    ),
    "GuardMcpOperation": GuardSchema(
        label="GuardMcpOperation",
        properties=McpOperationProperties(),
        other_relationships=OtherRelationships(
            [relationship("G_OPERATION_TOOL", "GuardTool", "tool_node_id")]
        ),
    ),
}

PROJECTION_LABELS = tuple(SCHEMAS)
