import { fail } from '../common.js';
import { safeProperties } from '../projection-fields.js';
import type { JsonObject, MapEdge, MapNode, MapProjection, MapSource, MapView } from '../types.js';
import { jsonObject } from './json.js';
import { ordered } from './ordering.js';
import { connected, matching, nodeIds, number, QueryWork, string, strings, unique } from './work.js';

export function hostObservation(node: MapNode): JsonObject {
  return {
    authorityId: string(node, 'authority_id'),
    manifestId: string(node, 'manifest_id'),
    manifestRevision: number(node, 'manifest_revision'),
    observedAt: string(node, 'manifest_observed_at'),
  };
}
export function deployments(projection: MapProjection, agent: MapNode, work: QueryWork): MapNode[] {
  return connected(projection, new Set([agent.id]), 'G_INSTANCE_OF', work, true).filter(
    node => node.label === 'GuardDeployment',
  );
}
export function agentSummary(
  source: MapSource,
  projection: MapProjection,
  agent: MapNode,
  work: QueryWork,
): JsonObject {
  const items = deployments(projection, agent, work).map(node => ({
    id: node.entityId,
    deploymentId: string(node, 'deployment_id'),
    environment: string(node, 'environment'),
  }));
  return {
    id: agent.entityId,
    agentId: string(agent, 'agent_id'),
    sourceId: source.id,
    name: string(agent, 'name'),
    ownerId: string(agent, 'owner_id'),
    teamId: string(agent, 'team_id'),
    purpose: string(agent, 'purpose'),
    lifecycleState: string(agent, 'lifecycle_state') ?? 'unknown',
    ownershipStatus: string(agent, 'ownership_status') ?? 'unknown',
    ownershipSource: string(agent, 'ownership_source'),
    ownerName:
      connected(projection, new Set([agent.id]), 'G_OWNED_BY', work)
        .filter(n => n.label === 'GuardOwner')
        .map(n => string(n, 'name'))[0] ?? null,
    ownershipObservedAt: string(agent, 'manifest_observed_at'),
    ...hostObservation(agent),
    environments: unique(items.map(item => item.environment).filter((item): item is string => item !== null)).sort(),
    deployments: items,
  };
}
export function taskSummary(node: MapNode): JsonObject {
  return {
    id: node.entityId,
    taskId: string(node, 'task_id'),
    principalId: string(node, 'principal_id'),
    revoked: node.properties.revoked ?? null,
    sensitive: node.properties.sensitive ?? null,
    usage: {
      calls: number(node, 'calls'),
      concurrent: number(node, 'concurrent'),
      spent: number(node, 'spent'),
      reserved: number(node, 'reserved'),
    },
    budget: {
      maxCalls: number(node, 'max_calls'),
      maxConcurrent: number(node, 'max_concurrent'),
      maxCost: number(node, 'max_cost'),
      deadline: number(node, 'deadline'),
    },
  };
}
export function grantSummary(node: MapNode): JsonObject {
  return {
    id: node.entityId,
    taskId: string(node, 'task_id'),
    tool: string(node, 'tool'),
    resources: strings(node, 'resources'),
    evidenceKind: 'declared',
    assessment: 'unknown',
  };
}
export function receipt(source: MapSource, projection = source.current): JsonObject {
  return {
    sourceId: source.id,
    tenantId: source.tenantId,
    profile: source.profile,
    projectionId: projection.id,
    snapshotId: projection.snapshotId,
    generatedAt: projection.generatedAt,
    coverage: jsonObject(projection.coverage),
  };
}
export function findSource(view: MapView, id: string): MapSource {
  const source = view.sources.find(item => item.id === id);
  if (!source) fail('MAP_NOT_FOUND');
  return source;
}
export function findAgent(projection: MapProjection, id: string): MapNode {
  const agent = projection.nodes.find(node => node.label === 'GuardAgent' && matching(node, id, 'agent_id'));
  if (!agent) fail('MAP_NOT_FOUND');
  return agent;
}

/** Keep the selected agent's neighborhood explicit; never expand through shared tools to other agents. */
/** An agent's own nodes and the edges among them, in projection order. */
export interface FocusedGraph {
  nodes: MapNode[];
  edges: MapEdge[];
}
export function focus(projection: MapProjection, agent: MapNode, work: QueryWork): FocusedGraph {
  const deployment = deployments(projection, agent, work);
  const tasks = connected(projection, nodeIds(deployment), 'G_ASSIGNED_TO', work, true);
  const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true);
  const grants = connected(projection, nodeIds(tasks), 'G_HAS_GRANT', work);
  const resources = connected(projection, nodeIds(grants), 'G_TARGETS', work);
  const resourceBindings = connected(projection, nodeIds(resources), 'G_BINDS_SELECTOR', work, true);
  const tools = [
    ...connected(projection, nodeIds(grants), 'G_FOR_TOOL', work),
    ...connected(projection, nodeIds(executions), 'G_EXECUTES_TOOL', work),
  ];
  const connections = connected(projection, nodeIds(executions), 'G_VIA_CONNECTION', work),
    toolIds = nodeIds(tools);
  const operations = connected(projection, nodeIds(connections), 'G_EXPOSES_OPERATION', work).filter(operation =>
    connected(projection, new Set([operation.id]), 'G_OPERATION_TOOL', work).some(tool => toolIds.has(tool.id)),
  );
  const selected = nodeIds([
    agent,
    ...deployment,
    ...tasks,
    ...executions,
    ...grants,
    ...resources,
    ...resourceBindings,
    ...tools,
    ...connections,
    ...operations,
    ...connected(projection, nodeIds(tasks), 'G_ACTS_AS', work),
    ...connected(projection, new Set([agent.id]), 'G_OWNED_BY', work),
    ...connected(projection, nodeIds(resourceBindings), 'G_RESOURCE_OWNED_BY', work),
    ...connected(projection, nodeIds(deployment), 'G_USES_CREDENTIAL', work),
    ...connected(projection, nodeIds(deployment), 'G_DIRECT_ACCESS_FOR', work, true),
    ...connected(projection, nodeIds(executions), 'G_USES_IDENTITY', work),
    ...connected(projection, nodeIds(resourceBindings), 'G_MAPS_TO', work),
  ]);
  // Build the subgraph from the index instead of scanning the whole projection per agent:
  // the same nodes and edges in projection order, at a cost proportional to this subgraph.
  const index = work.index(projection),
    nodePositions: number[] = [],
    edgePositions: number[] = [];
  for (const id of selected) {
    nodePositions.push(...(index.nodePositions.get(id) ?? []));
    const outgoing = index.edgesFrom.get(id) ?? [];
    work.step(1 + outgoing.length);
    for (const position of outgoing) if (selected.has(projection.edges[position]!.target)) edgePositions.push(position);
  }
  nodePositions.sort((a, b) => a - b);
  edgePositions.sort((a, b) => a - b);
  return {
    nodes: nodePositions.map(position => projection.nodes[position]!),
    edges: edgePositions.map(position => projection.edges[position]!),
  };
}

export function freshness(observedAt: unknown, now: number, staleSeconds: number): JsonObject {
  const captured = typeof observedAt === 'string' ? Date.parse(observedAt) : NaN,
    age = now - captured;
  return {
    stale: !Number.isFinite(captured) || age < -60_000 || age > staleSeconds * 1000,
    ageSeconds: Number.isFinite(captured) ? Math.max(0, Math.floor(age / 1000)) : null,
  };
}
export function changeSummary(node: MapNode): JsonObject {
  return {
    entityId: node.entityId,
    label: node.label,
    name:
      string(node, 'name') ??
      string(node, 'display_name') ??
      string(node, 'description') ??
      string(node, 'task_id') ??
      string(node, 'agent_id') ??
      string(node, 'deployment_id') ??
      string(node, 'binding_id') ??
      string(node, 'connection_id') ??
      string(node, 'resource_id') ??
      string(node, 'tool') ??
      node.entityId,
  };
}

export const collection = Object.freeze({
  approvals: 'not_collected',
  requestTimeDecisions: 'not_collected',
  backendReceipts: 'not_collected',
  externalPolicyHistory: 'not_collected',
});
/**
 * `counts` only over a whole scoped projection (list_owners). Over one agent's neighborhood
 * they would count that agent alone, so the agent inventory leaves them out.
 */
export function ownerSummary(
  source: MapSource,
  projection: MapProjection,
  node: MapNode,
  work: QueryWork,
  counts = true,
): JsonObject {
  return {
    id: node.entityId,
    ownerId: string(node, 'owner_id'),
    name: string(node, 'name'),
    kind: string(node, 'kind'),
    sourceId: source.id,
    ...hostObservation(node),
    ...(counts
      ? {
          agentCount: connected(projection, new Set([node.id]), 'G_OWNED_BY', work, true).filter(
            n => n.label === 'GuardAgent',
          ).length,
          resourceCount: connected(projection, new Set([node.id]), 'G_RESOURCE_OWNED_BY', work, true).filter(
            n => n.label === 'GuardResourceBinding',
          ).length,
        }
      : {}),
  };
}
export function resourceSummary(
  source: MapSource,
  projection: MapProjection,
  node: MapNode,
  work: QueryWork,
): JsonObject {
  return {
    id: node.entityId,
    bindingId: string(node, 'binding_id'),
    sourceId: source.id,
    displayName: string(node, 'display_name') ?? string(node, 'resource_ref'),
    tool: string(node, 'tool'),
    resourceRef: string(node, 'resource_ref'),
    scope: string(node, 'scope'),
    actions: strings(node, 'actions'),
    ownerId: string(node, 'owner_id'),
    ownerName:
      connected(projection, new Set([node.id]), 'G_RESOURCE_OWNED_BY', work)
        .filter(n => n.label === 'GuardOwner')
        .map(n => string(n, 'name'))[0] ?? null,
    ownershipStatus: string(node, 'ownership_status') ?? 'unknown',
    ownershipSource: string(node, 'ownership_source'),
    sensitivity: string(node, 'sensitivity') ?? 'unknown',
    approvedDestinations: strings(node, 'approved_destinations'),
    targets: connected(projection, new Set([node.id]), 'G_MAPS_TO', work)
      .filter(n => n.label === 'GuardExternalResource')
      .map(n => ({ id: n.entityId, ...safeProperties(n) })),
    dependencies: connected(projection, new Set([node.id]), 'G_DEPENDS_ON', work)
      .filter(n => n.label === 'GuardResourceBinding')
      .map(n => ({
        id: n.entityId,
        bindingId: string(n, 'binding_id'),
        displayName: string(n, 'display_name') ?? string(n, 'resource_ref'),
      })),
    ...hostObservation(node),
  };
}
export function relationshipRows(projection: MapProjection, work: QueryWork): JsonObject[] {
  const index = work.index(projection);
  work.step(projection.edges.length);
  return ordered(
    projection.edges.flatMap(edge => {
      const source = index.nodes.get(edge.source),
        target = index.nodes.get(edge.target);
      return source && target
        ? [
            {
              source: source.entityId,
              target: target.entityId,
              kind: edge.kind,
              sourceName: changeSummary(source).name!,
              sourceLabel: source.label,
              targetName: changeSummary(target).name!,
              targetLabel: target.label,
            },
          ]
        : [];
    }),
  );
}
