import { safeProperties } from '../projection-fields.js';
import type { JsonObject, MapNode, MapProjection, MapSource } from '../types.js';
import { ordered } from './ordering.js';
import { sections } from './schemas.js';
import {
  agentSummary,
  deployments,
  grantSummary,
  hostObservation,
  ownerSummary,
  relationshipRows,
  resourceSummary,
  taskSummary,
} from './summaries.js';
import { connected, number, QueryWork, string, strings } from './work.js';

export function inventorySections(
  source: MapSource,
  projection: MapProjection,
  agent: MapNode,
  work: QueryWork,
): Record<(typeof sections)[number], JsonObject[]> {
  const byLabel = (label: MapNode['label']): MapNode[] => projection.nodes.filter(node => node.label === label);
  const described = (label: MapNode['label']): JsonObject[] =>
    byLabel(label).map(node => ({ id: node.entityId, ...safeProperties(node) }));
  const summary = agentSummary(source, projection, agent, work);
  return {
    overview: [
      {
        purpose: summary.purpose!,
        lifecycleState: summary.lifecycleState!,
        ownershipStatus: summary.ownershipStatus!,
        ownershipSource: summary.ownershipSource!,
        ownerName: summary.ownerName!,
        ...hostObservation(agent),
      },
    ],
    owners: ordered(byLabel('GuardOwner').map(node => ownerSummary(source, projection, node, work, false))),
    deployments: ordered(
      byLabel('GuardDeployment').map(node => ({
        id: node.entityId,
        deploymentId: string(node, 'deployment_id'),
        environment: string(node, 'environment'),
        runtimeRef: string(node, 'runtime_ref'),
        workloadGeneration: string(node, 'workload_generation'),
        buildRef: string(node, 'build_ref'),
        bindingAuthority: string(node, 'binding_authority'),
        // The same rule as get_agent_access: `found` needs an entry in the read.
        directAccessStatus: connected(projection, new Set([node.id]), 'G_DIRECT_ACCESS_FOR', work, true).length
          ? 'found'
          : string(node, 'direct_access_status') === 'none_declared'
            ? 'none_declared'
            : 'unknown',
        ...hostObservation(node),
      })),
    ),
    tasks: ordered(byLabel('GuardTask').map(taskSummary)),
    permissions: ordered(byLabel('GuardGrant').map(grantSummary)),
    resources: ordered(byLabel('GuardResourceBinding').map(node => resourceSummary(source, projection, node, work))),
    connections: ordered(described('GuardMcpConnection')),
    credentials: ordered(
      byLabel('GuardCredentialReference').map(node => ({
        id: node.entityId,
        credentialId: string(node, 'credential_id'),
        name: string(node, 'name'),
        issuerRef: string(node, 'issuer_ref'),
        audienceRefs: strings(node, 'audience_refs'),
        recipientRefs: strings(node, 'recipient_refs'),
        lifecycleState: string(node, 'lifecycle_state') ?? 'unknown',
        expiresAt: string(node, 'expires_at'),
        rotationStatus: string(node, 'rotation_status') ?? 'unknown',
        ...hostObservation(node),
      })),
    ),
    relationships: relationshipRows(projection, work),
    tools: ordered(described('GuardTool')),
    bindings: ordered(
      projection.nodes
        .filter(node => ['GuardExecutionBinding', 'GuardResourceBinding'].includes(node.label))
        .map(node => ({ id: node.entityId, kind: node.label, ...safeProperties(node) })),
    ),
    identities: ordered(described('GuardExternalIdentity')),
    policies: [],
  };
}
