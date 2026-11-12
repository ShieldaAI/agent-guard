import type { Json } from '@shieldaai/agent-guard';
import { canonicalJson } from '@shieldaai/agent-guard/internal';
import { fail } from '../common.js';
import { safeProperties } from '../projection-fields.js';
import type { JsonObject, JsonValue, MapNode, MapProjection, MapSource, ReadScope } from '../types.js';
import { compare, ordered, page } from './ordering.js';
import { targetVisibility } from './outside-guard.js';
import { changeSummary, collection, focus, receipt, relationshipRows } from './summaries.js';
import { connected, matching, nodeIds, QueryWork, string } from './work.js';

export const IGNORE_DIFF = new Set([
  'lastupdated',
  'manifest_observed_at',
  'manifest_revision',
  'observed_at',
  'capture_observed_at',
  'cloud_observed_at',
  // Recorded since 1.0.0; they cannot change for a task, so they are never a change.
  'delegated',
  'derived',
]);
export function nodeState(node: MapNode, projection: MapProjection, work: QueryWork): string {
  const index = work.index(projection);
  const properties = Object.fromEntries(Object.entries(safeProperties(node)).filter(([key]) => !IGNORE_DIFF.has(key)));
  const edges = [...(index.outgoing.get(node.id)?.entries() ?? [])]
    .flatMap(([kind, targets]) => {
      work.step(targets.length);
      return targets.map(target => ({ kind, target: index.nodes.get(target)?.entityId ?? null }));
    })
    .sort((a, b) => compare(`${a.kind}:${a.target}`, `${b.kind}:${b.target}`));
  return canonicalJson({ properties, edges } as Json);
}
export function retainedChanges(
  source: MapSource,
  args: Readonly<Record<string, JsonValue>>,
  scope: ReadScope,
  work: QueryWork,
): JsonObject {
  const current = source.current,
    since = args.since ?? 'previous';
  const previous = [current.id, current.snapshotId].includes(since as string)
    ? current
    : source.previous &&
        (since === 'previous' || [source.previous.id, source.previous.snapshotId].includes(since as string))
      ? source.previous
      : null;
  const projections = previous && previous !== current ? [current, previous] : [current];
  const related = new Map<MapProjection, Map<string, JsonObject[]>>();
  for (const projection of projections) {
    const impacted = new Map<string, JsonObject[]>();
    for (const agent of projection.nodes.filter(node => node.label === 'GuardAgent')) {
      const brief = {
        id: agent.entityId,
        agentId: string(agent, 'agent_id'),
        name: string(agent, 'name'),
        sourceId: source.id,
      };
      for (const node of focus(projection, agent, work).nodes) {
        const owners = impacted.get(node.entityId) ?? [];
        owners.push(brief);
        impacted.set(node.entityId, owners);
      }
    }
    related.set(projection, impacted);
  }
  const selectedAgents = new Set<string>(),
    selectedResources = new Set<string>();
  for (const projection of projections) {
    for (const node of projection.nodes) {
      work.step();
      if (args.agentId && node.label === 'GuardAgent' && matching(node, args.agentId as string, 'agent_id'))
        selectedAgents.add(node.entityId);
      if (
        args.resourceId &&
        node.label === 'GuardResourceBinding' &&
        matching(node, args.resourceId as string, 'binding_id')
      ) {
        const selectors = connected(projection, new Set([node.id]), 'G_BINDS_SELECTOR', work);
        const grants = connected(projection, nodeIds(selectors), 'G_TARGETS', work, true);
        const tasks = connected(projection, nodeIds(grants), 'G_HAS_GRANT', work, true);
        const deployment = connected(projection, nodeIds(tasks), 'G_ASSIGNED_TO', work);
        const tools = connected(projection, nodeIds(grants), 'G_FOR_TOOL', work);
        const toolIds = nodeIds(tools);
        const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true).filter(execution =>
          connected(projection, new Set([execution.id]), 'G_EXECUTES_TOOL', work).some(tool => toolIds.has(tool.id)),
        );
        for (const item of [
          node,
          ...selectors,
          ...grants,
          ...tasks,
          ...deployment,
          ...tools,
          ...executions,
          ...connected(projection, new Set([node.id]), 'G_MAPS_TO', work),
          ...connected(projection, new Set([node.id]), 'G_RESOURCE_OWNED_BY', work),
          ...connected(projection, nodeIds(executions), 'G_USES_IDENTITY', work),
        ])
          selectedResources.add(item.entityId);
      }
    }
  }
  if ((args.agentId && !selectedAgents.size) || (args.resourceId && !selectedResources.size)) fail('MAP_NOT_FOUND');
  // Callers list the current snapshot's entries first, and the first entry for an id wins, so
  // a renamed agent appears under its current name.
  const uniqueAgents = (items: JsonObject[]): JsonObject[] => {
    const first = new Map<JsonValue | undefined, JsonObject>();
    for (const item of items) if (!first.has(item.id)) first.set(item.id, item);
    return ordered([...first.values()]);
  };
  const before = new Map(previous?.nodes.map(node => [node.entityId, node]) ?? []),
    after = new Map(current.nodes.map(node => [node.entityId, node]));
  const beforeEdges = previous ? relationshipRows(previous, work) : [],
    afterEdges = relationshipRows(current, work);
  const edgeKey = (edge: JsonObject): string => JSON.stringify([edge.source, edge.target, edge.kind]);
  const oldEdges = new Set(beforeEdges.map(edgeKey)),
    newEdges = new Set(afterEdges.map(edgeKey));
  const relationships = {
    added: previous ? afterEdges.filter(edge => !oldEdges.has(edgeKey(edge))) : [],
    removed: previous ? beforeEdges.filter(edge => !newEdges.has(edgeKey(edge))) : [],
  };
  const outgoing = (edges: JsonObject[]): Map<string, JsonObject[]> => {
    const result = new Map<string, JsonObject[]>();
    for (const edge of edges) {
      const list = result.get(edge.source as string) ?? [];
      list.push(edge);
      result.set(edge.source as string, list);
    }
    return result;
  };
  const oldOutgoing = outgoing(beforeEdges),
    newOutgoing = outgoing(afterEdges),
    changedOutgoing = outgoing([...relationships.added, ...relationships.removed]);
  // A declared path's target is shown only when that resource is in the reader's scope.
  const visibleNow = targetVisibility(current, scope, work),
    visibleBefore = previous ? targetVisibility(previous, scope, work) : visibleNow;
  const state = (
    node: MapNode | undefined,
    edges: Map<string, JsonObject[]>,
    visible: (target: string) => boolean,
  ): JsonObject | null =>
    node
      ? {
          properties: Object.fromEntries(
            Object.entries(safeProperties(node)).filter(
              ([key, value]) =>
                !IGNORE_DIFF.has(key) &&
                !(
                  node.label === 'GuardDirectAccess' &&
                  key === 'target_ref' &&
                  typeof value === 'string' &&
                  !visible(value)
                ),
            ),
          ),
          relationships: edges.get(node.entityId) ?? [],
        }
      : null;
  const details: JsonObject[] = [];
  if (previous)
    for (const id of new Set([...after.keys(), ...before.keys()])) {
      work.step();
      const old = before.get(id),
        node = after.get(id),
        display = node ?? old!;
      if (node && old && nodeState(node, current, work) === nodeState(old, previous, work)) continue;
      const oldState = state(old, oldOutgoing, visibleBefore),
        newState = state(node, newOutgoing, visibleNow);
      const oldProps = oldState?.properties as JsonObject | undefined,
        newProps = newState?.properties as JsonObject | undefined;
      const fields = [...new Set([...Object.keys(oldProps ?? {}), ...Object.keys(newProps ?? {})])]
        .filter(
          key => canonicalJson((oldProps?.[key] ?? null) as Json) !== canonicalJson((newProps?.[key] ?? null) as Json),
        )
        .sort();
      const edgeChanges = changedOutgoing.get(id) ?? [];
      const categories: string[] = [];
      if (
        display.label === 'GuardOwner' ||
        fields.some(field => ['owner_id', 'team_id', 'ownership_status', 'ownership_source'].includes(field)) ||
        edgeChanges.some(edge => ['G_OWNED_BY', 'G_RESOURCE_OWNED_BY'].includes(edge.kind as string))
      )
        categories.push('ownership');
      if (
        ['GuardGrant', 'GuardTool', 'GuardTask'].includes(display.label) ||
        edgeChanges.some(edge => ['G_HAS_GRANT', 'G_FOR_TOOL', 'G_TARGETS'].includes(edge.kind as string))
      )
        categories.push('permissions');
      if (
        [
          'GuardDeployment',
          'GuardResourceBinding',
          'GuardExecutionBinding',
          'GuardExternalResource',
          'GuardExternalIdentity',
          'GuardCredentialReference',
          'GuardMcpConnection',
          'GuardMcpOperation',
        ].includes(display.label) ||
        edgeChanges.some(
          edge =>
            ![
              'G_OWNED_BY',
              'G_RESOURCE_OWNED_BY',
              'G_HAS_GRANT',
              'G_FOR_TOOL',
              'G_TARGETS',
              'G_DIRECT_ACCESS_FOR',
            ].includes(edge.kind as string),
        )
      )
        categories.push('bindings');
      // Host-declared paths around the guard, and a deployment's declaration status.
      const outsideGuard =
        display.label === 'GuardDirectAccess' ||
        fields.includes('direct_access_status') ||
        edgeChanges.some(edge => edge.kind === 'G_DIRECT_ACCESS_FOR');
      if (outsideGuard) categories.push('outside_guard');
      if (!categories.length) categories.push('inventory');
      const affected = uniqueAgents([
        ...(related.get(current)?.get(id) ?? []),
        ...(related.get(previous)?.get(id) ?? []),
      ]);
      if (args.agentId && !affected.some(agent => selectedAgents.has(agent.id as string))) continue;
      if (args.resourceId && !selectedResources.has(id)) continue;
      if (args.changeKind && args.changeKind !== 'all' && !categories.includes(args.changeKind as string)) continue;
      const navigation =
        display.label === 'GuardOwner' && string(display, 'owner_id')
          ? {
              operation: 'list_agents',
              args: { sourceId: source.id, ownerId: string(display, 'owner_id') },
              scope: 'direct_current_ownership',
              limitation: 'Lists agents directly owned now; excludes indirect impact through resource ownership.',
            }
          : display.label === 'GuardResourceBinding' && node
            ? {
                operation: 'get_resource_access',
                args: { sourceId: source.id, resourceId: node.entityId },
                scope: 'current_observations',
              }
            : null;
      details.push({
        ...changeSummary(display),
        kind: !old ? 'added' : !node ? 'removed' : 'changed',
        categories,
        ...(outsideGuard ? { evidenceKind: 'declared' } : {}),
        changedFields: fields,
        before: oldState,
        after: newState,
        affectedAgents: affected.slice(0, 100),
        affectedAgentsTotal: affected.length,
        affectedAgentsTruncated: affected.length > 100,
        affectedAgentNavigation: navigation,
      });
    }
  ordered(details);
  const { items, ...pagination } = page(details, args);
  const explicitlyPaged = args.offset !== undefined || args.limit !== undefined;
  const companion = explicitlyPaged ? (items as JsonObject[]) : details;
  const changedIds = new Set(companion.map(item => item.entityId));
  const relevantEdge = (edge: JsonObject): boolean => changedIds.has(edge.source);
  const affected = uniqueAgents(
    companion.flatMap(item => [
      ...(related.get(current)?.get(item.entityId as string) ?? []),
      ...(previous ? (related.get(previous)?.get(item.entityId as string) ?? []) : []),
    ]),
  );
  return {
    sourceId: source.id,
    from: previous ? receipt(source, previous) : null,
    to: receipt(source),
    changes: Object.fromEntries(
      ['added', 'removed', 'changed'].map(kind => [
        kind,
        companion
          .filter(item => item.kind === kind)
          .map(item => ({ entityId: item.entityId!, label: item.label!, name: item.name! })),
      ]),
    ),
    details: items!,
    ...pagination,
    relationships: {
      added: relationships.added.filter(relevantEdge),
      removed: relationships.removed.filter(relevantEdge),
    },
    changeSummaryScope: explicitlyPaged ? 'page' : 'retained',
    affectedAgents: affected.slice(0, 100),
    affectedAgentsTotal: affected.length,
    affectedAgentsTruncated: affected.length > 100,
    coverageGap: previous === null,
    policyHistory: 'not_collected',
    collection,
    limitations: [
      'Net changes in authorized retained snapshots only; not an invocation or intermediate-event log.',
      'Declared permission and binding changes do not establish effective access gain or loss.',
      'Current IAM policy observations are separate from retained Guard snapshots; policy history is not collected.',
    ],
  };
}
