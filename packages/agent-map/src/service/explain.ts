import { safeProperties } from '../projection-fields.js';
import type { JsonObject, MapNode, MapProjection, ReadScope } from '../types.js';
import { jsonList } from './json.js';
import { policyCoverage, policyCoverageOf, selectedPolicy } from './policy.js';
import { grantSummary } from './summaries.js';
import { bindingKey, connected, nodeIds, number, QueryWork, string, strings, unique } from './work.js';

export function knownBlockers(task: MapNode, tool: MapNode | undefined, now: number): string[] {
  const blockers: string[] = [];
  if (task.properties.revoked === true) blockers.push('task_revoked');
  const deadline = number(task, 'deadline');
  if (deadline !== null && now >= deadline) blockers.push('deadline_expired');
  const calls = number(task, 'calls'),
    maxCalls = number(task, 'max_calls');
  if (calls !== null && maxCalls !== null && calls >= maxCalls) blockers.push('call_budget_exhausted');
  const concurrent = number(task, 'concurrent'),
    maxConcurrent = number(task, 'max_concurrent');
  if (concurrent !== null && maxConcurrent !== null && concurrent >= maxConcurrent)
    blockers.push('concurrency_full_at_capture');
  const spent = number(task, 'spent'),
    reserved = number(task, 'reserved'),
    maxCost = number(task, 'max_cost');
  const cost = tool ? number(tool, 'max_cost') : null;
  if (spent !== null && reserved !== null && maxCost !== null && cost !== null && spent + reserved + cost > maxCost)
    blockers.push('cost_budget_exceeded');
  if (tool?.properties.control_plane === true && task.properties.allow_control_plane === false)
    blockers.push('control_plane_disabled');
  return blockers;
}
export function externalEvidence(
  projection: MapProjection,
  task: MapNode,
  toolName: string,
  resourceId: string,
  work: QueryWork,
  policySelection: { action?: string; resourceBindingId?: string } = {},
): JsonObject {
  const deployment = connected(projection, new Set([task.id]), 'G_ASSIGNED_TO', work);
  const executions = connected(projection, nodeIds(deployment), 'G_EXECUTES_FOR', work, true).filter(
    node => string(node, 'tool') === toolName,
  );
  const bound = work.lookup(projection).bindings.get(bindingKey(toolName, resourceId)) ?? [];
  work.step(bound.length);
  const resources = bound.filter(
    node => !policySelection.resourceBindingId || node.entityId === policySelection.resourceBindingId,
  );
  const policy = selectedPolicy(projection, work, {
    task,
    executions,
    resources,
    ...(policySelection.action ? { action: policySelection.action } : {}),
  });
  return {
    // Allowlisted properties only, also for a host-provided store.
    executionBindings: executions.map(node => ({
      id: node.entityId,
      ...safeProperties(node),
      identities: connected(projection, new Set([node.id]), 'G_USES_IDENTITY', work).map(safeProperties),
      connections: connected(projection, new Set([node.id]), 'G_VIA_CONNECTION', work).map(safeProperties),
    })),
    resourceBindings: resources.map(node => ({
      id: node.entityId,
      ...safeProperties(node),
      targets: connected(projection, new Set([node.id]), 'G_MAPS_TO', work).map(safeProperties),
    })),
    policyEvidence: jsonList(policy),
    policyCoverage: policyCoverageOf(projection, policy),
    assessment: 'unknown',
    limitations: [
      'Host bindings and provider inventory are evidence, not effective cloud permissions.',
      'Container matches do not establish exact object or prefix access; missing evidence does not establish denial.',
    ],
  };
}
export const COMMON_UNKNOWN = [
  'live_authorization',
  'request_arguments_and_resolution',
  'custom_policy',
  'backend_authorization',
  'action_approval',
];
export function explain(
  projection: MapProjection,
  scope: ReadScope,
  task: MapNode,
  toolName: string,
  resourceId: string,
  now: number,
  work: QueryWork,
  policySelection: { action?: string; resourceBindingId?: string } = {},
): JsonObject {
  const index = work.index(projection),
    nodes = index.nodes;
  const tool = work.lookup(projection).tools.get(toolName);
  const blockers: string[] = [],
    matched: JsonObject[] = [],
    chain: JsonObject[] = [];
  const unknown = [...COMMON_UNKNOWN];
  if (!scope.allTeams) unknown.push('ancestor_evidence_outside_visible_scope');
  if (!tool || tool.properties.known_metadata === false || tool.properties.registered === false)
    blockers.push('tool_unregistered_at_capture');
  else if (tool.properties.registered !== true) unknown.push('tool_registration');
  if (tool?.properties.approved === false) blockers.push('tool_metadata_unapproved');
  else if (tool?.properties.approved !== true) unknown.push('tool_metadata_approval');
  const visited = new Set<string>();
  let current: MapNode | undefined = task;
  for (let depth = 0; current; depth++) {
    work.step();
    if (depth >= 16 || visited.has(current.id)) {
      unknown.push('delegation_depth_or_cycle');
      break;
    }
    visited.add(current.id);
    chain.push({ id: current.entityId, taskId: string(current, 'task_id') });
    blockers.push(...knownBlockers(current, tool, now));
    const grants = connected(projection, new Set([current.id]), 'G_HAS_GRANT', work).filter(
      node =>
        node.label === 'GuardGrant' &&
        string(node, 'tool') === toolName &&
        strings(node, 'resources').some(resource => resource === resourceId || resource === '*'),
    );
    if (!grants.length)
      blockers.push(current.id === task.id ? 'declared_grant_missing' : 'ancestor_declared_grant_missing');
    matched.push(...grants.map(grantSummary));
    const parents: readonly string[] = index.outgoing.get(current.id)?.get('G_DELEGATED_FROM') ?? [];
    work.step(parents.length);
    if (parents.length > 1) {
      unknown.push('delegation_evidence_ambiguous');
      break;
    }
    current = parents[0] ? nodes.get(parents[0]) : undefined;
  }
  if (task.properties.sensitive === true) unknown.push('sensitive_egress_and_recipient_checks');
  return {
    taskId: string(task, 'task_id'),
    tool: toolName,
    resourceId,
    assessment: blockers.length ? 'blocked' : 'unknown',
    evidenceKind: 'declared_and_observed',
    blockers: unique(blockers),
    unknownChecks: unique(unknown),
    delegation: chain,
    matchedGrants: matched,
    externalEvidence: externalEvidence(projection, task, toolName, resourceId, work, policySelection),
    limitations: [
      'Explanation only; no action was prepared or executed.',
      'A clear exported gate does not establish effective permission.',
    ],
  };
}
