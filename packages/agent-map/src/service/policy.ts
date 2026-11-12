import { Buffer } from 'node:buffer';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { compareCodePoints, fail } from '../common.js';
import {
  mapIdentifier,
  type JsonObject,
  type MapEdge,
  type MapNode,
  type MapPolicyEvidence,
  type MapProjection,
} from '../types.js';
import { connected, QueryWork, string, strings } from './work.js';

export const POLICY_ACTIONS: Readonly<Record<string, string>> = Object.freeze({
  's3:GetObject': 'CAN_READ',
  's3:PutObject': 'CAN_WRITE',
  's3:ListBucket': 'CAN_LIST',
});
export const POLICY_REASONS = Object.freeze({
  unavailable: [
    'binding_ambiguous',
    'cloud_unresolved',
    'provider_missing',
    'collection_invalid',
    'stale',
    'changed',
    'boundary_unresolved',
    'unsupported_policy',
    'evidence_invalid',
  ],
  not_collected: [
    'unsupported_action',
    'identity_not_static',
    'unsupported_binding',
    'cloud_not_collected',
    'collection_missing',
    'disabled',
  ],
});
export const POLICY_FIELDS = [
  'taskId',
  'deploymentId',
  'executionBindingId',
  'resourceBindingId',
  'identityId',
  'resourceId',
  'action',
  'status',
  'reason',
  'observedAt',
  'assessment',
  'candidates',
]
  .sort()
  .join(',');
export function policyObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
export function policyTime(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const instant = Date.parse(value);
  return (
    Number.isFinite(instant) &&
    instant >= 0 &&
    instant <= 253_402_300_799_999 &&
    new Date(instant).toISOString() === value
  );
}
/**
 * A copy made by `immutableJson` is plain JSON; the checks in `validatedPolicyEvidence` are what
 * establish that each entry has the record's shape, so nothing reads a field before they run.
 */
const policyList = (copy: unknown): readonly MapPolicyEvidence[] => copy as readonly MapPolicyEvidence[];
/** Custom stores receive the same closed output contract and binding-path checks. */
function validatedPolicyEvidence(projection: MapProjection, work: QueryWork): readonly MapPolicyEvidence[] {
  const rawInput = projection.policyEvidence;
  if (rawInput === undefined) return [];
  if (!Array.isArray(rawInput)) fail('MAP_UNAVAILABLE');
  if (rawInput.length > 512) fail('MAP_LIMIT_EXCEEDED');
  let input: readonly MapPolicyEvidence[];
  try {
    input = policyList(immutableJson(rawInput, 8, 100_000, 4 * 1024 * 1024));
  } catch {
    return fail('MAP_UNAVAILABLE');
  }
  work.step(projection.nodes.length);
  const entities = new Map(projection.nodes.map(node => [node.entityId, node]));
  if (input.length && entities.size !== projection.nodes.length) fail('MAP_UNAVAILABLE');
  const seen = new Set<string>(),
    result: MapPolicyEvidence[] = [];
  let materializedBytes = 0;
  const link = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length);
    return targets.includes(target.id);
  };
  const exactLink = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length);
    return targets.length === 1 && targets[0] === target.id;
  };
  // Tasks may have several grants and grants several selectors, but the
  // particular pair proving this record must not have duplicate relationships.
  const uniqueLink = (source: MapNode, target: MapNode, kind: MapEdge['kind']): boolean => {
    const targets = work.index(projection).outgoing.get(source.id)?.get(kind) ?? [];
    work.step(targets.length);
    return targets.filter(id => id === target.id).length === 1;
  };
  const endpoint = (id: unknown, label: MapNode['label']): MapNode => {
    mapIdentifier(id, 'MAP_UNAVAILABLE');
    const node = entities.get(id as string);
    if (!node || node.label !== label) fail('MAP_UNAVAILABLE');
    return node;
  };
  for (const raw of input) {
    work.step();
    if (
      !policyObject(raw) ||
      Object.keys(raw).sort().join(',') !== POLICY_FIELDS ||
      raw.assessment !== 'unknown' ||
      typeof raw.action !== 'string' ||
      (raw.observedAt !== null && !policyTime(raw.observedAt))
    )
      fail('MAP_UNAVAILABLE');
    mapIdentifier(raw.action, 'MAP_UNAVAILABLE');
    // Generic host actions carry no cloud-policy inference. Keep their explicit
    // unsupported observation readable without admitting a cloud candidate.
    const genericAction = !/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(raw.action);
    if (genericAction) {
      if (raw.status !== 'not_collected' || raw.reason !== 'unsupported_action') fail('MAP_UNAVAILABLE');
    }
    if (!Array.isArray(raw.candidates) || raw.candidates.length > 1) fail('MAP_UNAVAILABLE');
    if (raw.status === 'complete') {
      if (
        !policyTime(raw.observedAt) ||
        !POLICY_ACTIONS[raw.action] ||
        raw.reason !== (raw.candidates.length ? null : 'no_candidate')
      )
        fail('MAP_UNAVAILABLE');
    } else if (
      (raw.status !== 'unavailable' && raw.status !== 'not_collected') ||
      !POLICY_REASONS[raw.status].includes(raw.reason as string) ||
      raw.candidates.length
    )
      fail('MAP_UNAVAILABLE');
    for (const candidate of raw.candidates) {
      if (
        !policyObject(candidate) ||
        Object.keys(candidate).sort().join(',') !== 'conditionKeys,hasCondition,relationship,resourceScope' ||
        candidate.relationship !== POLICY_ACTIONS[raw.action] ||
        candidate.resourceScope !== 'bucket_summary' ||
        typeof candidate.hasCondition !== 'boolean' ||
        !Array.isArray(candidate.conditionKeys) ||
        candidate.conditionKeys.length > 128
      )
        fail('MAP_UNAVAILABLE');
      for (const key of candidate.conditionKeys) {
        work.step();
        mapIdentifier(key, 'MAP_UNAVAILABLE');
        if (Buffer.byteLength(key as string, 'utf8') > 256 || /[\u0000-\u001f]/.test(key as string))
          fail('MAP_UNAVAILABLE');
      }
      if (
        candidate.hasCondition !== !!candidate.conditionKeys.length ||
        JSON.stringify(candidate.conditionKeys) !==
          JSON.stringify([...new Set(candidate.conditionKeys as string[])].sort(compareCodePoints))
      )
        fail('MAP_UNAVAILABLE');
    }
    const task = endpoint(raw.taskId, 'GuardTask'),
      deployment = endpoint(raw.deploymentId, 'GuardDeployment');
    const execution = endpoint(raw.executionBindingId, 'GuardExecutionBinding'),
      resource = endpoint(raw.resourceBindingId, 'GuardResourceBinding');
    const tool = string(execution, 'tool');
    if (
      !tool ||
      string(resource, 'tool') !== tool ||
      !strings(resource, 'actions').includes(raw.action) ||
      !link(task, deployment, 'G_ASSIGNED_TO') ||
      !link(execution, deployment, 'G_EXECUTES_FOR')
    )
      fail('MAP_UNAVAILABLE');
    const tools = connected(projection, new Set([execution.id]), 'G_EXECUTES_TOOL', work).filter(
      node => node.label === 'GuardTool' && string(node, 'name') === tool,
    );
    const grants = connected(projection, new Set([task.id]), 'G_HAS_GRANT', work).filter(
      node => node.label === 'GuardGrant' && string(node, 'tool') === tool,
    );
    const selectors = connected(projection, new Set([resource.id]), 'G_BINDS_SELECTOR', work).filter(
      node =>
        node.label === 'GuardResource' &&
        string(node, 'tool') === tool &&
        string(node, 'resource_id') === string(resource, 'resource_ref'),
    );
    if (
      !grants.some(
        grant =>
          strings(grant, 'resources').includes(string(resource, 'resource_ref') ?? '') &&
          (raw.status !== 'complete' || uniqueLink(task, grant, 'G_HAS_GRANT')) &&
          tools.some(toolNode => (raw.status === 'complete' ? exactLink : link)(grant, toolNode, 'G_FOR_TOOL')) &&
          selectors.some(selector => (raw.status === 'complete' ? uniqueLink : link)(grant, selector, 'G_TARGETS')),
      )
    )
      fail('MAP_UNAVAILABLE');
    for (const [key, label, relation, owner] of [
      ['identityId', 'GuardExternalIdentity', 'G_USES_IDENTITY', execution],
      ['resourceId', 'GuardExternalResource', 'G_MAPS_TO', resource],
    ] as const) {
      if (raw[key] === null) {
        if (raw.status === 'complete') fail('MAP_UNAVAILABLE');
        continue;
      }
      const target = endpoint(raw[key], label);
      if (!(raw.status === 'complete' ? exactLink(owner, target, relation) : link(owner, target, relation)))
        fail('MAP_UNAVAILABLE');
    }
    if (
      genericAction &&
      (raw.resourceId === null || string(endpoint(raw.resourceId, 'GuardExternalResource'), 'provider') !== 'host')
    )
      fail('MAP_UNAVAILABLE');
    if (raw.status === 'complete') {
      const agents = connected(projection, new Set([deployment.id]), 'G_INSTANCE_OF', work).filter(
        node => node.label === 'GuardAgent',
      );
      if (
        agents.length !== 1 ||
        !exactLink(deployment, agents[0]!, 'G_INSTANCE_OF') ||
        string(execution, 'identity_selection') !== 'static' ||
        !exactLink(task, deployment, 'G_ASSIGNED_TO') ||
        !exactLink(execution, deployment, 'G_EXECUTES_FOR') ||
        tools.length !== 1 ||
        !exactLink(execution, tools[0]!, 'G_EXECUTES_TOOL') ||
        selectors.length !== 1 ||
        !exactLink(resource, selectors[0]!, 'G_BINDS_SELECTOR')
      )
        fail('MAP_UNAVAILABLE');
    }
    const identity = JSON.stringify([
      raw.taskId,
      raw.deploymentId,
      raw.executionBindingId,
      raw.resourceBindingId,
      raw.action,
    ]);
    if (seen.has(identity)) fail('MAP_UNAVAILABLE');
    seen.add(identity);
    try {
      const copy = policyList([immutableJson(raw, 6, 1024, 64 * 1024)])[0]!;
      materializedBytes += Buffer.byteLength(JSON.stringify(copy));
      if (materializedBytes > 4 * 1024 * 1024) fail('MAP_LIMIT_EXCEEDED');
      result.push(copy);
    } catch {
      fail('MAP_LIMIT_EXCEEDED');
    }
  }
  return result;
}
export function policyCoverage(records: readonly MapPolicyEvidence[]): JsonObject {
  const complete = records.filter(item => item.status === 'complete').length;
  const observed = records.flatMap(item => (item.observedAt === null ? [] : [item.observedAt])).sort();
  return {
    status:
      !records.length || records.every(item => item.status === 'not_collected')
        ? 'not_collected'
        : complete === records.length
          ? 'complete'
          : complete
            ? 'partial'
            : 'unavailable',
    observedAt: observed[0] ?? null,
    assessment: 'unknown',
  };
}
/**
 * Coverage for a selection of one projection's policy evidence. When the store found more
 * task/binding/action pairs than one read evaluates it loaded none: that is unknown, never
 * "not collected".
 */
export function policyCoverageOf(projection: MapProjection, records: readonly MapPolicyEvidence[]): JsonObject {
  return projection.policyEvidenceNotLoaded === true
    ? { status: 'unknown', reason: 'limit_exceeded', observedAt: null, assessment: 'unknown' }
    : policyCoverage(records);
}
export function selectedPolicy(
  projection: MapProjection,
  work: QueryWork,
  options: {
    nodes?: readonly MapNode[];
    task?: MapNode;
    executions?: readonly MapNode[];
    resources?: readonly MapNode[];
    action?: string;
  } = {},
): readonly MapPolicyEvidence[] {
  const ids = options.nodes ? new Set(options.nodes.map(node => node.entityId)) : undefined;
  const executions = options.executions ? new Set(options.executions.map(node => node.entityId)) : undefined;
  const resources = options.resources ? new Set(options.resources.map(node => node.entityId)) : undefined;
  const records = options.task
    ? policyRecordsOfTask(projection, options.task.entityId, work)
    : policyRecords(projection, work);
  return records.filter(record => {
    work.step();
    return (
      (!ids ||
        [
          record.taskId,
          record.deploymentId,
          record.executionBindingId,
          record.resourceBindingId,
          record.identityId,
          record.resourceId,
        ].every(id => id === null || ids.has(id))) &&
      (!options.task || record.taskId === options.task.entityId) &&
      (!executions || executions.has(record.executionBindingId)) &&
      (!resources || resources.has(record.resourceBindingId)) &&
      (!options.action || record.action === options.action)
    );
  });
}

/** The projection's policy evidence, validated once per query. */
export function policyRecords(projection: MapProjection, work: QueryWork): readonly MapPolicyEvidence[] {
  return work.cached(projection, 'policy', () => validatedPolicyEvidence(projection, work));
}
/** Validated policy records of one task, in their original order; indexed once per projection. */
function policyRecordsOfTask(
  projection: MapProjection,
  taskEntityId: string,
  work: QueryWork,
): readonly MapPolicyEvidence[] {
  const index = work.cached(projection, 'policyByTask', () => {
    const records = policyRecords(projection, work);
    work.step(records.length);
    const byTask = new Map<string, MapPolicyEvidence[]>();
    for (const record of records) {
      const items = byTask.get(record.taskId);
      if (items) items.push(record);
      else byTask.set(record.taskId, [record]);
    }
    return byTask;
  });
  return index.get(taskEntityId) ?? [];
}
