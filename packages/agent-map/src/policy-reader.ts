import { createHash } from 'node:crypto';
import { immutableJson } from '@shieldaai/agent-guard';
import { MapQueryError, type JsonObject, type MapEdge, type MapNode, type MapPolicyCandidate, type MapPolicyEvidence } from './types.js';

const MAPPING: Readonly<Record<string, MapPolicyCandidate['relationship']>> = Object.freeze({
  's3:GetObject': 'CAN_READ', 's3:PutObject': 'CAN_WRITE', 's3:ListBucket': 'CAN_LIST',
});
const VERSION = 's3-identity-policy-v1';
const HASH = /^[a-f0-9]{64}$/;
const reason = (record: MapPolicyEvidence, status: MapPolicyEvidence['status'], code: MapPolicyEvidence['reason'], observedAt: string | null = null): MapPolicyEvidence =>
  ({ ...record, status, reason: code, observedAt, candidates: [] });
function value(node: MapNode, name: string): string | null { return typeof node.properties[name] === 'string' ? node.properties[name] as string : null; }
function fail(code = 'MAP_UNAVAILABLE'): never { throw new MapQueryError(code); }

interface Probe {
  readonly key: number;
  readonly identity: MapNode;
  readonly resource: MapNode;
  readonly accountId: string;
  readonly partition: string;
  readonly principalArn: string;
  readonly bucketArn: string;
  readonly bucketName: string;
  readonly principalLabel: 'AWSRole' | 'AWSUser';
  readonly relationship: MapPolicyCandidate['relationship'];
  readonly collectionId: string;
  readonly proof: Readonly<Record<string, string | null>>;
}
export interface PolicyPlan { readonly records: readonly MapPolicyEvidence[]; readonly probes: readonly Probe[] }

/** Pair only the selected task's grants with its deployment's declared execution identity. */
export function policyPlan(companyId: string, tenantId: string, nodes: readonly MapNode[], edges: readonly MapEdge[], maximum: number): PolicyPlan {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const outgoing = new Map<string, Map<string, string[]>>(), incoming = new Map<string, Map<string, string[]>>();
  for (const edge of edges) {
    for (const [index, from, to] of [[outgoing, edge.source, edge.target], [incoming, edge.target, edge.source]] as const) {
      let kinds = index.get(from); if (!kinds) index.set(from, kinds = new Map());
      let ids = kinds.get(edge.kind); if (!ids) kinds.set(edge.kind, ids = []);
      ids.push(to);
    }
  }
  let work = 0;
  const step = (n = 1): void => { work += n; if (work > 100_000) fail('MAP_LIMIT_EXCEEDED'); };
  const linked = (node: MapNode, kind: string, label: MapNode['label'], reverse = false): MapNode[] => {
    const ids = (reverse ? incoming : outgoing).get(node.id)?.get(kind) ?? []; step(ids.length);
    return ids.flatMap(id => { const item = byId.get(id); return item?.label === label ? [item] : []; });
  };
  const exact = (node: MapNode, kind: string, target: MapNode): boolean => {
    const ids = outgoing.get(node.id)?.get(kind) ?? []; step();
    return ids.length === 1 && ids[0] === target.id;
  };
  const records: MapPolicyEvidence[] = [], probes: Probe[] = [], seen = new Set<string>();
  for (const task of nodes.filter(node => node.label === 'GuardTask')) {
    const deployments = linked(task, 'G_ASSIGNED_TO', 'GuardDeployment');
    for (const deployment of deployments) {
      const agents = linked(deployment, 'G_INSTANCE_OF', 'GuardAgent');
      const executions = linked(deployment, 'G_EXECUTES_FOR', 'GuardExecutionBinding', true);
      for (const grant of linked(task, 'G_HAS_GRANT', 'GuardGrant')) {
        const tool = value(grant, 'tool'); if (!tool) continue;
        for (const selector of linked(grant, 'G_TARGETS', 'GuardResource')) {
          for (const binding of linked(selector, 'G_BINDS_SELECTOR', 'GuardResourceBinding', true)) {
            step(); if (value(binding, 'tool') !== tool || value(selector, 'tool') !== tool) continue;
            const selectorValue = value(selector, 'resource_id');
            if (selectorValue !== value(binding, 'resource_ref')) continue;
            const grantResources = grant.properties.resources;
            if (!Array.isArray(grantResources) || !grantResources.includes(selectorValue!)) continue;
            const actions = binding.properties.actions;
            if (!Array.isArray(actions) || actions.length > 128 || actions.some(action => typeof action !== 'string' || !action || action.length > 4096)) fail('MAP_UNAVAILABLE');
            for (const execution of executions.filter(item => value(item, 'tool') === tool)) {
              const identities = linked(execution, 'G_USES_IDENTITY', 'GuardExternalIdentity');
              const resources = linked(binding, 'G_MAPS_TO', 'GuardExternalResource');
              const executionDeployments = linked(execution, 'G_EXECUTES_FOR', 'GuardDeployment');
              const selectors = linked(binding, 'G_BINDS_SELECTOR', 'GuardResource');
              const grantTools = linked(grant, 'G_FOR_TOOL', 'GuardTool');
              const executionTools = linked(execution, 'G_EXECUTES_TOOL', 'GuardTool');
              const unambiguous = deployments.length === 1 && executionDeployments.length === 1 &&
                agents.length === 1 && exact(deployment, 'G_INSTANCE_OF', agents[0]!) &&
                executionDeployments[0]!.id === deployment.id && selectors.length === 1 && selectors[0]!.id === selector.id &&
                grantTools.length === 1 && executionTools.length === 1 && grantTools[0]!.id === executionTools[0]!.id &&
                value(grantTools[0]!, 'name') === tool && exact(task, 'G_ASSIGNED_TO', deployment) &&
                exact(execution, 'G_EXECUTES_FOR', deployment) && exact(binding, 'G_BINDS_SELECTOR', selector) &&
                exact(grant, 'G_FOR_TOOL', grantTools[0]!) && exact(execution, 'G_EXECUTES_TOOL', executionTools[0]!);
              for (const action of actions as readonly string[]) {
                step();
                const key = JSON.stringify([task.id, deployment.id, execution.id, binding.id, action]);
                if (seen.has(key)) continue;
                seen.add(key); if (records.length >= maximum) fail('MAP_LIMIT_EXCEEDED');
                const identity = identities.length === 1 ? identities[0]! : null;
                const resource = resources.length === 1 ? resources[0]! : null;
                const base: MapPolicyEvidence = { taskId: task.entityId, deploymentId: deployment.entityId,
                  executionBindingId: execution.entityId, resourceBindingId: binding.entityId,
                  identityId: identity?.entityId ?? null, resourceId: resource?.entityId ?? null,
                  action, status: 'not_collected', reason: 'collection_missing', observedAt: null, assessment: 'unknown', candidates: [] };
                const recordIndex = records.length;
                const relationship = MAPPING[action];
                if (!relationship) { records.push(reason(base, 'not_collected', 'unsupported_action')); continue; }
                if (value(execution, 'identity_selection') !== 'static') { records.push(reason(base, 'not_collected', 'identity_not_static')); continue; }
                if (!unambiguous || !identity || !resource || !exact(execution, 'G_USES_IDENTITY', identity) || !exact(binding, 'G_MAPS_TO', resource)) {
                  records.push(reason(base, 'unavailable', 'binding_ambiguous')); continue;
                }
                const accountId = value(identity, 'account_id'), partition = value(identity, 'partition');
                const principalArn = value(identity, 'arn'), resourceArn = value(resource, 'arn');
                const principal = /^arn:aws:iam::([0-9]{12}):(role|user)\/.+$/.exec(principalArn ?? '');
                const bucket = /^arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:\/(.+))?$/.exec(resourceArn ?? '');
                const kind = value(resource, 'kind');
                if (value(identity, 'provider') !== 'aws' || value(resource, 'provider') !== 'aws' || partition !== 'aws' ||
                    value(resource, 'partition') !== partition || !accountId || !/^[0-9]{12}$/.test(accountId) ||
                    value(resource, 'account_id') !== accountId || !principal || principal[1] !== accountId || !bucket ||
                    !['bucket', 'object', 'prefix'].includes(kind ?? '') || (kind === 'bucket') !== (bucket[2] === undefined)) {
                  records.push(reason(base, 'not_collected', 'unsupported_binding')); continue;
                }
                if (identity.properties.cloud_status === null || identity.properties.cloud_status === undefined ||
                    resource.properties.cloud_status === null || resource.properties.cloud_status === undefined) {
                  records.push(reason(base, 'not_collected', 'cloud_not_collected')); continue;
                }
                if (identity.properties.cloud_status !== 'resolved' || resource.properties.cloud_status !== 'resolved') {
                  records.push(reason(base, 'unavailable', 'cloud_unresolved')); continue;
                }
                // Python's scope ID uses compact ensure_ascii JSON; preserve that byte contract.
                const encoded = JSON.stringify([companyId, tenantId, partition, accountId]).replace(/[\u007f-\uffff]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
                records.push(base);
                probes.push({ key: recordIndex, identity, resource, accountId, partition, principalArn: principalArn!,
                  bucketArn: `arn:aws:s3:::${bucket[1]}`, bucketName: bucket[1]!, principalLabel: principal[2] === 'role' ? 'AWSRole' : 'AWSUser',
                  relationship, collectionId: createHash('sha256').update(encoded).digest('hex'), proof: {
                    agentNodeId: agents[0]!.id, agentEntityId: agents[0]!.entityId, agentTeamId: value(agents[0]!, 'team_id'),
                    taskNodeId: task.id, taskEntityId: task.entityId, deploymentNodeId: deployment.id, deploymentEntityId: deployment.entityId,
                    executionNodeId: execution.id, executionEntityId: execution.entityId, grantNodeId: grant.id, grantEntityId: grant.entityId,
                    selectorNodeId: selector.id, selectorEntityId: selector.entityId, bindingNodeId: binding.id, bindingEntityId: binding.entityId,
                    toolNodeId: grantTools[0]!.id, toolEntityId: grantTools[0]!.entityId, tool, resourceRef: selectorValue!, action,
                  } });
              }
            }
          }
        }
      }
    }
  }
  return { records, probes };
}

// These are fixed property projections; neither query text nor property names come from requests.
const referenceText = { id: 4096, entity_id: 4096, provider: 32, partition: 32, account_id: 12, region: 64, arn: 2048,
  kind: 32, cloud_status: 32, cloud_assessment: 32, cloud_provider_label: 32, cloud_provider_id: 2048, cloud_match_kind: 32 };
const referenceNumbers = ['cloud_observed_at', 'cloud_node_updated', 'cloud_ownership_updated', 'cloud_account_updated'];
const referenceFields = [...Object.keys(referenceText), ...referenceNumbers];
const referenceProjection = (variable: string): string => [
  ...Object.entries(referenceText).map(([field, maximum]) => `${field}:substring(${variable}.${field},0,${maximum + 1})`),
  ...referenceNumbers.map(field => `${field}:${variable}.${field}`),
].join(',');
const memberFields = 'eid:elementId(m),capture_hash:substring(m.capture_hash,0,65),captured_at:m.captured_at,region:substring(m.region,0,65),policy_status:substring(m.policy_status,0,33),policy_boundary_present:m.policy_boundary_present,policy_hash:substring(m.policy_hash,0,65),policy_mapping_version:substring(m.policy_mapping_version,0,65),policy_assessment:substring(m.policy_assessment,0,33)';
const proofScope = (variable: string): string =>
  `${variable}.source_id=$sourceId AND ${variable}.projection_id=$projectionId AND ${variable}.tenant_id=$tenantId`;
// Correlate short paths instead of planning one large cycle. Each nested branch
// retains the same bound endpoints; NOT EXISTS still rejects a second relation.
// Reduce cold planning cost without relaxing the existing query deadline or
// removing scope, binding identity or ambiguity checks.
const bindingProof = `EXISTS {
  MATCH (task:GuardTask {id:pair.taskNodeId,entity_id:pair.taskEntityId})-[td:G_ASSIGNED_TO]->(deployment:GuardDeployment {id:pair.deploymentNodeId,entity_id:pair.deploymentEntityId})
  WHERE ${proofScope('task')} AND ${proofScope('deployment')}
    AND NOT EXISTS { MATCH (task)-[other:G_ASSIGNED_TO]->() WHERE other<>td }
    AND EXISTS {
      MATCH (deployment)-[da:G_INSTANCE_OF]->(agent:GuardAgent {id:pair.agentNodeId,entity_id:pair.agentEntityId})
      WHERE ${proofScope('agent')} AND ($allTeams OR agent.team_id IN $teamIds)
        AND (agent.team_id=pair.agentTeamId OR (agent.team_id IS NULL AND pair.agentTeamId IS NULL))
        AND NOT EXISTS { MATCH (deployment)-[other:G_INSTANCE_OF]->() WHERE other<>da }
    }
    AND EXISTS {
      MATCH (execution:GuardExecutionBinding {id:pair.executionNodeId,entity_id:pair.executionEntityId})-[ed:G_EXECUTES_FOR]->(deployment)
      WHERE ${proofScope('execution')} AND execution.tool=pair.tool AND execution.identity_selection='static'
        AND NOT EXISTS { MATCH (execution)-[other:G_EXECUTES_FOR]->() WHERE other<>ed }
        AND EXISTS {
          MATCH (execution)-[ei:G_USES_IDENTITY]->(i)
          WHERE NOT EXISTS { MATCH (execution)-[other:G_USES_IDENTITY]->() WHERE other<>ei }
        }
        AND EXISTS {
          MATCH (execution)-[et:G_EXECUTES_TOOL]->(tool:GuardTool {id:pair.toolNodeId,entity_id:pair.toolEntityId})
          WHERE ${proofScope('tool')} AND tool.name=pair.tool
            AND NOT EXISTS { MATCH (execution)-[other:G_EXECUTES_TOOL]->() WHERE other<>et }
            AND EXISTS {
              MATCH (task)-[tg:G_HAS_GRANT]->(grant:GuardGrant {id:pair.grantNodeId,entity_id:pair.grantEntityId})-[gt:G_FOR_TOOL]->(tool)
              WHERE ${proofScope('grant')} AND grant.tool=pair.tool AND pair.resourceRef IN grant.resources
                AND NOT EXISTS { MATCH (grant)-[other:G_FOR_TOOL]->() WHERE other<>gt }
                AND NOT EXISTS { MATCH (task)-[other:G_HAS_GRANT]->(grant) WHERE other<>tg }
                AND EXISTS {
                  MATCH (grant)-[gs:G_TARGETS]->(selector:GuardResource {id:pair.selectorNodeId,entity_id:pair.selectorEntityId})
                    <-[bs:G_BINDS_SELECTOR]-(binding:GuardResourceBinding {id:pair.bindingNodeId,entity_id:pair.bindingEntityId})-[bx:G_MAPS_TO]->(x)
                  WHERE ${proofScope('selector')} AND ${proofScope('binding')}
                    AND binding.tool=pair.tool AND binding.resource_ref=pair.resourceRef AND pair.action IN binding.actions
                    AND selector.tool=pair.tool AND selector.resource_id=pair.resourceRef
                    AND NOT EXISTS { MATCH (binding)-[other:G_BINDS_SELECTOR]->() WHERE other<>bs }
                    AND NOT EXISTS { MATCH (binding)-[other:G_MAPS_TO]->() WHERE other<>bx }
                    AND NOT EXISTS { MATCH (grant)-[other:G_TARGETS]->(selector) WHERE other<>gs }
                }
            }
        }
    }
}`;
export const POLICY_QUERY = `UNWIND $policyPairs AS pair
OPTIONAL MATCH (i:GuardExternalIdentity {id:pair.identityNodeId,source_id:$sourceId,projection_id:$projectionId,tenant_id:$tenantId})
OPTIONAL MATCH (x:GuardExternalResource {id:pair.resourceNodeId,source_id:$sourceId,projection_id:$projectionId,tenant_id:$tenantId})
OPTIONAL MATCH (i)-[ic:G_CLOUD_MATCH]->(p)
OPTIONAL MATCH (x)-[bc:G_CLOUD_MATCH|G_CLOUD_CONTAINER]->(b)
OPTIONAL MATCH (pa:AWSAccount)-[po:RESOURCE]->(p)
OPTIONAL MATCH (ba:AWSAccount)-[bo:RESOURCE]->(b)
OPTIONAL MATCH (c:GuardAwsCollection {company_id:$companyId,tenant_id:$tenantId,partition:pair.partition,account_id:pair.accountId})
OPTIONAL MATCH (c)-[pm:G_AWS_OBSERVED]->(p)
OPTIONAL MATCH (c)-[bm:G_AWS_OBSERVED]->(b)
OPTIONAL MATCH (p)-[candidate:G_AWS_POLICY_CANDIDATE {collection_id:c.id}]->(b)
RETURN pair.key AS key,${bindingProof} AS bindingProof,
 i {${referenceProjection('i')}} AS identity,x {${referenceProjection('x')}} AS resource,
 CASE WHEN ic IS NULL THEN null ELSE {eid:elementId(ic),kind:type(ic),evidence_kind:substring(ic.evidence_kind,0,65),assessment:substring(ic.assessment,0,33),observed_at:ic.observed_at} END AS identityLink,
 CASE WHEN bc IS NULL THEN null ELSE {eid:elementId(bc),kind:type(bc),evidence_kind:substring(bc.evidence_kind,0,65),assessment:substring(bc.assessment,0,33),observed_at:bc.observed_at} END AS resourceLink,
 CASE WHEN p IS NULL THEN null ELSE {eid:elementId(p),id:substring(p.id,0,2049),arn:substring(p.arn,0,2049),lastupdated:p.lastupdated,principal:p:AWSPrincipal,role:p:AWSRole,user:p:AWSUser} END AS principal,
 CASE WHEN b IS NULL THEN null ELSE {eid:elementId(b),id:substring(b.id,0,64),arn:substring(b.arn,0,2049),region:substring(b.region,0,65),lastupdated:b.lastupdated,bucket:b:AWSS3Bucket} END AS bucket,
 CASE WHEN pa IS NULL THEN null ELSE {eid:elementId(pa),id:substring(pa.id,0,13),lastupdated:pa.lastupdated} END AS principalAccount,
 CASE WHEN ba IS NULL THEN null ELSE {eid:elementId(ba),id:substring(ba.id,0,13),lastupdated:ba.lastupdated} END AS bucketAccount,
 CASE WHEN po IS NULL THEN null ELSE {eid:elementId(po),lastupdated:po.lastupdated} END AS principalOwnership,
 CASE WHEN bo IS NULL THEN null ELSE {eid:elementId(bo),lastupdated:bo.lastupdated} END AS bucketOwnership,
 CASE WHEN c IS NULL THEN null ELSE {eid:elementId(c),id:substring(c.id,0,65),schema_version:c.schema_version,status:substring(c.status,0,33),captured_at:c.captured_at,content_hash:substring(c.content_hash,0,65),policy_status:substring(c.policy_status,0,33),policy_hash:substring(c.policy_hash,0,65),policy_mapping_version:substring(c.policy_mapping_version,0,65)} END AS collection,
 CASE WHEN pm IS NULL THEN null ELSE {${memberFields.replaceAll('m.', 'pm.').replaceAll('elementId(m)', 'elementId(pm)')}} END AS principalMember,
 CASE WHEN bm IS NULL THEN null ELSE {${memberFields.replaceAll('m.', 'bm.').replaceAll('elementId(m)', 'elementId(bm)')}} END AS bucketMember,
 CASE WHEN candidate IS NULL THEN null ELSE {eid:elementId(candidate),collection_id:substring(candidate.collection_id,0,65),capture_hash:substring(candidate.capture_hash,0,65),captured_at:candidate.captured_at,policy_hash:substring(candidate.policy_hash,0,65),mapping_version:substring(candidate.mapping_version,0,65),relationship:substring(candidate.relationship,0,33),has_condition:candidate.has_condition,condition_keys:[key IN candidate.condition_keys[..129] | substring(key,0,257)],condition_key_count:size(candidate.condition_keys),condition_key_lengths:[key IN candidate.condition_keys[..129] | size(key)],resource_scope:substring(candidate.resource_scope,0,33),assessment:substring(candidate.assessment,0,33),evidence_kind:substring(candidate.evidence_kind,0,65)} END AS candidate
LIMIT $policyRowLimit`;

export const POLICY_COLUMNS = ['key', 'bindingProof', 'identity', 'resource', 'identityLink', 'resourceLink', 'principal', 'bucket',
  'principalAccount', 'bucketAccount', 'principalOwnership', 'bucketOwnership', 'collection', 'principalMember', 'bucketMember', 'candidate'] as const;
export function policyParameters(plan: PolicyPlan): readonly Record<string, unknown>[] {
  return plan.probes.map(probe => ({ ...probe.proof, key: probe.key, identityNodeId: probe.identity.id, resourceNodeId: probe.resource.id,
    accountId: probe.accountId, partition: probe.partition }));
}
export function safePolicyRow(raw: unknown): JsonObject {
  try { return immutableJson(raw, 8, 10_000, 128 * 1024) as JsonObject; }
  catch { return fail('MAP_LIMIT_EXCEEDED'); }
}
function object(value: unknown): Record<string, unknown> | null { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null; }
function stamp(value: unknown, now: number): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= now; }
function hash(value: unknown): value is string { return typeof value === 'string' && HASH.test(value); }
function unicodeOrder(a: string, b: string): number {
  const left = [...a], right = [...b];
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    const difference = left[index]!.codePointAt(0)! - right[index]!.codePointAt(0)!;
    if (difference) return difference;
  }
  return left.length - right.length;
}
function referenceMatches(actual: Record<string, unknown>, expected: MapNode): boolean {
  if (actual.id !== expected.id || actual.entity_id !== expected.entityId) return false;
  return referenceFields.filter(field => field !== 'id' && field !== 'entity_id')
    .every(field => (actual[field] ?? null) === (expected.properties[field] ?? null));
}

/** Pure classification: no positive candidate survives a malformed endpoint or stale receipt. */
export function policyEvidence(plan: PolicyPlan, rows: readonly JsonObject[], now: number, maximumAge: number): readonly MapPolicyEvidence[] {
  const groups = new Map<number, JsonObject[]>();
  const requested = new Set(plan.probes.map(probe => probe.key));
  for (const row of rows) {
    const key = row.key;
    if (typeof key !== 'number' || !Number.isSafeInteger(key) || !requested.has(key)) fail();
    const items = groups.get(key) ?? []; items.push(row); groups.set(key, items);
  }
  const result = [...plan.records];
  for (const probe of plan.probes) {
    const base = result[probe.key]!, matches = groups.get(probe.key) ?? [];
    const set = (status: MapPolicyEvidence['status'], code: MapPolicyEvidence['reason'], time: string | null = null): void => { result[probe.key] = reason(base, status, code, time); };
    if (!matches.length) { set('unavailable', 'changed'); continue; }
    const row = matches[0]!;
    if (row.bindingProof !== true) { set('unavailable', 'changed'); continue; }
    const structural = ({ candidate: _candidate, ...rest }: JsonObject): string => JSON.stringify(rest);
    if (matches.some(item => structural(item) !== structural(row))) { set('unavailable', 'evidence_invalid'); continue; }
    const i = object(row.identity), x = object(row.resource), p = object(row.principal), b = object(row.bucket);
    const pa = object(row.principalAccount), ba = object(row.bucketAccount), po = object(row.principalOwnership), bo = object(row.bucketOwnership);
    const ic = object(row.identityLink), bc = object(row.resourceLink), c = object(row.collection), pm = object(row.principalMember), bm = object(row.bucketMember);
    if (!i || !x || !referenceMatches(i, probe.identity) || !referenceMatches(x, probe.resource)) { set('unavailable', 'changed'); continue; }
    if (!p || !b || !pa || !ba || !po || !bo || !ic || !bc) { set('unavailable', 'provider_missing'); continue; }
    const containment = x.kind !== 'bucket';
    if (p.principal !== true || p.role !== (probe.principalLabel === 'AWSRole') || p.user !== (probe.principalLabel === 'AWSUser') ||
        p.id !== probe.principalArn || p.arn !== probe.principalArn || b.bucket !== true || b.id !== probe.bucketName || b.arn !== probe.bucketArn ||
        pa.id !== probe.accountId || ba.id !== probe.accountId || pa.eid !== ba.eid ||
        i.cloud_provider_id !== probe.principalArn || i.cloud_provider_label !== probe.principalLabel || i.cloud_match_kind !== 'exact' ||
        x.cloud_provider_id !== probe.bucketName || x.cloud_provider_label !== 'AWSS3Bucket' || x.cloud_match_kind !== (containment ? 'containment' : 'exact') ||
        ic.kind !== 'G_CLOUD_MATCH' || bc.kind !== (containment ? 'G_CLOUD_CONTAINER' : 'G_CLOUD_MATCH') ||
        [i, x, ic, bc].some(item => (item.cloud_assessment ?? item.assessment) !== 'unknown') ||
        ic.evidence_kind !== 'provider_inventory' || bc.evidence_kind !== 'provider_inventory' ||
        ic.observed_at !== i.cloud_observed_at || bc.observed_at !== x.cloud_observed_at ||
        (x.region && x.region !== b.region)) { set('unavailable', 'evidence_invalid'); continue; }
    if (!c) { set('not_collected', 'collection_missing'); continue; }
    if (c.id !== probe.collectionId || c.schema_version !== 1 || c.status !== 'complete' || !hash(c.content_hash) || !stamp(c.captured_at, now)) {
      set('unavailable', 'collection_invalid'); continue;
    }
    const observedAt = new Date(c.captured_at * 1000).toISOString();
    const times = [p.lastupdated, b.lastupdated, pa.lastupdated, ba.lastupdated, po.lastupdated, bo.lastupdated,
      i.cloud_observed_at, x.cloud_observed_at, i.cloud_node_updated, x.cloud_node_updated,
      i.cloud_ownership_updated, x.cloud_ownership_updated, i.cloud_account_updated, x.cloud_account_updated];
    if (times.some(time => !stamp(time, now))) { set('unavailable', 'changed', observedAt); continue; }
    if ([c.captured_at, ...times].some(time => now - (time as number) > maximumAge)) { set('unavailable', 'stale', observedAt); continue; }
    if (!pm || !bm || [pm, bm].some(member => member.capture_hash !== c.content_hash || member.captured_at !== c.captured_at) ||
        p.lastupdated !== c.captured_at || b.lastupdated !== c.captured_at || po.lastupdated !== c.captured_at || bo.lastupdated !== c.captured_at ||
        i.cloud_node_updated !== p.lastupdated || x.cloud_node_updated !== b.lastupdated ||
        i.cloud_ownership_updated !== po.lastupdated || x.cloud_ownership_updated !== bo.lastupdated ||
        i.cloud_account_updated !== pa.lastupdated || x.cloud_account_updated !== ba.lastupdated || bm.region !== b.region) {
      set('unavailable', 'changed', observedAt); continue;
    }
    if (c.policy_status === 'disabled' || c.policy_status === null || c.policy_status === undefined) { set('not_collected', 'disabled', observedAt); continue; }
    if (c.policy_status !== 'complete' || !hash(c.policy_hash) || c.policy_mapping_version !== VERSION ||
        pm.policy_hash !== c.policy_hash || pm.policy_mapping_version !== VERSION || pm.policy_assessment !== 'unknown' ||
        !['mapped', 'unsupported', 'boundary_unresolved'].includes(String(pm.policy_status)) ||
        typeof pm.policy_boundary_present !== 'boolean' || pm.policy_boundary_present !== (pm.policy_status === 'boundary_unresolved')) {
      set('unavailable', 'collection_invalid', observedAt); continue;
    }
    if (pm.policy_status !== 'mapped') { set('unavailable', pm.policy_status === 'boundary_unresolved' ? 'boundary_unresolved' : 'unsupported_policy', observedAt); continue; }
    const candidates: MapPolicyCandidate[] = [], seen = new Set<string>(); let invalid = false;
    for (const match of matches) {
      const candidate = object(match.candidate); if (!candidate) { if (matches.length !== 1) invalid = true; continue; }
      const keys = candidate.condition_keys, lengths = candidate.condition_key_lengths;
      const relation = candidate.relationship;
      if (candidate.collection_id !== c.id || candidate.capture_hash !== c.content_hash || candidate.captured_at !== c.captured_at ||
          candidate.policy_hash !== c.policy_hash || candidate.mapping_version !== VERSION || candidate.assessment !== 'unknown' ||
          candidate.resource_scope !== 'bucket_summary' || candidate.evidence_kind !== 'iam_identity_policy_candidate' ||
          typeof relation !== 'string' || !Object.values(MAPPING).includes(relation as MapPolicyCandidate['relationship']) || seen.has(relation) ||
          typeof candidate.has_condition !== 'boolean' || !Array.isArray(keys) || keys.length > 128 ||
          candidate.condition_key_count !== keys.length || !Array.isArray(lengths) || lengths.length !== keys.length ||
          keys.some((key, index) => typeof key !== 'string' || !key || /[\u0000-\u001f\ud800-\udfff]/u.test(key) || Buffer.byteLength(key) > 256 || lengths[index] !== [...key].length) ||
          new Set(keys).size !== keys.length || JSON.stringify(keys) !== JSON.stringify([...(keys as string[])].sort(unicodeOrder)) || candidate.has_condition !== (keys.length > 0)) {
        invalid = true; break;
      }
      seen.add(relation);
      if (relation === probe.relationship) candidates.push({ relationship: relation as MapPolicyCandidate['relationship'], hasCondition: candidate.has_condition,
        conditionKeys: keys as string[], resourceScope: 'bucket_summary' });
    }
    if (invalid) { set('unavailable', 'evidence_invalid', observedAt); continue; }
    result[probe.key] = { ...base, status: 'complete', reason: candidates.length ? null : 'no_candidate', observedAt, candidates };
  }
  return result;
}
