import { s3BucketName, shortenScopeList } from '../common.js';
import {
  MapQueryError,
  type JsonObject,
  type MapIdentityExtraResource,
  type MapIdentityScope,
  type MapNode,
  type MapProjection,
  type ReadScope,
} from '../types.js';
import { jsonList, jsonObject } from './json.js';
import { compare, ordered } from './ordering.js';
import { deployments, type FocusedGraph } from './summaries.js';
import { connected, number, QueryWork, string } from './work.js';

/** A declared target names a host resource; name it only when that resource is in the reader's scope. */
export function targetVisibility(
  projection: MapProjection,
  scope: ReadScope,
  work: QueryWork,
): (target: string) => boolean {
  if (scope.allTeams) return () => true;
  work.step(projection.nodes.length);
  const visible = new Set([
    ...projection.nodes
      .filter(node => node.label === 'GuardExternalResource')
      .map(node => string(node, 'host_resource_id'))
      .filter((id): id is string => id !== null),
    ...(projection.inScopeTargets ?? []),
  ]);
  return target => visible.has(target);
}
/**
 * Host-declared paths that act without the guard, per deployment in the agent's focus.
 * Manifest v3 sets `direct_access_status`; older manifests leave it absent, which reads as
 * `unknown` and never as `none_declared`.
 */
export function directAccess(
  projection: MapProjection,
  graph: FocusedGraph,
  scope: ReadScope,
  work: QueryWork,
): JsonObject[] {
  const visibleTarget = targetVisibility(projection, scope, work);
  return ordered(
    graph.nodes
      .filter(node => node.label === 'GuardDeployment')
      .map(deployment => {
        const entries = connected(projection, new Set([deployment.id]), 'G_DIRECT_ACCESS_FOR', work, true);
        const declared = string(deployment, 'direct_access_status');
        // An entry without the v3 status would be inconsistent; report what was found.
        const status = entries.length ? 'found' : declared === 'none_declared' ? 'none_declared' : 'unknown';
        return {
          id: deployment.entityId,
          deploymentId: string(deployment, 'deployment_id'),
          status,
          evidenceKind: 'declared',
          entries: ordered(
            entries.map(entry => {
              const target = string(entry, 'target_ref');
              const targetStatus =
                target === null ? 'none' : visibleTarget(target) ? 'visible' : 'outside_visible_scope';
              return {
                id: entry.entityId,
                accessId: string(entry, 'access_id'),
                kind: string(entry, 'kind'),
                targetRef: targetStatus === 'visible' ? target : null,
                targetStatus,
                description: string(entry, 'description'),
              };
            }),
          ),
        };
      }),
  );
}

/** `data` with each identity-scope list cut to `keep` entries, or null if nothing would change. */
export function shortenIdentityScope(data: JsonObject, keep: number): JsonObject | null {
  const outside = data.outsideGuard as JsonObject | undefined;
  const records = outside?.identityScope as readonly MapIdentityScope[] | undefined;
  if (!Array.isArray(records)) return null;
  const shortened = records.map(record => shortenScopeList(record, keep));
  if (shortened.every((record, index) => record === records[index])) return null;
  return { ...data, outsideGuard: { ...outside, identityScope: jsonList(shortened) } };
}

export type Reach = 'yes' | 'none_found' | 'unknown';
export interface ReachIndex {
  readonly undeclaredDeployments: number;
  /** Declared paths without a target, such as a shell, can touch any resource. */
  readonly untargetedPaths: number;
  /** Declared paths whose target matches no resource in this read (perhaps another team's). */
  readonly unresolvedPaths: number;
  /** Visible granted tools with no declared execution identity (ambient or unknown). */
  readonly undeclaredIdentities: number;
  readonly directByTarget: Map<string, MapNode[]>;
  readonly identitiesByBucket: Map<string, { record: MapIdentityScope; extra: MapIdentityExtraResource }[]>;
  readonly identityUnknown: number;
  readonly identityCollected: boolean;
  /** AWS accounts of the evaluated identities; a bucket elsewhere was never compared. */
  readonly identityAccounts: ReadonlySet<string | null>;
}
export const reachIndex = new WeakMap<MapProjection, ReachIndex>();
/**
 * Outside-guard reach over the whole visible projection: any declared direct path or any
 * evaluated tool identity can touch any resource, so `none_found` needs every visible
 * deployment to have declared its paths and every visible identity to be evaluated.
 */
export function outsideGuardIndex(projection: MapProjection, work: QueryWork): ReachIndex {
  const existing = reachIndex.get(projection);
  if (existing) return existing;
  work.step(projection.nodes.length);
  let undeclaredDeployments = 0,
    untargetedPaths = 0,
    undeclaredIdentities = 0;
  const identityAccounts = new Set<string | null>();
  const directByTarget = new Map<string, MapNode[]>();
  // The tools each deployment has an execution binding for, read once per deployment.
  const executed = new Map<string, Set<string | null>>();
  const executedTools = (deployment: MapNode): Set<string | null> => {
    let tools = executed.get(deployment.id);
    if (!tools) {
      tools = new Set(
        connected(projection, new Set([deployment.id]), 'G_EXECUTES_FOR', work, true).map(item => string(item, 'tool')),
      );
      executed.set(deployment.id, tools);
    }
    return tools;
  };
  for (const node of projection.nodes) {
    if (node.label === 'GuardDeployment') {
      const status = string(node, 'direct_access_status');
      // `found` with no entry in the read is inconsistent, so it is not a declaration either.
      const entries = connected(projection, new Set([node.id]), 'G_DIRECT_ACCESS_FOR', work, true).length;
      if (!(status === 'none_declared' || (status === 'found' && entries > 0))) undeclaredDeployments++;
    }
    if (node.label === 'GuardDirectAccess') {
      const target = string(node, 'target_ref');
      if (target === null) untargetedPaths++;
      else {
        const paths = directByTarget.get(target);
        if (paths) paths.push(node);
        else directByTarget.set(target, [node]);
      }
    }
    if (node.label === 'GuardTask') {
      // A granted tool runs under some identity on every deployment the task is assigned to;
      // a deployment without an execution binding for it leaves that identity undeclared.
      const granted = new Set(
        connected(projection, new Set([node.id]), 'G_HAS_GRANT', work).map(item => string(item, 'tool')),
      );
      if (granted.size) {
        const deployments = connected(projection, new Set([node.id]), 'G_ASSIGNED_TO', work);
        work.step(granted.size * deployments.length);
        if (!deployments.length || deployments.some(item => [...granted].some(tool => !executedTools(item).has(tool))))
          undeclaredIdentities++;
      }
    }
  }
  const identitiesByBucket: ReachIndex['identitiesByBucket'] = new Map();
  let identityUnknown = 0;
  // A visible execution binding the reach read never reported on was not evaluated.
  if (projection.identityReach !== undefined) {
    const reported = new Set(projection.identityReach.map(record => record.executionBindingId));
    for (const node of projection.nodes)
      if (node.label === 'GuardExecutionBinding' && !reported.has(node.entityId)) identityUnknown++;
  }
  // A target the read cannot match may be any resource, so it counts like no target.
  const hostIds = new Set(
    projection.nodes
      .filter(node => node.label === 'GuardExternalResource')
      .map(node => string(node, 'host_resource_id'))
      .filter((id): id is string => id !== null),
  );
  let unresolvedPaths = 0;
  for (const [target, paths] of directByTarget) if (!hostIds.has(target)) unresolvedPaths += paths.length;
  for (const record of projection.identityReach ?? []) {
    work.step(1 + record.extraResources.length);
    // Only a complete comparison counts: any other status, or a record whose list was cut
    // (it may reach buckets it no longer names), leaves reach unknown.
    if (!(record.status === 'matches_grants' || record.status === 'broader_than_grants') || record.truncated)
      identityUnknown++;
    identityAccounts.add(record.accountId ?? null);
    for (const extra of record.extraResources) {
      const reached = identitiesByBucket.get(extra.bucketName);
      if (reached) reached.push({ record, extra });
      else identitiesByBucket.set(extra.bucketName, [{ record, extra }]);
    }
  }
  const result = {
    undeclaredDeployments,
    untargetedPaths,
    unresolvedPaths,
    undeclaredIdentities,
    directByTarget,
    identitiesByBucket,
    identityUnknown,
    identityCollected: projection.identityReach !== undefined,
    identityAccounts,
  };
  reachIndex.set(projection, result);
  return result;
}
/** Entries listed per resource in get_resource_access before the list is marked truncated. */
export const REACH_LIST_LIMIT = 100;
export interface ReachResult {
  status: Reach;
  unknownReasons: string[];
  directAccess: JsonObject[];
  directAccessTruncated: boolean;
  identities: JsonObject[];
  identitiesTruncated: boolean;
}
/**
 * `detail` builds the (bounded) lists for one resource; the listing only needs the status,
 * which comes from index lookups.
 */
export function outsideGuardReach(
  projection: MapProjection,
  resource: MapNode,
  scope: ReadScope,
  work: QueryWork,
  detail = false,
): ReachResult {
  const index = outsideGuardIndex(projection, work);
  const targets = connected(projection, new Set([resource.id]), 'G_MAPS_TO', work);
  // The collector writes one target per binding; anything else is malformed and never none_found.
  const malformed = targets.length !== 1;
  const hosts = targets.map(node => string(node, 'host_resource_id')).filter((id): id is string => id !== null);
  const accounts = new Set(
    targets.filter(node => string(node, 'provider') === 'aws').map(node => string(node, 'account_id')),
  );
  const buckets = targets
    .filter(node => string(node, 'provider') === 'aws')
    .map(node => s3BucketName(string(node, 'arn')))
    .filter((name): name is string => name !== null);
  work.step(1 + hosts.length + buckets.length);
  const reached =
    hosts.some(id => index.directByTarget.has(id)) || buckets.some(name => index.identitiesByBucket.has(name));
  let directAccess: JsonObject[] = [],
    identities: JsonObject[] = [],
    directAccessTruncated = false,
    identitiesTruncated = false;
  if (detail) {
    const paths = hosts
      .flatMap(id => index.directByTarget.get(id) ?? [])
      .sort((a, b) => compare(a.entityId, b.entityId));
    const reaching = buckets
      .flatMap(name => index.identitiesByBucket.get(name) ?? [])
      .sort(
        (a, b) =>
          compare(a.record.executionBindingId, b.record.executionBindingId) ||
          compare(a.extra.bucketName, b.extra.bucketName) ||
          compare(a.extra.relationship, b.extra.relationship),
      );
    work.step(paths.length + reaching.length);
    directAccessTruncated = paths.length > REACH_LIST_LIMIT;
    identitiesTruncated = reaching.length > REACH_LIST_LIMIT;
    directAccess = paths.slice(0, REACH_LIST_LIMIT).map(node => ({
      id: node.entityId,
      accessId: string(node, 'access_id'),
      deploymentId: string(node, 'deployment_id'),
      kind: string(node, 'kind'),
      description: string(node, 'description'),
      evidenceKind: 'declared',
    }));
    identities = reaching.slice(0, REACH_LIST_LIMIT).map(({ record, extra }) =>
      jsonObject({
        id: record.executionBindingId,
        executionBindingId: record.executionBindingId,
        deploymentId: record.deploymentId,
        tool: record.tool,
        identityId: record.identityId,
        relationship: extra.relationship,
        hasCondition: extra.hasCondition,
        conditionKeys: extra.conditionKeys,
        evidenceKind: 'iam_identity_policy_candidate',
      }),
    );
  }
  const unknownReasons: string[] = [];
  if (malformed) unknownReasons.push('binding_ambiguous');
  // Candidates exist only for buckets the AWS collection observed; an unresolved bucket was
  // never compared with any identity.
  if (targets.some(node => string(node, 'provider') === 'aws' && string(node, 'cloud_status') !== 'resolved'))
    unknownReasons.push('resource_not_collected');
  if (index.undeclaredDeployments) unknownReasons.push('direct_access_undeclared');
  if (index.untargetedPaths) unknownReasons.push('direct_access_untargeted');
  if (index.unresolvedPaths) unknownReasons.push('direct_access_target_unresolved');
  if (!buckets.length) unknownReasons.push('identity_scope_not_collected_for_resource');
  else if (!index.identityCollected) unknownReasons.push('identity_scope_not_collected');
  else {
    if (index.identityUnknown) unknownReasons.push('identity_scope_unknown');
    // Candidates are collected per account: an identity elsewhere was never compared with
    // this bucket, and a cross-account bucket policy can still let it in.
    if ([...index.identityAccounts].some(account => account === null || !accounts.has(account)) || accounts.has(null))
      unknownReasons.push('identity_scope_other_account');
    if (index.undeclaredIdentities) unknownReasons.push('execution_identity_undeclared');
  }
  // Paths and identities of teams this reader cannot see may reach the resource too.
  if (!scope.allTeams && projection.outsideVisibleScope !== false) unknownReasons.push('outside_visible_scope');
  const status: Reach = reached ? 'yes' : unknownReasons.length ? 'unknown' : 'none_found';
  return { status, unknownReasons, directAccess, directAccessTruncated, identities, identitiesTruncated };
}
/**
 * Reach with its own work budget, shared by every row of one response: if it runs out, that
 * row and every later one read `unknown` (`reach_not_evaluated`) and the response still
 * answers. Rows judged before that keep their status: each used a complete index.
 */
export function boundedReach(remaining: number, maxBytes: number) {
  const work = new QueryWork(Math.max(1, remaining - 25), maxBytes);
  let exhausted = false;
  return (projection: MapProjection, resource: MapNode, scope: ReadScope, detail = false): ReachResult => {
    if (!exhausted)
      try {
        return outsideGuardReach(projection, resource, scope, work, detail);
      } catch (error) {
        const code = error instanceof MapQueryError ? error.code : '';
        if (code !== 'MAP_LIMIT_EXCEEDED' && code !== 'MAP_TIMEOUT') throw error;
        exhausted = true;
      }
    return {
      status: 'unknown',
      unknownReasons: ['reach_not_evaluated'],
      directAccess: [],
      directAccessTruncated: false,
      identities: [],
      identitiesTruncated: false,
    };
  };
}
export const OUTSIDE_GUARD_LIMITATION =
  'Only S3 identity policies and host declarations of this source are checked, within your visible scope; none_found is not proof that no path exists.';

/**
 * C2 per execution binding in the agent's focus. A store that did not run the reverse identity
 * read reports every binding as `unknown` rather than leaving it out.
 */
export function identityScope(projection: MapProjection, graph: { nodes: MapNode[] }): JsonObject[] {
  const executions = graph.nodes.filter(node => node.label === 'GuardExecutionBinding');
  const known = new Map((projection.identityScope ?? []).map(item => [item.executionBindingId, item]));
  return ordered(
    executions.map(execution => {
      const item = known.get(execution.entityId);
      return jsonObject({
        id: execution.entityId,
        ...(item ?? {
          executionBindingId: execution.entityId,
          deploymentId: null,
          tool: string(execution, 'tool'),
          identityId: null,
          accountId: null,
          status: 'unknown',
          // The store did not evaluate this binding (not run, or more work than allowed).
          reason: 'not_evaluated',
          observedAt: null,
          boundBuckets: [],
          extraResources: [],
          truncated: false,
          evidenceKind: 'iam_identity_policy_candidate',
          assessment: 'unknown',
        }),
      });
    }),
  );
}
