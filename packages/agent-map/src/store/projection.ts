import neo4j from 'neo4j-driver';
import { s3BucketName } from '../common.js';
import { identityScopePlan, policyEvidence, policyPlan, type PolicyPlan } from '../policy-reader.js';
import {
  MAP_LABELS,
  MAP_RELATIONSHIPS,
  mapIdentifier,
  MapQueryError,
  type GuardRelation,
  type JsonObject,
  type MapEdge,
  type MapNode,
  type MapPolicySelection,
  type MapProjection,
  type MapSource,
} from '../types.js';
import { readPolicyRows } from './evidence.js';
import { boundBuckets, converted, coreCaptureTimes, coverage, safeNode, SCOPE_RECORD_BYTES, text } from './nodes.js';
import {
  EDGES,
  HIDDEN_SCOPE,
  IN_SCOPE_TARGETS,
  NODES,
  OWNER_INDEX,
  OWNER_INDEX_SCOPED,
  PREVIOUS,
  READ_ORDER,
  WILDCARD,
} from './queries.js';
import { StoreRead } from './read.js';

/** One source row, as the source query returned it. */
export interface SourceRow {
  readonly sourceId: string;
  readonly tenantId: string;
  readonly currentId: string;
  readonly profile: MapSource['profile'];
  /** The snapshot's enrolled cloud coverage (its policy age limit), unparsed; read only when evidence is judged. */
  readonly enrolled: () => unknown;
}
/**
 * One projection of one source: its nodes label by label (each query limited to what earlier
 * ones authorized), the edges among them and, for the current projection, the evidence the
 * read mode asks for. Ancestors and identity scope are queued and read after every source.
 */
export async function readProjection(
  read: StoreRead,
  source: SourceRow,
  id: string,
  snapshotId: string,
  generatedAt: string,
  rawCoverage: unknown,
  currentNodes: readonly MapNode[] = [],
): Promise<MapProjection> {
  const { scope, selection, agentSelected, boundary, accessMode } = read;
  const { sourceId, tenantId, currentId, profile } = source;
  const captures = coreCaptureTimes(rawCoverage);
  const params = {
    ...read.common,
    sourceId,
    tenantId,
    projectionId: id,
    currentId,
    labels: [...MAP_LABELS],
    currentAgentEntityIds: currentNodes.filter(node => node.label === 'GuardAgent').map(node => node.entityId),
    currentTaskEntityIds: currentNodes.filter(node => node.label === 'GuardTask').map(node => node.entityId),
  };
  const nodes: MapNode[] = [];
  // Ids already loaded, by label: each label's query is limited to what earlier ones found.
  const idsByLabel = new Map<string, string[]>();
  const nodeQueries = NODES[accessMode]![id === currentId ? 0 : 1]!;
  for (const label of selection.summary
    ? (['GuardAgent', 'GuardDeployment', 'GuardOwner'] as const)
    : selection.owners
      ? scope.allTeams
        ? OWNER_INDEX
        : OWNER_INDEX_SCOPED
      : READ_ORDER) {
    const authorized: Record<string, unknown> = Object.fromEntries(
      MAP_LABELS.map(kind => [`${kind}Ids`, idsByLabel.get(kind) ?? []]),
    );
    await read.run(
      nodeQueries[label],
      { ...params, ...authorized, nodeLimit: neo4j.int(read.limits.nodes - read.nodeCount + 1) },
      item => {
        if (++read.nodeCount > read.limits.nodes) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
        if (item.get('label') !== label) throw new MapQueryError('MAP_UNAVAILABLE');
        const node = safeNode(item.get('node'), label, sourceId, id);
        read.charge(node);
        nodes.push(node);
        const ids = idsByLabel.get(label);
        if (ids) ids.push(node.id);
        else idsByLabel.set(label, [node.id]);
      },
    );
  }
  // Delegation ancestors are read after every source's own nodes and edges (below).
  if (agentSelected && boundary && id === currentId) read.ancestorJobs.push({ sourceId, params });
  const nodeIds = nodes.map(node => node.id);
  if (new Set(nodeIds).size !== nodes.length || new Set(nodes.map(node => node.entityId)).size !== nodes.length)
    throw new MapQueryError('MAP_UNAVAILABLE');
  const ids = new Set(nodeIds);
  const edges: MapEdge[] = [];
  await read.run(
    EDGES,
    {
      ...params,
      nodeIds,
      relationships: [...MAP_RELATIONSHIPS],
      edgeLimit: neo4j.int(read.limits.edges - read.edgeCount + 1),
    },
    item => {
      if (++read.edgeCount > read.limits.edges) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
      const source = text(item.get('source')),
        target = text(item.get('target')),
        kind = item.get('kind');
      if (!ids.has(source) || !ids.has(target) || !MAP_RELATIONSHIPS.includes(kind))
        throw new MapQueryError('MAP_UNAVAILABLE');
      const edge = { source, target, kind: kind as GuardRelation };
      read.charge(edge);
      edges.push(edge);
    },
  );
  let projection: MapProjection = {
    id,
    snapshotId,
    generatedAt,
    status: 'published',
    nodes,
    edges,
    coverage: coverage(
      nodes,
      captures,
      profile,
      (selection.summary ?? false) || selection.owners === true,
      read.now() * 1000,
    ),
  };
  if (agentSelected && boundary && id === currentId) {
    // The agent's own `*` grants (ancestors' grants are not read).
    const wildcardTools = [
      ...new Set(
        nodes
          .filter(node => node.label === 'GuardGrant')
          .filter(node => (node.properties.resources as readonly string[]).includes('*'))
          .map(node => node.properties.tool as string),
      ),
    ].sort();
    // No prototype: a tool may be named like an Object.prototype member.
    const wildcardSensitivity: Record<string, { id: string; sensitivity: string }[]> = Object.create(null);
    if (wildcardTools.length)
      await read.run(WILDCARD[accessMode]!, { ...params, wildcardTools }, item => {
        const tool = item.get('tool'),
          bindings = converted(item.get('bindings'));
        if (
          typeof tool !== 'string' ||
          !wildcardTools.includes(tool) ||
          !Array.isArray(bindings) ||
          bindings.length > 5 ||
          Object.hasOwn(wildcardSensitivity, tool) ||
          bindings.some(
            binding =>
              !binding ||
              typeof binding.id !== 'string' ||
              !['confidential', 'restricted'].includes(binding.sensitivity),
          )
        )
          throw new MapQueryError('MAP_UNAVAILABLE');
        // The same identifier rule as every node id, so list and detail agree.
        for (const binding of bindings) mapIdentifier(binding.id, 'MAP_UNAVAILABLE');
        wildcardSensitivity[tool] = bindings.map(binding => ({
          id: binding.id as string,
          sensitivity: binding.sensitivity as string,
        }));
      });
    read.charge(wildcardSensitivity);
    projection = { ...projection, wildcardSensitivity };
  }
  const reach = selection.agentId === undefined && selection.outsideGuard === true;
  // Policy evidence only where the caller shows it. A listing that asked for none
  // (`policy: false`) is not bound by the pair limit; it still gets the reach and
  // boundary reads below, which share this block's recheck.
  const wantsPolicy = selection.policy !== false;
  const evidenceRead =
    !selection.summary && !selection.history && !selection.flags && !selection.owners && id === currentId;
  if (evidenceRead && (wantsPolicy || reach || (selection.agentId !== undefined && boundary))) {
    let plan: PolicyPlan = { records: [], probes: [] };
    let policyNotLoaded = false;
    if (wantsPolicy) {
      const select: MapPolicySelection = selection.policy || {};
      try {
        plan = policyPlan(scope.companyId, tenantId, nodes, edges, 512 - read.policyPairCount, select);
      } catch (error) {
        // An optional read answers without policy evidence and says so.
        if (select.optional !== true || !(error instanceof MapQueryError) || error.code !== 'MAP_LIMIT_EXCEEDED')
          throw error;
        policyNotLoaded = true;
      }
    }
    read.policyPairCount += plan.records.length;
    const enrolled = source.enrolled();
    const maximumAge = plan.probes.length ? read.maximumAgeFor(enrolled) : read.limits.policyAge;
    const rows = await readPolicyRows(read, plan, params, true);
    const evidence = policyEvidence(plan, rows, read.now(), maximumAge);
    for (const item of evidence) read.charge(item);
    // A team reader sees only buckets and host targets that an in-scope binding maps;
    // null allows all.
    let readable: Set<string> | null = null;
    let inScopeTargets: string[] | undefined;
    if (selection.agentId !== undefined && boundary && !scope.allTeams) {
      const names = new Set(boundBuckets(nodes));
      const hosts = new Set<string>();
      let count = 0;
      // Host ids only for targets the agent's own declared paths name: bounded by the read.
      const targetRefs = [
        ...new Set(
          nodes
            .filter(node => node.label === 'GuardDirectAccess')
            .map(node => node.properties.target_ref)
            .filter((ref): ref is string => typeof ref === 'string'),
        ),
      ];
      await read.run(IN_SCOPE_TARGETS, { ...params, targetRefs }, item => {
        if (++count > 20_000) return;
        const name = s3BucketName(item.get('arn'));
        if (name !== null) names.add(name);
        const host = item.get('host');
        if (typeof host === 'string' && /^opaque:[a-f0-9]{64}$/.test(host)) hosts.add(host);
      });
      // Past the bound, fall back to what this read holds: that only withholds more.
      readable = count > 20_000 ? new Set(boundBuckets(nodes)) : names;
      inScopeTargets = count > 20_000 ? [] : [...hosts].sort();
      read.charge(inScopeTargets);
    }
    let outsideVisibleScope: boolean | undefined;
    if (reach && !scope.allTeams) {
      const visibleIds = nodes
        .filter(node => node.label === 'GuardDeployment' || node.label === 'GuardTask')
        .map(node => node.id);
      const [hidden] = await read.run(HIDDEN_SCOPE, { ...params, visibleIds });
      // Only an explicit "nothing hidden" lets none_found stand.
      outsideVisibleScope = hidden?.get('hidden') !== false;
    }
    const enriched = {
      ...projection,
      ...(!wantsPolicy ? {} : policyNotLoaded ? { policyEvidenceNotLoaded: true } : { policyEvidence: evidence }),
      ...(outsideVisibleScope === undefined ? {} : { outsideVisibleScope }),
      ...(inScopeTargets === undefined ? {} : { inScopeTargets }),
    };
    const check = {
      plan,
      scopePlan: identityScopePlan(scope.companyId, tenantId, [], [], 0),
      params,
      rows,
      scopeRows: [] as JsonObject[],
      readable,
      projection: enriched,
      maximumAge,
      scopeBudget: SCOPE_RECORD_BYTES,
    };
    read.policyChecks.push(check);
    if ((selection.agentId !== undefined && boundary) || reach)
      read.scopeJobs.push({ sourceId, check, reach, enrolled });
    return enriched;
  }
  return projection;
}

/** Every selected source with its current projection and, for a history read, its previous one. */
export async function readSources(read: StoreRead): Promise<MapSource[]> {
  const { scope, selection } = read;
  const sources: MapSource[] = [];
  for (const record of read.selected) {
    const sourceId = text(record.get('id'));
    const tenantId = text(record.get('tenantId'));
    const currentId = text(record.get('currentId'));
    const profile = record.get('profile');
    if (!scope.tenantIds.includes(tenantId) || !['core', 'host', 'host-mcp'].includes(profile))
      throw new MapQueryError('MAP_UNAVAILABLE');
    const source: SourceRow = {
      sourceId,
      tenantId,
      currentId,
      profile,
      enrolled: () => record.get('policyCoverage'),
    };
    const current = await readProjection(
      read,
      source,
      currentId,
      text(record.get('currentSnapshotId')),
      text(record.get('currentGeneratedAt')),
      record.get('currentCoverage'),
    );
    let previous: MapProjection | null = null;
    if (selection.history && record.get('previousId')) {
      const previousId = text(record.get('previousId'));
      const previousRecords = await read.run(PREVIOUS, { sourceId, projectionId: previousId });
      if (previousRecords.length === 1) {
        const item = previousRecords[0]!;
        previous = await readProjection(
          read,
          source,
          previousId,
          text(item.get('snapshotId')),
          text(item.get('generatedAt')),
          item.get('coverage'),
          current.nodes,
        );
      }
    }
    sources.push({ id: sourceId, tenantId, sourceId: text(record.get('nativeSourceId')), profile, current, previous });
  }
  return sources;
}
