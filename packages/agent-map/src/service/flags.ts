import { DANGEROUS_THREE_LIMITATIONS, dangerousThree, type FlagGraph } from '../boundary-flags.js';
import { MapQueryError, type JsonObject, type MapNode, type MapProjection, type ReadScope } from '../types.js';
import { jsonObject } from './json.js';
import { connected, number, QueryWork, string } from './work.js';

/**
 * The bounded, read-only graph view the boundary flags use. Sensitive bindings for `*` grants
 * come from the store's wildcard read when it ran (one-agent boundary reads); a team-wide read
 * already holds every in-scope binding, indexed once per projection.
 */
export const sensitiveIndex = new WeakMap<MapProjection, Map<string, { id: string; sensitivity: string }[]>>();
export function flagGraph(projection: MapProjection, work: QueryWork): FlagGraph {
  return {
    linked: (node, kind, reverse = false) => connected(projection, new Set([node.id]), kind, work, reverse),
    sensitiveBindings: tool => {
      if (projection.wildcardSensitivity)
        return Object.hasOwn(projection.wildcardSensitivity, tool) ? projection.wildcardSensitivity[tool]! : [];
      let index = sensitiveIndex.get(projection);
      if (!index) {
        work.step(projection.nodes.length);
        index = new Map();
        for (const node of projection.nodes) {
          const name = string(node, 'tool'),
            sensitivity = string(node, 'sensitivity');
          if (node.label !== 'GuardResourceBinding' || name === null) continue;
          if (sensitivity !== 'confidential' && sensitivity !== 'restricted') continue;
          const items = index.get(name) ?? [];
          items.push({ id: node.entityId, sensitivity });
          index.set(name, items);
        }
        for (const [name, items] of index)
          index.set(name, items.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).slice(0, 5));
        sensitiveIndex.set(projection, index);
      }
      return index.get(tool) ?? [];
    },
    step: amount => work.step(amount),
  };
}
/** Task expiry is judged at the snapshot's own capture time, so list and detail agree. */
export function agentFlags(projection: MapProjection, agent: MapNode, scope: ReadScope, work: QueryWork) {
  return dangerousThree(
    flagGraph(projection, work),
    agent,
    Date.parse(projection.generatedAt),
    scope.allTeams,
    projection.ancestorsNotLoaded === true,
  );
}

/**
 * The detail flag with its own work budget: a very large lineage degrades the flag to
 * `unknown`, it never fails the rest of get_agent_access.
 */
export function detailFlags(
  projection: MapProjection,
  agent: MapNode,
  scope: ReadScope,
  remaining: number,
  maxBytes: number,
): JsonObject {
  try {
    return jsonObject(agentFlags(projection, agent, scope, new QueryWork(Math.max(1, remaining - 25), maxBytes)));
  } catch (error) {
    const code = error instanceof MapQueryError ? error.code : '';
    if (code !== 'MAP_LIMIT_EXCEEDED' && code !== 'MAP_TIMEOUT') throw error;
    return jsonObject({
      kind: 'dangerous_three',
      status: 'unknown',
      taskId: null,
      legs: { privateData: 'unknown', outsideContent: 'unknown', externalSend: 'unknown' },
      evidence: [],
      evidenceTruncated: false,
      notes: [code === 'MAP_TIMEOUT' ? 'flags_timeout' : 'flags_limit_exceeded'],
      liveTasks: 0,
      evidenceKind: 'declared',
      assessment: 'unknown',
      limitations: DANGEROUS_THREE_LIMITATIONS,
    });
  }
}
