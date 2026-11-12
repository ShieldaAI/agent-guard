import { dangerousThree, type DangerousThreeStatus } from '../../boundary-flags.js';
import { fail } from '../../common.js';
import { MapQueryError, type JsonObject } from '../../types.js';
import { sourceSelection, type Operation } from '../context.js';
import { agentFlags } from '../flags.js';
import { agentSortKey, page, sortedBy } from '../ordering.js';
import { agentSummary } from '../summaries.js';
import { QueryWork, string } from '../work.js';

/** The agent index, optionally filtered by boundary flag or carrying each row's flag. */
export const listAgents: Operation = {
  request(args) {
    // `flag` lists flagged agents; asking it for the absent ones is a contradiction.
    if (args.flag !== undefined && args.flagStatus === 'absent') fail('MAP_REQUEST_INVALID');
    return {
      ...sourceSelection(args),
      // Filtering by flag needs every agent's flags; showing them needs only the page's.
      ...(args.flag !== undefined || args.flagStatus !== undefined ? { flags: true } : { summary: true }),
    };
  },
  async run({ scope, args, work, maxBytes, read }, view) {
    const search = typeof args.search === 'string' ? args.search.toLocaleLowerCase('en-US') : '';
    const filtered = args.flag !== undefined || args.flagStatus !== undefined;
    const statuses: readonly DangerousThreeStatus[] =
      args.flagStatus !== undefined
        ? [args.flagStatus as DangerousThreeStatus]
        : args.flag !== undefined
          ? ['exposed', 'mitigated', 'unknown']
          : ['exposed', 'mitigated', 'unknown', 'absent'];
    const agents = view.sources
      .flatMap(source => {
        work.step(source.current.nodes.length);
        return source.current.nodes
          .filter(node => node.label === 'GuardAgent')
          .flatMap(agent => {
            const summary = agentSummary(source, source.current, agent, work);
            if (!filtered) return [summary];
            const status = agentFlags(source.current, agent, scope, work).status;
            return statuses.includes(status) ? [{ ...summary, boundaryFlags: { dangerousThree: status } }] : [];
          });
      })
      .filter(
        agent =>
          (!search ||
            [agent.name, agent.agentId].some(
              value => typeof value === 'string' && value.toLocaleLowerCase('en-US').includes(search),
            )) &&
          (args.ownerId === undefined || agent.ownerId === args.ownerId) &&
          (args.teamId === undefined || agent.teamId === args.teamId) &&
          (args.ownershipStatus === undefined || agent.ownershipStatus === args.ownershipStatus) &&
          (args.lifecycleState === undefined || agent.lifecycleState === args.lifecycleState) &&
          (args.environment === undefined ||
            (agent.environments as readonly string[]).includes(args.environment as string)),
      );
    // Unnamed agents sort last; code-point order keeps paging identical on every host and locale.
    sortedBy(agents, agentSortKey);
    const { items, ...pagination } = page(agents, args);
    let rows = items as JsonObject[];
    let flagsUnavailable: string | null = null;
    if (args.includeFlags === true && !filtered && rows.length) {
      // Flags for this page only: one read of these agents under the one-agent rules, so a
      // badge here matches get_agent_access and the work follows the page, not the fleet.
      // If that read is too large or fails, the listing still answers, with every flag unknown.
      // The page flags get what is left of this query's time, keep a margin for the answer,
      // and count their work separately: running out degrades flags, not the listing.
      const budget = work.remaining() - 50;
      const found = new Map<JsonObject, DangerousThreeStatus>();
      try {
        if (budget <= 0) fail('MAP_TIMEOUT');
        const flagged = await read(
          { ...sourceSelection(args), flags: true, agentIds: rows.map(agent => agent.id as string) },
          budget,
        );
        const flagWork = new QueryWork(Math.max(1, work.remaining() - 25), maxBytes);
        for (const agent of rows) {
          const source = flagged.sources.find(item => item.id === agent.sourceId);
          const node = source?.current.nodes.find(item => item.label === 'GuardAgent' && item.entityId === agent.id);
          // An agent gone between the two reads has no evidence now.
          if (source && node) found.set(agent, agentFlags(source.current, node, scope, flagWork).status);
        }
      } catch (error) {
        const code = error instanceof MapQueryError ? error.code : 'MAP_UNAVAILABLE';
        if (!['MAP_LIMIT_EXCEEDED', 'MAP_TIMEOUT', 'MAP_UNAVAILABLE'].includes(code)) throw error;
        found.clear();
        flagsUnavailable =
          code === 'MAP_LIMIT_EXCEEDED'
            ? 'flags_limit_exceeded'
            : code === 'MAP_TIMEOUT'
              ? 'flags_timeout'
              : 'flags_read_unavailable';
      }
      rows = rows.map(agent => ({ ...agent, boundaryFlags: { dangerousThree: found.get(agent) ?? 'unknown' } }));
    }
    return { data: { agents: rows, ...pagination, ...(flagsUnavailable ? { flagsUnavailable } : {}) } };
  },
};
