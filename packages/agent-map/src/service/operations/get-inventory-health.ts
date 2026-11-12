import { fail } from '../../common.js';
import { MapQueryError, type JsonObject, type MapSource } from '../../types.js';
import { sourceSelection, type Operation } from '../context.js';
import { undeclaredCounts } from '../discovery.js';
import { policyCoverageOf, policyRecords } from '../policy.js';
import { freshness } from '../summaries.js';
import { string } from '../work.js';

/** Capture freshness and coverage per source, plus how much activity nobody declared. */
export const getInventoryHealth: Operation = {
  // Health reports policy coverage for the whole source: past the pair limit it reads
  // unknown instead of failing the health answer.
  request: args => ({ ...sourceSelection(args), policy: { optional: true } }),
  async run({ scope, args, now, work, staleSeconds, read }, view) {
    // Activity nobody declared, per source: a second, optional read. If it fails, is too
    // large or runs out of time, health still answers and the count reads unknown.
    const activity = new Map<string, MapSource>();
    let activityUnknown = 'not_reported';
    if (scope.allTeams && view.sources.length) {
      const budget = work.remaining() - 50;
      try {
        if (budget <= 0) fail('MAP_TIMEOUT');
        const found = await read({ ...sourceSelection(args), undeclared: true }, budget);
        for (const source of found.sources) activity.set(source.id, source);
      } catch (error) {
        const code = error instanceof MapQueryError ? error.code : 'MAP_UNAVAILABLE';
        activityUnknown =
          code === 'MAP_TIMEOUT'
            ? 'read_timeout'
            : code === 'MAP_LIMIT_EXCEEDED'
              ? 'limit_exceeded'
              : 'read_unavailable';
      }
    }
    const undeclaredActivity = (source: MapSource): JsonObject => {
      if (!scope.allTeams) return { status: 'not_visible', reason: 'all_teams_required' };
      const counted = activity.get(source.id);
      if (!counted?.current.undeclared) return { status: 'unknown', reason: activityUnknown };
      // Counted against a newer publication than the one this response describes.
      if (counted.current.id !== source.current.id) return { status: 'unknown', reason: 'publication_changed' };
      return undeclaredCounts(source, counted.current.undeclared);
    };
    return {
      data: {
        sources: view.sources.map(source => {
          work.step();
          return {
            id: source.id,
            sourceId: source.sourceId,
            tenantId: source.tenantId,
            profile: source.profile,
            generatedAt: source.current.generatedAt,
            snapshotId: source.current.snapshotId,
            projectionId: source.current.id,
            ...freshness(source.current.generatedAt, now, staleSeconds),
            coverage: {
              ...Object.fromEntries(
                Object.entries(source.current.coverage)
                  .filter(([component]) => component !== 'policy')
                  .map(([component, status]) => {
                    work.step();
                    return [component, { ...status, ...freshness(status.observedAt, now, staleSeconds) }];
                  }),
              ),
              policy: policyCoverageOf(source.current, policyRecords(source.current, work)),
            },
            undeclaredActivity: undeclaredActivity(source),
          };
        }),
        visibility: scope.allTeams ? 'enrolled_sources' : 'visible_agent_sources',
        limitations: [
          'Collection freshness is separate from current execution authority.',
          'undeclaredActivity counts tasks and caller principals that ran through this executor and belong to no declared agent. It is shown to all-teams readers only, and says nothing about agents that do not use the guard.',
        ],
      },
    };
  },
};
