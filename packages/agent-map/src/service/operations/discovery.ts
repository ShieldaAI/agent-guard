import { fail } from '../../common.js';
import type { Operation } from '../context.js';
import { notVisible, UNCLAIMED_LIMITATIONS, UNDECLARED_LIMITATIONS, undeclaredCounts } from '../discovery.js';
import { page } from '../ordering.js';
import { pageArguments } from '../schemas.js';
import { findSource, freshness, receipt } from '../summaries.js';
import { string } from '../work.js';

// Discovery operations use their own bounded reads, and none at all for a team-scoped reader.

/** Tasks or caller principals of one source that no declared agent accounts for. */
export const listUndeclaredActivity: Operation = {
  request: () => null,
  async run({ scope, args, work, read }) {
    if (!scope.allTeams) return { data: notVisible() };
    const kind = (args.kind ?? 'tasks') as 'tasks' | 'principals';
    const { offset, limit } = pageArguments(args);
    const found = await read({ sourceId: args.sourceId as string, undeclared: true, page: { kind, offset, limit } });
    const source = findSource(found, args.sourceId as string);
    const activity = source.current.undeclared;
    if (!activity || activity.page?.kind !== kind) fail('MAP_UNAVAILABLE');
    work.step(activity.page.items.length);
    const total = kind === 'tasks' ? activity.tasks : activity.principals;
    const minimum = kind === 'tasks' ? activity.tasksCapped : activity.principalsCapped;
    return {
      data: {
        visibility: 'all_teams',
        kind,
        items: activity.page.items.map(item => ({ ...item, evidenceKind: 'observed', assessment: 'unknown' })),
        total,
        totalIsMinimum: minimum,
        offset,
        limit,
        truncated: minimum || offset + limit < total,
        counts: undeclaredCounts(source, activity),
        receipt: receipt(source),
        assessment: 'unknown',
        limitations: UNDECLARED_LIMITATIONS,
      },
    };
  },
};

/** IAM roles and users of the enrolled AWS accounts that no declared agent names. */
export const listUnclaimedIdentities: Operation = {
  request: () => null,
  async run({ scope, args, now, work, staleSeconds, read }) {
    if (!scope.allTeams) return { data: notVisible() };
    const { offset, limit } = pageArguments(args);
    const found = await read({ unclaimedIdentities: true, page: { offset, limit } });
    const result = found.unclaimedIdentities;
    if (!result) fail('MAP_UNAVAILABLE');
    work.step(result.accounts.length + result.identities.length + found.sources.length);
    const complete = result.accounts.filter(account => account.status === 'complete').length;
    // No usable collection: nothing is known, so no total and no list. Some unusable: the
    // total and the list cover the complete accounts only.
    const status = !complete ? 'unknown' : complete === result.accounts.length ? 'complete' : 'partial';
    return {
      data: {
        visibility: 'all_teams',
        status,
        reason: result.accounts.length ? null : 'cloud_not_collected',
        identities: result.identities.map(identity => ({
          ...identity,
          candidate: true,
          evidenceKind: 'provider_inventory',
          assessment: 'unknown',
        })),
        total: status === 'unknown' ? null : result.total,
        offset,
        limit,
        truncated: status !== 'unknown' && offset + limit < result.total,
        accounts: result.accounts.map(account => ({
          ...account,
          ...(account.observedAt ? freshness(account.observedAt, now, staleSeconds) : {}),
        })),
        bindingsWithoutIdentity: result.bindingsWithoutIdentity,
        // The snapshots whose declared bindings decided what counts as claimed.
        declaredFrom: found.sources.map(source => ({
          sourceId: source.id,
          tenantId: source.tenantId,
          snapshotId: source.current.snapshotId,
          generatedAt: source.current.generatedAt,
        })),
        assessment: 'unknown',
        limitations: UNCLAIMED_LIMITATIONS,
      },
    };
  },
};
