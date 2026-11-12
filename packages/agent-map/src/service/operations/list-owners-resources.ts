import type { JsonObject, MapNode, MapProjection } from '../../types.js';
import { sourceSelection, type Operation } from '../context.js';
import { ordered, page } from '../ordering.js';
import { boundedReach, OUTSIDE_GUARD_LIMITATION } from '../outside-guard.js';
import type { QueryArguments } from '../schemas.js';
import { ownerSummary, resourceSummary } from '../summaries.js';
import { string } from '../work.js';

const matches = (item: JsonObject, search: string): boolean =>
  !search ||
  [item.name, item.displayName, item.ownerId, item.bindingId, item.resourceRef].some(
    value => typeof value === 'string' && value.toLocaleLowerCase('en-US').includes(search),
  );
const searchText = (args: QueryArguments): string =>
  typeof args.search === 'string' ? args.search.toLocaleLowerCase('en-US') : '';

/** Owners and teams, with how many visible agents and resources each one owns. */
export const listOwners: Operation = {
  request: args => ({ ...sourceSelection(args), owners: true }),
  run({ args, work }, view) {
    const search = searchText(args);
    const rows = ordered(
      view.sources
        .flatMap(source => {
          work.step(source.current.nodes.length);
          return source.current.nodes
            .filter(node => node.label === 'GuardOwner')
            .map(node => ownerSummary(source, source.current, node, work));
        })
        .filter(item => matches(item, search) && (args.kind === undefined || item.kind === args.kind)),
    );
    const { items, ...pagination } = page(rows, args);
    return { data: { owners: items!, ...pagination } };
  },
};

/** Host-bound resources, each with whether something reaches it outside the guard. */
export const listResources: Operation = {
  // Policy evidence is read only where it is returned: a listing asks for none, so the store's
  // 512-pair policy limit does not bound it.
  request: args => ({ ...sourceSelection(args), outsideGuard: true, policy: false }),
  run({ scope, args, work, maxBytes }, view) {
    const search = searchText(args);
    // Where each resource row came from, so reach can be judged after paging.
    const origins = new Map<JsonObject, { projection: MapProjection; node: MapNode }>();
    const rows = ordered(
      view.sources
        .flatMap(source => {
          work.step(source.current.nodes.length);
          return source.current.nodes
            .filter(node => node.label === 'GuardResourceBinding')
            .map(node => {
              const summary = resourceSummary(source, source.current, node, work);
              origins.set(summary, { projection: source.current, node });
              return summary;
            });
        })
        .filter(
          item =>
            matches(item, search) &&
            (args.ownerId === undefined || item.ownerId === args.ownerId) &&
            (args.sensitivity === undefined || item.sensitivity === args.sensitivity),
        ),
    );
    const { items, ...pagination } = page(rows, args);
    // Reach is judged for the returned page only: its budget is never spent on rows the
    // caller does not see, and a filter or a later page costs no more than its own rows.
    const reach = boundedReach(work.remaining(), maxBytes);
    const resources = (items as JsonObject[]).map(item => {
      const origin = origins.get(item)!;
      return { ...item, outsideGuard: reach(origin.projection, origin.node, scope).status };
    });
    return {
      data: {
        resources,
        ...pagination,
        resourceCoverage: 'host_bound_resources',
        limitations: [
          'Declared selectors without a host resource binding are not included; see agent permissions.',
          OUTSIDE_GUARD_LIMITATION,
        ],
      },
    };
  },
};
