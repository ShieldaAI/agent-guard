import { fail } from '../../common.js';
import { sourceSelection, type Operation } from '../context.js';
import { ordered, page } from '../ordering.js';
import { boundedReach, directAccess, OUTSIDE_GUARD_LIMITATION } from '../outside-guard.js';
import { agentSummary, collection, findSource, focus, receipt, resourceSummary } from '../summaries.js';
import { matching, string } from '../work.js';

/** One host-bound resource, the agents mapped to it, and what reaches it outside the guard. */
export const getResourceAccess: Operation = {
  request: args => ({ ...sourceSelection(args), outsideGuard: true, policy: false }),
  run({ scope, args, work, maxBytes }, view) {
    const source = findSource(view, args.sourceId as string),
      projection = source.current;
    const resource = projection.nodes.find(
      node => node.label === 'GuardResourceBinding' && matching(node, args.resourceId as string, 'binding_id'),
    );
    if (!resource) fail('MAP_NOT_FOUND');
    const agents = ordered(
      projection.nodes
        .filter(node => node.label === 'GuardAgent')
        .filter(agent => {
          work.step();
          return focus(projection, agent, work).nodes.some(node => node.id === resource.id);
        })
        .map(agent => agentSummary(source, projection, agent, work)),
    );
    const { items, ...pagination } = page(agents, args);
    const reach = boundedReach(work.remaining(), maxBytes)(projection, resource, scope, true);
    return {
      data: {
        resource: resourceSummary(source, projection, resource, work),
        agents: items!,
        ...pagination,
        outsideGuard: {
          status: reach.status,
          directAccess: reach.directAccess,
          directAccessTruncated: reach.directAccessTruncated,
          identities: reach.identities,
          identitiesTruncated: reach.identitiesTruncated,
          unknownReasons: reach.unknownReasons,
          evidenceKind: 'declared',
        },
        receipt: receipt(source),
        assessment: 'unknown',
        collection,
        limitations: [
          'Agents have a declared selector mapped to this resource; this is not proof of current effective access.',
          OUTSIDE_GUARD_LIMITATION,
        ],
      },
    };
  },
};
