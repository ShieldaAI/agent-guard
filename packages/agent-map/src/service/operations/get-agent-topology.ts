import { Buffer } from 'node:buffer';
import { fail } from '../../common.js';
import type { JsonObject } from '../../types.js';
import type { Operation } from '../context.js';
import { agentTopology, compactTopology, withoutHubLinks } from '../topology.js';

/**
 * The fleet as one graph: visible agents, what two or more of them share, the declared
 * relationships between them, each agent's isolation summary and its last snapshot change.
 */
export const getAgentTopology: Operation = {
  // A history read of every visible source, current and previous, without policy evidence.
  // `sourceId` only chooses what is drawn: an IAM identity shared with another source must
  // still read as shared.
  request: () => ({ history: true }),
  run: ({ scope, args, work, maxBytes }, view) => {
    // As everywhere in the map, a source you may not see and one that does not exist read the same.
    if (typeof args.sourceId === 'string' && !view.sources.some(source => source.id === args.sourceId))
      fail('MAP_NOT_FOUND');
    const data = agentTopology(
      view.sources,
      {
        ...(typeof args.sourceId === 'string' ? { sourceId: args.sourceId } : {}),
        ...(typeof args.teamId === 'string' ? { teamId: args.teamId } : {}),
        ...(typeof args.environment === 'string' ? { environment: args.environment } : {}),
      },
      scope,
      work,
      maxBytes,
    );
    // A large fleet answers without the optional detail lists, then without the links to shared
    // items, before it would fail on size.
    const fits = (value: JsonObject): boolean => Buffer.byteLength(JSON.stringify(value)) <= maxBytes * 0.9;
    work.step();
    if (fits(data)) return { data };
    const compact = compactTopology(data);
    work.step();
    return { data: fits(compact) ? compact : withoutHubLinks(compact) };
  },
};
