import { immutableJson } from '@shieldaai/agent-guard/internal';
import { mapIdentifier, MapQueryError, type MapReadRequest, type ReadScope } from '../types.js';
import { POLICY_SELECTION_KEYS } from './queries.js';

/** The read request, copied and checked: one read mode at a time, with only the options that mode takes. */
export function validateSelection(scope: ReadScope, request: MapReadRequest): MapReadRequest {
  try {
    const copied = immutableJson(request, 3, 128, 64 * 1024) as unknown as Record<string, unknown>;
    if (
      !copied ||
      Array.isArray(copied) ||
      typeof copied !== 'object' ||
      Object.keys(copied).some(
        key =>
          ![
            'sourceId',
            'agentId',
            'agentIds',
            'boundary',
            'history',
            'summary',
            'flags',
            'outsideGuard',
            'owners',
            'policy',
            'undeclared',
            'unclaimedIdentities',
            'page',
          ].includes(key),
      )
    )
      throw new Error();
    for (const key of ['flags', 'outsideGuard', 'owners', 'boundary', 'undeclared', 'unclaimedIdentities'])
      if (copied[key] !== undefined && typeof copied[key] !== 'boolean') throw new Error();
    // `false` reads no policy evidence; an object narrows the pairs to what the caller shows.
    if (copied.policy !== undefined && copied.policy !== false) {
      const policy = copied.policy as Record<string, unknown>;
      if (
        !policy ||
        typeof policy !== 'object' ||
        Array.isArray(policy) ||
        Object.keys(policy).some(key => !POLICY_SELECTION_KEYS.includes(key)) ||
        (policy.optional !== undefined && typeof policy.optional !== 'boolean')
      )
        throw new Error();
      for (const key of ['taskId', 'tool', 'resourceRef', 'action'])
        if (policy[key] !== undefined) mapIdentifier(policy[key]);
    }
    // One read mode at a time: summary, history, flags, outside-guard and discovery reads
    // differ in what they load, and no caller needs two.
    if (
      ['summary', 'history', 'flags', 'outsideGuard', 'owners', 'boundary', 'undeclared', 'unclaimedIdentities'].filter(
        key => copied[key] === true,
      ).length > 1
    )
      throw new Error();
    // Discovery reads: all-teams readers only, never for one agent. Undeclared activity
    // pages within one source; unclaimed identities span the reader's sources.
    const discovery = copied.undeclared === true || copied.unclaimedIdentities === true;
    if (discovery && (!scope.allTeams || copied.agentId !== undefined || copied.agentIds !== undefined))
      throw new Error();
    if (copied.unclaimedIdentities === true && copied.sourceId !== undefined) throw new Error();
    if (copied.page !== undefined) {
      const page = copied.page as Record<string, unknown>;
      const whole = (value: unknown, minimum: number, maximum: number): boolean =>
        typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
      if (
        !discovery ||
        !page ||
        typeof page !== 'object' ||
        Array.isArray(page) ||
        Object.keys(page).some(key => !['kind', 'offset', 'limit'].includes(key)) ||
        !whole(page.offset, 0, 100_000) ||
        !whole(page.limit, 1, 100) ||
        (copied.undeclared === true
          ? copied.sourceId === undefined || !['tasks', 'principals'].includes(page.kind as string)
          : page.kind !== undefined)
      )
        throw new Error();
    }
    if (copied.outsideGuard === true && copied.agentId !== undefined) throw new Error();
    if (copied.owners === true && (copied.agentId !== undefined || copied.agentIds !== undefined)) throw new Error();
    // A one-agent flags read must carry boundary evidence; the page read uses agentIds.
    if (copied.flags === true && copied.agentId !== undefined) throw new Error();
    if (copied.boundary === true && copied.agentId === undefined) throw new Error();
    if (copied.sourceId !== undefined) mapIdentifier(copied.sourceId);
    if (copied.agentId !== undefined) mapIdentifier(copied.agentId);
    // A page of agents for a flags read: one to 100 ids, never together with agentId.
    if (copied.agentIds !== undefined) {
      if (
        !Array.isArray(copied.agentIds) ||
        !copied.agentIds.length ||
        copied.agentIds.length > 100 ||
        copied.agentId !== undefined ||
        copied.flags !== true
      )
        throw new Error();
      for (const id of copied.agentIds) mapIdentifier(id);
    }
    if (copied.history !== undefined && typeof copied.history !== 'boolean') throw new Error();
    if (copied.summary !== undefined && typeof copied.summary !== 'boolean') throw new Error();
    return copied as MapReadRequest;
  } catch {
    throw new MapQueryError('MAP_REQUEST_INVALID');
  }
}
