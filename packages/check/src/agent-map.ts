import { isRecord } from './text.js';

/**
 * Mode C: read-only evidence from a running Agent Map. Three queries, all reads: inventory
 * health (freshness and activity no declared agent accounts for), unclaimed cloud identities,
 * and agents whose dangerous-three flag is `exposed`. Nothing is written.
 */

export interface LiveSource {
  readonly id: string;
  readonly sourceId: string;
  readonly stale: boolean;
  /** Undeclared activity counts; null when the credential cannot see them (team-scoped). */
  readonly undeclared: {
    readonly status: string;
    readonly tasks: number | null;
    readonly principals: number | null;
    readonly minimum: boolean;
  } | null;
}

export interface LiveEvidence {
  readonly url: string;
  readonly sources: readonly LiveSource[];
  readonly unclaimed: {
    readonly status: string;
    readonly total: number | null;
    readonly names: readonly string[];
  } | null;
  readonly exposedAgents: readonly {
    readonly id: string;
    readonly agentId: string;
    readonly name: string;
    readonly sourceId: string;
  }[];
  readonly notes: readonly string[];
}

export interface LiveOptions {
  readonly url: string;
  readonly token: string;
  readonly timeoutMs?: number;
  /** For tests; defaults to the global fetch. */
  readonly fetch?: typeof fetch;
}

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export class AgentMapError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
    this.name = 'AgentMapError';
  }
}

async function query(
  options: LiveOptions,
  operation: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const doFetch = options.fetch ?? fetch;
  let response: Response;
  try {
    response = await doFetch(`${options.url.replace(/\/$/, '')}/v1/query`, {
      method: 'POST',
      redirect: 'error',
      headers: {
        authorization: `Bearer ${options.token}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({ operation, args }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
    });
  } catch (error) {
    throw new AgentMapError(`Agent Map ${operation}: ${error instanceof Error ? error.message : String(error)}`, null);
  }
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader)
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new AgentMapError(
          `Agent Map ${operation}: response larger than ${MAX_RESPONSE_BYTES} bytes`,
          response.status,
        );
      }
      chunks.push(value);
    }
  const text = Buffer.concat(chunks).toString('utf8');
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new AgentMapError(
      `Agent Map ${operation}: answered ${response.status} with a non-JSON body`,
      response.status,
    );
  }
  if (!response.ok) {
    const code = isRecord(body) && typeof body['error'] === 'string' ? body['error'] : `HTTP ${response.status}`;
    throw new AgentMapError(`Agent Map ${operation}: ${code}`, response.status);
  }
  if (!isRecord(body) || !isRecord(body['data']))
    throw new AgentMapError(`Agent Map ${operation}: unexpected answer`, response.status);
  return body['data'];
}

const num = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) ? value : null);
const text = (value: unknown, fallback = ''): string => (typeof value === 'string' ? value : fallback);

/** Queries a running Agent Map. Throws AgentMapError on a transport, auth or format problem. */
export async function fetchLiveEvidence(options: LiveOptions): Promise<LiveEvidence> {
  const notes: string[] = [];
  const health = await query(options, 'get_inventory_health', {});
  const sources: LiveSource[] = (Array.isArray(health['sources']) ? health['sources'] : [])
    .filter(isRecord)
    .map(source => {
      const activity = isRecord(source['undeclaredActivity']) ? source['undeclaredActivity'] : undefined;
      const visible = activity && activity['status'] !== 'not_visible';
      if (activity && !visible) notes.push('Undeclared activity needs an all-teams Agent Map credential.');
      return {
        id: text(source['id']),
        sourceId: text(source['sourceId'], text(source['id'])),
        stale: source['stale'] === true,
        undeclared:
          activity && visible
            ? {
                status: text(activity['status'], 'unknown'),
                tasks: num(activity['tasks']),
                principals: num(activity['principals']),
                minimum: activity['tasksIsMinimum'] === true || activity['principalsIsMinimum'] === true,
              }
            : null,
      };
    });
  // Unclaimed identities need cloud collection, which many maps do not have: a note, not a failure.
  let identities: Record<string, unknown> | undefined;
  try {
    identities = await query(options, 'list_unclaimed_identities', { limit: 20 });
  } catch (error) {
    if (!(error instanceof AgentMapError) || error.status === null || error.status === 401 || error.status === 403)
      throw error;
    notes.push(`Unclaimed identities could not be read (${error.message.replace(/^Agent Map [a-z_]+: /, '')}).`);
  }
  const unclaimed =
    identities === undefined || identities['status'] === 'not_visible'
      ? null
      : {
          status: text(identities['status'], 'unknown'),
          total: num(identities['total']),
          names: (Array.isArray(identities['identities']) ? identities['identities'] : [])
            .filter(isRecord)
            .map(identity => text(identity['name'], text(identity['arn'], text(identity['id']))))
            .filter(Boolean),
        };
  if (identities?.['status'] === 'not_visible')
    notes.push('Unclaimed identities need an all-teams Agent Map credential.');
  const listed = await query(options, 'list_agents', { flagStatus: 'exposed', limit: 100 });
  if (listed['truncated'] === true) notes.push('More than 100 exposed agents; only the first 100 are listed.');
  const exposedAgents = (Array.isArray(listed['agents']) ? listed['agents'] : []).filter(isRecord).map(agent => ({
    id: text(agent['id']),
    agentId: text(agent['agentId'], text(agent['id'])),
    name: text(agent['name'], text(agent['agentId'])),
    sourceId: text(agent['sourceId']),
  }));
  return { url: options.url, sources, unclaimed, exposedAgents, notes: [...new Set(notes)] };
}
