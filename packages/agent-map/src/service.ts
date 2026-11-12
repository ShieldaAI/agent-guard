import { immutableJson } from '@shieldaai/agent-guard/internal';
import { fail, integer } from './common.js';
import {
  MapQueryError,
  validateReadScope,
  type JsonObject,
  type MapEdge,
  type MapNode,
  type MapReadRequest,
  type MapStore,
  type MapView,
  type ReadScope,
} from './types.js';
import { validateQueryArguments, type MapOperation } from './service/schemas.js';
import type { Operation } from './service/context.js';
import { QueryWork } from './service/work.js';
import { shortenIdentityScope } from './service/outside-guard.js';
import { listAgents } from './service/operations/list-agents.js';
import { getAgentAccess } from './service/operations/get-agent-access.js';
import { explainAccess } from './service/operations/explain-access.js';
import { findAgentsWithAccess } from './service/operations/find-agents-with-access.js';
import { getChanges } from './service/operations/get-changes.js';
import { getInventoryHealth } from './service/operations/get-inventory-health.js';
import { listOwners, listResources } from './service/operations/list-owners-resources.js';
import { getResourceAccess } from './service/operations/get-resource-access.js';
import { getAgentInventory } from './service/operations/get-agent-inventory.js';
import { listUnclaimedIdentities, listUndeclaredActivity } from './service/operations/discovery.js';

export {
  MAP_OPERATIONS,
  MAP_INPUT_SCHEMAS,
  MAP_OPERATION_DESCRIPTIONS,
  validateQueryArguments,
  type MapOperation,
} from './service/schemas.js';

// The closed vocabularies of the graph, for a viewer that labels every value it can be sent.
export { MAP_LABELS, MAP_RELATIONSHIPS } from './types.js';
export { MAP_PROPERTIES } from './projection-fields.js';

export interface MapResponse {
  readonly operation: MapOperation;
  readonly observedAt: string;
  readonly data: JsonObject;
  readonly graph?: { readonly nodes: readonly MapNode[]; readonly edges: readonly MapEdge[] };
}
export interface MapServiceOptions {
  readonly clock?: () => number;
  readonly maxResponseBytes?: number;
  readonly maxGraphNodes?: number;
  readonly maxGraphEdges?: number;
  readonly queryTimeoutMs?: number;
  readonly staleAfterSeconds?: number;
}

/** One handler per operation; each lives in its own module under `service/operations`. */
const OPERATIONS: Readonly<Record<MapOperation, Operation>> = Object.freeze({
  list_agents: listAgents,
  get_agent_access: getAgentAccess,
  explain_access: explainAccess,
  find_agents_with_access: findAgentsWithAccess,
  get_changes: getChanges,
  get_inventory_health: getInventoryHealth,
  list_owners: listOwners,
  list_resources: listResources,
  get_resource_access: getResourceAccess,
  get_agent_inventory: getAgentInventory,
  list_undeclared_activity: listUndeclaredActivity,
  list_unclaimed_identities: listUnclaimedIdentities,
});
/** Store errors a caller may see as they are; anything else reads as unavailable. */
const READ_ERRORS = ['MAP_NOT_FOUND', 'MAP_LIMIT_EXCEEDED', 'MAP_UNAVAILABLE', 'MAP_TIMEOUT', 'MAP_SCOPE_INVALID'];

/** One read-only evidence layer shared by HTTP, MCP and the browser. */
export class MapService {
  readonly #store: MapStore;
  readonly #clock: () => number;
  readonly #maxBytes: number;
  readonly #maxNodes: number;
  readonly #maxEdges: number;
  readonly #timeout: number;
  readonly #staleSeconds: number;
  constructor(store: MapStore, options: MapServiceOptions = {}) {
    if (
      !store ||
      typeof store.read !== 'function' ||
      (options.clock !== undefined && typeof options.clock !== 'function')
    )
      fail('MAP_CONFIG_INVALID');
    this.#store = store;
    this.#clock = options.clock ?? Date.now;
    this.#maxBytes = integer(options.maxResponseBytes, 1024 * 1024, 128, 8 * 1024 * 1024);
    this.#maxNodes = integer(options.maxGraphNodes, 500, 1, 2000);
    this.#maxEdges = integer(options.maxGraphEdges, 1000, 1, 5000);
    this.#timeout = integer(options.queryTimeoutMs, 5000, 10, 10_000);
    this.#staleSeconds = integer(options.staleAfterSeconds, 900, 1, 86400);
  }

  /** One store read under the caller's scope, bounded by `timeout`. */
  async #read(scope: ReadScope, request: MapReadRequest, timeout: number): Promise<MapView> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        this.#store.read(scope, request),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new MapQueryError('MAP_TIMEOUT')), timeout);
        }),
      ]);
    } catch (error) {
      if (error instanceof MapQueryError && READ_ERRORS.includes(error.code)) throw error;
      return fail('MAP_UNAVAILABLE');
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async query(inputScope: ReadScope, inputOperation: unknown, inputArgs: unknown): Promise<MapResponse> {
    const scope = validateReadScope(inputScope);
    const args = validateQueryArguments(inputOperation, inputArgs);
    const operation = inputOperation as MapOperation;
    const work = new QueryWork(this.#timeout, this.#maxBytes);
    let now: number;
    try {
      now = this.#clock();
    } catch {
      return fail('MAP_UNAVAILABLE');
    }
    if (!Number.isSafeInteger(now) || now < 0 || now > 253_402_300_799_999) fail('MAP_UNAVAILABLE');
    const handler = OPERATIONS[operation];
    const read = (request: MapReadRequest, timeout = this.#timeout): Promise<MapView> =>
      this.#read(scope, request, timeout);
    const request = handler.request(args);
    const view: MapView = request === null ? { sources: [] } : await read(request);
    work.step(view.sources.length);
    const result = await handler.run(
      { scope, args, now, work, maxBytes: this.#maxBytes, staleSeconds: this.#staleSeconds, read },
      view,
    );
    let { data, graph } = result;
    // The focused graph is an optional picture of evidence the response already lists. Past the
    // display cap it is left out and `graphStatus` says so; the evidence itself still answers.
    const withoutGraph = (payload: JsonObject): JsonObject => ({
      ...payload,
      graphStatus: 'too_large',
      graphLimit: { nodes: this.#maxNodes, edges: this.#maxEdges },
    });
    if (graph && (graph.nodes.length > this.#maxNodes || graph.edges.length > this.#maxEdges)) {
      graph = undefined;
      data = withoutGraph(data);
    }
    work.step();
    const observedAt = new Date(now).toISOString();
    const freeze = (payload: JsonObject): MapResponse | null => {
      try {
        // The copy is the response: `operation`, `observedAt`, `data` and, when kept, `graph`.
        return immutableJson(
          { operation, observedAt, data: payload, ...(graph ? { graph } : {}) },
          32,
          100_000,
          this.#maxBytes,
        ) as object as MapResponse;
      } catch {
        return null;
      }
    };
    // The identity-scope bucket lists are optional detail. If the response does not fit with
    // them, shorten them (marked truncated) before giving up on the whole response.
    const fitted = (payload: JsonObject): MapResponse | null => {
      let copied = freeze(payload);
      for (const keep of [25, 5, 0]) {
        if (copied) break;
        const shortened = shortenIdentityScope(payload, keep);
        if (shortened) copied = freeze(shortened);
      }
      return copied;
    };
    let copied = fitted(data);
    // Still too large with the graph: answer with the evidence alone.
    if (!copied && graph) {
      graph = undefined;
      copied = fitted(withoutGraph(data));
    }
    if (!copied) return fail('MAP_LIMIT_EXCEEDED');
    work.step();
    return copied;
  }
}
