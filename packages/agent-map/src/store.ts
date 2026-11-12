import neo4j, { type Driver, type Transaction } from 'neo4j-driver';
import { isIP } from 'node:net';
import { immutableJson } from '@shieldaai/agent-guard/internal';
import { integer, shortenScopeList } from './common.js';
import { loadAncestors } from './store/ancestors.js';
import { readDiscovery } from './store/discovery.js';
import { verifyEvidence } from './store/evidence.js';
import { loadIdentityScope } from './store/identity-scope.js';
import { readSources } from './store/projection.js';
import { MAX_STORE_BYTES, MAX_STORE_EDGES, MAX_STORE_NODES } from './store/queries.js';
import { StoreRead, type StoreLimits } from './store/read.js';
import { validateSelection } from './store/selection.js';
import {
  mapIdentifier,
  MapQueryError,
  validateReadScope,
  type MapIdentityScope,
  type MapReadRequest,
  type MapSource,
  type MapStore,
  type MapView,
  type ReadScope,
} from './types.js';

export interface Neo4jMapStoreOptions {
  readonly database?: string;
  /** The read's transaction deadline: default and at most 5,000 ms. It does not grow with the limits below. */
  readonly timeoutMs?: number;
  readonly maxSources?: number;
  /**
   * Nodes one read may load across its sources: default 2,000, at most 10,000. Values above
   * the default are accepted but have been exercised only against a fake driver, never against
   * a Neo4j database: a host that raises this, `maxEdges` or `maxBytes` should measure its own
   * reads against its own database, within the fixed 5-second deadline, before relying on them.
   */
  readonly maxNodes?: number;
  /** Edges one read may load across its sources: default 5,000, at most 25,000. */
  readonly maxEdges?: number;
  /** Bytes one read may materialize: default 4 MiB, at most 16 MiB. Raise it together with `maxNodes`. */
  readonly maxBytes?: number;
  /** Host ceiling, also limited by the snapshot's enrolled cloud age limit. */
  readonly policyMaxAgeSeconds?: number;
  readonly clock?: () => number;
}
/**
 * The view as the store returns it. The identity-scope bucket lists are optional detail: if
 * the view does not fit with them they are dropped (their statuses stand; see
 * `shortenScopeList`) before the read is refused.
 */
function freezeView(sources: readonly MapSource[], limits: StoreLimits): MapView {
  const freeze = (items: readonly MapSource[]): MapView =>
    immutableJson({ sources: items }, 16, limits.values, limits.bytes) as object as MapView;
  try {
    return freeze(sources);
  } catch {
    const bare = (records: readonly MapIdentityScope[]): readonly MapIdentityScope[] =>
      records.map(record => shortenScopeList(record, 0));
    const lean: MapSource[] = sources.map(item => ({
      ...item,
      current: {
        ...item.current,
        ...(item.current.identityScope ? { identityScope: bare(item.current.identityScope) } : {}),
        ...(item.current.identityReach ? { identityReach: bare(item.current.identityReach) } : {}),
      },
    }));
    try {
      return freeze(lean);
    } catch {
      throw new MapQueryError('MAP_LIMIT_EXCEEDED');
    }
  }
}

export class Neo4jMapStore implements MapStore {
  readonly #driver: Driver;
  readonly #database: string;
  readonly #timeout: number;
  readonly #limits: StoreLimits;
  readonly #clock: () => number;
  #active = 0;
  constructor(driver: Driver, options: Neo4jMapStoreOptions = {}) {
    this.#driver = driver;
    this.#database = mapIdentifier(options.database ?? 'neo4j', 'MAP_CONFIG_INVALID');
    this.#timeout = integer(options.timeoutMs, 5000, 1, 5000);
    const sources = integer(options.maxSources, 64, 1, 64);
    const nodes = integer(options.maxNodes, 2000, 1, MAX_STORE_NODES);
    const edges = integer(options.maxEdges, 5000, 1, MAX_STORE_EDGES);
    const bytes = integer(options.maxBytes, 4 * 1024 * 1024, 1, MAX_STORE_BYTES);
    this.#limits = {
      sources,
      nodes,
      edges,
      bytes,
      // JSON values the final copy may hold: the long-standing 200,000, or what the configured
      // node and edge limits need (about 30 values per node and 4 per edge).
      values: Math.max(200_000, nodes * 30 + edges * 4),
      policyAge: integer(options.policyMaxAgeSeconds, 7200, 1, 86400),
    };
    if (options.clock !== undefined && typeof options.clock !== 'function')
      throw new MapQueryError('MAP_CONFIG_INVALID');
    this.#clock = options.clock ?? Date.now;
  }
  async close(): Promise<void> {
    await this.#driver.close();
  }
  /**
   * One bounded, read-only transaction. The phases run in a fixed order: the source rows, then
   * either a discovery read or each source's projections, delegation ancestors and identity
   * scope; the sources are rechecked and the evidence read again before the view is returned.
   */
  async read(input: ReadScope, request: MapReadRequest = {}): Promise<MapView> {
    const scope = validateReadScope(input);
    const selection = validateSelection(scope, request);
    if (this.#active >= 8) throw new MapQueryError('MAP_UNAVAILABLE');
    this.#active++;
    const deadline = Date.now() + this.#timeout;
    let cancel = (): void => {};
    const work = (async (): Promise<MapView> => {
      const session = this.#driver.session({
        database: this.#database,
        defaultAccessMode: neo4j.session.READ,
        fetchSize: 32,
      });
      let transaction: Transaction | undefined;
      try {
        transaction = session.beginTransaction({ timeout: this.#timeout });
        const tx = transaction;
        cancel = () => {
          void tx.rollback().catch(() => {});
        };
        const read = new StoreRead(scope, selection, this.#limits, this.#clock, tx, deadline);
        await read.selectSources();
        if (selection.undeclared === true || selection.unclaimedIdentities === true) return await readDiscovery(read);
        const sources = await readSources(read);
        await loadAncestors(read, sources);
        await loadIdentityScope(read, sources);
        await read.recheckSources();
        await verifyEvidence(read);
        return freezeView(sources, this.#limits);
      } catch (error) {
        if (error instanceof MapQueryError) throw error;
        const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
        throw new MapQueryError(/TimedOut|Timeout/.test(code) ? 'MAP_TIMEOUT' : 'MAP_UNAVAILABLE');
      } finally {
        if (transaction?.isOpen()) await transaction.rollback().catch(() => {});
        await session.close().catch(() => {});
      }
    })();
    void work
      .finally(() => {
        this.#active--;
      })
      .catch(() => {});
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        cancel();
        reject(new MapQueryError('MAP_TIMEOUT'));
      }, this.#timeout);
    });
    try {
      return await Promise.race([work, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

export interface Neo4jMapConnectionOptions extends Neo4jMapStoreOptions {
  readonly uri: string;
  readonly username: string;
  readonly password: string;
}
export function createNeo4jMapStore(options: Neo4jMapConnectionOptions): Neo4jMapStore {
  try {
    const uri = new URL(options.uri);
    const host = uri.hostname.replace(/^\[|\]$/g, '');
    const local = isIP(host) === 4 ? host.startsWith('127.') : host === '::1';
    if (
      !['bolt:', 'bolt+s:', 'neo4j+s:'].includes(uri.protocol) ||
      !host ||
      uri.username ||
      uri.password ||
      uri.pathname ||
      uri.search ||
      uri.hash ||
      (uri.port && (+uri.port < 1 || +uri.port > 65535)) ||
      (uri.protocol === 'bolt:' && !local)
    )
      throw new Error();
    mapIdentifier(options.username);
    if (typeof options.password !== 'string' || !options.password || options.password.length > 8192) throw new Error();
    const driver = neo4j.driver(options.uri, neo4j.auth.basic(options.username, options.password), {
      connectionTimeout: 5000,
      connectionAcquisitionTimeout: 5000,
      maxTransactionRetryTime: 0,
      maxConnectionPoolSize: 8,
    });
    return new Neo4jMapStore(driver, options);
  } catch {
    throw new MapQueryError('MAP_CONFIG_INVALID');
  }
}
