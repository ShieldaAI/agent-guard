import neo4j, { type Transaction, type Record as GraphRecord } from 'neo4j-driver';
import type { IdentityScopePlan, PolicyPlan } from '../policy-reader.js';
import { MapQueryError, type JsonObject, type MapProjection, type MapReadRequest, type ReadScope } from '../types.js';
import { SOURCES } from './queries.js';

/** The per-read limits a store was configured with. */
export interface StoreLimits {
  readonly sources: number;
  readonly nodes: number;
  readonly edges: number;
  readonly bytes: number;
  /** JSON values the final copy may hold. */
  readonly values: number;
  /** Host ceiling on policy evidence age, in seconds. */
  readonly policyAge: number;
}
/** Evidence read for one projection, kept so it can be read again and compared before answering. */
export interface PolicyCheck {
  plan: PolicyPlan;
  scopePlan: IdentityScopePlan;
  params: Record<string, unknown>;
  rows: JsonObject[];
  scopeRows: JsonObject[];
  readable: ReadonlySet<string> | null;
  projection: MapProjection;
  maximumAge: number;
  scopeBudget: number;
}
export interface AncestorJob {
  sourceId: string;
  params: Record<string, unknown>;
}
/** Identity scope runs after the ancestor phase, so task liveness sees the ancestors. */
export interface ScopeJob {
  sourceId: string;
  check: PolicyCheck;
  reach: boolean;
  enrolled: unknown;
}

/**
 * One read: its scope and selection, the open transaction, the deadline and the budgets every
 * phase draws from. Phases (sources, projections, ancestors, identity scope, verification) are
 * functions over this object, in the modules next to it.
 */
export class StoreRead {
  nodeCount = 0;
  edgeCount = 0;
  materializedBytes = 0;
  policyPairCount = 0;
  scopePairCount = 0;
  readonly ancestorJobs: AncestorJob[] = [];
  readonly policyChecks: PolicyCheck[] = [];
  readonly scopeJobs: ScopeJob[] = [];
  readonly agentSelected: boolean;
  /**
   * Boundary evidence (ancestors, `*` bindings, identity scope) for get_agent_access and the
   * page-of-agents flags read; get_agent_inventory keeps its cheaper read.
   */
  readonly boundary: boolean;
  /** Index into the per-scope query templates: all-teams or not, agent selected or not. */
  readonly accessMode: number;
  readonly common: Record<string, unknown>;
  /** The source rows this read answers for; set by `selectSources`. */
  selected: GraphRecord[] = [];
  readonly #sourceQuery: string;
  readonly #transaction: Transaction;
  readonly #deadline: number;
  readonly #clock: () => number;
  constructor(
    readonly scope: ReadScope,
    readonly selection: MapReadRequest,
    readonly limits: StoreLimits,
    clock: () => number,
    transaction: Transaction,
    deadline: number,
  ) {
    this.agentSelected = selection.agentId !== undefined || selection.agentIds !== undefined;
    this.boundary = selection.agentIds !== undefined || selection.boundary === true;
    this.accessMode = (scope.allTeams ? 2 : 0) + (this.agentSelected ? 1 : 0);
    this.#sourceQuery = SOURCES[this.accessMode]![selection.sourceId !== undefined ? 1 : 0]!;
    this.#transaction = transaction;
    this.#deadline = deadline;
    this.#clock = clock;
    this.common = {
      companyId: scope.companyId,
      tenantIds: [...scope.tenantIds],
      teamIds: [...scope.teamIds],
      allTeams: scope.allTeams,
      sourceId: selection.sourceId ?? null,
      agentIds: selection.agentIds ?? (selection.agentId !== undefined ? [selection.agentId] : null),
      boundary: this.boundary,
      sourceLimit: neo4j.int(limits.sources + 1),
    };
  }
  check(): void {
    if (Date.now() >= this.#deadline) throw new MapQueryError('MAP_TIMEOUT');
  }
  /** Runs one query inside the read's transaction, checking the deadline around every record. */
  async run(
    query: string,
    parameters: Record<string, unknown>,
    receive?: (record: GraphRecord) => void,
  ): Promise<GraphRecord[]> {
    this.check();
    const records: GraphRecord[] = [];
    for await (const record of this.#transaction.run(query, parameters)) {
      this.check();
      if (receive) receive(record);
      else records.push(record);
    }
    this.check();
    return records;
  }
  async selectSources(): Promise<void> {
    this.selected = await this.run(this.#sourceQuery, this.common);
    if (this.selected.length > this.limits.sources) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
  }
  /** Publication may advance while the read transaction is open. Never return mixed generations. */
  async recheckSources(): Promise<void> {
    const pointers = (items: readonly GraphRecord[]): string =>
      JSON.stringify(
        items.map(record => [
          record.get('id'),
          record.get('currentId'),
          record.get('previousId'),
          record.get('currentCoverage'),
          record.get('policyCoverage'),
        ]),
      );
    if (pointers(this.selected) !== pointers(await this.run(this.#sourceQuery, this.common)))
      throw new MapQueryError('MAP_UNAVAILABLE');
  }
  /** Counts what the read materializes against its byte budget. */
  charge(value: unknown): void {
    this.materializedBytes += Buffer.byteLength(JSON.stringify(value), 'utf8');
    if (this.materializedBytes > this.limits.bytes) throw new MapQueryError('MAP_LIMIT_EXCEEDED');
  }
  /** The store clock, in whole seconds. */
  now(): number {
    let stamp: number;
    try {
      stamp = this.#clock();
    } catch {
      throw new MapQueryError('MAP_UNAVAILABLE');
    }
    if (!Number.isSafeInteger(stamp) || stamp < 0 || stamp > 253_402_300_799_999)
      throw new MapQueryError('MAP_UNAVAILABLE');
    return Math.floor(stamp / 1000);
  }
  /** The enrolled policy age bound, when a read has evidence to judge. */
  maximumAgeFor(enrolled: unknown): number {
    if (enrolled === null || enrolled === undefined) return this.limits.policyAge;
    try {
      if (typeof enrolled !== 'string' || enrolled.length > 16_384) throw new Error();
      const parsed = JSON.parse(enrolled) as { maxAgeSeconds?: unknown };
      if (
        !parsed ||
        typeof parsed !== 'object' ||
        !Number.isSafeInteger(parsed.maxAgeSeconds) ||
        (parsed.maxAgeSeconds as number) < 1 ||
        (parsed.maxAgeSeconds as number) > 604800
      )
        throw new Error();
      return Math.min(this.limits.policyAge, parsed.maxAgeSeconds as number);
    } catch {
      throw new MapQueryError('MAP_UNAVAILABLE');
    }
  }
  transactionOpen(): boolean {
    return this.#transaction.isOpen();
  }
}
