import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { Action, TaskOptions } from '@shieldaai/agent-guard';

export class ExecutorError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'ExecutorError'; }
}
/** Keep this second SQLite file outside the authority database's backup/restore domain. */
export interface LedgerWitness { readonly path: string; readonly mode: 'create' | 'resume' }
export const executionStatuses = Object.freeze(['PREPARED', 'ADMITTED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'UNKNOWN'] as const);
export type ExecutionStatus = typeof executionStatuses[number];
export interface ExecutionReceipt {
  readonly id: string;
  readonly status: ExecutionStatus;
  readonly charged?: number;
  readonly reconciliation?: { readonly referenceHash: string; readonly time: number };
}
export interface StoredTask {
  options: TaskOptions; parent: string | null; family: string; tokenHash: string; revoked: boolean;
  sourceTaskId?: string;
  calls: number; concurrent: number; spent: number; reserved: number;
}
export interface StoredAction {
  id: string; taskId: string; action: Action; digest: string; toolRevision: number;
  requiresApproval: boolean; status: ExecutionStatus; maxCost: number; charged?: number;
  reconciliation?: { referenceHash: string; time: number };
}
export interface MemoryRecord {
  id: string; tenantId: string; origin: string; sensitive: boolean; trusted: boolean;
  version: number; parentIds: string[]; quarantined: boolean; value: unknown;
  familyId?: string;
}
export interface Ledger {
  schema: 1; revision: number; epoch: number; lastClock: number;
  /** Stable for the lifetime of this ledger, including restarts and additive schema-1 upgrades. */
  inventoryInstanceId: string;
  tasks: Record<string, StoredTask>;
  families: Record<string, { sensitive: boolean; memorySources?: string[] }>;
  tools: Record<string, { fingerprint: string; revision: number; approved: boolean }>;
  actions: Record<string, StoredAction>;
  approvals: Record<string, { actionId: string; digest: string; expiresAt: number; approverId: string; used: boolean }>;
  memory: Record<string, MemoryRecord[]>;
  audit: { time: number; event: string; taskId?: string; actionId?: string }[];
}

function decode(text: string): Ledger {
  return JSON.parse(text, (_key, value: unknown) => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.assign(Object.create(null), value) : value) as Ledger;
}

function privateDatabasePath(path: string, flags: number): string {
  const absolute = resolve(path), directory = dirname(absolute);
  const parent = lstatSync(directory);
  if (!parent.isDirectory() || parent.isSymbolicLink() || realpathSync(directory) !== directory ||
      (process.platform !== 'win32' && ((parent.mode & 0o077) !== 0 || parent.uid !== process.getuid?.()))) {
    throw new ExecutorError('STORE_DIRECTORY_UNSAFE');
  }
  const fd = openSync(absolute, flags | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0), 0o600);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (process.platform !== 'win32' &&
        ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new ExecutorError('STORE_FILE_UNSAFE');
  } finally { closeSync(fd); }
  if (lstatSync(absolute).isSymbolicLink()) throw new ExecutorError('STORE_FILE_UNSAFE');
  return absolute;
}
const commitment = (payload: string) => createHash('sha256').update(payload).digest('hex');

/** A spelling comparison alone misses case-insensitive filesystem aliases. */
function custodyChain(path: string): string[] {
  const chain = [];
  for (let directory = dirname(resolve(path)); ; directory = dirname(directory)) {
    const stat = lstatSync(directory, { bigint: true });
    if (!stat.isDirectory() || (stat.uid !== 0n && stat.uid !== BigInt(process.geteuid!())) ||
        ((stat.mode & 0o022n) !== 0n && (stat.mode & 0o1000n) === 0n)) throw new ExecutorError('STORE_DIRECTORY_UNSAFE');
    chain.push(`${stat.dev}:${stat.ino}`);
    if (dirname(directory) === directory) return chain;
  }
}

/** A single owner, encrypted SQLite ledger. SQLite's exclusive lock is released by the OS on crash. */
export class LedgerStore {
  readonly #db: DatabaseSync;
  readonly #key: Buffer;
  readonly #witnessed: boolean;
  #closed = false;
  constructor(path: string, key: Uint8Array, readonly maxBytes = 16 * 1024 * 1024, witness?: LedgerWitness) {
    if (key.byteLength !== 32 || !Number.isSafeInteger(maxBytes) || maxBytes < 1024) throw new ExecutorError('STORE_CONFIG_INVALID');
    this.#witnessed = witness !== undefined;
    let anchor: string | undefined;
    if (this.#witnessed) {
      if (!witness || typeof witness.path !== 'string' || !isAbsolute(witness.path) || !isAbsolute(path) ||
          !['create', 'resume'].includes(witness.mode) || process.platform === 'win32') throw new ExecutorError('STORE_CONFIG_INVALID');
      let primaryChain: string[], witnessChain: string[];
      try { primaryChain = custodyChain(path); witnessChain = custodyChain(witness.path); }
      catch { throw new ExecutorError('STORE_DIRECTORY_UNSAFE'); }
      if (primaryChain.includes(witnessChain[0]!) || witnessChain.includes(primaryChain[0]!)) throw new ExecutorError('STORE_CONFIG_INVALID');
      const flags = witness.mode === 'create' ? constants.O_CREAT | constants.O_EXCL : 0;
      try { path = privateDatabasePath(path, flags); anchor = privateDatabasePath(witness.path, flags); }
      catch { throw new ExecutorError('STORE_WITNESS_UNAVAILABLE'); }
    } else if (path !== ':memory:') path = privateDatabasePath(path, constants.O_CREAT);
    this.#db = new DatabaseSync(path);
    this.#key = Buffer.from(key);
    try {
      this.#db.exec('PRAGMA busy_timeout=0; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE;');
      if (anchor) {
        this.#db.prepare('ATTACH DATABASE ? AS witness').run(anchor);
        this.#db.exec('PRAGMA main.synchronous=EXTRA; PRAGMA witness.journal_mode=DELETE; PRAGMA witness.synchronous=EXTRA; PRAGMA fullfsync=ON;');
        for (const schema of ['main', 'witness']) {
          if (this.#db.prepare(`PRAGMA ${schema}.journal_mode`).get()?.journal_mode !== 'delete' ||
              this.#db.prepare(`PRAGMA ${schema}.synchronous`).get()?.synchronous !== 3) throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
        }
      }
      this.#db.exec('BEGIN EXCLUSIVE');
      if (witness?.mode !== 'resume') this.#db.exec('CREATE TABLE IF NOT EXISTS main.ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)');
      const exists = this.#db.prepare('SELECT id FROM main.ledger WHERE id=1').get();
      if (!exists) {
        if (witness?.mode === 'resume') throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
        const payload = this.#seal(JSON.stringify({
          schema: 1, revision: 0, epoch: 0, lastClock: 0, inventoryInstanceId: randomUUID(),
          tasks: {}, families: {}, tools: {}, actions: {}, approvals: {}, memory: {}, audit: [],
        }));
        this.#db.prepare('INSERT INTO main.ledger(id,payload) VALUES(1,?)').run(payload);
        if (anchor) {
          this.#db.exec('CREATE TABLE witness.commitment (id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL)');
          this.#db.prepare('INSERT INTO witness.commitment(id,digest) VALUES(1,?)').run(commitment(payload));
        }
      }
      const state = this.read(); // Wrong keys and corrupt state fail at open, not at first effect.
      this.#db.exec('COMMIT');
      if (!Object.hasOwn(state, 'inventoryInstanceId')) {
        // Schema 1 readers preserve unknown properties. Migrate once before exposing the store;
        // a failed write rolls back without returning an identity that was never persisted.
        this.transaction(legacy => { legacy.inventoryInstanceId = randomUUID(); });
      }
    } catch {
      this.#db.close(); this.#key.fill(0);
      throw new ExecutorError(this.#witnessed ? 'STORE_WITNESS_UNAVAILABLE' : 'STORE_UNAVAILABLE');
    }
  }
  #seal(value: string): string {
    if (Buffer.byteLength(value) > this.maxBytes) throw new ExecutorError('STORE_CAPACITY_EXCEEDED');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(this.#aad());
    const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return JSON.stringify([iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')]);
  }
  #aad(): Buffer { return Buffer.from(this.#witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1'); }
  read(): Ledger {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    try {
      const row = this.#db.prepare("SELECT payload FROM main.ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB)) <= ?").get(this.maxBytes * 2 + 512);
      if (!row || typeof row.payload !== 'string') throw new Error();
      if (this.#witnessed && this.#db.prepare('SELECT digest FROM witness.commitment WHERE id=1').get()?.digest !== commitment(row.payload)) throw new Error();
      const [iv, tag, value] = JSON.parse(row.payload) as [string, string, string];
      if (value.length > this.maxBytes * 2) throw new Error();
      const cipher = createDecipheriv('aes-256-gcm', this.#key, Buffer.from(iv, 'base64'));
      cipher.setAAD(this.#aad());
      cipher.setAuthTag(Buffer.from(tag, 'base64'));
      const state = decode(Buffer.concat([cipher.update(Buffer.from(value, 'base64')), cipher.final()]).toString('utf8'));
      if (state.schema !== 1 || !Number.isSafeInteger(state.revision) || !state.tasks || !state.actions) throw new Error();
      if (Object.hasOwn(state, 'inventoryInstanceId') && (typeof state.inventoryInstanceId !== 'string' ||
          !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.inventoryInstanceId))) throw new Error();
      return state;
    } catch { throw new ExecutorError('STORE_CORRUPT'); }
  }
  transaction<T>(operation: (state: Ledger) => T): T {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const state = this.read();
      const result = operation(state);
      if (result && typeof (result as { then?: unknown }).then === 'function') throw new ExecutorError('ASYNC_TRANSACTION_FORBIDDEN');
      state.revision++;
      const payload = this.#seal(JSON.stringify(state));
      this.#db.prepare('UPDATE main.ledger SET payload=? WHERE id=1').run(payload);
      if (this.#witnessed && this.#db.prepare('UPDATE witness.commitment SET digest=? WHERE id=1').run(commitment(payload)).changes !== 1) {
        throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
      }
      this.#db.exec('COMMIT');
      return result;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  close(): void { if (!this.#closed) { this.#db.close(); this.#key.fill(0); this.#closed = true; } }
}
