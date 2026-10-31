import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { Action, TaskOptions } from '@shieldaai/agent-guard';

export class ExecutorError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'ExecutorError'; }
}
export type ExecutionStatus = 'PREPARED' | 'ADMITTED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'UNKNOWN';
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

/** A single owner, encrypted SQLite ledger. SQLite's exclusive lock is released by the OS on crash. */
export class LedgerStore {
  readonly #db: DatabaseSync;
  readonly #key: Buffer;
  #closed = false;
  constructor(path: string, key: Uint8Array, readonly maxBytes = 16 * 1024 * 1024) {
    if (key.byteLength !== 32 || !Number.isSafeInteger(maxBytes) || maxBytes < 1024) throw new ExecutorError('STORE_CONFIG_INVALID');
    this.#key = Buffer.from(key);
    if (path !== ':memory:') {
      const absolute = resolve(path);
      const directory = dirname(absolute);
      const parent = lstatSync(directory);
      if (!parent.isDirectory() || parent.isSymbolicLink() || realpathSync(directory) !== directory ||
          (process.platform !== 'win32' && ((parent.mode & 0o077) !== 0 || parent.uid !== process.getuid?.()))) {
        throw new ExecutorError('STORE_DIRECTORY_UNSAFE');
      }
      const fd = openSync(absolute, constants.O_CREAT | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0), 0o600);
      try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.nlink !== 1 || (process.platform !== 'win32' &&
            ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new ExecutorError('STORE_FILE_UNSAFE');
      } finally { closeSync(fd); }
      // Also reject a replaced/symlinked path before SQLite opens it. The directory is owner-only.
      if (lstatSync(absolute).isSymbolicLink()) throw new ExecutorError('STORE_FILE_UNSAFE');
      path = absolute;
    }
    this.#db = new DatabaseSync(path);
    try {
      this.#db.exec('PRAGMA busy_timeout=0; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;');
      this.#db.exec('CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)');
      const exists = this.#db.prepare('SELECT id FROM ledger WHERE id=1').get();
      if (!exists) this.#db.prepare('INSERT INTO ledger(id,payload) VALUES(1,?)').run(this.#seal(JSON.stringify({
        schema: 1, revision: 0, epoch: 0, lastClock: 0, inventoryInstanceId: randomUUID(),
        tasks: {}, families: {}, tools: {}, actions: {}, approvals: {}, memory: {}, audit: [],
      })));
      const state = this.read(); // Wrong keys and corrupt state fail at open, not at first effect.
      if (!Object.hasOwn(state, 'inventoryInstanceId')) {
        // Schema 1 readers preserve unknown properties. Migrate once before exposing the store;
        // a failed write rolls back without returning an identity that was never persisted.
        this.transaction(legacy => { legacy.inventoryInstanceId = randomUUID(); });
      }
    } catch {
      this.#db.close(); this.#key.fill(0);
      throw new ExecutorError('STORE_UNAVAILABLE');
    }
  }
  #seal(value: string): string {
    if (Buffer.byteLength(value) > this.maxBytes) throw new ExecutorError('STORE_CAPACITY_EXCEEDED');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(Buffer.from('agent-guard-ledger-v1'));
    const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return JSON.stringify([iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')]);
  }
  read(): Ledger {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    try {
      const row = this.#db.prepare('SELECT payload FROM ledger WHERE id=1').get()!;
      const [iv, tag, value] = JSON.parse(String(row.payload)) as [string, string, string];
      if (value.length > this.maxBytes * 2) throw new Error();
      const cipher = createDecipheriv('aes-256-gcm', this.#key, Buffer.from(iv, 'base64'));
      cipher.setAAD(Buffer.from('agent-guard-ledger-v1'));
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
      this.#db.prepare('UPDATE ledger SET payload=? WHERE id=1').run(this.#seal(JSON.stringify(state)));
      this.#db.exec('COMMIT');
      return result;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  close(): void { if (!this.#closed) { this.#db.close(); this.#key.fill(0); this.#closed = true; } }
}
