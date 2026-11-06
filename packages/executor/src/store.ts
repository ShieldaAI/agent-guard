import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { Action, TaskOptions } from '@shieldaai/agent-guard';

export class ExecutorError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'ExecutorError'; }
}
export function validateLedgerMaxBytes(value: number = 16 * 1024 * 1024): number {
  if (!Number.isSafeInteger(value) || value < 1024 || value > 64 * 1024 * 1024) throw new ExecutorError('STORE_CONFIG_INVALID');
  return value;
}
/** Keep this second SQLite file outside the authority database's backup/restore domain. */
export interface LedgerWitness { readonly path: string; readonly mode: 'create' | 'resume'; readonly recovery?: 'mirror' }
export interface LedgerArchiveAccess {
  putArchive(id: string, ciphertext: string): void;
  readArchive(id: string): string;
  deleteArchive(id: string, ciphertextSha256: string): void;
  /** Host custody catalog only; callers bind its aggregate digest inside the witnessed ledger. */
  putCustodyRecord(id: string, ciphertext: string): void;
}
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
  schema: 1 | 2 | 3; revision: number; epoch: number; lastClock: number;
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
  // Only JSON.parse-created data enters this walk: no caller references,
  // accessors, proxies, cycles or callbacks can observe intermediate prototypes.
  const value: unknown = JSON.parse(text);
  const pending: object[] = value !== null && typeof value === 'object' ? [value] : [];
  while (pending.length) {
    const current = pending.pop()!;
    const children: unknown[] = Array.isArray(current) ? current : Object.values(Object.setPrototypeOf(current, null));
    for (let index = 0; index < children.length; index++) {
      const child = children[index];
      if (child !== null && typeof child === 'object') pending.push(child);
    }
  }
  // No new depth policy: normalization avoids the old reviver's engine-dependent
  // recursion overflow on unusually deep JSON outside supported workload states.
  return value as Ledger;
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
  #mirror = false;
  constructor(path: string, key: Uint8Array, readonly maxBytes = 16 * 1024 * 1024, witness?: LedgerWitness,
    options: { existingOnly?: boolean } = {}) {
    if (key.byteLength !== 32) throw new ExecutorError('STORE_CONFIG_INVALID');
    validateLedgerMaxBytes(maxBytes);
    if (options.existingOnly && (path === ':memory:' || witness?.mode === 'create')) throw new ExecutorError('STORE_CONFIG_INVALID');
    this.#witnessed = witness !== undefined;
    if (witness?.recovery !== undefined && witness.recovery !== 'mirror') throw new ExecutorError('STORE_CONFIG_INVALID');
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
    } else if (path !== ':memory:') path = privateDatabasePath(path, options.existingOnly ? 0 : constants.O_CREAT);
    this.#db = new DatabaseSync(anchor ?? path);
    this.#key = Buffer.from(key);
    try {
      this.#exec('PRAGMA busy_timeout=0; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE;');
      if (anchor) {
        this.#prepare('ATTACH DATABASE ? AS authority').run(path);
        this.#exec('PRAGMA main.journal_mode=DELETE; PRAGMA main.synchronous=EXTRA; PRAGMA witness.journal_mode=DELETE; PRAGMA witness.synchronous=EXTRA; PRAGMA fullfsync=ON;');
        for (const schema of ['main', 'witness']) {
          if (this.#prepare(`PRAGMA ${schema}.journal_mode`).get()?.journal_mode !== 'delete' ||
              this.#prepare(`PRAGMA ${schema}.synchronous`).get()?.synchronous !== 3) throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
        }
      }
      this.#exec('BEGIN EXCLUSIVE');
      if (!options.existingOnly && witness?.mode !== 'resume') this.#exec('CREATE TABLE IF NOT EXISTS main.ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)');
      const exists = this.#prepare('SELECT id FROM main.ledger WHERE id=1').get();
      if (!exists) {
        if (options.existingOnly || witness?.mode === 'resume') throw new ExecutorError('STORE_UNAVAILABLE');
        this.#mirror = witness?.recovery === 'mirror';
        if (this.#mirror) this.#createMirrorTables();
        const payload = this.#seal(JSON.stringify({
          schema: this.#mirror ? 3 : 1, ...(this.#mirror ? { recoveryMirror: 1 } : {}), revision: 0, epoch: 0, lastClock: 0, inventoryInstanceId: randomUUID(),
          tasks: {}, families: {}, tools: {}, actions: {}, approvals: {}, memory: {}, audit: [],
        }));
        this.#prepare('INSERT INTO main.ledger(id,payload) VALUES(1,?)').run(payload);
        if (anchor) {
          this.#exec('CREATE TABLE witness.commitment (id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL)');
          this.#prepare('INSERT INTO witness.commitment(id,digest) VALUES(1,?)').run(commitment(payload));
          if (this.#mirror) this.#writeMirrorPayload(payload);
        }
      }
      const state = this.read();
      if (witness?.recovery === 'mirror' && !this.#mirror) throw new ExecutorError('STORE_RECOVERY_ENROLLMENT_REQUIRED');
      if (this.#mirror) this.#checkMirrorTables(); // Wrong keys and corrupt state fail at open, not at first effect.
      this.#exec('COMMIT');
      if (!options.existingOnly && !Object.hasOwn(state, 'inventoryInstanceId')) {
        // Schema 1 readers preserve unknown properties. Migrate once before exposing the store;
        // a failed write rolls back without returning an identity that was never persisted.
        this.transaction(legacy => { legacy.inventoryInstanceId = randomUUID(); });
      }
    } catch (error) {
      this.#db.close(); this.#key.fill(0);
      if (error instanceof ExecutorError && error.code === 'STORE_RECOVERY_ENROLLMENT_REQUIRED') throw error;
      throw new ExecutorError(this.#witnessed ? 'STORE_WITNESS_UNAVAILABLE' : 'STORE_UNAVAILABLE');
    }
  }
  // The witness is SQLite's physical main database, so the super-journal is
  // retained with the independent witness if primary authority storage is lost.
  #sql(sql: string): string {
    if (!this.#witnessed) return sql;
    return sql.replace(/\bmain\./g, 'authority.').replace(/\bwitness\./g, 'main.').replace(/\bVACUUM main\b/g, 'VACUUM authority');
  }
  #exec(sql: string): void { this.#db.exec(this.#sql(sql)); }
  #prepare(sql: string): ReturnType<DatabaseSync['prepare']> { return this.#db.prepare(this.#sql(sql)); }
  #createMirrorTables(): void {
    this.#exec('CREATE TABLE IF NOT EXISTS witness.ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS witness.authority_archives (id TEXT PRIMARY KEY, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS witness.custody_catalog (id TEXT PRIMARY KEY, payload TEXT NOT NULL)');
  }
  #writeMirrorPayload(payload: string): void {
    this.#prepare('INSERT INTO witness.ledger(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload').run(payload);
  }
  #checkMirrorTables(): void {
    for (const table of ['authority_archives', 'custody_catalog']) {
      const exists = this.#prepare("SELECT name FROM main.sqlite_schema WHERE type='table' AND name=?").get(table);
      if (!exists) {
        if (this.#prepare(`SELECT COUNT(*) AS count FROM witness.${table}`).get()?.count !== 0) throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      } else {
        const counts = ['main','witness'].map(schema => this.#prepare(`SELECT COUNT(*) AS count,COALESCE(SUM(length(CAST(payload AS BLOB))),0) AS bytes FROM ${schema}.${table}`).get()!);
        const limit = table === 'authority_archives' ? 4096 : 100000;
        if (counts.some(row => Number(row.count) > limit || Number(row.bytes) > 256 * 1024 * 1024) || counts[0]!.count !== counts[1]!.count || counts[0]!.bytes !== counts[1]!.bytes ||
            this.#prepare(`SELECT 1 FROM main.${table} AS source LEFT JOIN witness.${table} AS mirror ON mirror.id=source.id WHERE mirror.id IS NULL OR source.payload<>mirror.payload LIMIT 1`).get()) throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      }
    }
  }
  /** Explicit offline migration; copies complete current ciphertext in the paired commit. */
  enableRecoveryMirror(): void {
    if (!this.#witnessed || this.#closed) throw new ExecutorError('STORE_CONFIG_INVALID');
    if (this.#mirror) { this.read(); this.#checkMirrorTables(); return; }
    try {
      this.transaction(state => {
        this.#createMirrorTables();
        for (const table of ['authority_archives', 'custody_catalog']) {
          this.#exec(`DELETE FROM witness.${table}`);
          if (this.#prepare("SELECT name FROM main.sqlite_schema WHERE type='table' AND name=?").get(table)) this.#exec(`INSERT INTO witness.${table}(id,payload) SELECT id,payload FROM main.${table}`);
        }
        this.#mirror = true; state.schema = 3; (state as Ledger & {recoveryMirror?:number}).recoveryMirror = 1;
      });
    } catch (error) { this.#mirror = false; throw error; }
  }
  recoveryMirrored(): boolean { this.read(); return this.#mirror; }
  #seal(value: string | Buffer, key = this.#key): string {
    if (Buffer.byteLength(value) > this.maxBytes) throw new ExecutorError('STORE_CAPACITY_EXCEEDED');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(this.#aad());
    const encrypted = Buffer.concat([typeof value === 'string' ? cipher.update(value, 'utf8') : cipher.update(value), cipher.final()]);
    return JSON.stringify([iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')]);
  }
  #aad(): Buffer { return Buffer.from(this.#witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1'); }
  #payload(): string {
    const row = this.#prepare("SELECT payload FROM main.ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB)) <= ?").get(this.maxBytes * 2 + 512);
    if (!row || typeof row.payload !== 'string') throw new Error();
    if (this.#witnessed && this.#prepare('SELECT digest FROM witness.commitment WHERE id=1').get()?.digest !== commitment(row.payload)) throw new Error();
    return row.payload;
  }
  #decrypt(payload: string): Buffer {
    const [iv, tag, value] = JSON.parse(payload) as [string, string, string];
    if (value.length > this.maxBytes * 2) throw new Error();
    const cipher = createDecipheriv('aes-256-gcm', this.#key, Buffer.from(iv, 'base64'));
    cipher.setAAD(this.#aad());
    cipher.setAuthTag(Buffer.from(tag, 'base64'));
    const plaintext = Buffer.concat([cipher.update(Buffer.from(value, 'base64')), cipher.final()]);
    if (plaintext.byteLength > this.maxBytes) { plaintext.fill(0); throw new Error(); }
    return plaintext;
  }
  read(): Ledger {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    try {
      const payload = this.#payload(), plaintext = this.#decrypt(payload);
      let state: Ledger;
      try { state = decode(plaintext.toString('utf8')); } finally { plaintext.fill(0); }
      if (![1, 2, 3].includes(state.schema) || !Number.isSafeInteger(state.revision) || !state.tasks || !state.actions) throw new Error();
      if (Object.hasOwn(state, 'inventoryInstanceId') && (typeof state.inventoryInstanceId !== 'string' ||
          !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.inventoryInstanceId))) throw new Error();
      const mode = (state as Ledger & {recoveryMirror?:unknown}).recoveryMirror;
      if (mode !== undefined || state.schema === 3 || this.#mirror) {
        if (!this.#witnessed || mode !== 1 || state.schema !== 3 ||
            this.#prepare("SELECT payload FROM witness.ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?").get(this.maxBytes * 2 + 512)?.payload !== payload) throw new Error();
        this.#mirror = true;
      }
      return state;
    } catch { throw new ExecutorError('STORE_CORRUPT'); }
  }
  /** Ciphertext is authenticated by the caller's catalog in the encrypted main ledger. */
  readArchive(id: string): string {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new ExecutorError('STORE_ARCHIVE_INVALID');
    try {
      const row = this.#prepare("SELECT payload FROM main.authority_archives WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?").get(id, 32 * 1024 * 1024);
      if (!row || typeof row.payload !== 'string') throw new Error();
      if (this.#mirror && this.#prepare("SELECT payload FROM witness.authority_archives WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?").get(id,32*1024*1024)?.payload !== row.payload) throw new Error();
      return row.payload;
    } catch { throw new ExecutorError('STORE_ARCHIVE_UNAVAILABLE'); }
  }
  /** Ciphertext-only append journal. Authentication belongs to the witnessed custody head. */
  *custodyRecords(): Iterable<{ id: string; ciphertext: string }> {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (!this.#prepare("SELECT name FROM main.sqlite_schema WHERE type='table' AND name='custody_catalog'").get()) return;
    const rows = this.#prepare("SELECT CASE WHEN typeof(id)='text' AND length(id)<=128 THEN id END AS id, CASE WHEN typeof(payload)='text' AND length(CAST(payload AS BLOB))<=131072 THEN payload END AS payload FROM main.custody_catalog ORDER BY id").iterate();
    for (const row of rows) {
      if (typeof row.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(row.id) || typeof row.payload !== 'string') throw new ExecutorError('STORE_CUSTODY_CORRUPT');
      if (this.#mirror && this.#prepare("SELECT payload FROM witness.custody_catalog WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=131072").get(row.id)?.payload !== row.payload) throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      yield { id: row.id, ciphertext: row.payload };
    }
  }
  custodyDigest(): string {
    const digest = createHash('sha256').update('agent-guard-custody-catalog-v1\0');
    for (const row of this.custodyRecords()) digest.update(row.id).update('\0').update(row.ciphertext).update('\0');
    return digest.digest('hex');
  }
  /** Consistent ciphertext snapshot. The original authority and its witness are unchanged. */
  snapshotCommitment(): string { return commitment(this.#payload()); }
  snapshot(destination: string): { commitment: string; inventoryInstanceId: string; revision: number } {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (!this.#witnessed || !isAbsolute(destination)) throw new ExecutorError('STORE_SNAPSHOT_INVALID');
    const state = this.read(), payload = this.#payload();
    const path = privateDatabasePath(destination, constants.O_CREAT | constants.O_EXCL);
    try {
      this.#prepare('VACUUM main INTO ?').run(path);
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { fsyncSync(fd); } finally { closeSync(fd); }
      return { commitment: commitment(payload), inventoryInstanceId: state.inventoryInstanceId, revision: state.revision };
    } catch { throw new ExecutorError('STORE_SNAPSHOT_FAILED'); }
  }
  #putArchive(id: string, ciphertext: string): void {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id) || typeof ciphertext !== 'string' || !ciphertext) throw new ExecutorError('STORE_ARCHIVE_INVALID');
    const bytes = Buffer.byteLength(ciphertext);
    if (bytes > 32 * 1024 * 1024) throw new ExecutorError('STORE_ARCHIVE_CAPACITY');
    this.#exec('CREATE TABLE IF NOT EXISTS main.authority_archives (id TEXT PRIMARY KEY, payload TEXT NOT NULL)');
    const totals = this.#prepare('SELECT COUNT(*) AS count, COALESCE(SUM(length(CAST(payload AS BLOB))),0) AS bytes FROM main.authority_archives').get()!;
    if (Number(totals.count) >= 4096 || Number(totals.bytes) + bytes > 256 * 1024 * 1024) throw new ExecutorError('STORE_ARCHIVE_CAPACITY');
    if (this.#prepare('SELECT id FROM main.authority_archives WHERE id=?').get(id)) throw new ExecutorError('STORE_ARCHIVE_INVALID');
    this.#prepare('INSERT INTO main.authority_archives(id,payload) VALUES(?,?)').run(id, ciphertext);
    if (this.#mirror) this.#prepare('INSERT INTO witness.authority_archives(id,payload) VALUES(?,?)').run(id, ciphertext);
  }
  transaction<T>(operation: (state: Ledger, archives: LedgerArchiveAccess) => T): T {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    this.#exec('BEGIN IMMEDIATE');
    let acceptingWrites = true;
    try {
      const state = this.read();
      const result = operation(state, { readArchive: id => this.readArchive(id), putArchive: (id, ciphertext) => {
        if (!acceptingWrites) throw new ExecutorError('STORE_ARCHIVE_INVALID');
        this.#putArchive(id, ciphertext);
      }, deleteArchive: (id, ciphertextSha256) => {
        if (!acceptingWrites || !/^[a-f0-9]{64}$/.test(ciphertextSha256)) throw new ExecutorError('STORE_ARCHIVE_INVALID');
        if (commitment(this.readArchive(id)) !== ciphertextSha256 ||
            this.#prepare('DELETE FROM main.authority_archives WHERE id=?').run(id).changes !== 1) {
          throw new ExecutorError('STORE_ARCHIVE_INVALID');
        }
        if (this.#mirror && this.#prepare('DELETE FROM witness.authority_archives WHERE id=?').run(id).changes !== 1) throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      }, putCustodyRecord: (id, ciphertext) => {
        if (!acceptingWrites || !/^[A-Za-z0-9_-]{1,128}$/.test(id) || typeof ciphertext !== 'string' || !ciphertext ||
            Buffer.byteLength(ciphertext) > 131072) throw new ExecutorError('STORE_CUSTODY_INVALID');
        this.#exec('CREATE TABLE IF NOT EXISTS main.custody_catalog (id TEXT PRIMARY KEY, payload TEXT NOT NULL)');
        const totals = this.#prepare('SELECT COUNT(*) AS count,COALESCE(SUM(length(CAST(payload AS BLOB))),0) AS bytes FROM main.custody_catalog').get()!;
        if (Number(totals.count) >= 100000 || Number(totals.bytes) + Buffer.byteLength(ciphertext) > 256 * 1024 * 1024) throw new ExecutorError('STORE_CUSTODY_CAPACITY');
        if (this.#prepare('SELECT id FROM main.custody_catalog WHERE id=?').get(id)) throw new ExecutorError('STORE_CUSTODY_INVALID');
        this.#prepare('INSERT INTO main.custody_catalog(id,payload) VALUES(?,?)').run(id, ciphertext);
        if (this.#mirror) this.#prepare('INSERT INTO witness.custody_catalog(id,payload) VALUES(?,?)').run(id, ciphertext);
      } });
      acceptingWrites = false;
      if (result && typeof (result as { then?: unknown }).then === 'function') throw new ExecutorError('ASYNC_TRANSACTION_FORBIDDEN');
      if (this.#mirror && (state.schema !== 3 || (state as Ledger & {recoveryMirror?:unknown}).recoveryMirror !== 1)) throw new ExecutorError('STORE_RECOVERY_MODE_CHANGED');
      state.revision++;
      const payload = this.#seal(JSON.stringify(state));
      this.#prepare('UPDATE main.ledger SET payload=? WHERE id=1').run(payload);
      if (this.#witnessed && this.#prepare('UPDATE witness.commitment SET digest=? WHERE id=1').run(commitment(payload)).changes !== 1) {
        throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
      }
      if (this.#mirror) this.#writeMirrorPayload(payload);
      this.#exec('COMMIT');
      return result;
    } catch (error) { this.#exec('ROLLBACK'); throw error; }
    finally { acceptingWrites = false; }
  }
  /** Offline maintenance only. Preserves every plaintext byte and updates the witness in the same commit. */
  rotateEncryptionKey(nextKey: Uint8Array): void {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (nextKey.byteLength !== 32 || this.#key.equals(nextKey)) throw new ExecutorError('STORE_ROTATION_INVALID');
    const next = Buffer.from(nextKey);
    let plaintext: Buffer | undefined;
    let transactionStarted = false;
    try {
      this.#exec('BEGIN IMMEDIATE');
      transactionStarted = true;
      this.read();
      plaintext = this.#decrypt(this.#payload());
      const payload = this.#seal(plaintext, next);
      this.#prepare('UPDATE main.ledger SET payload=? WHERE id=1').run(payload);
      if (this.#witnessed && this.#prepare('UPDATE witness.commitment SET digest=? WHERE id=1').run(commitment(payload)).changes !== 1) throw new Error();
      if (this.#mirror) this.#writeMirrorPayload(payload);
      this.#exec('COMMIT');
      next.copy(this.#key);
    } catch {
      if (!transactionStarted) throw new ExecutorError('STORE_ROTATION_FAILED');
      try { this.#exec('ROLLBACK'); }
      catch { this.close(); throw new ExecutorError('STORE_ROTATION_UNCERTAIN'); }
      throw new ExecutorError('STORE_ROTATION_FAILED');
    } finally { plaintext?.fill(0); next.fill(0); }
  }
  close(): void { if (!this.#closed) { this.#db.close(); this.#key.fill(0); this.#closed = true; } }
}
