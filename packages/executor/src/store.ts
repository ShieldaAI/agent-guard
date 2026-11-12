import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, constants, fsyncSync, openSync, rmSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { Action, TaskOptions } from '@shieldaai/agent-guard';
import { bindLedgerObservation, closeLedgerObservation } from './inventory-observer.js';
import type { LifecycleState } from './lifecycle.js';
import type { RetentionState } from './retention.js';
import { ledgerFeatures, type LedgerFeature } from './ledger-format.js';
import { checkOpenFile, openChecked, privateDirectory, trustedDirectoryChain, type Refuse } from './private-files.js';

export class ExecutorError extends Error {
  /** Safe uppercase reason behind the code (for example KEY_MISMATCH); never a path, key or request data. */
  readonly detail?: string;
  constructor(
    readonly code: string,
    options: { detail?: string; cause?: unknown } = {},
  ) {
    super(code, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'ExecutorError';
    if (options.detail !== undefined) this.detail = options.detail;
  }
}
/** Smallest ledger bound any public API accepts: the executor and the /ops key tools agree. */
export const MIN_LEDGER_BYTES = 1024 * 1024;
export function validatePublicLedgerMaxBytes(value: number = 16 * 1024 * 1024): number {
  if (!Number.isSafeInteger(value) || value < MIN_LEDGER_BYTES || value > 64 * 1024 * 1024)
    throw new ExecutorError('STORE_CONFIG_INVALID');
  return value;
}
/** Internal store bound; tests may use tiny stores. Public entry points use validatePublicLedgerMaxBytes. */
export function validateLedgerMaxBytes(value: number = 16 * 1024 * 1024): number {
  if (!Number.isSafeInteger(value) || value < 1024 || value > 64 * 1024 * 1024)
    throw new ExecutorError('STORE_CONFIG_INVALID');
  return value;
}
/** Keep this second SQLite file outside the authority database's backup/restore domain. */
export interface LedgerWitness {
  readonly path: string;
  readonly mode: 'create' | 'resume';
  readonly recovery?: 'mirror';
}
/**
 * How one commit is treated at the size bound.
 * - `growth`: an operation that only adds state (a new task, preparation, approval, memory
 *   version, tool). Refused once the ledger would pass the soft limit, `maxBytes - reserveBytes`.
 * - `relief`: for writes that must not fail (revoke, cancel, settle, mark UNKNOWN, reconcile,
 *   recovery at open). Called while the ledger is over the hard bound; it drops expendable state
 *   and returns false when nothing is left to drop.
 * Without options a commit is bounded by `maxBytes` only, as maintenance and archive writes are.
 */
export interface LedgerWriteOptions {
  growth?: boolean;
  relief?: (state: Ledger) => boolean;
}
/** Internal: why the stored ledger could not be read. The detail is a fixed, safe word. */
class LedgerFault extends Error {
  constructor(readonly detail: 'KEY_MISMATCH' | 'WITNESS_MISMATCH' | 'MIRROR_MISMATCH') {
    super(detail);
  }
}
/** A safe reason for a failed open or read: LOCKED, KEY_MISMATCH, CORRUPT and similar; never a path or key. */
function storeFailureDetail(error: unknown): string | undefined {
  if (error instanceof LedgerFault) return error.detail;
  if (error instanceof ExecutorError)
    return (
      error.detail ??
      (error.code === 'STORE_CORRUPT' || error.code === 'STORE_RECOVERY_CORRUPT' ? 'CORRUPT' : undefined)
    );
  const errcode = (error as { errcode?: unknown } | null)?.errcode;
  if (typeof errcode !== 'number') return undefined;
  // SQLite primary result codes: BUSY 5, LOCKED 6, CORRUPT 11, CANTOPEN 14, NOTADB 26.
  const primary = errcode & 0xff;
  if (primary === 5 || primary === 6) return 'LOCKED';
  if (primary === 11 || primary === 26) return 'CORRUPT';
  if (primary === 14) return 'FILE_UNAVAILABLE';
  return undefined;
}
export interface LedgerArchiveAccess {
  putArchive(id: string, ciphertext: string): void;
  readArchive(id: string): string;
  deleteArchive(id: string, ciphertextSha256: string): void;
  /** Host custody catalog only; callers bind its aggregate digest inside the witnessed ledger. */
  putCustodyRecord(id: string, ciphertext: string): void;
}
export const executionStatuses = Object.freeze([
  'PREPARED',
  'ADMITTED',
  'RUNNING',
  'SUCCEEDED',
  'FAILED',
  'UNKNOWN',
] as const);
export type ExecutionStatus = (typeof executionStatuses)[number];
/**
 * PRUNED: the settled record was removed by retention. `outcome` keeps its result while the
 * compact stub is retained; once that is evicted too, only the fact that it settled remains.
 */
export type ReceiptStatus = ExecutionStatus | 'PRUNED';
export interface ExecutionReceipt {
  readonly id: string;
  readonly status: ReceiptStatus;
  /** Only on a PRUNED receipt, and only while its compact stub is retained. */
  readonly outcome?: 'SUCCEEDED' | 'FAILED';
  readonly charged?: number;
  readonly reconciliation?: { readonly referenceHash: string; readonly time: number };
}
export interface StoredTask {
  options: TaskOptions;
  parent: string | null;
  family: string;
  tokenHash: string;
  revoked: boolean;
  sourceTaskId?: string;
  calls: number;
  concurrent: number;
  spent: number;
  reserved: number;
}
export interface StoredAction {
  id: string;
  taskId: string;
  action: Action;
  digest: string;
  toolRevision: number;
  requiresApproval: boolean;
  status: ExecutionStatus;
  maxCost: number;
  charged?: number;
  reconciliation?: { referenceHash: string; time: number };
}
export interface MemoryRecord {
  id: string;
  tenantId: string;
  origin: string;
  sensitive: boolean;
  trusted: boolean;
  version: number;
  parentIds: string[];
  quarantined: boolean;
  value: unknown;
  familyId?: string;
  /** Written by a family that had read outside content, or imported as outside content. */
  untrusted?: boolean;
}
/** One recent metadata event, as `audit()` returns it. `sequence` is strictly increasing; a gap means events were evicted. */
export interface AuditEvent {
  time: number;
  event: string;
  sequence?: number;
  tenantId?: string;
  taskId?: string;
  actionId?: string;
}
export interface Ledger {
  schema: 1 | 2 | 3;
  revision: number;
  epoch: number;
  lastClock: number;
  /** Stable for the lifetime of this ledger, including restarts and additive schema-1 upgrades. */
  inventoryInstanceId: string;
  tasks: Record<string, StoredTask>;
  /** untrusted: a family call read outside content (set at admission, never cleared). */
  families: Record<string, { sensitive: boolean; untrusted?: boolean; memorySources?: string[] }>;
  tools: Record<string, { fingerprint: string; revision: number; approved: boolean }>;
  actions: Record<string, StoredAction>;
  /** untrusted: the family state when the approval was issued; absent on approvals older than 0.2. */
  approvals: Record<
    string,
    { actionId: string; digest: string; expiresAt: number; approverId: string; used: boolean; untrusted?: boolean }
  >;
  memory: Record<string, MemoryRecord[]>;
  /** Recent metadata events: bounded per tenant, not a complete history. */
  audit: AuditEvent[];
  /** Data layout version (ledger-format.ts); absent in alpha ledgers. Migrated at executor open. */
  formatVersion?: number;
  /** Optional state present in this ledger, recomputed at each commit once formatVersion is set. */
  features?: LedgerFeature[];
  /** 1 once a recovery mirror is enrolled (with schema 3). */
  recoveryMirror?: number;
  /** ID of the enrolled key-custody record. */
  keyCustody?: string;
  /** Custody catalog metadata; validated by ledger-custody.ts. */
  custody?: unknown;
  lifecycle?: LifecycleState;
  retention?: RetentionState;
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

/**
 * Deep copy with null prototypes everywhere, like a fresh decode: `__proto__` and other
 * keys stay plain data. Iterative, so a deep ledger cannot overflow the stack.
 */
function detachedCopy<T>(value: T, freeze: boolean): T {
  if (value === null || typeof value !== 'object') return value;
  const make = (source: object): object => (Array.isArray(source) ? new Array(source.length) : Object.create(null));
  const root = make(value as object);
  const pending: [object, object][] = [[value as object, root]];
  const created: object[] = [root];
  while (pending.length) {
    const [source, target] = pending.pop()!;
    for (const key of Object.keys(source)) {
      const child = (source as Record<string, unknown>)[key];
      if (child !== null && typeof child === 'object') {
        const copy = make(child);
        created.push(copy);
        pending.push([child, copy]);
        (target as Record<string, unknown>)[key] = copy;
      } else (target as Record<string, unknown>)[key] = child;
    }
  }
  if (freeze) for (const item of created) Object.freeze(item);
  return root as T;
}

/** Shared private decoder for authority reads and host/MCP observations. */
export function decodeLedgerObservation(
  payload: string,
  key: Uint8Array,
  maxBytes: number,
  witnessed: boolean,
): Ledger {
  const plaintext = decryptLedgerPayload(payload, key, maxBytes, witnessed);
  try {
    const state = decode(plaintext.toString('utf8'));
    if (![1, 2, 3].includes(state.schema) || !Number.isSafeInteger(state.revision) || !state.tasks || !state.actions)
      throw new Error();
    if (
      Object.hasOwn(state, 'inventoryInstanceId') &&
      (typeof state.inventoryInstanceId !== 'string' ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.inventoryInstanceId))
    )
      throw new Error();
    return state;
  } finally {
    plaintext.fill(0);
  }
}

/** Private projection input; deliberately insufficient for an authority Ledger. */
export type InventoryLedgerState = Readonly<
  Pick<Ledger, 'schema' | 'revision' | 'epoch' | 'inventoryInstanceId' | 'tasks' | 'families' | 'tools'>
>;

/**
 * Core observation only. Fresh authenticated JSON data can retain ordinary nested
 * prototypes because inventory reads only own data descriptors and constructs a
 * detached DTO. Never use this path for authority reads or host/MCP composition.
 */
export function decodeCoreInventoryObservation(
  payload: string,
  key: Uint8Array,
  maxBytes: number,
  witnessed: boolean,
): InventoryLedgerState {
  const plaintext = decryptLedgerPayload(payload, key, maxBytes, witnessed);
  try {
    const state: Ledger = JSON.parse(plaintext.toString('utf8'));
    // Base validation and the worker's mirror checks use direct root properties.
    if (state !== null && typeof state === 'object' && !Array.isArray(state)) Object.setPrototypeOf(state, null);
    if (![1, 2, 3].includes(state.schema) || !Number.isSafeInteger(state.revision) || !state.tasks || !state.actions)
      throw new Error();
    if (
      Object.hasOwn(state, 'inventoryInstanceId') &&
      (typeof state.inventoryInstanceId !== 'string' ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(state.inventoryInstanceId))
    )
      throw new Error();
    return state;
  } finally {
    plaintext.fill(0);
  }
}
function decryptLedgerPayload(payload: string, key: Uint8Array, maxBytes: number, witnessed: boolean): Buffer {
  const [iv, tag, value] = JSON.parse(payload) as [string, string, string];
  if (value.length > maxBytes * 2) throw new Error();
  const nonce = Buffer.from(iv, 'base64');
  const authTag = Buffer.from(tag, 'base64');
  // Node before 26 accepts a truncated tag unless the length is pinned.
  if (nonce.length !== 12 || authTag.length !== 16) throw new Error();
  const cipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1'));
  cipher.setAuthTag(authTag);
  let plaintext: Buffer | undefined, final: Buffer | undefined;
  try {
    plaintext = cipher.update(Buffer.from(value, 'base64'));
    // GCM authentication must finish before exposing any plaintext. Its normal
    // empty final buffer does not require copying the entire update result.
    try {
      final = cipher.final();
    } catch {
      // A well-formed envelope that does not authenticate: the wrong key, or altered ciphertext.
      throw new LedgerFault('KEY_MISMATCH');
    }
    if (final.byteLength) {
      const combined = Buffer.concat([plaintext, final]);
      plaintext.fill(0);
      plaintext = combined;
    }
    if (plaintext.byteLength > maxBytes) throw new Error();
    return plaintext;
  } catch (error) {
    plaintext?.fill(0);
    throw error;
  } finally {
    final?.fill(0);
  }
}

function privateDatabasePath(path: string, flags: number, opened?: (absolute: string) => void): string {
  const absolute = resolve(path);
  // Shared with the keyring, custody and manifest loaders (private-files.ts). The
  // directory must be private and canonical; the file must be this user's own.
  privateDirectory(dirname(absolute), (problem, cause) => {
    throw new ExecutorError('STORE_DIRECTORY_UNSAFE', { detail: problem, cause });
  });
  const refuse: Refuse = (problem, cause) => {
    throw new ExecutorError(problem === 'FILE_MISSING' ? 'STORE_UNAVAILABLE' : 'STORE_FILE_UNSAFE', {
      detail: problem,
      cause,
    });
  };
  const fd = openChecked(absolute, flags | constants.O_RDWR, refuse);
  opened?.(absolute);
  try {
    // A live owner may be committing, so size and change time are not compared.
    checkOpenFile(fd, absolute, { owner: 'self', deny: 0o077, quiet: false }, refuse);
  } finally {
    closeSync(fd);
  }
  return absolute;
}
const commitment = (payload: string) => createHash('sha256').update(payload).digest('hex');

/** A spelling comparison alone misses case-insensitive filesystem aliases. */
function custodyChain(path: string): string[] {
  return trustedDirectoryChain(dirname(resolve(path)), (problem, cause) => {
    throw new ExecutorError('STORE_DIRECTORY_UNSAFE', { detail: problem, cause });
  });
}

/** A single owner, encrypted SQLite ledger. SQLite's exclusive lock is released by the OS on crash. */
export class LedgerStore {
  readonly #db: DatabaseSync;
  readonly #key: Buffer;
  readonly #witnessed: boolean;
  #closed = false;
  #mirror = false;
  /**
   * The last verified ciphertext and its deep-frozen decoded state. read() still fetches the
   * row and runs every witness/mirror check; only when the bytes equal the cached ciphertext
   * does it skip decrypt, parse and walk, returning a detached copy instead. Any out-of-band
   * change forces a full verified decode.
   */
  #cache: { payload: string; state: Ledger } | undefined;
  constructor(
    path: string,
    key: Uint8Array,
    readonly maxBytes = 16 * 1024 * 1024,
    witness?: LedgerWitness,
    options: { existingOnly?: boolean } = {},
  ) {
    if (key.byteLength !== 32) throw new ExecutorError('STORE_CONFIG_INVALID');
    validateLedgerMaxBytes(maxBytes);
    if (options.existingOnly && (path === ':memory:' || witness?.mode === 'create'))
      throw new ExecutorError('STORE_CONFIG_INVALID');
    this.#witnessed = witness !== undefined;
    if (witness?.recovery !== undefined && witness.recovery !== 'mirror')
      throw new ExecutorError('STORE_CONFIG_INVALID');
    let anchor: string | undefined;
    // Files this call created with O_EXCL. A failed create removes them again: an empty
    // ledger left behind would make every retry fail on the exclusive create.
    const created: string[] = [];
    const discardCreated = (): void => {
      for (const file of created.splice(0))
        for (const leftover of [file, `${file}-journal`])
          try {
            rmSync(leftover, { force: true });
          } catch {
            /* Best effort: the original failure is what the caller needs. */
          }
    };
    if (this.#witnessed) {
      if (
        !witness ||
        typeof witness.path !== 'string' ||
        !isAbsolute(witness.path) ||
        !isAbsolute(path) ||
        !['create', 'resume'].includes(witness.mode) ||
        process.platform === 'win32'
      )
        throw new ExecutorError('STORE_CONFIG_INVALID');
      let primaryChain: string[], witnessChain: string[];
      try {
        primaryChain = custodyChain(path);
        witnessChain = custodyChain(witness.path);
      } catch (error) {
        const detail = storeFailureDetail(error);
        throw new ExecutorError('STORE_DIRECTORY_UNSAFE', {
          ...(detail === undefined ? {} : { detail }),
          cause: error,
        });
      }
      if (primaryChain.includes(witnessChain[0]!) || witnessChain.includes(primaryChain[0]!))
        throw new ExecutorError('STORE_CONFIG_INVALID');
      const flags = witness.mode === 'create' ? constants.O_CREAT | constants.O_EXCL : 0;
      const remember = flags ? (file: string) => void created.push(file) : undefined;
      try {
        path = privateDatabasePath(path, flags, remember);
        anchor = privateDatabasePath(witness.path, flags, remember);
      } catch (error) {
        discardCreated();
        const detail = storeFailureDetail(error);
        throw new ExecutorError('STORE_WITNESS_UNAVAILABLE', {
          ...(detail === undefined ? {} : { detail }),
          cause: error,
        });
      }
    } else if (path !== ':memory:') path = privateDatabasePath(path, options.existingOnly ? 0 : constants.O_CREAT);
    try {
      this.#db = new DatabaseSync(anchor ?? path);
    } catch (error) {
      discardCreated();
      const detail = storeFailureDetail(error);
      throw new ExecutorError(this.#witnessed ? 'STORE_WITNESS_UNAVAILABLE' : 'STORE_UNAVAILABLE', {
        ...(detail === undefined ? {} : { detail }),
        cause: error,
      });
    }
    this.#key = Buffer.from(key);
    try {
      this.#exec(
        'PRAGMA busy_timeout=0; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE;',
      );
      if (anchor) {
        this.#prepare('ATTACH DATABASE ? AS authority').run(path);
        this.#exec(
          'PRAGMA main.journal_mode=DELETE; PRAGMA main.synchronous=EXTRA; PRAGMA witness.journal_mode=DELETE; PRAGMA witness.synchronous=EXTRA; PRAGMA fullfsync=ON;',
        );
        for (const schema of ['main', 'witness']) {
          if (
            this.#prepare(`PRAGMA ${schema}.journal_mode`).get()?.journal_mode !== 'delete' ||
            this.#prepare(`PRAGMA ${schema}.synchronous`).get()?.synchronous !== 3
          )
            throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
        }
      }
      this.#exec('BEGIN EXCLUSIVE');
      if (!options.existingOnly && witness?.mode !== 'resume')
        this.#exec(
          'CREATE TABLE IF NOT EXISTS main.ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)',
        );
      const exists = this.#prepare('SELECT id FROM main.ledger WHERE id=1').get();
      if (!exists) {
        if (options.existingOnly || witness?.mode === 'resume')
          throw new ExecutorError('STORE_UNAVAILABLE', { detail: 'LEDGER_MISSING' });
        this.#mirror = witness?.recovery === 'mirror';
        if (this.#mirror) this.#createMirrorTables();
        const payload = this.#seal(
          JSON.stringify({
            schema: this.#mirror ? 3 : 1,
            ...(this.#mirror ? { recoveryMirror: 1 } : {}),
            revision: 0,
            epoch: 0,
            lastClock: 0,
            inventoryInstanceId: randomUUID(),
            tasks: {},
            families: {},
            tools: {},
            actions: {},
            approvals: {},
            memory: {},
            audit: [],
          }),
        );
        this.#prepare('INSERT INTO main.ledger(id,payload) VALUES(1,?)').run(payload);
        if (anchor) {
          this.#exec('CREATE TABLE witness.commitment (id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL)');
          this.#prepare('INSERT INTO witness.commitment(id,digest) VALUES(1,?)').run(commitment(payload));
          if (this.#mirror) this.#writeMirrorPayload(payload);
        }
      }
      const state = this.read();
      if (witness?.recovery === 'mirror' && !this.#mirror)
        throw new ExecutorError('STORE_RECOVERY_ENROLLMENT_REQUIRED');
      if (this.#mirror) this.#checkMirrorTables(); // Wrong keys and corrupt state fail at open, not at first effect.
      this.#exec('COMMIT');
      if (!options.existingOnly && !Object.hasOwn(state, 'inventoryInstanceId')) {
        // Schema 1 readers preserve unknown properties. Migrate once before exposing the store;
        // a failed write rolls back without returning an identity that was never persisted.
        this.transaction(legacy => {
          legacy.inventoryInstanceId = randomUUID();
        });
      }
    } catch (error) {
      this.#db.close();
      this.#key.fill(0);
      discardCreated();
      if (error instanceof ExecutorError && error.code === 'STORE_RECOVERY_ENROLLMENT_REQUIRED') throw error;
      // Wrong key, a second owner and a damaged file share one code; the detail tells them apart.
      const detail = storeFailureDetail(error);
      throw new ExecutorError(this.#witnessed ? 'STORE_WITNESS_UNAVAILABLE' : 'STORE_UNAVAILABLE', {
        ...(detail === undefined ? {} : { detail }),
        cause: error,
      });
    }
    bindLedgerObservation(this, this.maxBytes, () => {
      if (this.#closed) throw new ExecutorError('STORE_CLOSED');
      try {
        const payload = this.#payload();
        if (
          this.#mirror &&
          this.#prepare(
            "SELECT payload FROM witness.ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?",
          ).get(this.maxBytes * 2 + 512)?.payload !== payload
        )
          throw new Error();
        return {
          payload,
          key: new Uint8Array(this.#key),
          maxBytes: this.maxBytes,
          witnessed: this.#witnessed,
          mirror: this.#mirror,
        };
      } catch {
        throw new ExecutorError('STORE_CORRUPT');
      }
    });
  }
  // The witness is SQLite's physical main database, so the super-journal is
  // retained with the independent witness if primary authority storage is lost.
  #sql(sql: string): string {
    if (!this.#witnessed) return sql;
    return sql
      .replace(/\bmain\./g, 'authority.')
      .replace(/\bwitness\./g, 'main.')
      .replace(/\bVACUUM main\b/g, 'VACUUM authority');
  }
  #exec(sql: string): void {
    this.#db.exec(this.#sql(sql));
  }
  #prepare(sql: string): ReturnType<DatabaseSync['prepare']> {
    return this.#db.prepare(this.#sql(sql));
  }
  #createMirrorTables(): void {
    this.#exec(
      'CREATE TABLE IF NOT EXISTS witness.ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS witness.authority_archives (id TEXT PRIMARY KEY, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS witness.custody_catalog (id TEXT PRIMARY KEY, payload TEXT NOT NULL)',
    );
  }
  #writeMirrorPayload(payload: string): void {
    this.#prepare(
      'INSERT INTO witness.ledger(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
    ).run(payload);
  }
  #checkMirrorTables(): void {
    for (const table of ['authority_archives', 'custody_catalog']) {
      const exists = this.#prepare("SELECT name FROM main.sqlite_schema WHERE type='table' AND name=?").get(table);
      if (!exists) {
        if (this.#prepare(`SELECT COUNT(*) AS count FROM witness.${table}`).get()?.count !== 0)
          throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      } else {
        const counts = ['main', 'witness'].map(schema =>
          this.#prepare(
            `SELECT COUNT(*) AS count,COALESCE(SUM(length(CAST(payload AS BLOB))),0) AS bytes FROM ${schema}.${table}`,
          ).get()!,
        );
        const limit = table === 'authority_archives' ? 4096 : 100000;
        if (
          counts.some(row => Number(row.count) > limit || Number(row.bytes) > 256 * 1024 * 1024) ||
          counts[0]!.count !== counts[1]!.count ||
          counts[0]!.bytes !== counts[1]!.bytes ||
          this.#prepare(
            `SELECT 1 FROM main.${table} AS source LEFT JOIN witness.${table} AS mirror ON mirror.id=source.id WHERE mirror.id IS NULL OR source.payload<>mirror.payload LIMIT 1`,
          ).get()
        )
          throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      }
    }
  }
  /** Explicit offline migration; copies complete current ciphertext in the paired commit. */
  enableRecoveryMirror(): void {
    if (!this.#witnessed || this.#closed) throw new ExecutorError('STORE_CONFIG_INVALID');
    if (this.#mirror) {
      this.read();
      this.#checkMirrorTables();
      return;
    }
    try {
      this.transaction(state => {
        this.#createMirrorTables();
        for (const table of ['authority_archives', 'custody_catalog']) {
          this.#exec(`DELETE FROM witness.${table}`);
          if (this.#prepare("SELECT name FROM main.sqlite_schema WHERE type='table' AND name=?").get(table))
            this.#exec(`INSERT INTO witness.${table}(id,payload) SELECT id,payload FROM main.${table}`);
        }
        this.#mirror = true;
        state.schema = 3;
        state.recoveryMirror = 1;
      });
    } catch (error) {
      this.#mirror = false;
      throw error;
    }
  }
  recoveryMirrored(): boolean {
    this.read();
    return this.#mirror;
  }
  /** Bytes kept free below `maxBytes` so safety-critical writes always fit: an eighth, at most 1 MiB. */
  get reserveBytes(): number {
    return Math.min(Math.floor(this.maxBytes / 8), 1024 * 1024);
  }
  #seal(value: string | Buffer, key = this.#key, bytes = Buffer.byteLength(value)): string {
    if (bytes > this.maxBytes) throw new ExecutorError('STORE_CAPACITY_EXCEEDED', { detail: 'HARD_LIMIT' });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(this.#aad());
    const updated = typeof value === 'string' ? cipher.update(value, 'utf8') : cipher.update(value);
    const final = cipher.final();
    const encrypted = final.byteLength ? Buffer.concat([updated, final]) : updated;
    return JSON.stringify([
      iv.toString('base64'),
      cipher.getAuthTag().toString('base64'),
      encrypted.toString('base64'),
    ]);
  }
  #aad(): Buffer {
    return Buffer.from(this.#witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1');
  }
  #payload(): string {
    const row = this.#prepare(
      "SELECT payload FROM main.ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB)) <= ?",
    ).get(this.maxBytes * 2 + 512);
    if (!row || typeof row.payload !== 'string') throw new Error();
    if (
      this.#witnessed &&
      this.#prepare('SELECT digest FROM witness.commitment WHERE id=1').get()?.digest !== commitment(row.payload)
    )
      throw new LedgerFault('WITNESS_MISMATCH');
    return row.payload;
  }
  #decrypt(payload: string): Buffer {
    return decryptLedgerPayload(payload, this.#key, this.maxBytes, this.#witnessed);
  }
  read(): Ledger {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    try {
      const payload = this.#payload();
      const cached = this.#cache?.payload === payload ? this.#cache.state : undefined;
      const state = cached ?? decodeLedgerObservation(payload, this.#key, this.maxBytes, this.#witnessed);
      const mode = state.recoveryMirror;
      if (mode !== undefined || state.schema === 3 || this.#mirror) {
        if (
          !this.#witnessed ||
          mode !== 1 ||
          state.schema !== 3 ||
          this.#prepare(
            "SELECT payload FROM witness.ledger WHERE id=1 AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?",
          ).get(this.maxBytes * 2 + 512)?.payload !== payload
        )
          throw new LedgerFault('MIRROR_MISMATCH');
        this.#mirror = true;
      }
      if (!cached) this.#cache = { payload, state: detachedCopy(state, true) };
      // Every read stays a fresh, detached, mutable graph, exactly as a full decode returns.
      return detachedCopy(this.#cache!.state, false);
    } catch (error) {
      this.#cache = undefined;
      throw new ExecutorError('STORE_CORRUPT', { detail: storeFailureDetail(error) ?? 'CORRUPT', cause: error });
    }
  }
  /** Ciphertext is authenticated by the caller's catalog in the encrypted main ledger. */
  readArchive(id: string): string {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new ExecutorError('STORE_ARCHIVE_INVALID');
    try {
      const row = this.#prepare(
        "SELECT payload FROM main.authority_archives WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?",
      ).get(id, 32 * 1024 * 1024);
      if (!row || typeof row.payload !== 'string') throw new Error();
      if (
        this.#mirror &&
        this.#prepare(
          "SELECT payload FROM witness.authority_archives WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=?",
        ).get(id, 32 * 1024 * 1024)?.payload !== row.payload
      )
        throw new Error();
      return row.payload;
    } catch {
      throw new ExecutorError('STORE_ARCHIVE_UNAVAILABLE');
    }
  }
  /** Ciphertext-only append journal. Authentication belongs to the witnessed custody head. */
  *custodyRecords(): Iterable<{ id: string; ciphertext: string }> {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (!this.#prepare("SELECT name FROM main.sqlite_schema WHERE type='table' AND name='custody_catalog'").get())
      return;
    const rows = this.#prepare(
      "SELECT CASE WHEN typeof(id)='text' AND length(id)<=128 THEN id END AS id, CASE WHEN typeof(payload)='text' AND length(CAST(payload AS BLOB))<=131072 THEN payload END AS payload FROM main.custody_catalog ORDER BY id",
    ).iterate();
    // Compiled once, not once per row: a custody ledger holds up to 100,000 records.
    const mirrored = this.#mirror
      ? this.#prepare(
          "SELECT payload FROM witness.custody_catalog WHERE id=? AND typeof(payload)='text' AND length(CAST(payload AS BLOB))<=131072",
        )
      : undefined;
    for (const row of rows) {
      if (typeof row.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(row.id) || typeof row.payload !== 'string')
        throw new ExecutorError('STORE_CUSTODY_CORRUPT');
      if (mirrored && mirrored.get(row.id)?.payload !== row.payload) throw new ExecutorError('STORE_RECOVERY_CORRUPT');
      yield { id: row.id, ciphertext: row.payload };
    }
  }
  custodyDigest(): string {
    const digest = createHash('sha256').update('agent-guard-custody-catalog-v1\0');
    for (const row of this.custodyRecords()) digest.update(row.id).update('\0').update(row.ciphertext).update('\0');
    return digest.digest('hex');
  }
  /** Consistent ciphertext snapshot. The original authority and its witness are unchanged. */
  snapshotCommitment(): string {
    return commitment(this.#payload());
  }
  snapshot(destination: string): { commitment: string; inventoryInstanceId: string; revision: number } {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    if (!this.#witnessed || !isAbsolute(destination)) throw new ExecutorError('STORE_SNAPSHOT_INVALID');
    const state = this.read(),
      payload = this.#payload();
    const path = privateDatabasePath(destination, constants.O_CREAT | constants.O_EXCL);
    try {
      this.#prepare('VACUUM main INTO ?').run(path);
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return {
        commitment: commitment(payload),
        inventoryInstanceId: state.inventoryInstanceId,
        revision: state.revision,
      };
    } catch {
      throw new ExecutorError('STORE_SNAPSHOT_FAILED');
    }
  }
  #putArchive(id: string, ciphertext: string): void {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id) || typeof ciphertext !== 'string' || !ciphertext)
      throw new ExecutorError('STORE_ARCHIVE_INVALID');
    const bytes = Buffer.byteLength(ciphertext);
    if (bytes > 32 * 1024 * 1024) throw new ExecutorError('STORE_ARCHIVE_CAPACITY');
    this.#exec('CREATE TABLE IF NOT EXISTS main.authority_archives (id TEXT PRIMARY KEY, payload TEXT NOT NULL)');
    const totals = this.#prepare(
      'SELECT COUNT(*) AS count, COALESCE(SUM(length(CAST(payload AS BLOB))),0) AS bytes FROM main.authority_archives',
    ).get()!;
    if (Number(totals.count) >= 4096 || Number(totals.bytes) + bytes > 256 * 1024 * 1024)
      throw new ExecutorError('STORE_ARCHIVE_CAPACITY');
    if (this.#prepare('SELECT id FROM main.authority_archives WHERE id=?').get(id))
      throw new ExecutorError('STORE_ARCHIVE_INVALID');
    this.#prepare('INSERT INTO main.authority_archives(id,payload) VALUES(?,?)').run(id, ciphertext);
    if (this.#mirror)
      this.#prepare('INSERT INTO witness.authority_archives(id,payload) VALUES(?,?)').run(id, ciphertext);
  }
  transaction<T>(operation: (state: Ledger, archives: LedgerArchiveAccess) => T, options: LedgerWriteOptions = {}): T {
    if (this.#closed) throw new ExecutorError('STORE_CLOSED');
    this.#exec('BEGIN IMMEDIATE');
    let acceptingWrites = true;
    try {
      // read() returns a detached working copy; the cached snapshot is unchanged on rollback.
      const state = this.read();
      const result = operation(state, {
        readArchive: id => this.readArchive(id),
        putArchive: (id, ciphertext) => {
          if (!acceptingWrites) throw new ExecutorError('STORE_ARCHIVE_INVALID');
          this.#putArchive(id, ciphertext);
        },
        deleteArchive: (id, ciphertextSha256) => {
          if (!acceptingWrites || !/^[a-f0-9]{64}$/.test(ciphertextSha256))
            throw new ExecutorError('STORE_ARCHIVE_INVALID');
          if (
            commitment(this.readArchive(id)) !== ciphertextSha256 ||
            this.#prepare('DELETE FROM main.authority_archives WHERE id=?').run(id).changes !== 1
          ) {
            throw new ExecutorError('STORE_ARCHIVE_INVALID');
          }
          if (this.#mirror && this.#prepare('DELETE FROM witness.authority_archives WHERE id=?').run(id).changes !== 1)
            throw new ExecutorError('STORE_RECOVERY_CORRUPT');
        },
        putCustodyRecord: (id, ciphertext) => {
          if (
            !acceptingWrites ||
            !/^[A-Za-z0-9_-]{1,128}$/.test(id) ||
            typeof ciphertext !== 'string' ||
            !ciphertext ||
            Buffer.byteLength(ciphertext) > 131072
          )
            throw new ExecutorError('STORE_CUSTODY_INVALID');
          this.#exec('CREATE TABLE IF NOT EXISTS main.custody_catalog (id TEXT PRIMARY KEY, payload TEXT NOT NULL)');
          const totals = this.#prepare(
            'SELECT COUNT(*) AS count,COALESCE(SUM(length(CAST(payload AS BLOB))),0) AS bytes FROM main.custody_catalog',
          ).get()!;
          if (
            Number(totals.count) >= 100000 ||
            Number(totals.bytes) + Buffer.byteLength(ciphertext) > 256 * 1024 * 1024
          )
            throw new ExecutorError('STORE_CUSTODY_CAPACITY');
          if (this.#prepare('SELECT id FROM main.custody_catalog WHERE id=?').get(id))
            throw new ExecutorError('STORE_CUSTODY_INVALID');
          this.#prepare('INSERT INTO main.custody_catalog(id,payload) VALUES(?,?)').run(id, ciphertext);
          if (this.#mirror)
            this.#prepare('INSERT INTO witness.custody_catalog(id,payload) VALUES(?,?)').run(id, ciphertext);
        },
      });
      acceptingWrites = false;
      if (result && typeof (result as { then?: unknown }).then === 'function')
        throw new ExecutorError('ASYNC_TRANSACTION_FORBIDDEN');
      if (this.#mirror && (state.schema !== 3 || state.recoveryMirror !== 1))
        throw new ExecutorError('STORE_RECOVERY_MODE_CHANGED');
      state.revision++;
      // Executor ledgers declare their optional state; other stores (no formatVersion) do not.
      if (state.formatVersion !== undefined) state.features = ledgerFeatures(state);
      let text = JSON.stringify(state);
      let bytes = Buffer.byteLength(text);
      // Growth stops below the hard bound: what is left is headroom for the writes that must not fail.
      if (options.growth && bytes > this.maxBytes - this.reserveBytes)
        throw new ExecutorError('STORE_CAPACITY_EXCEEDED', { detail: 'SOFT_LIMIT' });
      while (bytes > this.maxBytes && options.relief?.(state)) {
        text = JSON.stringify(state);
        bytes = Buffer.byteLength(text);
      }
      const payload = this.#seal(text, this.#key, bytes);
      this.#prepare('UPDATE main.ledger SET payload=? WHERE id=1').run(payload);
      if (
        this.#witnessed &&
        this.#prepare('UPDATE witness.commitment SET digest=? WHERE id=1').run(commitment(payload)).changes !== 1
      ) {
        throw new ExecutorError('STORE_WITNESS_UNAVAILABLE');
      }
      if (this.#mirror) this.#writeMirrorPayload(payload);
      this.#exec('COMMIT');
      this.#cache = { payload, state: detachedCopy(state, true) };
      return result;
    } catch (error) {
      try {
        this.#exec('ROLLBACK');
      } catch {
        // The transaction state is unknown: fail closed rather than serve later reads from it,
        // and keep the original error, which says what actually went wrong.
        this.close();
      }
      throw error;
    } finally {
      acceptingWrites = false;
    }
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
      if (
        this.#witnessed &&
        this.#prepare('UPDATE witness.commitment SET digest=? WHERE id=1').run(commitment(payload)).changes !== 1
      )
        throw new Error();
      if (this.#mirror) this.#writeMirrorPayload(payload);
      this.#exec('COMMIT');
      next.copy(this.#key);
    } catch {
      if (!transactionStarted) throw new ExecutorError('STORE_ROTATION_FAILED');
      try {
        this.#exec('ROLLBACK');
      } catch {
        this.close();
        throw new ExecutorError('STORE_ROTATION_UNCERTAIN');
      }
      throw new ExecutorError('STORE_ROTATION_FAILED');
    } finally {
      plaintext?.fill(0);
      next.fill(0);
    }
  }
  close(): void {
    if (!this.#closed) {
      this.#db.close();
      this.#key.fill(0);
      this.#cache = undefined; // Drop the decrypted snapshot with the key.
      this.#closed = true;
      closeLedgerObservation(this);
    }
  }
}
