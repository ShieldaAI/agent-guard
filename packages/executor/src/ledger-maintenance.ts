import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { parseEvidenceJson } from './evidence-json.js';
import { ExecutorError, LedgerStore, validateLedgerMaxBytes } from './store.js';

export interface LedgerKey {
  readonly keyId: string;
  readonly key: Buffer;
}
export interface LedgerKeyOptions {
  readonly database: string;
  readonly keyringFile: string;
  readonly witnessPath?: string;
  readonly maxBytes?: number;
}
export interface LedgerKeyringPolicy {
  readonly keyCount: number;
  readonly maxKeys: number;
}
export interface ManagedLedgerGroup {
  id: string;
  stores: { database: string; witnessPath: string; inventoryInstanceId: string }[];
}
export interface ParsedKeyring {
  keys: LedgerKey[];
  maxKeys: number;
  explicitLimit: boolean;
  managed?: ManagedLedgerGroup;
}
export interface LedgerRotationResult {
  readonly status: 'rotated' | 'already-rotated';
  readonly revision: number;
  readonly inventoryInstanceId?: string;
  readonly witnessed: boolean;
  /** Outer-key-derived inventory and trace references change; enroll a fresh collector generation. */
  readonly observationReenrollmentRequired: true;
}
const maxKeyringBytes = 32 * 1024;
const keyIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

function fail(code = 'KEYRING_INVALID'): never {
  throw new ExecutorError(code);
}
function validateMaxKeys(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > 64)
    fail('KEYRING_LIMIT_INVALID');
  return value;
}
function privateLocation(path: string): string {
  if (!['linux', 'darwin'].includes(process.platform) || typeof path !== 'string' || !isAbsolute(path))
    fail('MAINTENANCE_CONFIG_INVALID');
  const directory = dirname(path);
  if (realpathSync(directory) !== directory) fail('KEYRING_PATH_UNSAFE');
  for (let parent = directory; ; parent = dirname(parent)) {
    const stat = lstatSync(parent);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.uid !== 0 && stat.uid !== process.geteuid!()) ||
      ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0)
    )
      fail('KEYRING_PATH_UNSAFE');
    if (parent === directory && (stat.uid !== process.geteuid!() || (stat.mode & 0o077) !== 0))
      fail('KEYRING_PATH_UNSAFE');
    if (parent === dirname(parent)) break;
  }
  return path;
}
function privateDescriptor(fd: number, path: string, maximum: number): ReturnType<typeof fstatSync> {
  const stat = fstatSync(fd),
    named = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.nlink !== 1 ||
    stat.uid !== process.geteuid!() ||
    (stat.mode & 0o077) !== 0 ||
    stat.size > maximum ||
    !named.isFile() ||
    stat.dev !== named.dev ||
    stat.ino !== named.ino ||
    stat.size !== named.size ||
    stat.ctimeMs !== named.ctimeMs
  )
    fail('KEYRING_FILE_UNSAFE');
  return stat;
}
function readPrivate(path: string): Buffer {
  privateLocation(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = privateDescriptor(fd, path, maxKeyringBytes);
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let count = 0;
    while (count < bytes.length) {
      const next = readSync(fd, bytes, count, bytes.length - count, null);
      if (!next) break;
      count += next;
    }
    const after = privateDescriptor(fd, path, maxKeyringBytes);
    if (count !== before.size || before.ctimeMs !== after.ctimeMs || before.mtimeMs !== after.mtimeMs) {
      bytes.fill(0);
      fail();
    }
    return bytes.subarray(0, count);
  } finally {
    closeSync(fd);
  }
}
function parseKeyring(bytes: Buffer): ParsedKeyring {
  const keys: LedgerKey[] = [];
  try {
    const value = parseEvidenceJson(bytes, maxKeyringBytes) as {
      version?: unknown;
      keys?: unknown;
      maxKeys?: unknown;
      managed?: unknown;
    };
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      !Object.hasOwn(value, 'keys') ||
      !Object.hasOwn(value, 'version') ||
      Object.keys(value).some(name => !['keys', 'version', 'maxKeys', 'managed'].includes(name)) ||
      value.version !== 1 ||
      !Array.isArray(value.keys) ||
      value.keys.length < 1
    )
      fail();
    const explicitLimit = Object.hasOwn(value, 'maxKeys'),
      maxKeys = explicitLimit ? validateMaxKeys(value.maxKeys) : 4;
    if (value.keys.length > maxKeys) fail();
    for (const item of value.keys) {
      if (
        !item ||
        typeof item !== 'object' ||
        Array.isArray(item) ||
        Object.keys(item).sort().join(',') !== 'id,keyBase64' ||
        typeof item.id !== 'string' ||
        !keyIdPattern.test(item.id) ||
        typeof item.keyBase64 !== 'string'
      )
        fail();
      const key = Buffer.from(item.keyBase64, 'base64');
      if (
        key.byteLength !== 32 ||
        key.toString('base64') !== item.keyBase64 ||
        keys.some(previous => previous.keyId === item.id || previous.key.equals(key))
      ) {
        key.fill(0);
        fail();
      }
      keys.push(Object.freeze({ keyId: item.id, key }));
    }
    let managed: ManagedLedgerGroup | undefined;
    if (Object.hasOwn(value, 'managed')) {
      const group = value.managed as ManagedLedgerGroup;
      if (
        !group ||
        typeof group !== 'object' ||
        Array.isArray(group) ||
        Object.keys(group).sort().join(',') !== 'id,stores' ||
        typeof group.id !== 'string' ||
        !/^[a-f0-9-]{36}$/.test(group.id) ||
        !Array.isArray(group.stores) ||
        !group.stores.length ||
        group.stores.length > 16
      )
        fail();
      const paths = new Set<string>(),
        identities = new Set<string>();
      for (const member of group.stores) {
        if (
          !member ||
          typeof member !== 'object' ||
          Array.isArray(member) ||
          Object.keys(member).sort().join(',') !== 'database,inventoryInstanceId,witnessPath' ||
          typeof member.inventoryInstanceId !== 'string' ||
          !/^[a-f0-9-]{36}$/.test(member.inventoryInstanceId) ||
          identities.has(member.inventoryInstanceId)
        )
          fail();
        identities.add(member.inventoryInstanceId);
        for (const path of [member.database, member.witnessPath]) {
          if (typeof path !== 'string' || !isAbsolute(path) || Buffer.byteLength(path) > 512 || paths.has(path)) fail();
          paths.add(path);
        }
      }
      managed = group;
    }
    return { keys, maxKeys, explicitLimit, ...(managed ? { managed } : {}) };
  } catch {
    for (const entry of keys) entry.key.fill(0);
    return fail();
  }
}
/** Trusted initialization/maintenance only. The caller owns and must erase each returned key buffer. */
export function readLedgerKeyring(options: { keyringFile: string }): readonly LedgerKey[] {
  let bytes: Buffer | undefined;
  try {
    bytes = readPrivate(options.keyringFile);
    const parsed = parseKeyring(bytes);
    if (parsed.managed) {
      parsed.keys.forEach(entry => entry.key.fill(0));
      fail('KEYRING_MANAGED_OPERATION_REQUIRED');
    }
    return Object.freeze(parsed.keys);
  } catch (error) {
    if (error instanceof ExecutorError) throw error;
    return fail('KEYRING_UNAVAILABLE');
  } finally {
    bytes?.fill(0);
  }
}
/** Read only the public retention policy; key material never appears in the result. */
export function readLedgerKeyringPolicy(options: { keyringFile: string }): LedgerKeyringPolicy {
  let bytes: Buffer | undefined, parsed: ParsedKeyring | undefined;
  try {
    bytes = readPrivate(options.keyringFile);
    parsed = parseKeyring(bytes);
    return Object.freeze({ keyCount: parsed.keys.length, maxKeys: parsed.maxKeys });
  } catch (error) {
    if (error instanceof ExecutorError) throw error;
    return fail('KEYRING_UNAVAILABLE');
  } finally {
    bytes?.fill(0);
    parsed?.keys.forEach(entry => entry.key.fill(0));
  }
}
function openExisting(database: string, key: Uint8Array, witnessPath?: string, maxBytes?: number): LedgerStore {
  if (
    !['linux', 'darwin'].includes(process.platform) ||
    !isAbsolute(database) ||
    database === ':memory:' ||
    (witnessPath !== undefined && !isAbsolute(witnessPath))
  )
    fail('MAINTENANCE_CONFIG_INVALID');
  return new LedgerStore(
    database,
    key,
    maxBytes,
    witnessPath === undefined ? undefined : { path: witnessPath, mode: 'resume' },
    { existingOnly: true },
  );
}
function matchingStore(options: LedgerKeyOptions, keys: readonly LedgerKey[]): { store: LedgerStore; key: LedgerKey } {
  validateLedgerMaxBytes(options.maxBytes);
  for (const key of keys) {
    try {
      return { store: openExisting(options.database, key.key, options.witnessPath, options.maxBytes), key };
    } catch {
      /* Each attempted owner closes before trying the next authenticated key. */
    }
  }
  return fail('LEDGER_KEY_UNAVAILABLE');
}
/** Authenticate existing authority without changing epochs, approvals, budgets or plaintext state. */
export function loadLedgerKey(options: LedgerKeyOptions): LedgerKey {
  validateLedgerMaxBytes(options.maxBytes);
  let bytes: Buffer | undefined, parsed: ParsedKeyring;
  try {
    bytes = readPrivate(options.keyringFile);
    parsed = parseKeyring(bytes);
  } catch (error) {
    if (error instanceof ExecutorError) throw error;
    return fail('KEYRING_UNAVAILABLE');
  } finally {
    bytes?.fill(0);
  }
  const keys = parsed.keys;
  try {
    const member = parsed.managed?.stores.find(
      member => member.database === options.database && member.witnessPath === options.witnessPath,
    );
    if (parsed.managed && !member) fail('KEYRING_SCOPE_UNREGISTERED');
    const matched = matchingStore(options, keys);
    try {
      const state = matched.store.read() as ReturnType<LedgerStore['read']> & { keyCustody?: string };
      if (
        (member &&
          (state.inventoryInstanceId !== member.inventoryInstanceId || state.keyCustody !== parsed.managed!.id)) ||
        (!member && state.keyCustody !== undefined)
      )
        fail('KEYRING_SCOPE_UNREGISTERED');
      return Object.freeze({ keyId: matched.key.keyId, key: Buffer.from(matched.key.key) });
    } finally {
      matched.store.close();
    }
  } finally {
    for (const entry of keys) entry.key.fill(0);
  }
}
function withKeyringLock<T>(path: string, operation: () => T): T {
  privateLocation(path);
  const lock = path + '.maintenance.sqlite';
  const fd = openSync(lock, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
  try {
    privateDescriptor(fd, lock, 1024 * 1024);
  } finally {
    closeSync(fd);
  }
  const db = new DatabaseSync(lock);
  try {
    db.exec(
      'PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS maintenance_lock (id INTEGER PRIMARY KEY);',
    );
    return operation();
  } catch (error) {
    if (error instanceof ExecutorError) throw error;
    throw new ExecutorError('KEYRING_MAINTENANCE_FAILED');
  } finally {
    db.close();
  }
}
function writeKeyring(
  path: string,
  keys: readonly LedgerKey[],
  previous?: Buffer,
  maxKeys?: number,
  managed?: ManagedLedgerGroup,
): void {
  privateLocation(path);
  const bytes = Buffer.from(
    JSON.stringify({
      version: 1,
      ...(maxKeys === undefined ? {} : { maxKeys }),
      ...(managed === undefined ? {} : { managed }),
      keys: keys.map(({ keyId, key }) => ({ id: keyId, keyBase64: key.toString('base64') })),
    }) + '\n',
  );
  const temp = join(dirname(path), `.guard-keyring-${randomBytes(16).toString('hex')}`);
  let fd: number | undefined;
  try {
    const verified = parseKeyring(bytes);
    verified.keys.forEach(entry => entry.key.fill(0));
    fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    if (previous) {
      const current = readPrivate(path);
      try {
        if (!current.equals(previous)) fail('KEYRING_CHANGED');
      } finally {
        current.fill(0);
      }
    } else {
      try {
        lstatSync(path);
        fail('KEYRING_EXISTS');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    // All supported writers hold the same OS-released SQLite lock. Key transitions
    // preserve prior secrets through retention or managed independent escrow.
    renameSync(temp, path);
    const directory = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      fsyncSync(directory);
    } finally {
      closeSync(directory);
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
    bytes.fill(0);
    rmSync(temp, { force: true });
  }
}
/** Internal custody integration: all callbacks are synchronous host maintenance. */
export function withLedgerKeyringState<T>(
  path: string,
  operation: (state: ParsedKeyring, publish: () => void) => T,
): T {
  return withKeyringLock(path, () => {
    const previous = readPrivate(path);
    let parsed: ParsedKeyring | undefined,
      originals: LedgerKey[] = [],
      published = false,
      accepting = true;
    try {
      parsed = parseKeyring(previous);
      originals = [...parsed.keys];
      const result = operation(parsed, () => {
        if (!accepting || published || !parsed) fail('KEYRING_CHANGED');
        writeKeyring(path, parsed.keys, previous, parsed.explicitLimit ? parsed.maxKeys : undefined, parsed.managed);
        published = true;
      });
      accepting = false;
      if (result && typeof (result as { then?: unknown }).then === 'function') fail('ASYNC_MAINTENANCE_FORBIDDEN');
      return result;
    } finally {
      accepting = false;
      previous.fill(0);
      for (const entry of new Set([...originals, ...(parsed?.keys ?? [])])) entry.key.fill(0);
    }
  });
}
/** Explicit first enrollment. Never replaces an existing keyring. */
export function createLedgerKeyring(options: { keyringFile: string; keyId: string; maxKeys?: number }): {
  keyId: string;
} {
  if (!keyIdPattern.test(options.keyId)) fail();
  if (options.maxKeys !== undefined) validateMaxKeys(options.maxKeys);
  return withKeyringLock(options.keyringFile, () => {
    const key = randomBytes(32);
    try {
      writeKeyring(options.keyringFile, [{ keyId: options.keyId, key }], undefined, options.maxKeys);
      return { keyId: options.keyId };
    } finally {
      key.fill(0);
    }
  });
}
/** Offline policy change only. Keeps every existing key; never changes any ledger or backup. */
export function configureLedgerKeyring(options: { keyringFile: string; maxKeys: number }): LedgerKeyringPolicy {
  const maxKeys = validateMaxKeys(options.maxKeys);
  return withKeyringLock(options.keyringFile, () => {
    const previous = readPrivate(options.keyringFile);
    let parsed: ParsedKeyring | undefined;
    try {
      parsed = parseKeyring(previous);
      if (maxKeys < parsed.keys.length) fail('KEYRING_LIMIT_INVALID');
      if (maxKeys !== parsed.maxKeys || !parsed.explicitLimit)
        writeKeyring(options.keyringFile, parsed.keys, previous, maxKeys, parsed.managed);
      return Object.freeze({ keyCount: parsed.keys.length, maxKeys });
    } finally {
      previous.fill(0);
      parsed?.keys.forEach(entry => entry.key.fill(0));
    }
  });
}
/** Offline, retryable ciphertext replacement. Preserve both keys until recovery and retention review finish. */
export function rotateLedgerKey(options: {
  database: string;
  currentKey: Uint8Array;
  nextKey: Uint8Array;
  witnessPath?: string;
  maxBytes?: number;
}): LedgerRotationResult {
  validateLedgerMaxBytes(options.maxBytes);
  if (
    options.currentKey.byteLength !== 32 ||
    options.nextKey.byteLength !== 32 ||
    Buffer.compare(options.currentKey, options.nextKey) === 0
  )
    fail('STORE_ROTATION_INVALID');
  let store: LedgerStore;
  try {
    store = openExisting(options.database, options.currentKey, options.witnessPath, options.maxBytes);
  } catch {
    try {
      const current = openExisting(options.database, options.nextKey, options.witnessPath, options.maxBytes);
      try {
        return rotationResult(current, 'already-rotated', options.witnessPath);
      } finally {
        current.close();
      }
    } catch {
      return fail('LEDGER_KEY_UNAVAILABLE');
    }
  }
  try {
    if ((store.read() as { keyCustody?: string }).keyCustody !== undefined) fail('KEYRING_MANAGED_OPERATION_REQUIRED');
    try {
      store.rotateEncryptionKey(options.nextKey);
    } catch (error) {
      if (!(error instanceof ExecutorError) || error.code !== 'STORE_ROTATION_UNCERTAIN') throw error;
      // A COMMIT error can be reported after durable commit. Reopen using the new
      // key to distinguish that outcome without issuing another authority action.
      const recovered = openExisting(options.database, options.nextKey, options.witnessPath, options.maxBytes);
      try {
        return rotationResult(recovered, 'rotated', options.witnessPath);
      } finally {
        recovered.close();
      }
    }
    return rotationResult(store, 'rotated', options.witnessPath);
  } finally {
    store.close();
  }
}
function rotationResult(
  store: LedgerStore,
  status: LedgerRotationResult['status'],
  witnessPath?: string,
): LedgerRotationResult {
  const state = store.read();
  return {
    status,
    revision: state.revision,
    witnessed: witnessPath !== undefined,
    observationReenrollmentRequired: true,
    ...(state.inventoryInstanceId === undefined ? {} : { inventoryInstanceId: state.inventoryInstanceId }),
  };
}
/** Stage the new secret durably before the paired SQLite commit. Reuse its key ID when retrying. */
export function rotateLedgerKeyring(
  options: LedgerKeyOptions & { nextKeyId: string },
): LedgerRotationResult & { keyId: string } {
  if (!keyIdPattern.test(options.nextKeyId)) fail();
  validateLedgerMaxBytes(options.maxBytes);
  return withKeyringLock(options.keyringFile, () => {
    const previous = readPrivate(options.keyringFile);
    let keys: LedgerKey[] = [];
    let store: LedgerStore | undefined;
    try {
      const parsed = parseKeyring(previous);
      keys = parsed.keys;
      if (parsed.managed) fail('KEYRING_MANAGED_OPERATION_REQUIRED');
      const matched = matchingStore(options, keys);
      store = matched.store;
      if ((store.read() as { keyCustody?: string }).keyCustody !== undefined)
        fail('KEYRING_MANAGED_OPERATION_REQUIRED');
      if (matched.key.keyId === options.nextKeyId)
        return { ...rotationResult(store, 'already-rotated', options.witnessPath), keyId: options.nextKeyId };
      let next = keys.find(entry => entry.keyId === options.nextKeyId);
      if (!next) {
        if (keys.length >= parsed.maxKeys) fail('KEYRING_CAPACITY');
        next = { keyId: options.nextKeyId, key: randomBytes(32) };
        keys.push(next);
        writeKeyring(options.keyringFile, keys, previous, parsed.explicitLimit ? parsed.maxKeys : undefined);
      }
      store.rotateEncryptionKey(next.key);
      return { ...rotationResult(store, 'rotated', options.witnessPath), keyId: next.keyId };
    } finally {
      store?.close();
      previous.fill(0);
      for (const entry of keys) entry.key.fill(0);
    }
  });
}
