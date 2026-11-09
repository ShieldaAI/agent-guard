import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, renameSync, rmSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { LedgerStore, type Ledger, type LedgerWitness } from './store.js';
import {
  type LedgerKey,
  type ParsedKeyring,
  type ManagedLedgerGroup,
  withLedgerKeyringState,
} from './ledger-maintenance.js';
import { verifyAllArchiveStorage } from './lifecycle.js';
import { CustodySnapshot } from './custody-snapshot.js';
import {
  checkPrivate,
  copyPrivate,
  custodyFail as fail,
  independentDirectories,
  privateBytes,
  privateDirectory,
  syncDirectory,
  writeNewPrivate,
} from './custody-files.js';

export interface CustodyStore {
  readonly id: string;
  readonly database: string;
  readonly witnessPath: string;
}
/** Host adapter must derive the complete closure from authenticated ledger heads. Never accept workload file lists. */
export interface CustodyHistoryAdapter {
  readonly directory: string;
  verify(
    stores: ReadonlyMap<string, Pick<LedgerStore, 'read' | 'readArchive'>>,
    directory: string,
  ): readonly { name: string; sha256: string }[];
}
export interface LedgerCustodyOptions {
  readonly keyringFile: string;
  readonly custodyDatabase: string;
  readonly custodyWitness: string;
  readonly custodyKeyringFile: string;
  readonly backupDirectory: string;
  readonly stores: readonly CustodyStore[];
  readonly history?: CustodyHistoryAdapter;
}
export type CustodyRequest =
  | { readonly operation: 'enroll' | 'backup' | 'status' | 'recover' }
  | { readonly operation: 'verify' | 'restore'; readonly backupId: string }
  | { readonly operation: 'retire'; readonly keyId: string }
  | { readonly operation: 'rotate'; readonly nextKeyId: string };
export interface CustodyResult {
  readonly operation: CustodyRequest['operation'];
  readonly applied: boolean;
  readonly digest: string;
  readonly keyCount: number;
  readonly maxKeys: number;
  readonly storeCount: number;
  readonly backupCount: number;
  readonly pending: boolean;
  readonly backupFileLimit: 20000;
  readonly manifestByteLimit: 16777216;
  readonly catalogRecordLimit: 100000;
  readonly backupId?: string;
  readonly keyId?: string;
  readonly observationReenrollmentRequired?: true;
  readonly restoreSuperseded?: true;
}
interface StoreBinding extends CustodyStore {
  inventoryInstanceId: string;
}
interface Metadata {
  version: 1;
  id: string;
  keyringFile: string;
  backupDirectory: string;
  stores: StoreBinding[];
  historyDirectory?: string;
  sequence: number;
  catalogDigest: string;
  pending?: Pending;
}
type Pending =
  | { kind: 'rotate'; keyId: string }
  | { kind: 'retire'; keyId: string }
  | { kind: 'restore'; backupId: string; recoveryId: string };
interface CustodyLedger extends Ledger {
  custody?: Metadata;
}
interface RecordValue {
  kind: 'enroll' | 'issued' | 'retired' | 'backup' | 'restored' | 'restore-superseded';
  keys?: { id: string; keyBase64: string }[];
  keyId?: string;
  backupId?: string;
  manifestSha256?: string;
}
interface BackupStore extends StoreBinding {
  file: string;
  sha256: string;
  bytes: number;
  commitment: string;
  revision: number;
  keyId: string;
  keyBase64: string;
}
interface BackupManifest {
  version: 1;
  custodyId: string;
  backupId: string;
  stores: BackupStore[];
  history: { name: string; file: string; sha256: string; bytes: number }[];
}
interface Catalog {
  issued: Map<string, string>;
  retired: Set<string>;
  backups: Map<string, string>;
}
const sha = (value: string | Uint8Array): string => createHash('sha256').update(value).digest('hex');
const stable = (value: unknown): string =>
  JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : item,
  );
const keyPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const backupPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const hashPattern = /^[a-f0-9]{64}$/;
const maxBytes = 64 * 1024 * 1024;
function checkedOptions(options: LedgerCustodyOptions): void {
  if (
    !['linux', 'darwin'].includes(process.platform) ||
    !Array.isArray(options.stores) ||
    options.stores.length < 1 ||
    options.stores.length > 16
  )
    fail('CUSTODY_CONFIG_INVALID');
  const paths = [
    options.keyringFile,
    options.custodyDatabase,
    options.custodyWitness,
    options.custodyKeyringFile,
    ...options.stores.flatMap(s => [s.database, s.witnessPath]),
  ];
  if (
    paths.some(p => typeof p !== 'string' || !isAbsolute(p) || Buffer.byteLength(p) > 512) ||
    new Set(paths).size !== paths.length ||
    options.stores.some(s => !keyPattern.test(s.id)) ||
    new Set(options.stores.map(s => s.id)).size !== options.stores.length
  )
    fail('CUSTODY_CONFIG_INVALID');
  for (const path of paths) privateDirectory(dirname(path));
  const liveData = [...new Set(options.stores.map(s => dirname(s.database)))],
    liveWitness = [...new Set(options.stores.map(s => dirname(s.witnessPath)))];
  // Distinct stores may share their data or witness directory, but custody, backup,
  // offline keys and the runtime ring must be separate restore/custody domains.
  independentDirectories([
    ...liveData,
    ...liveWitness,
    dirname(options.keyringFile),
    dirname(options.custodyDatabase),
    dirname(options.custodyWitness),
    dirname(options.custodyKeyringFile),
    options.backupDirectory,
  ]);
  if (options.history)
    independentDirectories([
      options.history.directory,
      ...liveData,
      ...liveWitness,
      dirname(options.keyringFile),
      dirname(options.custodyKeyringFile),
      dirname(options.custodyDatabase),
      dirname(options.custodyWitness),
      options.backupDirectory,
    ]);
}
function envelope(value: unknown, key: LedgerKey, domain: string): string {
  const plain = Buffer.from(stable(value)),
    nonce = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key.key, nonce);
    cipher.setAAD(Buffer.from(`${domain}\0${key.keyId}`));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return stable({
      version: 1,
      keyId: key.keyId,
      nonce: nonce.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    });
  } finally {
    plain.fill(0);
  }
}
function unseal<T>(text: string, keys: readonly LedgerKey[], domain: string, maximum: number): T {
  let plain: Buffer | undefined;
  try {
    if (Buffer.byteLength(text) > maximum * 2 + 1024) fail('CUSTODY_AUTHENTICATION_FAILED');
    const header = JSON.parse(text);
    if (
      !header ||
      Object.keys(header).sort().join(',') !== 'ciphertext,keyId,nonce,tag,version' ||
      header.version !== 1
    )
      fail('CUSTODY_AUTHENTICATION_FAILED');
    const key = keys.find(k => k.keyId === header.keyId);
    if (!key) fail('CUSTODY_KEY_UNAVAILABLE');
    const buffers = [header.nonce, header.tag, header.ciphertext].map(v => {
      if (typeof v !== 'string') fail('CUSTODY_AUTHENTICATION_FAILED');
      const bytes = Buffer.from(v, 'base64');
      if (bytes.toString('base64') !== v) fail('CUSTODY_AUTHENTICATION_FAILED');
      return bytes;
    });
    if (buffers[0]!.length !== 12 || buffers[1]!.length !== 16 || buffers[2]!.length > maximum)
      fail('CUSTODY_AUTHENTICATION_FAILED');
    const decipher = createDecipheriv('aes-256-gcm', key.key, buffers[0]!);
    decipher.setAAD(Buffer.from(`${domain}\0${key.keyId}`));
    decipher.setAuthTag(buffers[1]!);
    plain = Buffer.concat([decipher.update(buffers[2]!), decipher.final()]);
    return JSON.parse(plain.toString('utf8')) as T;
  } catch {
    return fail('CUSTODY_AUTHENTICATION_FAILED');
  } finally {
    plain?.fill(0);
  }
}
function openStore(
  path: string,
  witnessPath: string,
  keys: readonly LedgerKey[],
): { store: LedgerStore; key: LedgerKey } {
  for (const key of keys) {
    try {
      return {
        store: new LedgerStore(path, key.key, maxBytes, { path: witnessPath, mode: 'resume' }, { existingOnly: true }),
        key,
      };
    } catch {
      /* Fail closed after every matching-key attempt. */
    }
  }
  return fail('CUSTODY_STORE_UNAVAILABLE');
}
function binding(metadata: Metadata, options: LedgerCustodyOptions): void {
  if (
    metadata.version !== 1 ||
    !backupPattern.test(metadata.id) ||
    metadata.keyringFile !== options.keyringFile ||
    metadata.backupDirectory !== options.backupDirectory ||
    metadata.historyDirectory !== options.history?.directory ||
    !Number.isSafeInteger(metadata.sequence) ||
    metadata.sequence < 1 ||
    metadata.sequence > 100000 ||
    !hashPattern.test(metadata.catalogDigest) ||
    stable(metadata.stores.map(({ id, database, witnessPath }) => ({ id, database, witnessPath }))) !==
      stable(options.stores)
  )
    fail('CUSTODY_SCOPE_MISMATCH');
}
function group(metadata: Metadata): ManagedLedgerGroup {
  return {
    id: metadata.id,
    stores: metadata.stores.map(({ database, witnessPath, inventoryInstanceId }) => ({
      database,
      witnessPath,
      inventoryInstanceId,
    })),
  };
}
function readCatalog(store: LedgerStore, metadata: Metadata, keys: readonly LedgerKey[]): Catalog {
  if (store.custodyDigest() !== metadata.catalogDigest) fail('CUSTODY_CATALOG_CHANGED');
  const result: Catalog = { issued: new Map(), retired: new Set(), backups: new Map() };
  let count = 0;
  for (const row of store.custodyRecords()) {
    count++;
    if (count > 100000) fail('CUSTODY_CATALOG_CAPACITY');
    if (row.id !== String(count).padStart(16, '0')) fail('CUSTODY_CATALOG_CHANGED');
    const value = unseal<RecordValue>(row.ciphertext, keys, `custody-record-v1\0${metadata.id}\0${row.id}`, 65536);
    if (value.kind === 'enroll' || value.kind === 'issued') {
      if (
        !Array.isArray(value.keys) ||
        !value.keys.length ||
        value.keys.length > 64 ||
        (value.kind === 'issued' && value.keys.length !== 1) ||
        (value.kind === 'enroll' && count !== 1)
      )
        fail('CUSTODY_CATALOG_CHANGED');
      for (const key of value.keys) {
        if (
          !keyPattern.test(key.id) ||
          typeof key.keyBase64 !== 'string' ||
          Buffer.from(key.keyBase64, 'base64').length !== 32 ||
          Buffer.from(key.keyBase64, 'base64').toString('base64') !== key.keyBase64 ||
          result.issued.has(key.id)
        )
          fail('CUSTODY_CATALOG_CHANGED');
        result.issued.set(key.id, key.keyBase64);
      }
    } else if (value.kind === 'retired') {
      if (!value.keyId || !result.issued.has(value.keyId) || result.retired.has(value.keyId))
        fail('CUSTODY_CATALOG_CHANGED');
      result.retired.add(value.keyId);
    } else if (value.kind === 'backup') {
      if (
        !value.backupId ||
        !backupPattern.test(value.backupId) ||
        !value.manifestSha256 ||
        !hashPattern.test(value.manifestSha256) ||
        result.backups.has(value.backupId)
      )
        fail('CUSTODY_CATALOG_CHANGED');
      result.backups.set(value.backupId, value.manifestSha256);
    } else if (value.kind === 'restored' || value.kind === 'restore-superseded') {
      if (!value.backupId || !result.backups.has(value.backupId)) fail('CUSTODY_CATALOG_CHANGED');
    } else fail('CUSTODY_CATALOG_CHANGED');
  }
  if (count !== metadata.sequence) fail('CUSTODY_CATALOG_CHANGED');
  return result;
}
function append(store: LedgerStore, key: LedgerKey, value: RecordValue, update?: (metadata: Metadata) => void): void {
  store.transaction((ledger, archives) => {
    if (ledger.schema === 1) ledger.schema = 2;
    const metadata = (ledger as CustodyLedger).custody!;
    if (metadata.sequence >= 100000) fail('CUSTODY_CATALOG_CAPACITY');
    metadata.sequence++;
    const id = String(metadata.sequence).padStart(16, '0');
    archives.putCustodyRecord(id, envelope(value, key, `custody-record-v1\0${metadata.id}\0${id}`));
    metadata.catalogDigest = store.custodyDigest();
    update?.(metadata);
  });
}
function ringMatches(ring: ParsedKeyring, metadata: Metadata, catalog: Catalog, allowEnrollment: boolean): void {
  if ((!ring.managed && !allowEnrollment) || (ring.managed && stable(ring.managed) !== stable(group(metadata))))
    fail('CUSTODY_SCOPE_MISMATCH');
  for (const key of ring.keys)
    if (catalog.issued.get(key.keyId) !== key.key.toString('base64') || catalog.retired.has(key.keyId))
      fail('CUSTODY_KEYRING_CHANGED');
  for (const id of catalog.issued.keys())
    if (
      !catalog.retired.has(id) &&
      !ring.keys.some(k => k.keyId === id) &&
      !((metadata.pending?.kind === 'retire' || metadata.pending?.kind === 'rotate') && metadata.pending.keyId === id)
    )
      fail('CUSTODY_KEYRING_CHANGED');
}
function historyClosure(
  options: LedgerCustodyOptions,
  stores: ReadonlyMap<string, Pick<LedgerStore, 'read' | 'readArchive'>>,
): readonly { name: string; sha256: string }[] {
  let exported = 0;
  for (const store of stores.values()) exported += verifyAllArchiveStorage(store).externalHistories;
  if (exported && !options.history) fail('CUSTODY_HISTORY_REQUIRED');
  const files = options.history?.verify(stores, options.history.directory) ?? [];
  if (files.length > 20000) fail('CUSTODY_HISTORY_CAPACITY');
  const names = new Set<string>();
  for (const file of files) {
    if (
      !/^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,240}$/.test(file.name) ||
      names.has(file.name) ||
      !hashPattern.test(file.sha256)
    )
      fail('CUSTODY_HISTORY_INVALID');
    names.add(file.name);
    copyPrivate(join(options.history!.directory, file.name), undefined, file.sha256);
  }
  return files;
}
function verifyBackup(
  options: LedgerCustodyOptions,
  metadata: Metadata,
  catalog: Catalog,
  custodyKeys: readonly LedgerKey[],
  backupId: string,
): BackupManifest {
  const expected = catalog.backups.get(backupId);
  if (!expected || !backupPattern.test(backupId)) fail('CUSTODY_BACKUP_UNKNOWN');
  const directory = join(options.backupDirectory, backupId),
    bytes = privateBytes(join(directory, 'manifest.enc'), 32 * 1024 * 1024 + 1024);
  let manifest: BackupManifest;
  try {
    if (sha(bytes) !== expected) fail('CUSTODY_BACKUP_CHANGED');
    manifest = unseal<BackupManifest>(
      bytes.toString('utf8'),
      custodyKeys,
      `custody-backup-v1\0${metadata.id}\0${backupId}`,
      16 * 1024 * 1024,
    );
  } finally {
    bytes.fill(0);
  }
  if (
    manifest.version !== 1 ||
    manifest.custodyId !== metadata.id ||
    manifest.backupId !== backupId ||
    !Array.isArray(manifest.stores) ||
    !Array.isArray(manifest.history) ||
    manifest.stores.length !== metadata.stores.length ||
    manifest.history.length > 20000
  )
    fail('CUSTODY_BACKUP_INVALID');
  const readers = new Map<string, CustodySnapshot>();
  try {
    for (let index = 0; index < metadata.stores.length; index++) {
      const source = metadata.stores[index]!,
        snapshot = manifest.stores[index]!;
      if (
        stable({
          id: snapshot.id,
          database: snapshot.database,
          witnessPath: snapshot.witnessPath,
          inventoryInstanceId: snapshot.inventoryInstanceId,
        }) !== stable(source) ||
        snapshot.file !== `store-${index}.sqlite` ||
        !hashPattern.test(snapshot.commitment) ||
        !hashPattern.test(snapshot.sha256) ||
        !Number.isSafeInteger(snapshot.bytes) ||
        snapshot.bytes <= 0 ||
        catalog.issued.get(snapshot.keyId) !== snapshot.keyBase64
      )
        fail('CUSTODY_BACKUP_INVALID');
      const path = join(directory, snapshot.file),
        file = copyPrivate(path, undefined, snapshot.sha256);
      if (file.bytes !== snapshot.bytes) fail('CUSTODY_BACKUP_CHANGED');
      const key = Buffer.from(snapshot.keyBase64, 'base64');
      let reader: CustodySnapshot;
      try {
        reader = new CustodySnapshot(path, key, snapshot.commitment);
      } finally {
        key.fill(0);
      }
      readers.set(snapshot.id, reader);
      const state = reader.read() as Ledger & { keyCustody?: string };
      if (
        state.inventoryInstanceId !== source.inventoryInstanceId ||
        state.revision !== snapshot.revision ||
        state.keyCustody !== metadata.id ||
        ![2, 3].includes(state.schema)
      )
        fail('CUSTODY_BACKUP_INVALID');
    }
    const historyDirectory = join(directory, 'history');
    const closure = historyClosure(
      { ...options, ...(options.history ? { history: { ...options.history, directory: historyDirectory } } : {}) },
      readers,
    );
    if (stable(closure) !== stable(manifest.history.map(({ name, sha256 }) => ({ name, sha256 }))))
      fail('CUSTODY_HISTORY_INVALID');
    for (const file of manifest.history) {
      if (
        file.file !== file.name ||
        copyPrivate(join(historyDirectory, file.file), undefined, file.sha256).bytes !== file.bytes
      )
        fail('CUSTODY_BACKUP_CHANGED');
    }
    return manifest;
  } finally {
    for (const reader of readers.values()) reader.close();
  }
}
function newBackup(
  options: LedgerCustodyOptions,
  metadata: Metadata,
  stores: Map<string, { store: LedgerStore; key: LedgerKey }>,
  custodyKey: LedgerKey,
): { backupId: string; manifestSha256: string } {
  const backupId = randomUUID(),
    staging = join(options.backupDirectory, `.pending-${backupId}`),
    destination = join(options.backupDirectory, backupId);
  mkdirSync(staging, { mode: 0o700 });
  syncDirectory(options.backupDirectory);
  try {
    const historyDirectory = join(staging, 'history');
    mkdirSync(historyDirectory, { mode: 0o700 });
    const manifest: BackupManifest = { version: 1, custodyId: metadata.id, backupId, stores: [], history: [] };
    for (let index = 0; index < metadata.stores.length; index++) {
      const source = metadata.stores[index]!,
        { store, key } = stores.get(source.id)!,
        file = `store-${index}.sqlite`,
        path = join(staging, file);
      const snapshot = store.snapshot(path);
      syncDirectory(staging);
      const copied = copyPrivate(path),
        reader = new CustodySnapshot(path, key.key, snapshot.commitment);
      try {
        verifyAllArchiveStorage(reader);
      } finally {
        reader.close();
      }
      manifest.stores.push({
        ...source,
        file,
        ...copied,
        ...snapshot,
        keyId: key.keyId,
        keyBase64: key.key.toString('base64'),
      });
    }
    const closure = historyClosure(options, new Map([...stores].map(([id, value]) => [id, value.store])));
    for (const file of closure) {
      const copied = copyPrivate(
        join(options.history!.directory, file.name),
        join(historyDirectory, file.name),
        file.sha256,
      );
      manifest.history.push({ ...file, file: file.name, bytes: copied.bytes });
    }
    if (Buffer.byteLength(stable(manifest)) > 16 * 1024 * 1024) fail('CUSTODY_BACKUP_CAPACITY');
    const sealed = envelope(manifest, custodyKey, `custody-backup-v1\0${metadata.id}\0${backupId}`);
    writeNewPrivate(join(staging, 'manifest.enc'), Buffer.from(sealed));
    syncDirectory(staging);
    renameSync(staging, destination);
    syncDirectory(options.backupDirectory);
    return { backupId, manifestSha256: sha(sealed) };
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
function lockWitness(path: string): { db: DatabaseSync; commitment: string } {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    checkPrivate(fd, path);
  } finally {
    closeSync(fd);
  }
  const db = new DatabaseSync(path);
  try {
    db.exec('PRAGMA busy_timeout=0; PRAGMA trusted_schema=OFF; BEGIN EXCLUSIVE');
    const value = db.prepare('SELECT digest FROM commitment WHERE id=1').get()?.digest;
    if (typeof value !== 'string' || !hashPattern.test(value)) fail('CUSTODY_WITNESS_UNAVAILABLE');
    return { db, commitment: value };
  } catch {
    db.close();
    return fail('CUSTODY_WITNESS_UNAVAILABLE');
  }
}
function restoreFiles(
  options: LedgerCustodyOptions,
  metadata: Metadata,
  manifest: BackupManifest,
  recoveryId: string,
): void {
  const recovery = join(options.backupDirectory, `.recovery-${recoveryId}`);
  if (!existsSync(recovery)) {
    mkdirSync(recovery, { mode: 0o700 });
    syncDirectory(options.backupDirectory);
  }
  privateDirectory(recovery);
  for (let index = 0; index < manifest.stores.length; index++) {
    const source = manifest.stores[index]!,
      target = source.database,
      staged = join(dirname(target), `.custody-restore-${recoveryId}-${index}`);
    if (existsSync(staged) && copyPrivate(staged).sha256 !== source.sha256) {
      renameSync(staged, `${staged}.partial-${randomUUID()}`);
      syncDirectory(dirname(staged));
    }
    if (!existsSync(staged))
      copyPrivate(join(options.backupDirectory, manifest.backupId, source.file), staged, source.sha256);
    // Preserve damaged/older files and their journals. Never remove a journal to
    // make stale authority appear valid. Witness locks prevent supported owners.
    for (const suffix of ['', '-journal', '-wal', '-shm']) {
      const path = target + suffix,
        saved = join(recovery, `original-${index}${suffix || '.sqlite'}`);
      if (existsSync(path)) {
        const currentHash = copyPrivate(path).sha256;
        if (
          existsSync(saved) &&
          copyPrivate(saved).sha256 !== currentHash &&
          (suffix || currentHash !== source.sha256)
        ) {
          renameSync(saved, `${saved}.partial-${randomUUID()}`);
          syncDirectory(recovery);
        }
        if (!existsSync(saved)) copyPrivate(path, saved, currentHash);
        if (suffix) {
          rmSync(path);
          syncDirectory(dirname(path));
        }
      }
    }
    renameSync(staged, target);
    syncDirectory(dirname(target));
  }
  for (const file of manifest.history) {
    const target = join(options.history!.directory, file.name),
      source = join(options.backupDirectory, manifest.backupId, 'history', file.file);
    if (existsSync(target) && copyPrivate(target).sha256 === file.sha256) continue;
    const staged = join(options.history!.directory, `.custody-history-${recoveryId}-${sha(file.name)}`);
    if (existsSync(staged) && copyPrivate(staged).sha256 !== file.sha256) {
      renameSync(staged, `${staged}.partial-${randomUUID()}`);
      syncDirectory(dirname(staged));
    }
    if (!existsSync(staged)) copyPrivate(source, staged, file.sha256);
    if (existsSync(target)) {
      renameSync(target, join(options.history!.directory, `.custody-original-${recoveryId}-${sha(file.name)}`));
      syncDirectory(dirname(target));
    }
    renameSync(staged, target);
    syncDirectory(dirname(target));
  }
  // Original bytes are retained in .recovery-ID for operator recovery review.
}
/** Offline managed custody. Preview and apply hold the same complete owner set.
 * Active-ring retirement preserves all historical secrets in independent escrow.
 */
export function manageLedgerCustody(
  options: LedgerCustodyOptions,
  request: CustodyRequest,
  apply?: { readonly expectedDigest: string },
): CustodyResult {
  checkedOptions(options);
  if (
    !['enroll', 'backup', 'status', 'recover', 'verify', 'restore', 'retire', 'rotate'].includes(request.operation) ||
    ('backupId' in request && !backupPattern.test(request.backupId)) ||
    ('keyId' in request && !keyPattern.test(request.keyId)) ||
    ('nextKeyId' in request && !keyPattern.test(request.nextKeyId)) ||
    (apply && !hashPattern.test(apply.expectedDigest))
  )
    fail('CUSTODY_REQUEST_INVALID');
  return withLedgerKeyringState(options.keyringFile, (ring, publishRing) =>
    withLedgerKeyringState(options.custodyKeyringFile, custodyRing => {
      if (custodyRing.managed || ring.keys.some(key => custodyRing.keys.some(other => other.key.equals(key.key))))
        fail('CUSTODY_KEY_SEPARATION_REQUIRED');
      let custody: LedgerStore | undefined, custodyKey: LedgerKey | undefined, metadata: Metadata | undefined;
      const stores = new Map<string, { store: LedgerStore; key: LedgerKey }>(),
        witnesses: { db: DatabaseSync; commitment: string }[] = [];
      try {
        const dbExists = existsSync(options.custodyDatabase),
          witnessExists = existsSync(options.custodyWitness);
        if (dbExists !== witnessExists) fail('CUSTODY_ENROLLMENT_INCOMPLETE');
        if (dbExists) {
          const opened = openStore(options.custodyDatabase, options.custodyWitness, custodyRing.keys);
          custody = opened.store;
          custodyKey = opened.key;
          metadata = (custody.read() as CustodyLedger).custody;
        }
        if (!metadata && request.operation !== 'enroll') fail('CUSTODY_NOT_ENROLLED');
        if (metadata) binding(metadata, options);
        if (!metadata && ring.managed) fail('CUSTODY_SCOPE_MISMATCH');
        const catalog = metadata
          ? readCatalog(custody!, metadata, custodyRing.keys)
          : { issued: new Map<string, string>(), retired: new Set<string>(), backups: new Map<string, string>() };
        if (metadata)
          ringMatches(ring, metadata, catalog, request.operation === 'enroll' || request.operation === 'recover');
        if (metadata && metadata.sequence >= 100000 && !['status', 'verify', 'recover'].includes(request.operation))
          fail('CUSTODY_CATALOG_CAPACITY');
        if (metadata?.pending && request.operation !== 'recover' && request.operation !== 'status')
          fail('CUSTODY_RECOVERY_REQUIRED');
        const restoring =
          request.operation === 'restore' ||
          (['recover', 'status'].includes(request.operation) && metadata?.pending?.kind === 'restore');
        let restoreSuperseded = false;
        if (restoring) {
          for (const source of options.stores) witnesses.push(lockWitness(source.witnessPath));
        } else {
          for (const source of options.stores) {
            const opened = openStore(source.database, source.witnessPath, ring.keys);
            stores.set(source.id, opened);
            const state = opened.store.read() as Ledger & { keyCustody?: string };
            if (!metadata && state.keyCustody !== undefined) fail('CUSTODY_ALREADY_MANAGED');
            if (
              metadata &&
              (metadata.stores.find(s => s.id === source.id)?.inventoryInstanceId !== state.inventoryInstanceId ||
                (state.keyCustody !== undefined && state.keyCustody !== metadata.id) ||
                (ring.managed && state.keyCustody !== metadata.id))
            )
              fail('CUSTODY_SCOPE_MISMATCH');
          }
          historyClosure(options, new Map([...stores].map(([id, value]) => [id, value.store])));
        }
        let manifest: BackupManifest | undefined;
        const selectedBackup =
          'backupId' in request
            ? request.backupId
            : metadata?.pending?.kind === 'restore'
              ? metadata.pending.backupId
              : undefined;
        if (selectedBackup) manifest = verifyBackup(options, metadata!, catalog, custodyRing.keys, selectedBackup);
        if (restoring) {
          if (witnesses.some((w, index) => w.commitment !== manifest!.stores[index]!.commitment)) {
            if (!['recover', 'status'].includes(request.operation)) fail('CUSTODY_RESTORE_STALE');
            // A fully authenticated owner may have resumed after the crash. Cancel
            // the obsolete restore intent only after verifying all current state;
            // never replay the older snapshot over advanced authority.
            for (const witness of witnesses.splice(0)) witness.db.close();
            for (const source of options.stores) {
              const opened = openStore(source.database, source.witnessPath, ring.keys);
              stores.set(source.id, opened);
              const state = opened.store.read() as Ledger & { keyCustody?: string };
              if (
                state.inventoryInstanceId !== metadata!.stores.find(s => s.id === source.id)?.inventoryInstanceId ||
                state.keyCustody !== metadata!.id
              )
                fail('CUSTODY_SCOPE_MISMATCH');
            }
            historyClosure(options, new Map([...stores].map(([id, value]) => [id, value.store])));
            restoreSuperseded = true;
          } else
            for (const item of manifest!.stores) {
              if (!ring.keys.some(key => key.keyId === item.keyId && key.key.toString('base64') === item.keyBase64))
                fail('CUSTODY_KEY_UNAVAILABLE');
            }
        }
        // Retirement audits the complete registered backup inventory and current stores.
        if (
          request.operation === 'retire' ||
          (request.operation === 'recover' && metadata?.pending?.kind === 'retire')
        ) {
          for (const id of catalog.backups.keys()) verifyBackup(options, metadata!, catalog, custodyRing.keys, id);
          const keyId = request.operation === 'retire' ? request.keyId : (metadata!.pending as { keyId: string }).keyId;
          if (ring.keys.length <= 1 && ring.keys.some(key => key.keyId === keyId)) fail('CUSTODY_LAST_KEY');
          if (
            !catalog.issued.has(keyId) ||
            catalog.retired.has(keyId) ||
            [...stores.values()].some(value => value.key.keyId === keyId)
          )
            fail('CUSTODY_KEY_IN_USE');
        }
        if (
          request.operation === 'rotate' &&
          (!metadata || catalog.issued.has(request.nextKeyId) || ring.keys.length >= ring.maxKeys)
        )
          fail('CUSTODY_ROTATION_INVALID');
        const digest = sha(
          stable({
            request,
            options: {
              keyringFile: options.keyringFile,
              custodyDatabase: options.custodyDatabase,
              custodyWitness: options.custodyWitness,
              custodyKeyringFile: options.custodyKeyringFile,
              backupDirectory: options.backupDirectory,
              stores: options.stores,
              historyDirectory: options.history?.directory,
            },
            ring: { keys: ring.keys.map(k => [k.keyId, sha(k.key)]), maxKeys: ring.maxKeys, managed: ring.managed },
            custody: custody?.snapshotCommitment(),
            sources:
              restoring && !restoreSuperseded
                ? witnesses.map(w => w.commitment)
                : [...stores].map(([id, s]) => [id, s.store.snapshotCommitment()]),
          }),
        );
        const result = (extra: Partial<CustodyResult> = {}): CustodyResult => ({
          operation: request.operation,
          applied: !!apply,
          digest,
          keyCount: ring.keys.length,
          maxKeys: ring.maxKeys,
          storeCount: options.stores.length,
          backupCount: catalog.backups.size,
          pending: !!metadata?.pending || (!!metadata && !ring.managed),
          backupFileLimit: 20000,
          manifestByteLimit: 16777216,
          catalogRecordLimit: 100000,
          ...(restoreSuperseded ? { restoreSuperseded: true as const } : {}),
          ...extra,
        });
        if (!apply || request.operation === 'status' || request.operation === 'verify')
          return result(selectedBackup ? { backupId: selectedBackup } : {});
        if (apply.expectedDigest !== digest) fail('CUSTODY_PREVIEW_CHANGED');
        if (request.operation === 'enroll') {
          if (!metadata) {
            if (!custody) {
              custodyKey = custodyRing.keys[0]!;
              custody = new LedgerStore(options.custodyDatabase, custodyKey.key, undefined, {
                path: options.custodyWitness,
                mode: 'create',
                recovery: 'mirror',
              });
            }
            const initial: Metadata = {
              version: 1,
              id: randomUUID(),
              keyringFile: options.keyringFile,
              backupDirectory: options.backupDirectory,
              stores: options.stores.map(s => ({
                ...s,
                inventoryInstanceId: stores.get(s.id)!.store.read().inventoryInstanceId,
              })),
              ...(options.history ? { historyDirectory: options.history.directory } : {}),
              sequence: 0,
              catalogDigest: custody.custodyDigest(),
            };
            custody.transaction((ledger, archives) => {
              if ((ledger as CustodyLedger).custody) fail('CUSTODY_ALREADY_ENROLLED');
              if (ledger.schema === 1) ledger.schema = 2;
              initial.sequence = 1;
              const id = String(1).padStart(16, '0');
              archives.putCustodyRecord(
                id,
                envelope(
                  { kind: 'enroll', keys: ring.keys.map(k => ({ id: k.keyId, keyBase64: k.key.toString('base64') })) },
                  custodyKey!,
                  `custody-record-v1\0${initial.id}\0${id}`,
                ),
              );
              initial.catalogDigest = custody!.custodyDigest();
              (ledger as CustodyLedger).custody = initial;
            });
            metadata = (custody.read() as CustodyLedger).custody!;
          }
          for (const { store } of stores.values())
            if ((store.read() as Ledger & { keyCustody?: string }).keyCustody !== metadata.id)
              store.transaction(state => {
                if (state.schema === 1) state.schema = 2;
                (state as Ledger & { keyCustody?: string }).keyCustody = metadata!.id;
              });
          ring.managed = group(metadata);
          publishRing();
          return result({ pending: false });
        }
        if (request.operation === 'backup') {
          const backup = newBackup(options, metadata!, stores, custodyKey!);
          // Validate durable files before acknowledging/registering any backup.
          const provisional = {
            ...catalog,
            backups: new Map([...catalog.backups, [backup.backupId, backup.manifestSha256]]),
          };
          verifyBackup(options, metadata!, provisional, custodyRing.keys, backup.backupId);
          append(custody!, custodyKey!, { kind: 'backup', ...backup });
          return result({ backupId: backup.backupId, backupCount: catalog.backups.size + 1 });
        }
        if (request.operation === 'rotate') {
          const next = { keyId: request.nextKeyId, key: randomBytes(32) };
          try {
            append(
              custody!,
              custodyKey!,
              { kind: 'issued', keys: [{ id: next.keyId, keyBase64: next.key.toString('base64') }] },
              state => {
                state.pending = { kind: 'rotate', keyId: next.keyId };
              },
            );
            ring.keys.push(next);
            publishRing();
            for (const { store } of stores.values()) store.rotateEncryptionKey(next.key);
            custody!.transaction(ledger => {
              delete (ledger as CustodyLedger).custody!.pending;
            });
          } finally {
            next.key.fill(0);
          }
          return result({ keyId: request.nextKeyId, pending: false, observationReenrollmentRequired: true });
        }
        if (request.operation === 'retire')
          custody!.transaction(ledger => {
            (ledger as CustodyLedger).custody!.pending = { kind: 'retire', keyId: request.keyId };
          });
        if (request.operation === 'restore')
          custody!.transaction(ledger => {
            (ledger as CustodyLedger).custody!.pending = {
              kind: 'restore',
              backupId: request.backupId,
              recoveryId: randomUUID(),
            };
          });
        metadata = (custody!.read() as CustodyLedger).custody!;
        if (!ring.managed) {
          for (const { store } of stores.values())
            if ((store.read() as Ledger & { keyCustody?: string }).keyCustody !== metadata.id)
              store.transaction(state => {
                if (state.schema === 1) state.schema = 2;
                (state as Ledger & { keyCustody?: string }).keyCustody = metadata!.id;
              });
          ring.managed = group(metadata);
          publishRing();
          return result({ pending: false });
        }
        const pending = metadata.pending;
        if (!pending) return result({ pending: false });
        if (pending.kind === 'retire') {
          ring.keys = ring.keys.filter(key => key.keyId !== pending.keyId);
          publishRing();
          append(custody!, custodyKey!, { kind: 'retired', keyId: pending.keyId }, state => {
            delete state.pending;
          });
          return result({ keyId: pending.keyId, pending: false });
        }
        if (pending.kind === 'rotate') {
          let next = ring.keys.find(key => key.keyId === pending.keyId);
          if (!next) {
            next = { keyId: pending.keyId, key: Buffer.from(catalog.issued.get(pending.keyId)!, 'base64') };
            ring.keys.push(next);
            publishRing();
          }
          for (const { store, key } of stores.values())
            if (key.keyId !== next.keyId) store.rotateEncryptionKey(next.key);
          custody!.transaction(ledger => {
            delete (ledger as CustodyLedger).custody!.pending;
          });
          return result({ keyId: pending.keyId, pending: false, observationReenrollmentRequired: true });
        }
        if (restoreSuperseded) {
          append(custody!, custodyKey!, { kind: 'restore-superseded', backupId: manifest!.backupId }, state => {
            delete state.pending;
          });
          return result({ backupId: manifest!.backupId, pending: false });
        }
        restoreFiles(options, metadata, manifest!, pending.recoveryId);
        // Release only these witness locks, then authenticate the restored pair using
        // normal store ownership. Pending state survives any verification failure.
        for (const witness of witnesses.splice(0)) witness.db.close();
        for (const source of options.stores) {
          const opened = openStore(source.database, source.witnessPath, ring.keys);
          stores.set(source.id, opened);
        }
        historyClosure(options, new Map([...stores].map(([id, value]) => [id, value.store])));
        append(custody!, custodyKey!, { kind: 'restored', backupId: manifest!.backupId }, state => {
          delete state.pending;
        });
        return result({ backupId: manifest!.backupId, pending: false });
      } finally {
        for (const witness of witnesses) witness.db.close();
        for (const { store } of stores.values()) store.close();
        custody?.close();
      }
    }),
  );
}
