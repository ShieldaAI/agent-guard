// Regression tests for the ledger operations: keyring, custody, recovery, their shared
// private-file checks and the two command-line tools.
import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import {
  createLedgerKeyring,
  configureLedgerKeyring,
  readLedgerKeyring,
  readLedgerKeyringPolicy,
  loadLedgerKey,
  rotateLedgerKey,
  rotateLedgerKeyring,
  manageLedgerCustody,
  manageLedgerRecovery,
} from '../dist/entry-ops.js';
import { verifyPilotReview } from '../dist/entry-pilot.js';
import { loadInventoryManifestFile } from '../dist/entry-inventory.js';
import { ExecutorError, LedgerStore } from '../dist/store.js';
import { copyPrivate, privateBytes } from '../dist/custody-files.js';
import { maintenanceHint } from '../dist/custody-cli.js';
import { privateDirectory, readPrivateFile, trustedDirectoryChain, PRIVATE_FILE } from '../dist/private-files.js';
import { createPilotReviewFixture } from './fixtures/pilot-review.mjs';

const test = (name, fn) => nodeTest(name, { skip: process.platform === 'win32' }, fn);
const ledgerCli = fileURLToPath(new URL('../dist/ledger-maintenance-cli.js', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function directories(t, prefix, names) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of names) fs.mkdirSync(join(root, name), { mode: 0o700 });
  return root;
}
/** Run `operation` and return what it threw. */
function thrown(operation) {
  try {
    operation();
  } catch (error) {
    return error;
  }
  return assert.fail('expected a refusal');
}
/** Replace one `node:fs` function for the duration of `operation`. */
function withFs(name, replacement, operation) {
  const original = fs[name];
  fs[name] = replacement(original);
  syncBuiltinESMExports();
  try {
    return operation();
  } finally {
    fs[name] = original;
    syncBuiltinESMExports();
  }
}
function keyFixture(t, witnessed = true) {
  const root = directories(t, 'guard-release-keys-', ['data', 'control', 'keys']);
  const keyringFile = join(root, 'keys', 'keyring.json'),
    database = join(root, 'data', 'ledger.sqlite'),
    witnessPath = witnessed ? join(root, 'control', 'witness.sqlite') : undefined;
  const options = { database, keyringFile, ...(witnessPath ? { witnessPath } : {}) };
  createLedgerKeyring({ keyringFile, keyId: 'initial' });
  const initial = readLedgerKeyring({ keyringFile })[0];
  t.after(() => initial.key.fill(0));
  const open = (create = false) =>
    new LedgerStore(
      database,
      initial.key,
      undefined,
      witnessPath ? { path: witnessPath, mode: create ? 'create' : 'resume' } : undefined,
      create ? {} : { existingOnly: true },
    );
  open(true).close();
  return { root, options, initial, open };
}
function custodyFixture(t, { history = false } = {}) {
  const root = directories(t, 'guard-release-custody-', [
    'active',
    'data',
    'witness',
    'custody',
    'custody-witness',
    'offline',
    'backups',
    'history',
  ]);
  const options = {
    keyringFile: join(root, 'active', 'keys.json'),
    custodyDatabase: join(root, 'custody', 'catalog.db'),
    custodyWitness: join(root, 'custody-witness', 'anchor.db'),
    custodyKeyringFile: join(root, 'offline', 'keys.json'),
    backupDirectory: join(root, 'backups'),
    stores: ['authority', 'tickets'].map(id => ({
      id,
      database: join(root, 'data', `${id}.db`),
      witnessPath: join(root, 'witness', `${id}.db`),
    })),
  };
  const failing = { copy: false };
  if (history)
    options.history = {
      directory: join(root, 'history'),
      // The backup copy is verified in its own directory; `failing.copy` breaks only that step.
      verify(_stores, directory) {
        if (failing.copy && directory !== join(root, 'history')) throw new Error('injected history failure');
        return [];
      },
    };
  createLedgerKeyring({ keyringFile: options.keyringFile, keyId: 'first', maxKeys: 8 });
  createLedgerKeyring({ keyringFile: options.custodyKeyringFile, keyId: 'custody-first', maxKeys: 64 });
  const keys = readLedgerKeyring({ keyringFile: options.keyringFile });
  try {
    for (const source of options.stores)
      new LedgerStore(source.database, keys[0].key, undefined, { path: source.witnessPath, mode: 'create' }).close();
  } finally {
    keys.forEach(k => k.key.fill(0));
  }
  const apply = (request, using = options) => {
    const preview = manageLedgerCustody(using, request);
    return manageLedgerCustody(using, request, { expectedDigest: preview.digest });
  };
  return { root, options, apply, failing };
}
function recoveryFixture(t) {
  const root = directories(t, 'guard-release-recovery-', ['data', 'witness', 'keys']);
  const options = {
    keyringFile: join(root, 'keys', 'ring.json'),
    stores: ['a', 'b'].map(id => ({
      id,
      database: join(root, 'data', id + '.sqlite'),
      witnessPath: join(root, 'witness', id + '.sqlite'),
    })),
  };
  createLedgerKeyring({ keyringFile: options.keyringFile, keyId: 'initial' });
  const key = readLedgerKeyring(options)[0].key;
  t.after(() => key.fill(0));
  for (const source of options.stores)
    new LedgerStore(source.database, key, 64 * 1024 * 1024, {
      path: source.witnessPath,
      mode: 'create',
      recovery: 'mirror',
    }).close();
  const apply = operation => {
    const preview = manageLedgerRecovery(options, { operation });
    return manageLedgerRecovery(options, { operation }, { expectedDigest: preview.digest });
  };
  return { root, options, key, apply };
}

// Item 8 ------------------------------------------------------------------------------------

test('custody refuses a store with any property beyond id, database and witnessPath', t => {
  const { options } = custodyFixture(t);
  const withStores = stores => ({ ...options, stores });
  const extra = withStores([{ ...options.stores[0], note: 'kept forever' }, options.stores[1]]);
  for (const bad of [
    extra,
    withStores([{ id: 'authority', database: options.stores[0].database }, options.stores[1]]),
    withStores([{ ...options.stores[0], id: 7 }, options.stores[1]]),
    withStores([{ ...options.stores[0], database: 'relative.db' }, options.stores[1]]),
    withStores([null, options.stores[1]]),
    withStores([[], options.stores[1]]),
    { ...options, backupDirectory: 5 },
    { ...options, history: { directory: join(options.backupDirectory, '..', 'history') } },
    null,
    'options',
  ]) {
    const error = thrown(() => manageLedgerCustody(bad, { operation: 'enroll' }));
    assert.equal(error instanceof ExecutorError, true);
    assert.equal(error.code, 'CUSTODY_CONFIG_INVALID');
  }
  for (const request of [null, 'enroll', {}, { operation: 'verify', backupId: 7 }, { operation: 'retire' }])
    assert.throws(() => manageLedgerCustody(options, request), { code: 'CUSTODY_REQUEST_INVALID' });
  assert.throws(() => manageLedgerCustody(options, { operation: 'status' }, 'apply'), {
    code: 'CUSTODY_REQUEST_INVALID',
  });
  // Nothing was enrolled by a refused call.
  assert.equal(fs.existsSync(options.custodyDatabase), false);
});

test('an enrollment that once stored extra store properties still backs up and verifies', t => {
  const { options, apply } = custodyFixture(t);
  apply({ operation: 'enroll' });
  // What the unvalidated API used to persist: an extra property inside the custody metadata.
  const custodyKeys = readLedgerKeyring({ keyringFile: options.custodyKeyringFile });
  try {
    const custody = new LedgerStore(
      options.custodyDatabase,
      custodyKeys[0].key,
      undefined,
      { path: options.custodyWitness, mode: 'resume' },
      { existingOnly: true },
    );
    custody.transaction(ledger => {
      ledger.custody.stores[0].note = 'persisted by an earlier release';
    });
    custody.close();
  } finally {
    custodyKeys.forEach(k => k.key.fill(0));
  }
  const backup = apply({ operation: 'backup' });
  assert.equal(manageLedgerCustody(options, { operation: 'verify', backupId: backup.backupId }).backupCount, 1);
});

test('recovery validates the exact store shape and its request', t => {
  const { options } = recoveryFixture(t);
  for (const bad of [
    { ...options, stores: [{ ...options.stores[0], extra: 1 }, options.stores[1]] },
    { ...options, stores: [{ ...options.stores[0], database: 'relative.sqlite' }, options.stores[1]] },
    { ...options, stores: [null] },
    { ...options, keyringFile: 4 },
    null,
  ])
    assert.throws(() => manageLedgerRecovery(bad, { operation: 'enroll' }), { code: 'RECOVERY_CONFIG_INVALID' });
  for (const request of [null, {}, { operation: 'restore' }])
    assert.throws(() => manageLedgerRecovery(options, request), { code: 'RECOVERY_REQUEST_INVALID' });
  assert.throws(() => manageLedgerRecovery(options, { operation: 'enroll' }, { expectedDigest: 9 }), {
    code: 'RECOVERY_REQUEST_INVALID',
  });
});

// Item 10 -----------------------------------------------------------------------------------

test('a stored key limit outside 1..64 keeps KEYRING_LIMIT_INVALID', t => {
  const f = keyFixture(t);
  const value = JSON.parse(fs.readFileSync(f.options.keyringFile, 'utf8'));
  fs.writeFileSync(f.options.keyringFile, JSON.stringify({ ...value, maxKeys: 65 }));
  assert.throws(() => readLedgerKeyringPolicy(f.options), { code: 'KEYRING_LIMIT_INVALID' });
  assert.throws(() => readLedgerKeyring(f.options), { code: 'KEYRING_LIMIT_INVALID' });
  assert.throws(() => loadLedgerKey(f.options), { code: 'KEYRING_LIMIT_INVALID' });
  fs.writeFileSync(f.options.keyringFile, JSON.stringify({ ...value, surprise: true }));
  assert.throws(() => readLedgerKeyringPolicy(f.options), { code: 'KEYRING_INVALID' });
});

test('a ledger no key opens says why: still owned, missing, or not a key problem at all', t => {
  const f = keyFixture(t);
  const owner = f.open();
  try {
    for (const attempt of [
      () => loadLedgerKey(f.options),
      () => rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }),
      () =>
        rotateLedgerKey({
          ...f.options,
          currentKey: f.initial.key,
          nextKey: Buffer.alloc(32, 7),
          keyringFile: undefined,
        }),
    ]) {
      const error = thrown(attempt);
      assert.equal(error.code, 'LEDGER_KEY_UNAVAILABLE');
      assert.equal(error.detail, 'LOCKED');
      assert.equal(error.cause instanceof ExecutorError, true);
    }
  } finally {
    owner.close();
  }
  const missing = thrown(() => loadLedgerKey({ ...f.options, database: join(f.root, 'data', 'absent.sqlite') }));
  assert.equal(missing.code, 'LEDGER_KEY_UNAVAILABLE');
  assert.equal(missing.detail, 'FILE_MISSING');
  assert.equal(fs.existsSync(join(f.root, 'data', 'absent.sqlite')), false);
  // A relative path is a configuration error whatever the keys are.
  assert.throws(() => loadLedgerKey({ ...f.options, database: 'ledger.sqlite' }), {
    code: 'MAINTENANCE_CONFIG_INVALID',
  });
  assert.throws(() => rotateLedgerKeyring({ ...f.options, database: 'ledger.sqlite', nextKeyId: 'next' }), {
    code: 'MAINTENANCE_CONFIG_INVALID',
  });
  assert.equal(loadLedgerKey(f.options).keyId, 'initial');
});

test('an unsafe ledger directory is reported as such, not as a missing key', t => {
  const f = keyFixture(t, false);
  fs.chmodSync(join(f.root, 'data'), 0o755);
  try {
    const error = thrown(() => loadLedgerKey(f.options));
    assert.equal(error.code, 'STORE_DIRECTORY_UNSAFE');
    assert.equal(error.detail, 'DIRECTORY_UNSAFE');
  } finally {
    fs.chmodSync(join(f.root, 'data'), 0o700);
  }
});

test('keyring maintenance keeps the original failure as cause and names a held lock', t => {
  const f = keyFixture(t);
  const injected = new Error('injected rename failure');
  const failure = withFs(
    'renameSync',
    () => () => {
      throw Object.assign(injected, { code: 'EROFS' });
    },
    () => thrown(() => configureLedgerKeyring({ ...f.options, maxKeys: 8 })),
  );
  assert.equal(failure.code, 'KEYRING_MAINTENANCE_FAILED');
  assert.equal(failure.cause, injected);
  assert.equal(failure.detail, 'EROFS');
  // A coded refusal from inside the lock is never rewritten.
  assert.throws(() => configureLedgerKeyring({ ...f.options, maxKeys: 0 }), { code: 'KEYRING_LIMIT_INVALID' });

  const lock = new DatabaseSync(f.options.keyringFile + '.maintenance.sqlite');
  try {
    lock.exec('PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE');
    const busy = thrown(() => configureLedgerKeyring({ ...f.options, maxKeys: 8 }));
    assert.equal(busy.code, 'KEYRING_BUSY');
    assert.notEqual(busy.cause, undefined);
  } finally {
    lock.close();
  }
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 1, maxKeys: 4 });
});

test('keyring functions throw coded errors for missing directories and malformed options', t => {
  const f = keyFixture(t);
  const absent = join(f.root, 'nowhere', 'keyring.json');
  for (const attempt of [
    () => createLedgerKeyring({ keyringFile: absent, keyId: 'first' }),
    () => readLedgerKeyring({ keyringFile: absent }),
    () => configureLedgerKeyring({ keyringFile: absent, maxKeys: 4 }),
  ]) {
    const error = thrown(attempt);
    assert.equal(error.code, 'KEYRING_UNAVAILABLE');
    assert.equal(error.detail, 'DIRECTORY_MISSING');
  }
  const noFile = thrown(() => readLedgerKeyring({ keyringFile: join(f.root, 'keys', 'absent.json') }));
  assert.equal(noFile.code, 'KEYRING_UNAVAILABLE');
  assert.equal(noFile.detail, 'FILE_MISSING');
  for (const attempt of [
    () => readLedgerKeyring(),
    () => readLedgerKeyringPolicy(null),
    () => loadLedgerKey(undefined),
    () => createLedgerKeyring(null),
    () => rotateLedgerKeyring(undefined),
    () => loadLedgerKey({ ...f.options, database: 5 }),
  ])
    assert.equal(thrown(attempt).code, 'MAINTENANCE_CONFIG_INVALID');
  assert.throws(() => rotateLedgerKey({ database: f.options.database, currentKey: 'a', nextKey: 'b' }), {
    code: 'STORE_ROTATION_INVALID',
  });
  assert.throws(() => createLedgerKeyring({ keyringFile: absent, keyId: 5 }), { code: 'KEYRING_INVALID' });
});

test('a custody record sealed under a key the ring no longer holds is CUSTODY_KEY_UNAVAILABLE', t => {
  const { options, apply } = custodyFixture(t);
  apply({ operation: 'enroll' });
  rotateLedgerKeyring({
    database: options.custodyDatabase,
    witnessPath: options.custodyWitness,
    keyringFile: options.custodyKeyringFile,
    nextKeyId: 'custody-second',
  });
  assert.equal(manageLedgerCustody(options, { operation: 'status' }).pending, false);
  const ring = JSON.parse(fs.readFileSync(options.custodyKeyringFile, 'utf8'));
  fs.writeFileSync(
    options.custodyKeyringFile,
    JSON.stringify({ ...ring, keys: ring.keys.filter(key => key.id !== 'custody-first') }),
  );
  assert.throws(() => manageLedgerCustody(options, { operation: 'status' }), { code: 'CUSTODY_KEY_UNAVAILABLE' });
  // A forged record under a key that is present stays an authentication failure.
  fs.writeFileSync(options.custodyKeyringFile, JSON.stringify(ring));
  assert.equal(manageLedgerCustody(options, { operation: 'status' }).pending, false);
});

// Item 11 -----------------------------------------------------------------------------------

test('a failed private copy removes its partial destination and can be repeated', t => {
  const root = directories(t, 'guard-release-copy-', ['from', 'to']);
  const source = join(root, 'from', 'source.bin'),
    destination = join(root, 'to', 'copy.bin'),
    bytes = Buffer.alloc(3 * 1024 * 1024, 0x61);
  fs.writeFileSync(source, bytes, { mode: 0o600 });
  const digest = sha256(bytes);
  assert.throws(() => copyPrivate(source, destination, 'f'.repeat(64)), { code: 'CUSTODY_DIGEST_MISMATCH' });
  assert.equal(fs.readdirSync(dirname(destination)).includes(basename(destination)), false);
  // The same call, now with the right digest, succeeds; repeating it is a no-op.
  assert.deepEqual(copyPrivate(source, destination, digest), { sha256: digest, bytes: bytes.length });
  assert.deepEqual(copyPrivate(source, destination, digest), { sha256: digest, bytes: bytes.length });
  assert.deepEqual(fs.readFileSync(destination), bytes);
  // Any other existing destination is refused with a code and left untouched.
  fs.writeFileSync(destination, 'different', { mode: 0o600 });
  for (const expected of [digest, undefined]) {
    const error = thrown(() => copyPrivate(source, destination, expected));
    assert.equal(error instanceof ExecutorError, true);
    assert.equal(error.code, 'CUSTODY_FILE_EXISTS');
  }
  assert.equal(fs.readFileSync(destination, 'utf8'), 'different');
  // A write failure part-way through also leaves nothing behind.
  const second = join(root, 'to', 'second.bin');
  const failure = withFs(
    'writeSync',
    original =>
      function (fd, buffer, offset, length, ...rest) {
        if (length > 16) {
          original.call(this, fd, buffer, offset, 16, ...rest);
          throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
        }
        return original.call(this, fd, buffer, offset, length, ...rest);
      },
    () => thrown(() => copyPrivate(source, second, digest)),
  );
  assert.equal(failure.code, 'CUSTODY_FILE_UNAVAILABLE');
  assert.equal(failure.cause.code, 'ENOSPC');
  assert.equal(fs.existsSync(second), false);
  const absent = thrown(() => copyPrivate(join(root, 'from', 'absent.bin')));
  assert.equal(absent.code, 'CUSTODY_FILE_UNAVAILABLE');
  assert.equal(absent.detail, 'FILE_MISSING');
});

test('a failed repair leaves no staged ciphertext copy and the retry succeeds', t => {
  const f = recoveryFixture(t);
  const data = join(f.root, 'data');
  fs.writeFileSync(f.options.stores[0].database, 'damaged primary', { mode: 0o600 });
  const preview = manageLedgerRecovery(f.options, { operation: 'repair' });
  const failure = withFs(
    'linkSync',
    () => () => {
      throw Object.assign(new Error('injected publication failure'), { code: 'EIO' });
    },
    () => thrown(() => manageLedgerRecovery(f.options, { operation: 'repair' }, { expectedDigest: preview.digest })),
  );
  assert.equal(failure.code, 'KEYRING_MAINTENANCE_FAILED');
  assert.equal(failure.cause.code, 'EIO');
  assert.deepEqual(
    fs.readdirSync(data).filter(name => name.startsWith('.guard-repair-')),
    [],
  );
  // The damaged original was preserved, and the same operation now completes.
  assert.equal(fs.readdirSync(data).filter(name => name.startsWith('.guard-original-')).length, 1);
  assert.equal(f.apply('repair').applied, true);
  for (const source of f.options.stores) {
    const store = new LedgerStore(
      source.database,
      f.key,
      64 * 1024 * 1024,
      { path: source.witnessPath, mode: 'resume' },
      { existingOnly: true },
    );
    assert.equal(store.read().recoveryMirror, 1);
    store.close();
  }
  assert.deepEqual(
    fs.readdirSync(data).filter(name => name.startsWith('.guard-repair-')),
    [],
  );
});

test('a backup that fails verification is never published, and the next backup works', t => {
  const { options, apply, failing } = custodyFixture(t, { history: true });
  apply({ operation: 'enroll' });
  failing.copy = true;
  const preview = manageLedgerCustody(options, { operation: 'backup' });
  failing.copy = true;
  const failure = thrown(() =>
    manageLedgerCustody(options, { operation: 'backup' }, { expectedDigest: preview.digest }),
  );
  assert.equal(failure.code, 'KEYRING_MAINTENANCE_FAILED');
  assert.equal(failure.cause.message, 'injected history failure');
  // No staging directory and no unregistered backup directory remain.
  assert.deepEqual(fs.readdirSync(options.backupDirectory), []);
  failing.copy = false;
  assert.equal(manageLedgerCustody(options, { operation: 'status' }).backupCount, 0);
  const backup = apply({ operation: 'backup' });
  assert.deepEqual(fs.readdirSync(options.backupDirectory), [backup.backupId]);
  assert.equal(manageLedgerCustody(options, { operation: 'verify', backupId: backup.backupId }).backupCount, 1);
});

test('a backup whose catalog record fails to commit is removed again', t => {
  const { options, apply } = custodyFixture(t);
  apply({ operation: 'enroll' });
  const preview = manageLedgerCustody(options, { operation: 'backup' });
  // The backup is complete and published; then the catalog refuses its record.
  const original = LedgerStore.prototype.transaction;
  let calls = 0;
  LedgerStore.prototype.transaction = function (operation) {
    return original.call(this, (ledger, archives) =>
      operation(ledger, {
        ...archives,
        putCustodyRecord(id, ciphertext) {
          if (++calls === 1) throw new ExecutorError('STORE_CUSTODY_CAPACITY');
          return archives.putCustodyRecord(id, ciphertext);
        },
      }),
    );
  };
  try {
    assert.throws(() => manageLedgerCustody(options, { operation: 'backup' }, { expectedDigest: preview.digest }), {
      code: 'STORE_CUSTODY_CAPACITY',
    });
  } finally {
    LedgerStore.prototype.transaction = original;
  }
  assert.deepEqual(fs.readdirSync(options.backupDirectory), []);
  assert.equal(apply({ operation: 'backup' }).backupCount, 1);
});

// Item 14 -----------------------------------------------------------------------------------

test('one private-file module gives every caller the same refusals', t => {
  const root = directories(t, 'guard-release-private-', ['private', 'shared']);
  const refuse = problem => {
    throw new ExecutorError('REFUSED', { detail: problem });
  };
  const detail = operation => thrown(operation).detail;
  fs.chmodSync(join(root, 'shared'), 0o755);
  assert.equal(
    detail(() => privateDirectory(join(root, 'shared'), refuse)),
    'DIRECTORY_UNSAFE',
  );
  assert.equal(
    detail(() => privateDirectory(join(root, 'absent'), refuse)),
    'DIRECTORY_MISSING',
  );
  fs.symlinkSync(join(root, 'private'), join(root, 'alias'));
  assert.equal(
    detail(() => privateDirectory(join(root, 'alias'), refuse)),
    'DIRECTORY_UNSAFE',
  );
  assert.equal(
    detail(() => trustedDirectoryChain(join(root, 'alias'), refuse)),
    'DIRECTORY_UNSAFE',
  );
  privateDirectory(join(root, 'private'), refuse);
  const chain = trustedDirectoryChain(join(root, 'private'), refuse);
  assert.equal(chain[0], `${fs.statSync(join(root, 'private')).dev}:${fs.statSync(join(root, 'private')).ino}`);
  fs.chmodSync(join(root, 'shared'), 0o777);
  assert.equal(
    detail(() => trustedDirectoryChain(join(root, 'shared', 'child'), refuse)),
    'DIRECTORY_MISSING',
  );
  fs.mkdirSync(join(root, 'shared', 'child'), { mode: 0o700 });
  assert.equal(
    detail(() => trustedDirectoryChain(join(root, 'shared', 'child'), refuse)),
    'DIRECTORY_UNSAFE',
  );

  const rule = { ...PRIVATE_FILE, maximum: 8 };
  const file = join(root, 'private', 'file');
  fs.writeFileSync(file, '12345678', { mode: 0o600 });
  assert.equal(readPrivateFile(file, rule, refuse).toString(), '12345678');
  assert.equal(
    detail(() => readPrivateFile(join(root, 'private', 'absent'), rule, refuse)),
    'FILE_MISSING',
  );
  fs.writeFileSync(file, '123456789');
  assert.equal(
    detail(() => readPrivateFile(file, rule, refuse)),
    'FILE_TOO_LARGE',
  );
  fs.writeFileSync(file, '1234');
  fs.chmodSync(file, 0o640);
  assert.equal(
    detail(() => readPrivateFile(file, rule, refuse)),
    'FILE_UNSAFE',
  );
  fs.chmodSync(file, 0o600);
  fs.linkSync(file, join(root, 'private', 'second-name'));
  assert.equal(
    detail(() => readPrivateFile(file, rule, refuse)),
    'FILE_UNSAFE',
  );
  fs.symlinkSync(file, join(root, 'private', 'link'));
  assert.equal(
    detail(() => readPrivateFile(join(root, 'private', 'link'), rule, refuse)),
    'FILE_UNREADABLE',
  );

  // The same reasons reach each caller under its own code.
  const key = Buffer.alloc(32, 1);
  const store = thrown(() => new LedgerStore(join(root, 'absent', 'ledger.sqlite'), key));
  assert.equal(store instanceof ExecutorError, true);
  assert.equal(store.code, 'STORE_DIRECTORY_UNSAFE');
  assert.equal(store.detail, 'DIRECTORY_MISSING');
  const unsafeStore = thrown(() => new LedgerStore(join(root, 'shared', 'ledger.sqlite'), key));
  assert.equal(unsafeStore.code, 'STORE_DIRECTORY_UNSAFE');
  assert.equal(unsafeStore.detail, 'DIRECTORY_UNSAFE');
  const custody = thrown(() => privateBytes(join(root, 'private', 'absent'), 16));
  assert.equal(custody.code, 'CUSTODY_FILE_UNAVAILABLE');
  assert.equal(custody.detail, 'FILE_MISSING');
  assert.equal(thrown(() => privateBytes(join(root, 'absent', 'file'), 16)).code, 'CUSTODY_PATH_UNAVAILABLE');
  assert.equal(thrown(() => privateBytes(join(root, 'shared', 'file'), 16)).code, 'CUSTODY_PATH_UNSAFE');
  const manifest = thrown(() => loadInventoryManifestFile(join(root, 'private', 'absent')));
  assert.equal(manifest.code, 'INVENTORY_MANIFEST_FILE_INVALID');
  assert.equal(manifest.detail, 'FILE_MISSING');
  assert.equal(thrown(() => loadInventoryManifestFile(file)).detail, 'FILE_UNSAFE');
});

test('ownership is checked against the effective user in every caller', t => {
  const root = directories(t, 'guard-release-euid-', ['private']);
  const file = join(root, 'private', 'file');
  fs.writeFileSync(file, '{}', { mode: 0o600 });
  const refuse = problem => {
    throw new ExecutorError('REFUSED', { detail: problem });
  };
  const real = process.geteuid;
  // A process whose effective user differs from the file owner must be refused, whatever
  // its real user is.
  process.geteuid = () => real() + 1;
  try {
    assert.equal(thrown(() => readPrivateFile(file, { ...PRIVATE_FILE, maximum: 16 }, refuse)).detail, 'FILE_UNSAFE');
    assert.equal(thrown(() => privateDirectory(join(root, 'private'), refuse)).detail, 'DIRECTORY_UNSAFE');
    assert.equal(thrown(() => loadInventoryManifestFile(file)).detail, 'FILE_UNSAFE');
    assert.equal(
      thrown(() => new LedgerStore(join(root, 'private', 'ledger.sqlite'), Buffer.alloc(32, 1))).code,
      'STORE_DIRECTORY_UNSAFE',
    );
    assert.equal(thrown(() => privateBytes(file, 16)).code, 'CUSTODY_PATH_UNSAFE');
  } finally {
    process.geteuid = real;
  }
  assert.equal(fs.existsSync(join(root, 'private', 'ledger.sqlite')), false);
});

// Item 15 -----------------------------------------------------------------------------------

function ledger(args) {
  return spawnSync(process.execPath, [ledgerCli, ...args], { encoding: 'utf8', timeout: 20_000 });
}
/** Code alone on line one, the hint on line two, and no path anywhere on stderr. */
function assertCliFailure(child, code, hint, root) {
  assert.equal(child.status, 1, child.stderr);
  assert.equal(child.stdout, '');
  const lines = child.stderr.split('\n');
  assert.equal(lines[0], code);
  if (hint === undefined) assert.deepEqual(lines.slice(1), ['']);
  else {
    assert.match(lines[1], hint);
    assert.deepEqual(lines.slice(2), ['']);
  }
  assert.equal(child.stderr.includes(root), false);
  assert.equal(child.stderr.includes('/'), false);
}

test('agent-guard-ledger prints the code, then one plain hint for common mistakes', t => {
  const f = keyFixture(t);
  const keyring = f.options.keyringFile;
  assertCliFailure(ledger(['status']), 'MAINTENANCE_ARGUMENT_INVALID', /--help/, f.root);
  assertCliFailure(
    ledger(['status', '--keyring', keyring, '--nope']),
    'MAINTENANCE_ARGUMENT_INVALID',
    /--help/,
    f.root,
  );
  assertCliFailure(
    ledger(['status', '--keyring', join(f.root, 'keys', 'absent.json')]),
    'KEYRING_UNAVAILABLE',
    /^The keyring file does not exist\.$/,
    f.root,
  );
  assertCliFailure(
    ledger(['keygen', '--keyring', join(f.root, 'absent', 'ring.json'), '--key-id', 'k']),
    'KEYRING_UNAVAILABLE',
    /^The directory that should hold the keyring file does not exist\.$/,
    f.root,
  );
  assertCliFailure(
    ledger(['keygen', '--keyring', keyring, '--key-id', 'k']),
    'KEYRING_EXISTS',
    /never replaces/,
    f.root,
  );
  assertCliFailure(ledger(['status', '--keyring', 'relative.json']), 'MAINTENANCE_CONFIG_INVALID', /absolute/, f.root);
  fs.chmodSync(keyring, 0o644);
  assertCliFailure(ledger(['status', '--keyring', keyring]), 'KEYRING_FILE_UNSAFE', /mode 0600/, f.root);
  fs.chmodSync(keyring, 0o600);
  fs.chmodSync(join(f.root, 'keys'), 0o755);
  assertCliFailure(ledger(['status', '--keyring', keyring]), 'KEYRING_PATH_UNSAFE', /mode 0700/, f.root);
  fs.chmodSync(join(f.root, 'keys'), 0o700);
  const database = ['--database', f.options.database, '--witness', f.options.witnessPath];
  const owner = f.open();
  try {
    assertCliFailure(
      ledger(['status', '--keyring', keyring, ...database]),
      'LEDGER_KEY_UNAVAILABLE',
      /still owned by a running process/,
      f.root,
    );
    assertCliFailure(
      ledger(['rotate', '--keyring', keyring, ...database, '--next-key-id', 'next']),
      'LEDGER_KEY_UNAVAILABLE',
      /Stop every ledger owner/,
      f.root,
    );
  } finally {
    owner.close();
  }
  assertCliFailure(
    ledger(['status', '--keyring', keyring, '--database', join(f.root, 'data', 'absent.sqlite')]),
    'LEDGER_KEY_UNAVAILABLE',
    /^The ledger file does not exist\.$/,
    f.root,
  );
  assertCliFailure(
    ledger(['status', '--keyring', keyring, ...database, '--max-bytes', '5']),
    'STORE_CONFIG_INVALID',
    /1048576/,
    f.root,
  );
  const ok = ledger(['status', '--keyring', keyring, ...database]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stderr, '');
  assert.deepEqual(JSON.parse(ok.stdout), { operation: 'status', keyId: 'initial', keyCount: 1, maxKeys: 4 });
});

test('custody and recovery commands name a missing, unsafe or malformed config', t => {
  const { root, options } = custodyFixture(t);
  const config = join(root, 'offline', 'custody.json');
  for (const command of [
    ['custody', 'status'],
    ['recovery', 'enroll'],
  ]) {
    assertCliFailure(
      ledger([...command, '--config', config]),
      'MAINTENANCE_CONFIG_UNREADABLE',
      /^The config file does not exist\.$/,
      root,
    );
    assertCliFailure(ledger([...command]), 'MAINTENANCE_ARGUMENT_INVALID', /--help/, root);
    assertCliFailure(
      ledger([...command, '--config', config, '--digest', 'a'.repeat(64)]),
      'MAINTENANCE_ARGUMENT_INVALID',
      /--help/,
      root,
    );
  }
  fs.writeFileSync(config, JSON.stringify({ version: 1, ...options }), { mode: 0o644 });
  assertCliFailure(
    ledger(['custody', 'status', '--config', config]),
    'MAINTENANCE_CONFIG_UNREADABLE',
    /^The config file must be an ordinary file that you own, with mode 0600/,
    root,
  );
  fs.chmodSync(config, 0o600);
  assertCliFailure(ledger(['custody', 'status', '--config', config]), 'CUSTODY_NOT_ENROLLED', /custody enroll/, root);
  assertCliFailure(ledger(['custody', 'explode', '--config', config]), 'CUSTODY_REQUEST_INVALID', /--help/, root);
  fs.writeFileSync(config, '{"version":1,"secret":"sk-canary",');
  for (const [command, code] of [
    [['custody', 'status'], 'CUSTODY_CONFIG_INVALID'],
    [['recovery', 'enroll'], 'RECOVERY_CONFIG_INVALID'],
  ]) {
    const child = ledger([...command, '--config', config]);
    assertCliFailure(child, code, /documented/, root);
    assert.equal(child.stderr.includes('canary'), false);
  }
  fs.writeFileSync(config, JSON.stringify({ version: 1, ...options, stores: [{ ...options.stores[0], extra: 1 }] }));
  assertCliFailure(ledger(['custody', 'status', '--config', config]), 'CUSTODY_CONFIG_INVALID', /documented/, root);
  fs.writeFileSync(config, JSON.stringify({ version: 1, keyringFile: options.keyringFile, stores: 'none' }));
  assertCliFailure(ledger(['recovery', 'enroll', '--config', config]), 'RECOVERY_CONFIG_INVALID', /documented/, root);
});

test('hints are built from codes and details only', () => {
  assert.equal(maintenanceHint('MAINTENANCE_FAILED'), undefined);
  assert.equal(maintenanceHint('CUSTODY_BACKUP_INVALID'), undefined);
  assert.equal(maintenanceHint('KEYRING_UNAVAILABLE', '/etc/secret'), undefined);
  assert.equal(maintenanceHint('KEYRING_MAINTENANCE_FAILED', 'ENOSPC'), 'The disk is full.');
  assert.match(maintenanceHint('CUSTODY_STORE_UNAVAILABLE', 'LOCKED'), /still owned/);
  assert.match(maintenanceHint('RECOVERY_STORE_UNAVAILABLE', 'FILE_MISSING'), /^The ledger file does not exist/);
  assert.match(maintenanceHint('KEYRING_BUSY'), /Another maintenance command/);
});

test('a failed pilot verification says which check failed and keeps its message', () => {
  const verify = (f, mode = 'rehearsal') => thrown(() => verifyPilotReview(f.policy, f.candidateBytes, f.bundle, mode));
  const expect = (error, check) => {
    assert.equal(error instanceof ExecutorError, true);
    assert.equal(error.code, 'PILOT_REVIEW_INVALID');
    assert.equal(error.detail, check);
    assert.equal(error.message, 'Pilot review verification failed');
    assert.equal(error.cause, undefined);
  };
  const base = createPilotReviewFixture();
  assert.equal(verifyPilotReview(base.policy, base.candidateBytes, base.bundle, 'rehearsal').status, 'verified');
  expect(verify(base, 'company-pilot'), 'MODE');
  expect(verify({ ...base, policy: { ...base.policy, surprise: 1 } }), 'POLICY');
  expect(verify({ ...base, policy: null }), 'POLICY');
  expect(verify({ ...base, candidateBytes: 'fixture' }), 'CANDIDATE');
  expect(verify({ ...base, bundle: { ...base.bundle, version: 2 } }), 'BUNDLE');
  expect(verify({ ...base, bundle: { ...base.bundle, boundary: Buffer.from('{}').toString('base64') } }), 'BOUNDARY');
  expect(verify({ ...base, candidateBytes: Buffer.from('another build') }), 'BUILD_ATTESTATION');
  expect(verify({ ...base, bundle: { ...base.bundle, observations: base.bundle.review } }), 'OBSERVATIONS');
  expect(verify({ ...base, bundle: { ...base.bundle, review: base.bundle.observations } }), 'REVIEW');
  for (const [name, check] of [
    ['access', 'ACCESS_EVIDENCE'],
    ['recovery', 'RECOVERY_EVIDENCE'],
    ['load', 'LOAD_EVIDENCE'],
  ])
    expect(
      verify({
        ...base,
        bundle: { ...base.bundle, evidence: { ...base.bundle.evidence, [name]: Buffer.from('{}').toString('base64') } },
      }),
      check,
    );
  const now = Date.now;
  Date.now = () => base.policy.expiresAt + 1;
  try {
    expect(verify(base), 'VALIDITY_WINDOW');
  } finally {
    Date.now = now;
  }
});
