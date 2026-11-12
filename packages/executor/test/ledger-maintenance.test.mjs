import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DurableExecutor } from '../dist/index.js';
import {
  createLedgerKeyring,
  readLedgerKeyring,
  loadLedgerKey,
  rotateLedgerKey,
  rotateLedgerKeyring,
  readLedgerKeyringPolicy,
  configureLedgerKeyring,
} from '../dist/entry-ops.js';
import { LedgerStore } from '../dist/store.js';
import { fileURLToPath } from 'node:url';

const posix = { skip: process.platform === 'win32' };
function fixture(t, witnessed = true) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'guard-key-rotation-')));
  for (const name of ['data', 'control', 'keys']) fs.mkdirSync(join(root, name), { mode: 0o700 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const keyringFile = join(root, 'keys', 'keyring.json'),
    database = join(root, 'data', 'ledger.sqlite');
  const witnessPath = witnessed ? join(root, 'control', 'witness.sqlite') : undefined;
  const options = { database, keyringFile, ...(witnessPath ? { witnessPath } : {}) };
  createLedgerKeyring({ keyringFile, keyId: 'initial' });
  const initial = readLedgerKeyring({ keyringFile })[0];
  t.after(() => initial.key.fill(0));
  const open = (key = initial.key, create = false) =>
    new LedgerStore(
      database,
      key,
      undefined,
      witnessPath ? { path: witnessPath, mode: create ? 'create' : 'resume' } : undefined,
      create ? {} : { existingOnly: true },
    );
  open(initial.key, true).close();
  return { root, options, initial, open };
}
function state(f, key = f.initial.key) {
  const store = f.open(key);
  try {
    return store.read();
  } finally {
    store.close();
  }
}
function selected(f) {
  const result = loadLedgerKey(f.options);
  try {
    return result.keyId;
  } finally {
    result.key.fill(0);
  }
}

for (const witnessed of [false, true])
  test(`offline rekey preserves all authority and retry semantics (witness ${witnessed})`, posix, async t => {
    const f = fixture(t, witnessed);
    const e = new DurableExecutor({
      database: f.options.database,
      encryptionKey: f.initial.key,
      clock: () => 1000,
      ...(f.options.witnessPath ? { rollbackWitness: { path: f.options.witnessPath, mode: 'resume' } } : {}),
    });
    let credential, uncertain;
    try {
      e.approveTool(
        'write',
        e.registerTool({
          name: 'write',
          description: 'fixture',
          maxCost: 2,
          resolve: () => ({ tenantId: 'tenant', resourceId: 'item' }),
          execute: () => ({ value: 'done', actualCost: 1 }),
        }),
      );
      credential = e.createTask({
        id: 'spent',
        tenantId: 'tenant',
        principalId: 'host',
        grants: [{ tool: 'write', resources: ['item'] }],
        budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 3, deadline: 2000 },
      });
      const action = await e.prepare('spent', { tool: 'write', args: null });
      await e.execute('spent', action.id);
      e.revokeTask('spent');
      e.approveTool(
        'uncertain',
        e.registerTool({
          name: 'uncertain',
          description: 'fixture',
          maxCost: 2,
          resolve: () => ({ tenantId: 'tenant', resourceId: 'item' }),
          execute() {
            throw Error('lost receipt');
          },
        }),
      );
      e.createTask({
        id: 'pending',
        tenantId: 'tenant',
        principalId: 'host',
        grants: [{ tool: 'uncertain', resources: ['item'] }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 2, deadline: 2000 },
      });
      uncertain = await e.prepare('pending', { tool: 'uncertain', args: null });
      await assert.rejects(e.execute('pending', uncertain.id), { code: 'TOOL_FAILED' });
    } finally {
      e.close();
    }
    const before = state(f),
      preservedKey = Buffer.from(f.initial.key);
    const result = rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' });
    assert.equal(result.status, 'rotated');
    assert.equal(result.revision, before.revision);
    assert.deepEqual(f.initial.key, preservedKey);
    preservedKey.fill(0);
    assert.throws(
      () => f.open(),
      error => ['STORE_UNAVAILABLE', 'STORE_WITNESS_UNAVAILABLE'].includes(error.code),
    );
    const loaded = loadLedgerKey(f.options);
    try {
      assert.equal(loaded.keyId, 'next');
      assert.deepEqual(state(f, loaded.key), before);
      assert.equal(rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }).status, 'already-rotated');
      assert.equal(
        rotateLedgerKey({
          database: f.options.database,
          currentKey: f.initial.key,
          nextKey: loaded.key,
          ...(f.options.witnessPath ? { witnessPath: f.options.witnessPath } : {}),
        }).status,
        'already-rotated',
      );
      const resumed = new DurableExecutor({
        database: f.options.database,
        encryptionKey: loaded.key,
        clock: () => 1000,
        ...(f.options.witnessPath ? { rollbackWitness: { path: f.options.witnessPath, mode: 'resume' } } : {}),
      });
      try {
        assert.throws(() => resumed.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
        assert.equal(resumed.snapshot('spent').spent, 1);
        assert.equal(resumed.snapshot('pending').reserved, 2);
        assert.equal(resumed.execution('pending', uncertain.id).status, 'UNKNOWN');
        await assert.rejects(resumed.execute('pending', uncertain.id), { code: 'ACTION_USED' });
      } finally {
        resumed.close();
      }
    } finally {
      loaded.key.fill(0);
    }
  });

test('a failed witness update retains old state and both staged keys for a retry', posix, t => {
  const f = fixture(t),
    before = state(f);
  const original = DatabaseSync.prototype.prepare;
  DatabaseSync.prototype.prepare = function (sql, ...args) {
    const statement = Reflect.apply(original, this, [sql, ...args]);
    if (sql === 'UPDATE main.commitment SET digest=? WHERE id=1')
      statement.run = () => {
        throw Error('disk write failure');
      };
    return statement;
  };
  try {
    assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }), { code: 'STORE_ROTATION_FAILED' });
  } finally {
    DatabaseSync.prototype.prepare = original;
  }
  assert.deepEqual(state(f), before);
  assert.equal(selected(f), 'initial');
  const ring = readLedgerKeyring(f.options);
  try {
    assert.deepEqual(
      ring.map(k => k.keyId),
      ['initial', 'next'],
    );
  } finally {
    ring.forEach(k => k.key.fill(0));
  }
  assert.equal(rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }).status, 'rotated');
});

test('failed key publication cannot change ledger authority or destroy the original keyring', posix, t => {
  const f = fixture(t),
    before = state(f),
    originalBytes = fs.readFileSync(f.options.keyringFile);
  const original = fs.renameSync;
  fs.renameSync = () => {
    throw Error('key filesystem unavailable');
  };
  syncBuiltinESMExports();
  try {
    assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }), {
      code: 'KEYRING_MAINTENANCE_FAILED',
    });
  } finally {
    fs.renameSync = original;
    syncBuiltinESMExports();
  }
  assert.deepEqual(fs.readFileSync(f.options.keyringFile), originalBytes);
  originalBytes.fill(0);
  assert.deepEqual(state(f), before);
  assert.equal(selected(f), 'initial');
});

for (const phase of ['key-staged', 'before-commit', 'after-commit'])
  test(`process loss at ${phase} retains a discoverable key and matching witness`, posix, t => {
    const f = fixture(t),
      before = state(f);
    const entry = new URL('../dist/entry-ops.js', import.meta.url).href;
    const script = `import fs from 'node:fs'; import {syncBuiltinESMExports} from 'node:module';
    import {DatabaseSync} from 'node:sqlite'; import {rotateLedgerKeyring} from ${JSON.stringify(entry)};
    const [database,keyringFile,witnessPath,phase]=process.argv.slice(1);
    const sync=fs.fsyncSync, prepare=DatabaseSync.prototype.prepare, exec=DatabaseSync.prototype.exec; let rotating=false;
    fs.fsyncSync=function(fd){sync(fd); if(phase==='key-staged' && fs.fstatSync(fd).isDirectory())process.kill(process.pid,'SIGKILL')};
    syncBuiltinESMExports();
    DatabaseSync.prototype.prepare=function(sql,...args){if(sql==='UPDATE authority.ledger SET payload=? WHERE id=1')rotating=true;return prepare.call(this,sql,...args)};
    DatabaseSync.prototype.exec=function(sql){if(rotating&&sql==='COMMIT'&&phase==='before-commit')process.kill(process.pid,'SIGKILL');
      const value=exec.call(this,sql);if(rotating&&sql==='COMMIT'&&phase==='after-commit')process.kill(process.pid,'SIGKILL');return value};
    rotateLedgerKeyring({database,keyringFile,witnessPath,nextKeyId:'next'});`;
    const child = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', script, f.options.database, f.options.keyringFile, f.options.witnessPath, phase],
      { encoding: 'utf8', timeout: 10_000 },
    );
    assert.equal(child.signal, 'SIGKILL', child.stderr);
    const current = loadLedgerKey(f.options);
    try {
      assert.equal(current.keyId, phase === 'after-commit' ? 'next' : 'initial');
      assert.deepEqual(state(f, current.key), before);
    } finally {
      current.key.fill(0);
    }
    assert.equal(
      rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }).status,
      phase === 'after-commit' ? 'already-rotated' : 'rotated',
    );
    assert.equal(selected(f), 'next');
  });

test('two separately witnessed stores can complete one shared keyring rotation after partial progress', posix, t => {
  const f = fixture(t),
    database = join(f.root, 'data', 'backend.sqlite'),
    witnessPath = join(f.root, 'control', 'backend-witness.sqlite');
  new LedgerStore(database, f.initial.key, undefined, { path: witnessPath, mode: 'create' }).close();
  const backend = { database, witnessPath, keyringFile: f.options.keyringFile };
  rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' });
  const older = loadLedgerKey(backend);
  try {
    assert.equal(older.keyId, 'initial');
  } finally {
    older.key.fill(0);
  }
  rotateLedgerKeyring({ ...backend, nextKeyId: 'next' });
  const newer = loadLedgerKey(backend);
  try {
    assert.equal(newer.keyId, 'next');
  } finally {
    newer.key.fill(0);
  }
  assert.equal(selected(f), 'next');
});

test('maintenance rejects missing authority, live owners, unsafe key files and duplicate key enrollment', posix, t => {
  const f = fixture(t),
    keyringBytes = fs.readFileSync(f.options.keyringFile);
  assert.throws(() => createLedgerKeyring({ keyringFile: f.options.keyringFile, keyId: 'replacement' }), {
    code: 'KEYRING_EXISTS',
  });
  assert.deepEqual(fs.readFileSync(f.options.keyringFile), keyringBytes);
  keyringBytes.fill(0);
  const missing = join(f.root, 'data', 'absent.sqlite');
  assert.throws(() => loadLedgerKey({ ...f.options, database: missing }), { code: 'LEDGER_KEY_UNAVAILABLE' });
  assert.equal(fs.existsSync(missing), false);
  const owner = f.open();
  try {
    assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }), { code: 'LEDGER_KEY_UNAVAILABLE' });
  } finally {
    owner.close();
  }
  fs.chmodSync(f.options.keyringFile, 0o644);
  assert.throws(() => loadLedgerKey(f.options), { code: 'KEYRING_FILE_UNSAFE' });
  fs.chmodSync(f.options.keyringFile, 0o600);
  const link = join(f.root, 'keys', 'alias');
  fs.symlinkSync(f.options.keyringFile, link);
  assert.throws(() => readLedgerKeyring({ keyringFile: link }), { code: 'KEYRING_UNAVAILABLE' });
  assert.equal(selected(f), 'initial');
});

test('offline CLI returns redacted JSON and refuses ordinary missing-store initialization', posix, t => {
  const f = fixture(t),
    cli = new URL('../dist/ledger-maintenance-cli.js', import.meta.url);
  const run = (...args) => spawnSync(process.execPath, [fileURLToPath(cli), ...args], { encoding: 'utf8' });
  const args = [
    '--keyring',
    f.options.keyringFile,
    '--database',
    f.options.database,
    '--witness',
    f.options.witnessPath,
  ];
  const rotated = run('rotate', ...args, '--next-key-id', 'next');
  assert.equal(rotated.status, 0, rotated.stderr);
  assert.equal(JSON.parse(rotated.stdout).keyId, 'next');
  assert.equal(rotated.stdout.includes('keyBase64'), false);
  assert.equal(run('status', ...args).status, 0);
  const missing = run('status', '--keyring', f.options.keyringFile, '--database', join(f.root, 'data', 'absent'));
  assert.equal(missing.status, 1);
  assert.equal(missing.stdout, '');
  assert.equal(missing.stderr.includes(f.root), false);
});

test('archive blob and catalog writes roll back together and survive rekey unchanged', posix, t => {
  const f = fixture(t),
    store = f.open();
  let access;
  try {
    const before = store.read();
    assert.throws(
      () =>
        store.transaction((ledger, archives) => {
          archives.putArchive('cancelled', 'encrypted-archive-fixture');
          ledger.archiveFixture = 'cancelled';
          throw Error('cancel transaction');
        }),
      /cancel transaction/,
    );
    assert.deepEqual(store.read(), before);
    assert.throws(() => store.readArchive('cancelled'), { code: 'STORE_ARCHIVE_UNAVAILABLE' });
    store.transaction((ledger, archives) => {
      archives.putArchive('retained', 'encrypted-archive-fixture');
      ledger.archiveFixture = { id: 'retained', key: 'fixture-only' };
      access = archives;
    });
    assert.throws(() => access.putArchive('late', 'late-write'), { code: 'STORE_ARCHIVE_INVALID' });
    assert.throws(() => store.transaction((_ledger, archives) => archives.putArchive('retained', 'overwrite')), {
      code: 'STORE_ARCHIVE_INVALID',
    });
    assert.equal(store.readArchive('retained'), 'encrypted-archive-fixture');
  } finally {
    store.close();
  }
  const before = state(f);
  rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' });
  const loaded = loadLedgerKey(f.options),
    reopened = f.open(loaded.key);
  try {
    assert.deepEqual(reopened.read(), before);
    assert.equal(reopened.readArchive('retained'), 'encrypted-archive-fixture');
  } finally {
    reopened.close();
    loaded.key.fill(0);
  }
});

test('a post-commit error is recoverable with the staged key and never resets state', posix, t => {
  const f = fixture(t),
    before = state(f),
    prepare = DatabaseSync.prototype.prepare,
    exec = DatabaseSync.prototype.exec;
  let rotating = false,
    injected = false;
  DatabaseSync.prototype.prepare = function (sql, ...args) {
    if (sql === 'UPDATE authority.ledger SET payload=? WHERE id=1') rotating = true;
    return Reflect.apply(prepare, this, [sql, ...args]);
  };
  DatabaseSync.prototype.exec = function (sql) {
    const result = Reflect.apply(exec, this, [sql]);
    if (rotating && sql === 'COMMIT' && !injected) {
      injected = true;
      throw Error('post-commit I/O report');
    }
    return result;
  };
  try {
    assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }), { code: 'STORE_ROTATION_UNCERTAIN' });
  } finally {
    DatabaseSync.prototype.prepare = prepare;
    DatabaseSync.prototype.exec = exec;
  }
  const loaded = loadLedgerKey(f.options);
  try {
    assert.equal(loaded.keyId, 'next');
    assert.deepEqual(state(f, loaded.key), before);
  } finally {
    loaded.key.fill(0);
  }
  assert.equal(rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }).status, 'already-rotated');
});

test('legacy capacity changes preserve every key and ledger and do not change other keyrings', posix, t => {
  const f = fixture(t),
    independent = fixture(t),
    before = state(f);
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 1, maxKeys: 4 });
  assert.equal(Object.hasOwn(JSON.parse(fs.readFileSync(f.options.keyringFile)), 'maxKeys'), false);
  for (const nextKeyId of ['second', 'third', 'fourth']) rotateLedgerKeyring({ ...f.options, nextKeyId });
  assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'fifth' }), { code: 'KEYRING_CAPACITY' });
  const originalKeys = JSON.parse(fs.readFileSync(f.options.keyringFile)).keys;
  assert.deepEqual(configureLedgerKeyring({ ...f.options, maxKeys: 8 }), { keyCount: 4, maxKeys: 8 });
  assert.deepEqual(JSON.parse(fs.readFileSync(f.options.keyringFile)).keys, originalKeys);
  rotateLedgerKeyring({ ...f.options, nextKeyId: 'fifth' });
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 5, maxKeys: 8 });
  const bytes = fs.readFileSync(f.options.keyringFile);
  try {
    assert.throws(() => configureLedgerKeyring({ ...f.options, maxKeys: 4 }), { code: 'KEYRING_LIMIT_INVALID' });
    assert.deepEqual(fs.readFileSync(f.options.keyringFile), bytes);
  } finally {
    bytes.fill(0);
  }
  assert.deepEqual(configureLedgerKeyring({ ...f.options, maxKeys: 5 }), { keyCount: 5, maxKeys: 5 });
  assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'sixth' }), { code: 'KEYRING_CAPACITY' });
  assert.deepEqual(readLedgerKeyringPolicy(independent.options), { keyCount: 1, maxKeys: 4 });
  const selectedKey = loadLedgerKey(f.options);
  try {
    assert.deepEqual(state(f, selectedKey.key), before);
  } finally {
    selectedKey.key.fill(0);
  }
});

test('keyring limits reject invalid values, duplicate fields and count mismatches without deleting keys', posix, t => {
  const f = fixture(t),
    original = fs.readFileSync(f.options.keyringFile);
  try {
    for (const maxKeys of [0, -1, 1.5, 65, NaN, Infinity, '8', null]) {
      assert.throws(() => configureLedgerKeyring({ ...f.options, maxKeys }), { code: 'KEYRING_LIMIT_INVALID' });
      assert.deepEqual(fs.readFileSync(f.options.keyringFile), original);
      const fresh = join(f.root, 'keys', 'absent.json');
      assert.throws(() => createLedgerKeyring({ keyringFile: fresh, keyId: 'invalid', maxKeys }), {
        code: 'KEYRING_LIMIT_INVALID',
      });
      assert.equal(fs.existsSync(fresh), false);
    }
    const value = JSON.parse(original);
    // A stored limit outside 1..64 keeps its own code; other damage is KEYRING_INVALID.
    const malformed = [
      [original.toString().replace('"version":1,', '"version":1,"maxKeys":4,"maxKeys":8,'), 'KEYRING_INVALID'],
      ...[0, 1.5, 65, '8', null].map(maxKeys => [JSON.stringify({ ...value, maxKeys }), 'KEYRING_LIMIT_INVALID']),
      [
        JSON.stringify({
          ...value,
          maxKeys: 1,
          keys: [...value.keys, { id: 'extra', keyBase64: randomBytes(32).toString('base64') }],
        }),
        'KEYRING_INVALID',
      ],
    ];
    for (const [text, code] of malformed) {
      fs.writeFileSync(f.options.keyringFile, text);
      assert.throws(() => readLedgerKeyringPolicy(f.options), { code });
      assert.throws(() => configureLedgerKeyring({ ...f.options, maxKeys: 64 }), { code });
      assert.equal(fs.readFileSync(f.options.keyringFile, 'utf8'), text);
    }
  } finally {
    fs.writeFileSync(f.options.keyringFile, original);
    original.fill(0);
  }
  assert.equal(selected(f), 'initial');
});

test('explicit 64-key policy accepts bounded full-size rings and never enrolls a 65th key', posix, t => {
  const f = fixture(t),
    file = join(f.root, 'keys', 'large.json');
  createLedgerKeyring({ keyringFile: file, keyId: 'first', maxKeys: 64 });
  assert.deepEqual(readLedgerKeyringPolicy({ keyringFile: file }), { keyCount: 1, maxKeys: 64 });
  const value = JSON.parse(fs.readFileSync(f.options.keyringFile));
  value.maxKeys = 64;
  for (let index = 1; index < 64; index++)
    value.keys.push({ id: String(index).padEnd(128, 'x'), keyBase64: randomBytes(32).toString('base64') });
  fs.writeFileSync(f.options.keyringFile, JSON.stringify(value));
  assert.ok(fs.statSync(f.options.keyringFile).size > 4096);
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 64, maxKeys: 64 });
  const all = readLedgerKeyring(f.options);
  try {
    assert.equal(all.length, 64);
  } finally {
    all.forEach(entry => entry.key.fill(0));
  }
  assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'overflow' }), { code: 'KEYRING_CAPACITY' });
  assert.equal(selected(f), 'initial');
});

test('failed atomic policy publication preserves the previous policy and keys', posix, t => {
  const f = fixture(t),
    original = fs.readFileSync(f.options.keyringFile),
    rename = fs.renameSync;
  fs.renameSync = () => {
    throw Error('injected rename failure');
  };
  syncBuiltinESMExports();
  try {
    assert.throws(() => configureLedgerKeyring({ ...f.options, maxKeys: 8 }), { code: 'KEYRING_MAINTENANCE_FAILED' });
  } finally {
    fs.renameSync = rename;
    syncBuiltinESMExports();
  }
  try {
    assert.deepEqual(fs.readFileSync(f.options.keyringFile), original);
  } finally {
    original.fill(0);
  }
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 1, maxKeys: 4 });
  assert.equal(selected(f), 'initial');
});

test('configured byte capacity reopens and rekeys a witnessed ledger above the default size', posix, t => {
  const f = fixture(t),
    maxBytes = 20 * 1024 * 1024;
  const large = new LedgerStore(
    f.options.database,
    f.initial.key,
    maxBytes,
    { path: f.options.witnessPath, mode: 'resume' },
    { existingOnly: true },
  );
  let revision;
  try {
    large.transaction(value => {
      value.largeFixture = 'x'.repeat(16 * 1024 * 1024 + 1024);
    });
    revision = large.read().revision;
  } finally {
    large.close();
  }
  assert.throws(() => loadLedgerKey(f.options), { code: 'LEDGER_KEY_UNAVAILABLE' });
  assert.throws(() => rotateLedgerKeyring({ ...f.options, nextKeyId: 'next' }), { code: 'LEDGER_KEY_UNAVAILABLE' });
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 1, maxKeys: 4 });
  const result = rotateLedgerKeyring({ ...f.options, maxBytes, nextKeyId: 'next' });
  assert.equal(result.revision, revision);
  const selectedKey = loadLedgerKey({ ...f.options, maxBytes });
  try {
    assert.equal(selectedKey.keyId, 'next');
    const reopened = new LedgerStore(
      f.options.database,
      selectedKey.key,
      maxBytes,
      { path: f.options.witnessPath, mode: 'resume' },
      { existingOnly: true },
    );
    try {
      const value = reopened.read();
      assert.equal(value.revision, revision);
      assert.equal(value.largeFixture.length, 16 * 1024 * 1024 + 1024);
    } finally {
      reopened.close();
    }
    assert.equal(
      rotateLedgerKey({
        database: f.options.database,
        witnessPath: f.options.witnessPath,
        currentKey: f.initial.key,
        nextKey: selectedKey.key,
        maxBytes,
      }).status,
      'already-rotated',
    );
  } finally {
    selectedKey.key.fill(0);
  }
});

test('byte limits reject invalid settings and refuse decoded state above a smaller configured limit', posix, t => {
  const f = fixture(t),
    store = f.open();
  try {
    store.transaction(value => {
      value.fixtureText = 'é'.repeat(500);
    });
  } finally {
    store.close();
  }
  const before = state(f),
    ring = fs.readFileSync(f.options.keyringFile);
  for (const maxBytes of [0, 1023, 1024.5, 64 * 1024 * 1024 + 1, Infinity, NaN]) {
    assert.throws(() => loadLedgerKey({ ...f.options, maxBytes }), { code: 'STORE_CONFIG_INVALID' });
    assert.throws(() => rotateLedgerKeyring({ ...f.options, maxBytes, nextKeyId: 'next' }), {
      code: 'STORE_CONFIG_INVALID',
    });
  }
  assert.throws(
    () =>
      new LedgerStore(
        f.options.database,
        f.initial.key,
        1024,
        { path: f.options.witnessPath, mode: 'resume' },
        { existingOnly: true },
      ),
    { code: 'STORE_WITNESS_UNAVAILABLE' },
  );
  // Below the public minimum, the size itself is refused before any key is tried.
  assert.throws(() => loadLedgerKey({ ...f.options, maxBytes: 1024 }), { code: 'STORE_CONFIG_INVALID' });
  try {
    assert.deepEqual(fs.readFileSync(f.options.keyringFile), ring);
  } finally {
    ring.fill(0);
  }
  assert.deepEqual(state(f), before);
});

test('CLI policy configuration and status expose only safe metadata and validate numeric arguments', posix, t => {
  const f = fixture(t),
    cli = new URL('../dist/ledger-maintenance-cli.js', import.meta.url);
  const run = (...args) => spawnSync(process.execPath, [fileURLToPath(cli), ...args], { encoding: 'utf8' });
  const ringArgs = ['--keyring', f.options.keyringFile];
  const original = run('status', ...ringArgs);
  assert.equal(original.status, 0, original.stderr);
  assert.deepEqual(JSON.parse(original.stdout), { operation: 'status', keyCount: 1, maxKeys: 4 });
  const configured = run('configure', ...ringArgs, '--max-keys', '8');
  assert.equal(configured.status, 0, configured.stderr);
  assert.deepEqual(JSON.parse(configured.stdout), { operation: 'configure', keyCount: 1, maxKeys: 8 });
  const databaseArgs = [
    ...ringArgs,
    '--database',
    f.options.database,
    '--witness',
    f.options.witnessPath,
    '--max-bytes',
    '1048576',
  ];
  const selected = run('status', ...databaseArgs);
  assert.equal(selected.status, 0, selected.stderr);
  assert.deepEqual(JSON.parse(selected.stdout), { operation: 'status', keyId: 'initial', keyCount: 1, maxKeys: 8 });
  assert.equal(run('rotate', ...databaseArgs, '--next-key-id', 'next').status, 0);
  for (const value of ['1.5', '1e1', 'NaN', '65', '-1'])
    assert.equal(run('configure', ...ringArgs, '--max-keys', value).status, 1);
  assert.equal(run('configure', ...ringArgs, '--max-keys', '4', '--max-keys', '8').status, 1);
  assert.equal(run('status', ...ringArgs, '--max-bytes', '1024').status, 1);
  // An unknown flag is reported like a repeated one: as an argument error, not a generic failure.
  // The code is the first line of stderr; Node 22 appends an experimental-SQLite warning after it.
  const code = result => result.stderr.split('\n')[0];
  const unknown = run('status', ...ringArgs, '--no-such-flag', 'x');
  assert.deepEqual([unknown.status, code(unknown)], [1, 'MAINTENANCE_ARGUMENT_INVALID']);
  const repeated = run('configure', ...ringArgs, '--max-keys', '4', '--max-keys', '8');
  assert.equal(code(repeated), 'MAINTENANCE_ARGUMENT_INVALID');
  assert.deepEqual(readLedgerKeyringPolicy(f.options), { keyCount: 2, maxKeys: 8 });
  assert.equal((configured.stdout + selected.stdout).includes('keyBase64'), false);
});
