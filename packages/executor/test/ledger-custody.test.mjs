import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, realpathSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  createLedgerKeyring,
  readLedgerKeyring,
  loadLedgerKey,
  readLedgerKeyringPolicy,
  rotateLedgerKeyring,
} from '../dist/ledger-maintenance.js';
import { manageLedgerRecovery } from '../dist/ledger-recovery.js';
import { manageLedgerCustody } from '../dist/ledger-custody.js';
import { LedgerStore } from '../dist/store.js';
import { removeAtExit } from './temp-directory.mjs';
import { fileURLToPath } from 'node:url';

function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'guard-custody-')));
  removeAtExit(root);
  for (const dir of ['active', 'data', 'witness', 'custody', 'custody-witness', 'offline', 'backups'])
    mkdirSync(join(root, dir), { mode: 0o700 });
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
  createLedgerKeyring({ keyringFile: options.keyringFile, keyId: 'first', maxKeys: 8 });
  createLedgerKeyring({ keyringFile: options.custodyKeyringFile, keyId: 'custody-first', maxKeys: 64 });
  const keys = readLedgerKeyring({ keyringFile: options.keyringFile });
  try {
    for (const source of options.stores) {
      const store = new LedgerStore(source.database, keys[0].key, undefined, {
        path: source.witnessPath,
        mode: 'create',
      });
      store.transaction(s => {
        s.audit.push({ time: 1, event: 'enrolled' });
      });
      store.close();
    }
  } finally {
    keys.forEach(k => k.key.fill(0));
  }
  const apply = request => {
    const preview = manageLedgerCustody(options, request);
    return manageLedgerCustody(options, request, { expectedDigest: preview.digest });
  };
  return { root, options, apply };
}
function open(options, index = 0) {
  const source = options.stores[index],
    key = loadLedgerKey({ ...source, keyringFile: options.keyringFile });
  const store = new LedgerStore(
    source.database,
    key.key,
    undefined,
    { path: source.witnessPath, mode: 'resume' },
    { existingOnly: true },
  );
  key.key.fill(0);
  return store;
}
const posix = { skip: process.platform === 'win32' };
const denied = code => error => error?.code === code;

test(
  'custody enrolls exact scope, denies raw key export and wrong stores, snapshots without advancing source witness',
  posix,
  t => {
    const { options, apply } = fixture(t);
    const preview = manageLedgerCustody(options, { operation: 'enroll' });
    assert.equal(existsSync(options.custodyDatabase), false);
    apply({ operation: 'enroll' });
    const before = options.stores.map(s => readFileSync(s.witnessPath));
    assert.throws(
      () => readLedgerKeyring({ keyringFile: options.keyringFile }),
      denied('KEYRING_MANAGED_OPERATION_REQUIRED'),
    );
    assert.throws(
      () =>
        loadLedgerKey({
          keyringFile: options.keyringFile,
          database: options.stores[0].database,
          witnessPath: options.stores[1].witnessPath,
        }),
      denied('KEYRING_SCOPE_UNREGISTERED'),
    );
    const backup = apply({ operation: 'backup' });
    assert.equal(backup.backupCount, 1);
    assert.equal(
      manageLedgerCustody(options, { operation: 'verify', backupId: backup.backupId }).backupId,
      backup.backupId,
    );
    for (let i = 0; i < 2; i++) assert.deepEqual(readFileSync(options.stores[i].witnessPath), before[i]);
    assert.throws(
      () => rotateLedgerKeyring({ ...options.stores[0], keyringFile: options.keyringFile, nextKeyId: 'bypass' }),
      denied('KEYRING_MANAGED_OPERATION_REQUIRED'),
    );
    assert.throws(
      () => manageLedgerCustody(options, { operation: 'backup' }, { expectedDigest: preview.digest }),
      denied('CUSTODY_PREVIEW_CHANGED'),
    );
  },
);

test('active retirement retains independent escrow and verifies old backups after rotation', posix, t => {
  const { options, apply } = fixture(t);
  const original = readFileSync(options.keyringFile, 'utf8');
  apply({ operation: 'enroll' });
  const old = apply({ operation: 'backup' });
  assert.throws(
    () => manageLedgerCustody(options, { operation: 'retire', keyId: 'first' }),
    denied('CUSTODY_LAST_KEY'),
  );
  const rotation = apply({ operation: 'rotate', nextKeyId: 'second' });
  assert.equal(rotation.observationReenrollmentRequired, true);
  for (let i = 0; i < 2; i++) {
    const key = loadLedgerKey({ ...options.stores[i], keyringFile: options.keyringFile });
    assert.equal(key.keyId, 'second');
    key.key.fill(0);
  }
  assert.equal(apply({ operation: 'retire', keyId: 'first' }).keyCount, 1);
  assert.equal(readLedgerKeyringPolicy({ keyringFile: options.keyringFile }).keyCount, 1);
  assert.equal(manageLedgerCustody(options, { operation: 'verify', backupId: old.backupId }).backupCount, 1);
  assert.throws(
    () => manageLedgerCustody(options, { operation: 'restore', backupId: old.backupId }),
    denied('CUSTODY_RESTORE_STALE'),
  );
  const catalogBytes = readFileSync(options.custodyDatabase);
  assert.equal(catalogBytes.includes(JSON.parse(original).keys[0].keyBase64), false);
  assert.throws(
    () => manageLedgerCustody(options, { operation: 'rotate', nextKeyId: 'first' }),
    denied('CUSTODY_ROTATION_INVALID'),
  );
});

test('current cold snapshot restores damaged authority and retains current witnesses', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  const witnesses = options.stores.map(s => readFileSync(s.witnessPath));
  writeFileSync(options.stores[0].database, Buffer.from('damaged database'), { mode: 0o600 });
  const restored = apply({ operation: 'restore', backupId: backup.backupId });
  assert.equal(restored.pending, false);
  const store = open(options);
  assert.equal(store.read().audit[0].event, 'enrolled');
  store.close();
  for (let i = 0; i < 2; i++) assert.deepEqual(readFileSync(options.stores[i].witnessPath), witnesses[i]);
});

test('restore refuses a stale checkpoint and never replaces an advanced witness or source', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  const store = open(options);
  store.transaction(s => s.audit.push({ time: 2, event: 'new authority' }));
  store.close();
  const current = options.stores.map(s => readFileSync(s.database)),
    witnesses = options.stores.map(s => readFileSync(s.witnessPath));
  assert.throws(
    () => manageLedgerCustody(options, { operation: 'restore', backupId: backup.backupId }),
    denied('CUSTODY_RESTORE_STALE'),
  );
  options.stores.forEach((s, i) => {
    assert.deepEqual(readFileSync(s.database), current[i]);
    assert.deepEqual(readFileSync(s.witnessPath), witnesses[i]);
  });
});

test('retirement refuses any missing or modified registered backup', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  apply({ operation: 'rotate', nextKeyId: 'second' });
  const manifest = join(options.backupDirectory, backup.backupId, 'manifest.enc');
  const bytes = readFileSync(manifest);
  bytes[20] ^= 1;
  writeFileSync(manifest, bytes);
  assert.throws(
    () => manageLedgerCustody(options, { operation: 'retire', keyId: 'first' }),
    denied('CUSTODY_BACKUP_CHANGED'),
  );
  assert.equal(readLedgerKeyringPolicy({ keyringFile: options.keyringFile }).keyCount, 2);
});

test('catalog rollback and removed records fail against independent current custody witness', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const before = readFileSync(options.custodyDatabase);
  apply({ operation: 'backup' });
  writeFileSync(options.custodyDatabase, before);
  assert.throws(() => manageLedgerCustody(options, { operation: 'status' }), denied('CUSTODY_STORE_UNAVAILABLE'));
});

test('partial multi-store rotation recovers using independently escrowed new key', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const original = LedgerStore.prototype.rotateEncryptionKey;
  let count = 0;
  LedgerStore.prototype.rotateEncryptionKey = function (key) {
    if (++count === 2) throw new Error('simulated interruption');
    return original.call(this, key);
  };
  try {
    assert.throws(() => apply({ operation: 'rotate', nextKeyId: 'second' }));
  } finally {
    LedgerStore.prototype.rotateEncryptionKey = original;
  }
  assert.equal(manageLedgerCustody(options, { operation: 'status' }).pending, true);
  assert.throws(() => manageLedgerCustody(options, { operation: 'backup' }), denied('CUSTODY_RECOVERY_REQUIRED'));
  assert.equal(apply({ operation: 'recover' }).pending, false);
  for (const source of options.stores) {
    const key = loadLedgerKey({ ...source, keyringFile: options.keyringFile });
    assert.equal(key.keyId, 'second');
    key.key.fill(0);
  }
});

test('SIGKILL after durable retirement intent recovers without losing escrow or keys', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  apply({ operation: 'backup' });
  apply({ operation: 'rotate', nextKeyId: 'second' });
  const script = `import {LedgerStore} from ${JSON.stringify(new URL('../dist/store.js', import.meta.url).href)}; import {manageLedgerCustody} from ${JSON.stringify(new URL('../dist/ledger-custody.js', import.meta.url).href)}; const options=${JSON.stringify(options)}; const request={operation:'retire',keyId:'first'}; const preview=manageLedgerCustody(options,request); const old=LedgerStore.prototype.transaction; LedgerStore.prototype.transaction=function(fn){const r=old.call(this,fn); if(this.read().custody?.pending?.kind==='retire') process.kill(process.pid,'SIGKILL'); return r;}; manageLedgerCustody(options,request,{expectedDigest:preview.digest});`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.signal, 'SIGKILL', child.stderr);
  assert.equal(readLedgerKeyringPolicy({ keyringFile: options.keyringFile }).keyCount, 2);
  assert.equal(apply({ operation: 'recover' }).keyCount, 1);
  assert.equal(manageLedgerCustody(options, { operation: 'status' }).pending, false);
});

test('custody secret rotation preserves older backup envelopes and uses new key for future snapshots', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const old = apply({ operation: 'backup' });
  rotateLedgerKeyring({
    database: options.custodyDatabase,
    witnessPath: options.custodyWitness,
    keyringFile: options.custodyKeyringFile,
    nextKeyId: 'custody-second',
  });
  const fresh = apply({ operation: 'backup' });
  assert.equal(
    JSON.parse(readFileSync(join(options.backupDirectory, fresh.backupId, 'manifest.enc'), 'utf8')).keyId,
    'custody-second',
  );
  assert.equal(manageLedgerCustody(options, { operation: 'verify', backupId: old.backupId }).backupId, old.backupId);
});

test('all owner and custody boundary checks happen before mutation', posix, t => {
  const { options, apply } = fixture(t),
    store = open(options);
  try {
    assert.throws(() => manageLedgerCustody(options, { operation: 'enroll' }), denied('CUSTODY_STORE_UNAVAILABLE'));
    assert.equal(existsSync(options.custodyDatabase), false);
  } finally {
    store.close();
  }
  assert.throws(() =>
    manageLedgerCustody(
      { ...options, backupDirectory: join(dirname(options.custodyDatabase)) },
      { operation: 'enroll' },
    ),
  );
  apply({ operation: 'enroll' });
  const source = open(options);
  try {
    assert.throws(
      () => manageLedgerCustody(options, { operation: 'restore', backupId: '00000000-0000-4000-8000-000000000000' }),
      denied('CUSTODY_WITNESS_UNAVAILABLE'),
    );
  } finally {
    source.close();
  }
});

test('transaction archive removal checks exact ciphertext and rolls back together with state', posix, t => {
  const { options } = fixture(t),
    store = open(options);
  t.after(() => store.close());
  store.transaction((s, a) => a.putArchive('test', 'ciphertext'));
  assert.throws(() =>
    store.transaction((s, a) => {
      a.deleteArchive('test', '0'.repeat(64));
    }),
  );
  assert.equal(store.readArchive('test'), 'ciphertext');
  assert.throws(() =>
    store.transaction((s, a) => {
      a.deleteArchive('test', createHash('sha256').update('ciphertext').digest('hex'));
      throw Error('abort');
    }),
  );
  assert.equal(store.readArchive('test'), 'ciphertext');
  store.transaction((s, a) => a.deleteArchive('test', createHash('sha256').update('ciphertext').digest('hex')));
  assert.throws(() => store.readArchive('test'));
});

test('restoring an older unmanaged keyring cannot bypass managed enrollment', posix, t => {
  const { options, apply } = fixture(t),
    original = readFileSync(options.keyringFile);
  apply({ operation: 'enroll' });
  writeFileSync(options.keyringFile, original);
  assert.throws(
    () => loadLedgerKey({ ...options.stores[0], keyringFile: options.keyringFile }),
    denied('KEYRING_SCOPE_UNREGISTERED'),
  );
  assert.throws(
    () => rotateLedgerKeyring({ ...options.stores[0], keyringFile: options.keyringFile, nextKeyId: 'untracked' }),
    denied('KEYRING_MANAGED_OPERATION_REQUIRED'),
  );
  apply({ operation: 'recover' });
  const key = loadLedgerKey({ ...options.stores[0], keyringFile: options.keyringFile });
  key.key.fill(0);
});

test('runtime secret ancestors cannot contain the offline custody keyring', posix, t => {
  const { options } = fixture(t);
  const nested = join(dirname(options.keyringFile), 'offline');
  mkdirSync(nested, { mode: 0o700 });
  for (const path of [join(dirname(options.keyringFile), 'custody.json'), join(nested, 'custody.json')])
    assert.throws(
      () => manageLedgerCustody({ ...options, custodyKeyringFile: path }, { operation: 'enroll' }),
      denied('CUSTODY_DIRECTORIES_OVERLAP'),
    );
});

test('SIGKILL while staging restore retains damaged source and recover rebuilds the partial stage', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  writeFileSync(options.stores[0].database, Buffer.from('damaged original'));
  const script = `import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';import {manageLedgerCustody} from ${JSON.stringify(new URL('../dist/ledger-custody.js', import.meta.url).href)};const options=${JSON.stringify(options)};const request={operation:'restore',backupId:${JSON.stringify(backup.backupId)}};const preview=manageLedgerCustody(options,request);const open=fs.openSync,write=fs.writeSync;let stageFd;fs.openSync=function(path,...args){const fd=open.call(this,path,...args);if(String(path).includes('.custody-restore-')&&(args[0]&fs.constants.O_WRONLY))stageFd=fd;return fd;};fs.writeSync=function(fd,b,offset,len,...args){if(fd===stageFd){write.call(this,fd,b,offset,Math.min(len,16),...args);process.kill(process.pid,'SIGKILL');}return write.call(this,fd,b,offset,len,...args);};syncBuiltinESMExports();manageLedgerCustody(options,request,{expectedDigest:preview.digest});`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.signal, 'SIGKILL', child.stderr);
  assert.equal(readFileSync(options.stores[0].database, 'utf8'), 'damaged original');
  assert.equal(apply({ operation: 'recover' }).pending, false);
  const store = open(options);
  assert.equal(store.read().audit[0].event, 'enrolled');
  store.close();
});

test('custody CLI previews and applies exact digest without disclosing escrow secrets', posix, t => {
  const { options, root } = fixture(t);
  const config = join(root, 'offline', 'custody.json');
  writeFileSync(config, JSON.stringify({ version: 1, ...options }), { mode: 0o600 });
  const cli = fileURLToPath(new URL('../dist/ledger-maintenance-cli.js', import.meta.url));
  const preview = spawnSync(process.execPath, [cli, 'custody', 'enroll', '--config', config], { encoding: 'utf8' });
  assert.equal(preview.status, 0, preview.stderr);
  const value = JSON.parse(preview.stdout);
  const apply = spawnSync(
    process.execPath,
    [cli, 'custody', 'enroll', '--config', config, '--apply', '--digest', value.digest],
    { encoding: 'utf8' },
  );
  assert.equal(apply.status, 0, apply.stderr);
  assert.equal(JSON.parse(apply.stdout).applied, true);
  assert.equal(apply.stdout.includes('keyBase64'), false);
  assert.equal(JSON.parse(apply.stdout).backupFileLimit, 20000);
});

test('SIGKILL after active-ring removal completes retirement from preserved escrow', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  apply({ operation: 'rotate', nextKeyId: 'second' });
  const script = `import fs from 'node:fs';import {LedgerStore} from ${JSON.stringify(new URL('../dist/store.js', import.meta.url).href)};import {manageLedgerCustody} from ${JSON.stringify(new URL('../dist/ledger-custody.js', import.meta.url).href)};const options=${JSON.stringify(options)};const request={operation:'retire',keyId:'first'};const preview=manageLedgerCustody(options,request);const old=LedgerStore.prototype.transaction;LedgerStore.prototype.transaction=function(fn){if(this.read().custody?.pending?.kind==='retire'&&JSON.parse(fs.readFileSync(options.keyringFile)).keys.length===1)process.kill(process.pid,'SIGKILL');return old.call(this,fn);};manageLedgerCustody(options,request,{expectedDigest:preview.digest});`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.signal, 'SIGKILL', child.stderr);
  assert.equal(readLedgerKeyringPolicy({ keyringFile: options.keyringFile }).keyCount, 1);
  assert.equal(apply({ operation: 'recover' }).pending, false);
  assert.equal(
    manageLedgerCustody(options, { operation: 'verify', backupId: backup.backupId }).backupId,
    backup.backupId,
  );
});

test('interrupted restore superseded by authenticated current authority cancels without rewinding it', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  const original = LedgerStore.prototype.transaction;
  let interrupted = false;
  LedgerStore.prototype.transaction = function (fn) {
    const result = original.call(this, fn);
    if (!interrupted && this.read().custody?.pending?.kind === 'restore') {
      interrupted = true;
      throw new Error('interrupt after intent');
    }
    return result;
  };
  try {
    assert.throws(() => apply({ operation: 'restore', backupId: backup.backupId }));
  } finally {
    LedgerStore.prototype.transaction = original;
  }
  const store = open(options);
  store.transaction(s => s.audit.push({ time: 3, event: 'resumed new authority' }));
  store.close();
  const before = readFileSync(options.stores[0].database),
    witness = readFileSync(options.stores[0].witnessPath);
  const preview = manageLedgerCustody(options, { operation: 'recover' });
  assert.equal(preview.restoreSuperseded, true);
  const result = manageLedgerCustody(options, { operation: 'recover' }, { expectedDigest: preview.digest });
  assert.equal(result.pending, false);
  assert.equal(result.restoreSuperseded, true);
  assert.deepEqual(readFileSync(options.stores[0].database), before);
  assert.deepEqual(readFileSync(options.stores[0].witnessPath), witness);
});

test('current custody catalog repair preserves retired-key escrow and registered backup verification', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const backup = apply({ operation: 'backup' });
  apply({ operation: 'rotate', nextKeyId: 'second' });
  apply({ operation: 'retire', keyId: 'first' });
  assert.equal(readLedgerKeyringPolicy({ keyringFile: options.keyringFile }).keyCount, 1);
  const currentWitness = readFileSync(options.custodyWitness);
  rmSync(options.custodyDatabase);
  const recovery = {
    keyringFile: options.custodyKeyringFile,
    stores: [{ id: 'custody', database: options.custodyDatabase, witnessPath: options.custodyWitness }],
  };
  const preview = manageLedgerRecovery(recovery, { operation: 'repair' });
  assert.equal(preview.alreadyMirrored, 1);
  manageLedgerRecovery(recovery, { operation: 'repair' }, { expectedDigest: preview.digest });
  assert.deepEqual(readFileSync(options.custodyWitness), currentWitness);
  assert.equal(
    manageLedgerCustody(options, { operation: 'verify', backupId: backup.backupId }).backupId,
    backup.backupId,
  );
  assert.equal(readLedgerKeyringPolicy({ keyringFile: options.keyringFile }).keyCount, 1);
  assert.equal(manageLedgerCustody(options, { operation: 'status' }).pending, false);
});

test('managed recovery requires the complete registered store group', posix, t => {
  const { options, apply } = fixture(t);
  apply({ operation: 'enroll' });
  const full = { keyringFile: options.keyringFile, stores: options.stores },
    partial = { ...full, stores: [options.stores[0]] };
  assert.throws(() => manageLedgerRecovery(partial, { operation: 'enroll' }), denied('RECOVERY_SCOPE_MISMATCH'));
  const review = manageLedgerRecovery(full, { operation: 'enroll' });
  manageLedgerRecovery(full, { operation: 'enroll' }, { expectedDigest: review.digest });
  assert.throws(() => manageLedgerRecovery(partial, { operation: 'repair' }), denied('RECOVERY_SCOPE_MISMATCH'));
  assert.equal(manageLedgerRecovery(full, { operation: 'repair' }).alreadyMirrored, 2);
});
