import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { LedgerStore } from '../dist/store.js';

// Exact private decode algorithm from store.ts at ee0d589057e3d367b8a0bd1f08f3e4cb5790f3f2.
// Keep this oracle independent of the replacement; exercise the actual encrypted read boundary.
const legacyDecode = text =>
  JSON.parse(text, (_key, value) =>
    value && typeof value === 'object' && !Array.isArray(value) ? Object.assign(Object.create(null), value) : value,
  );

function fixture(t, mirrored = false) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'guard-ledger-decoder-')));
  for (const name of ['data', 'witness']) mkdirSync(join(root, name), { mode: 0o700 });
  const database = join(root, 'data', 'ledger.sqlite'),
    witness = join(root, 'witness', 'witness.sqlite'),
    key = randomBytes(32);
  let active = new LedgerStore(
    database,
    key,
    undefined,
    mirrored ? { path: witness, mode: 'create', recovery: 'mirror' } : undefined,
  );
  const initial = active.read();
  active.close();
  active = undefined;
  const close = () => {
    active?.close();
    active = undefined;
  };
  const open = (encryptionKey = key) => {
    active = new LedgerStore(
      database,
      encryptionKey,
      undefined,
      mirrored ? { path: witness, mode: 'resume' } : undefined,
      { existingOnly: true },
    );
    return active;
  };
  t.after(() => {
    try {
      close();
    } finally {
      key.fill(0);
      rmSync(root, { recursive: true, force: true });
    }
  });
  return { database, witness, key, initial, open, close };
}
function withDatabase(path, operation) {
  const database = new DatabaseSync(path);
  try {
    return operation(database);
  } finally {
    database.close();
  }
}
const payload = path => withDatabase(path, db => db.prepare('SELECT payload FROM ledger WHERE id=1').get().payload);
const replacePayload = (path, value) =>
  withDatabase(path, db => db.prepare('UPDATE ledger SET payload=? WHERE id=1').run(value));
function encryptedJson(text, key) {
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('agent-guard-ledger-v1'));
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return JSON.stringify([iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')]);
}
const withValue = (initial, valueText) => JSON.stringify(initial).slice(0, -1) + ',"decoderFixture":' + valueText + '}';
function equivalent(actual, expected) {
  const pending = [[actual, expected]];
  while (pending.length) {
    const [left, right] = pending.pop();
    if (right === null || typeof right !== 'object') {
      assert.equal(left, right);
      continue;
    }
    assert.equal(Object.getPrototypeOf(left), Array.isArray(right) ? Array.prototype : null);
    assert.equal(Object.getPrototypeOf(left), Object.getPrototypeOf(right));
    const keys = Object.getOwnPropertyNames(right);
    assert.deepEqual(Object.getOwnPropertyNames(left), keys);
    assert.deepEqual(Object.getOwnPropertySymbols(left), []);
    assert.equal(Object.isExtensible(left), true);
    for (const name of keys) {
      const a = Object.getOwnPropertyDescriptor(left, name),
        b = Object.getOwnPropertyDescriptor(right, name);
      assert.equal(a.enumerable, b.enumerable);
      assert.equal(a.writable, b.writable);
      assert.equal(a.configurable, b.configurable);
      assert.ok('value' in a);
      pending.push([a.value, b.value]);
    }
  }
}

test('authenticated ledger JSON matches the legacy reviver for every key, descriptor, numeric value and nested record', t => {
  const f = fixture(t);
  const data = JSON.parse(
    '{"10":"ten","2":"two","__proto__":{"polluted":true},"constructor":{"prototype":{"own":true}},"prototype":"data","toJSON":{"literal":true},"then":[{"own":"value"}]}',
  );
  data.text = '雪😀 " \\ \n \u0000';
  data.loneSurrogate = '\ud800';
  data.numbers = ['NEGATIVE_ZERO', 0, 1.25, 1e-7, 1e-300, Number.MAX_SAFE_INTEGER];
  data.nested = [[], {}, [{ null: null, false: false, array: [{ leaf: 'value' }] }]];
  const valueText =
    JSON.stringify(data).replace('"NEGATIVE_ZERO"', '-0').slice(0, -1) + ',"duplicate":1,"duplicate":2}';
  const text = withValue(f.initial, valueText);
  const originalCiphertext = encryptedJson(text, f.key);
  replacePayload(f.database, originalCiphertext);
  const store = f.open();
  const decoded = store.read(),
    expected = legacyDecode(text);
  equivalent(decoded, expected);
  assert.equal(Object.is(decoded.decoderFixture.numbers[0], -0), true);
  assert.equal(decoded.decoderFixture.duplicate, 2);
  assert.equal(Object.hasOwn(decoded.decoderFixture, '__proto__'), true);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
  assert.equal(JSON.stringify(decoded), JSON.stringify(expected));
  f.close();
  equivalent(f.open().read(), expected);
  // Opening and observing cannot rewrite the plaintext or its randomized ciphertext.
  f.close();
  assert.equal(payload(f.database), originalCiphertext);
});

test('ordinary deep record/array state remains equivalent without retaining a caller graph', t => {
  const f = fixture(t);
  let value = { leaf: 'end' };
  for (let level = 0; level < 128; level++) value = level % 2 ? { child: value, level } : [value, { level }];
  const text = withValue(f.initial, JSON.stringify(value));
  replacePayload(f.database, encryptedJson(text, f.key));
  const store = f.open(),
    first = store.read(),
    second = store.read();
  equivalent(first, legacyDecode(text));
  equivalent(second, legacyDecode(text));
  assert.notEqual(first, second);
  assert.notEqual(first.decoderFixture, second.decoderFixture);
  first.decoderFixture.child = 'local only';
  equivalent(store.read(), legacyDecode(text));
});

test('fresh reads and retained transaction graphs cannot mutate persisted authority; rollback remains atomic', t => {
  const f = fixture(t),
    store = f.open();
  store.transaction(state => {
    state.decoderFixture = { list: [{ value: 'persisted' }], counter: 1 };
  });
  const committed = store.read(),
    observed = store.read();
  observed.decoderFixture.list[0].value = 'changed outside transaction';
  observed.tasks.fake = { private: 'local' };
  assert.deepEqual(store.read(), committed);
  let retained;
  store.transaction(state => {
    retained = state;
    state.decoderFixture.counter = 2;
  });
  const secondCommit = store.read();
  retained.decoderFixture.list.push({ value: 'late mutation' });
  retained.decoderFixture.counter = 999;
  assert.deepEqual(store.read(), secondCommit);
  const failure = new Error('rollback sentinel');
  assert.throws(
    () =>
      store.transaction(state => {
        state.decoderFixture.list[0].value = 'must roll back';
        state.tasks.fake = {};
        throw failure;
      }),
    error => error === failure,
  );
  assert.deepEqual(store.read(), secondCommit);
  f.close();
  assert.deepEqual(f.open().read(), secondCommit);
});

test('authenticated malformed JSON, invalid roots and unsupported schema still fail without replacing state', t => {
  const f = fixture(t);
  for (const text of [
    '{"schema":1,',
    'null',
    'true',
    '123',
    '"text"',
    '[]',
    JSON.stringify({ ...f.initial, schema: 4 }),
    JSON.stringify({ ...f.initial, revision: 0.5 }),
    JSON.stringify({ ...f.initial, inventoryInstanceId: 'invalid' }),
  ]) {
    const encrypted = encryptedJson(text, f.key);
    replacePayload(f.database, encrypted);
    assert.throws(() => f.open(), { code: 'STORE_UNAVAILABLE' });
    assert.equal(payload(f.database), encrypted);
  }
});

test('wrong keys and corrupted GCM ciphertext remain rejected before a ledger is exposed', t => {
  const f = fixture(t),
    original = payload(f.database);
  assert.throws(() => f.open(Buffer.alloc(32, 9)), { code: 'STORE_UNAVAILABLE' });
  assert.equal(payload(f.database), original);
  const envelope = JSON.parse(original),
    encrypted = Buffer.from(envelope[2], 'base64');
  encrypted[0] ^= 1;
  envelope[2] = encrypted.toString('base64');
  const corrupted = JSON.stringify(envelope);
  replacePayload(f.database, corrupted);
  assert.throws(() => f.open(), { code: 'STORE_UNAVAILABLE' });
  assert.equal(payload(f.database), corrupted);
});

test(
  'witnessed mirror reads preserve detached records and still reject stale commitment or mirror payload',
  { skip: process.platform === 'win32' },
  t => {
    const f = fixture(t, true),
      store = f.open();
    store.transaction(state => {
      state.decoderFixture = JSON.parse('{"__proto__":{"literal":true},"nested":[{"value":7}]}');
    });
    const expected = store.read(),
      observed = store.read();
    observed.decoderFixture.nested[0].value = 99;
    assert.equal(store.read().decoderFixture.nested[0].value, 7);
    f.close();
    const original = payload(f.database),
      mirrored = payload(f.witness);
    assert.equal(original, mirrored);
    equivalent(f.open().read(), expected);
    f.close();
    const commitment = withDatabase(
      f.witness,
      db => db.prepare('SELECT digest FROM commitment WHERE id=1').get().digest,
    );
    withDatabase(f.witness, db => db.prepare('UPDATE commitment SET digest=? WHERE id=1').run('0'.repeat(64)));
    assert.throws(() => f.open(), { code: 'STORE_WITNESS_UNAVAILABLE' });
    assert.equal(payload(f.database), original);
    withDatabase(f.witness, db => db.prepare('UPDATE commitment SET digest=? WHERE id=1').run(commitment));
    replacePayload(f.witness, original + ' ');
    assert.throws(() => f.open(), { code: 'STORE_WITNESS_UNAVAILABLE' });
    assert.equal(payload(f.database), original);
    assert.equal(payload(f.witness), original + ' ');
  },
);
