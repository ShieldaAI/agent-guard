import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { LedgerStore, decodeLedgerObservation } from '../dist/store.js';

const key = Buffer.alloc(32, 7), maximum = 1024 * 1024;
const stateText = value => JSON.stringify({ schema: 1, revision: 3, tasks: {}, actions: {}, value });
function seal(text, witnessed = false, encryptionKey = key) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  cipher.setAAD(Buffer.from(witnessed ? 'agent-guard-witnessed-ledger-v1' : 'agent-guard-ledger-v1'));
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return JSON.stringify([iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')]);
}
function patchCrypto(name, replacement, run) {
  const original = crypto[name];
  crypto[name] = replacement; syncBuiltinESMExports();
  try { return run(); } finally { crypto[name] = original; syncBuiltinESMExports(); }
}
function observeDecipher(run, finalOverride) {
  const original = crypto.createDecipheriv, updates = [], finals = [], events = [];
  return patchCrypto('createDecipheriv', function (...args) {
    const cipher = Reflect.apply(original, this, args), update = cipher.update, final = cipher.final;
    cipher.update = function (...args) {
      events.push('update'); const part = Reflect.apply(update, this, args); updates.push(part); return part;
    };
    cipher.final = function (...args) {
      events.push('final'); const part = Reflect.apply(final, this, args);
      const result = finalOverride ? finalOverride(part) : part; finals.push(result); return result;
    };
    return cipher;
  }, () => run({ updates, finals, events }));
}
const zeroed = buffer => assert.ok(buffer.every(byte => byte === 0));

test('observation authenticates every fresh buffer before decode and wipes successful plaintext', () => {
  for (const witnessed of [false, true]) {
    const payload = seal(stateText({ nested: [{ text: '雪😀', value: 7 }] }), witnessed);
    observeDecipher(({ updates, finals, events }) => {
      const first = decodeLedgerObservation(payload, key, maximum, witnessed);
      const second = decodeLedgerObservation(payload, key, maximum, witnessed);
      assert.deepEqual(events, ['update', 'final', 'update', 'final']);
      assert.deepEqual(first, second); assert.notEqual(first, second); assert.notEqual(first.value.nested, second.value.nested);
      assert.equal(Object.getPrototypeOf(first.value.nested[0]), null);
      assert.notEqual(updates[0], updates[1]); updates.forEach(zeroed); finals.forEach(zeroed);
      first.value.nested[0].value = 99; assert.equal(second.value.nested[0].value, 7);
    });
  }
});

test('ciphertext, tag, IV, key and AAD failures wipe tentative plaintext without returning state', () => {
  const payload = seal(stateText('private fixture'.repeat(100)), true), original = JSON.parse(payload);
  const mutations = [0, 1, 2].map(index => {
    const envelope = [...original], bytes = Buffer.from(envelope[index], 'base64'); bytes[0] ^= 1;
    envelope[index] = bytes.toString('base64'); return [JSON.stringify(envelope), key, true];
  });
  mutations.push([payload, Buffer.alloc(32, 8), true], [payload, key, false]);
  for (const [value, encryptionKey, witnessed] of mutations) {
    observeDecipher(({ updates, events }) => {
      assert.throws(() => decodeLedgerObservation(value, encryptionKey, maximum, witnessed));
      assert.deepEqual(events, ['update', 'final']); assert.equal(updates.length, 1); updates.forEach(zeroed);
    });
  }
});

test('exact plaintext size succeeds; over-limit authenticated plaintext is wiped and encoded precheck stays early', () => {
  const text = stateText('x'.repeat(2000)), bytes = Buffer.byteLength(text), payload = seal(text);
  assert.equal(decodeLedgerObservation(payload, key, bytes, false).value.length, 2000);
  observeDecipher(({ updates, events }) => {
    assert.throws(() => decodeLedgerObservation(payload, key, bytes - 1, false));
    assert.deepEqual(events, ['update', 'final']); updates.forEach(zeroed);
  });
  const envelope = JSON.parse(payload); envelope[2] = 'x'.repeat(bytes * 2 + 1);
  observeDecipher(({ updates, events }) => {
    assert.throws(() => decodeLedgerObservation(JSON.stringify(envelope), key, bytes, false));
    assert.deepEqual(events, []); assert.deepEqual(updates, []);
  });
});

test('authenticated parse/schema errors still wipe plaintext', () => {
  for (const text of ['{"schema":1,', 'null', '{"schema":4,"revision":3,"tasks":{},"actions":{}}']) {
    const payload = seal(text);
    observeDecipher(({ updates, events }) => {
      assert.throws(() => decodeLedgerObservation(payload, key, maximum, false));
      assert.deepEqual(events, ['update', 'final']); updates.forEach(zeroed);
    });
  }
});

test('nonempty final fallback wipes both input fragments and the decoded combined buffer', () => {
  const payload = seal(stateText('fallback')), originalConcat = Buffer.concat; let combined;
  observeDecipher(({ updates, finals }) => {
    Buffer.concat = function (...args) { combined = Reflect.apply(originalConcat, this, args); return combined; };
    try { assert.equal(decodeLedgerObservation(payload, key, maximum, false).value, 'fallback'); }
    finally { Buffer.concat = originalConcat; }
    assert.equal(updates.length, 1); assert.equal(finals.length, 1);
    updates.forEach(zeroed); finals.forEach(zeroed); zeroed(combined);
  }, part => { assert.equal(part.length, 0); return Buffer.from(' '); });
});

test('concat failure preserves its error and wipes tentative and nonempty final plaintext', () => {
  const payload = seal(stateText('fallback failure')), originalConcat = Buffer.concat, sentinel = new Error('test concat failure');
  observeDecipher(({ updates, finals }) => {
    Buffer.concat = () => { throw sentinel; };
    try { assert.throws(() => decodeLedgerObservation(payload, key, maximum, false), error => error === sentinel); }
    finally { Buffer.concat = originalConcat; }
    assert.equal(updates.length, 1); assert.equal(finals.length, 1); updates.forEach(zeroed); finals.forEach(zeroed);
  }, part => { assert.equal(part.length, 0); return Buffer.from(' '); });
});

function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'guard-crypto-copy-')));
  for (const part of ['data', 'witness']) mkdirSync(join(root, part), { mode: 0o700 });
  const database = join(root, 'data', 'ledger.sqlite'), witness = join(root, 'witness', 'witness.sqlite');
  const mirrored = process.platform !== 'win32'; let store;
  const open = (encryptionKey = key, create = false) => store = new LedgerStore(database, encryptionKey, maximum,
    mirrored ? { path: witness, mode: create ? 'create' : 'resume', ...(create ? { recovery: 'mirror' } : {}) } : undefined,
    { existingOnly: !create });
  const close = () => { store?.close(); store = undefined; };
  t.after(() => { try { close(); } finally { rmSync(root, { recursive: true, force: true }); } });
  return { database, witness, mirrored, open, close };
}
function readPayload(path) {
  const db = new DatabaseSync(path);
  try { return db.prepare('SELECT payload FROM ledger WHERE id=1').get().payload; } finally { db.close(); }
}

test('actual store seal/rekey avoids empty-final copies while preserving nonce freshness, mirrored bytes and reopen', t => {
  const f = fixture(t), originalCipher = crypto.createCipheriv, originalConcat = Buffer.concat;
  const updates = [], ivs = [], finalCalls = [], inputKinds = []; let targetConcats = 0;
  patchCrypto('createCipheriv', function (...args) {
    ivs.push(Buffer.from(args[2])); const cipher = Reflect.apply(originalCipher, this, args), update = cipher.update, final = cipher.final;
    cipher.update = function (...args) { inputKinds.push(typeof args[0]); const value = Reflect.apply(update, this, args); updates.push(value); return value; };
    cipher.final = function (...args) { const value = Reflect.apply(final, this, args); finalCalls.push(value.length); return value; }; return cipher;
  }, () => {
    Buffer.concat = function (parts, ...args) {
      if (parts.some(part => updates.includes(part))) targetConcats++;
      return Reflect.apply(originalConcat, this, [parts, ...args]);
    };
    try {
      const store = f.open(key, true); store.transaction(state => { state.value = { nested: ['persisted'] }; });
      const before = store.read(); store.rotateEncryptionKey(Buffer.alloc(32, 9));
      assert.deepEqual(store.read(), before); f.close(); assert.deepEqual(f.open(Buffer.alloc(32, 9)).read(), before); f.close();
      assert.throws(() => f.open(key), { code: f.mirrored ? 'STORE_WITNESS_UNAVAILABLE' : 'STORE_UNAVAILABLE' });
      if (f.mirrored) assert.equal(readPayload(f.database), readPayload(f.witness));
      const payload = readPayload(f.database);
      assert.deepEqual(decodeLedgerObservation(payload, Buffer.alloc(32, 9), maximum, f.mirrored), before);
    } finally { Buffer.concat = originalConcat; }
  });
  assert.equal(targetConcats, 0); assert.ok(updates.length >= 3); assert.equal(finalCalls.length, updates.length);
  assert.ok(finalCalls.every(length => length === 0)); assert.ok(inputKinds.includes('string')); assert.ok(inputKinds.includes('object'));
  assert.equal(new Set(ivs.map(iv => iv.toString('hex'))).size, ivs.length); assert.ok(ivs.every(iv => iv.length === 12));
});

test('cipher final failure rolls back an actual transaction and retains the previously readable state', t => {
  const f = fixture(t), store = f.open(key, true); store.transaction(state => { state.value = 'committed'; });
  const expected = store.read(), original = crypto.createCipheriv, sentinel = new Error('test cipher final failure');
  patchCrypto('createCipheriv', function (...args) {
    const cipher = Reflect.apply(original, this, args); cipher.final = () => { throw sentinel; }; return cipher;
  }, () => assert.throws(() => store.transaction(state => { state.value = 'must not commit'; }), error => error === sentinel));
  assert.deepEqual(store.read(), expected); f.close(); assert.deepEqual(f.open().read(), expected);
});
