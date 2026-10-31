import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { LedgerStore } from '../dist/store.js';

const key = Buffer.alloc(32, 37);
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function databaseFor(t) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-inventory-identity-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return join(directory, 'ledger.sqlite');
}

function legacyLedger() {
  return {
    schema: 1, revision: 19, epoch: 7, lastClock: 1234,
    tasks: {}, families: {}, tools: {}, actions: {}, approvals: {}, memory: {},
    audit: [{ time: 1234, event: 'LEGACY_STATE_CANARY' }],
  };
}

// Fixture codec matches the previous schema-1 reader/writer, including retention of extra fields.
function previousRead(payload) {
  const [iv, tag, encrypted] = JSON.parse(payload);
  const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  cipher.setAAD(Buffer.from('agent-guard-ledger-v1'));
  cipher.setAuthTag(Buffer.from(tag, 'base64'));
  const state = JSON.parse(Buffer.concat([cipher.update(Buffer.from(encrypted, 'base64')), cipher.final()]).toString('utf8'),
    (_key, value) => value && typeof value === 'object' && !Array.isArray(value)
      ? Object.assign(Object.create(null), value) : value);
  if (state.schema !== 1 || !Number.isSafeInteger(state.revision) || !state.tasks || !state.actions) throw new Error('corrupt');
  return state;
}

function seal(state) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('agent-guard-ledger-v1'));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(state), 'utf8'), cipher.final()]);
  return JSON.stringify([iv.toString('base64'), cipher.getAuthTag().toString('base64'), encrypted.toString('base64')]);
}

function payloadAt(database) {
  const db = new DatabaseSync(database);
  try { return db.prepare('SELECT payload FROM ledger WHERE id=1').get().payload; }
  finally { db.close(); }
}

function writeFixture(database, state) {
  writeFileSync(database, '', { mode: 0o600 });
  const db = new DatabaseSync(database);
  try {
    db.exec('CREATE TABLE ledger (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)');
    db.prepare('INSERT INTO ledger(id,payload) VALUES(1,?)').run(seal(state));
  } finally { db.close(); }
}

test('new inventory identities are encrypted, distinct and stable across reads, writes and reopen', t => {
  const database = databaseFor(t);
  const store = new LedgerStore(database, key);
  const first = store.read();
  assert.match(first.inventoryInstanceId, uuid);
  assert.equal(first.revision, 0);
  assert.deepEqual(store.read(), first);
  store.transaction(state => { state.epoch++; });
  assert.equal(store.read().inventoryInstanceId, first.inventoryInstanceId);
  store.close();
  assert.equal(readFileSync(database).includes(Buffer.from(first.inventoryInstanceId)), false);
  const reopened = new LedgerStore(database, key);
  try {
    assert.equal(reopened.read().inventoryInstanceId, first.inventoryInstanceId);
    assert.equal(reopened.read().revision, 1, 'opening an already migrated ledger must not write');
  } finally { reopened.close(); }
  const separate = new LedgerStore(':memory:', key);
  try { assert.notEqual(separate.read().inventoryInstanceId, first.inventoryInstanceId); }
  finally { separate.close(); }
});

test('legacy schema-1 migration is additive, atomic and performed only once', t => {
  const database = databaseFor(t);
  const original = legacyLedger();
  original.tasks.task = {
    options: { id: 'task', tenantId: 'tenant', principalId: 'principal',
      grants: [{ tool: 'read', resources: ['private-file'] }],
      budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 50, deadline: 10000 } },
    parent: null, family: 'task', tokenHash: 'b'.repeat(64), revoked: false,
    calls: 2, concurrent: 1, spent: 3, reserved: 5,
  };
  original.families.task = { sensitive: true, memorySources: ['memory'] };
  original.tools.read = { fingerprint: 'a'.repeat(64), revision: 3, approved: true };
  original.actions.action = {
    id: 'action', taskId: 'task', digest: 'c'.repeat(64), toolRevision: 3,
    action: { tool: 'read', args: { private: 'argument' }, resourceId: 'private-file', tenantId: 'tenant',
      toolFingerprint: 'a'.repeat(64), policyVersion: 7 },
    requiresApproval: true, status: 'RUNNING', maxCost: 5,
  };
  original.approvals.approval = { actionId: 'action', digest: 'c'.repeat(64), expiresAt: 10000, approverId: 'reviewer', used: true };
  original.memory.memory = [{ id: 'memory', tenantId: 'tenant', origin: 'tool', sensitive: true,
    trusted: false, version: 1, parentIds: [], quarantined: false, value: { private: 'memory body' }, familyId: 'task' }];
  writeFixture(database, original);
  const migrated = new LedgerStore(database, key);
  const state = JSON.parse(JSON.stringify(migrated.read()));
  migrated.close();
  const { inventoryInstanceId, ...rest } = state;
  assert.match(inventoryInstanceId, uuid);
  assert.deepEqual(rest, { ...original, revision: original.revision + 1 });
  assert.equal(readFileSync(database).includes(Buffer.from('LEGACY_STATE_CANARY')), false);
  const reopened = new LedgerStore(database, key);
  try { assert.deepEqual(JSON.parse(JSON.stringify(reopened.read())), state); }
  finally { reopened.close(); }
});

test('failed identity migration rolls back the encrypted row and can be retried', t => {
  const database = databaseFor(t);
  const original = legacyLedger();
  original.audit[0].event = '';
  original.audit[0].event = 'x'.repeat(1000 - Buffer.byteLength(JSON.stringify(original)));
  assert.equal(Buffer.byteLength(JSON.stringify(original)), 1000);
  writeFixture(database, original);
  const payload = payloadAt(database);
  assert.throws(() => new LedgerStore(database, key, 1024), { code: 'STORE_UNAVAILABLE' });
  assert.equal(payloadAt(database), payload, 'the original ciphertext survives rollback exactly');
  assert.equal(Object.hasOwn(previousRead(payloadAt(database)), 'inventoryInstanceId'), false);
  const retried = new LedgerStore(database, key);
  try {
    assert.match(retried.read().inventoryInstanceId, uuid);
    assert.equal(retried.read().revision, original.revision + 1);
  } finally { retried.close(); }
});

test('the previous schema-1 reader and writer preserve the additive identity', t => {
  const database = databaseFor(t);
  const store = new LedgerStore(database, key);
  const identity = store.read().inventoryInstanceId;
  store.close();
  const oldState = previousRead(payloadAt(database));
  assert.equal(oldState.inventoryInstanceId, identity);
  oldState.revision++;
  oldState.audit.push({ time: 10, event: 'OLD_READER_WRITE' });
  const db = new DatabaseSync(database);
  try { db.prepare('UPDATE ledger SET payload=? WHERE id=1').run(seal(oldState)); }
  finally { db.close(); }
  const reopened = new LedgerStore(database, key);
  try {
    assert.equal(reopened.read().inventoryInstanceId, identity);
    assert.equal(reopened.read().revision, 1);
    assert.equal(reopened.read().audit[0].event, 'OLD_READER_WRITE');
  } finally { reopened.close(); }
});

for (const identity of [null, '', 123, 'not-a-uuid', '00000000-0000-1000-8000-000000000000']) {
  test(`an invalid existing inventory identity is rejected, never replaced: ${JSON.stringify(identity)}`, t => {
    const database = databaseFor(t);
    writeFixture(database, { ...legacyLedger(), inventoryInstanceId: identity });
    const payload = payloadAt(database);
    assert.throws(() => new LedgerStore(database, key), { code: 'STORE_UNAVAILABLE' });
    assert.equal(payloadAt(database), payload);
  });
}

test('an incorrect key cannot cause legacy identity migration', t => {
  const database = databaseFor(t);
  writeFixture(database, legacyLedger());
  const payload = payloadAt(database);
  assert.throws(() => new LedgerStore(database, Buffer.alloc(32, 38)), { code: 'STORE_UNAVAILABLE' });
  assert.equal(payloadAt(database), payload);
});
