import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import * as publicApi from '../dist/index.js';
import { projectInventory, projectInventoryJson } from '../dist/inventory.js';

const source = { companyId: 'company', sourceId: 'source', enrollmentGeneration: 'generation' };
const scope = { tenantId: 'tenant' }, time = Date.UTC(2026, 10, 6);
const ledger = () => ({ schema: 1, revision: 4, epoch: 2, inventoryInstanceId: 'instance',
  tasks: { task: { options: { id: 'task', tenantId: 'tenant', principalId: 'principal',
    grants: [{ tool: 'read', resources: ['record'] }], allowedRecipients: ['record'],
    budget: { maxCalls: 3, maxConcurrent: 1, maxCost: 0, deadline: time + 1000 } },
    parent: null, family: 'family', revoked: false, calls: 0, concurrent: 0, spent: 0, reserved: 0 } },
  families: { family: { sensitive: false } }, tools: {} });

function compare(state, enrollment = source, selected = scope, key) {
  const snapshot = projectInventory(state, new Map(), enrollment, selected, time, key);
  const result = projectInventoryJson(state, new Map(), enrollment, selected, time, key);
  const parsed = JSON.parse(result.json);
  assert.equal(result.json, JSON.stringify(snapshot)
    .replace(`"snapshotId":"${snapshot.snapshotId}"`, `"snapshotId":"${parsed.snapshotId}"`));
  assert.equal(result.bytes, Buffer.byteLength(result.json, 'utf8'));
  assert.deepEqual({ ...result.source }, parsed.source);
  assert.equal(result.profile, parsed.profile);
  return result;
}

test('direct core serialization stays private and returns actual detached source metadata', () => {
  assert.equal(Object.hasOwn(publicApi, 'projectInventoryJson'), false);
  const state = ledger(), enrollment = { ...source }, selected = { ...scope };
  const first = compare(state, enrollment, selected, Buffer.alloc(32, 1));
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.source), true);
  assert.throws(() => { first.source.tenantId = 'foreign'; }, TypeError);
  state.tasks.task.calls = 2; state.revision = 8; state.epoch = 3;
  state.inventoryInstanceId = 'replacement-instance'; enrollment.companyId = 'replacement-company';
  state.tasks.task.options.tenantId = 'other'; selected.tenantId = 'other';
  const next = compare(state, enrollment, selected, Buffer.alloc(32, 2));
  assert.equal(first.source.companyId, 'company'); assert.equal(first.source.tenantId, 'tenant');
  assert.equal(first.source.inventoryInstanceId, 'instance');
  assert.equal(JSON.parse(first.json).tasks[0].usage.calls, 0);
  assert.equal(next.source.companyId, 'replacement-company'); assert.equal(next.source.tenantId, 'other');
  assert.equal(next.source.inventoryInstanceId, 'replacement-instance');
  assert.equal(JSON.parse(next.json).tasks[0].usage.calls, 2);
  assert.equal(JSON.parse(next.json).ledgerRevision, 8);
  assert.equal(JSON.parse(next.json).policyEpoch, 3);
  assert.notEqual(JSON.parse(next.json).snapshotId, JSON.parse(first.json).snapshotId);
  assert.notDeepEqual(JSON.parse(first.json).tasks[0].grants, JSON.parse(next.json).tasks[0].grants);
});

test('direct numeric encoding preserves JavaScript canonical bytes including negative zero and exponents', () => {
  for (const deadline of [-0, 0, Number.MIN_VALUE, 1e-7, 1e-6, 0.25, time + 0.25, Number.MAX_SAFE_INTEGER]) {
    const state = ledger(); state.tasks.task.options.budget.deadline = deadline;
    state.tasks.task.calls = -0; state.revision = -0;
    const result = compare(state);
    assert.equal(Object.is(JSON.parse(result.json).tasks[0].budget.deadline, -0), false);
  }
});

test('direct projection does not parse its own JSON or inspect non-inventory private state', () => {
  const state = ledger(); let invoked = 0;
  const forbidden = () => { invoked++; throw new Error('private callback'); };
  for (const key of ['actions', 'approvals', 'audit', 'memory'])
    Object.defineProperty(state, key, { get: forbidden });
  const original = JSON.parse;
  let result;
  try { JSON.parse = forbidden; result = projectInventoryJson(state, new Map(), source, scope, time); }
  finally { JSON.parse = original; }
  assert.equal(invoked, 0); assert.equal(JSON.parse(result.json).tasks.length, 1);
});

test('private constructed serializer retains depth and non-JSON guards without adding an input API', () => {
  // Exercise the actual compiled private function, not a copied test encoder.
  // These future-constructor guards are unreachable through today's fixed schema.
  const compiled = readFileSync(new URL('../dist/inventory.js', import.meta.url), 'utf8');
  const start = compiled.indexOf('function serializeConstructedInventory(');
  const end = compiled.indexOf('\n/** Fresh snapshot-local constructors', start);
  assert.ok(start >= 0 && end > start);
  const serialize = runInNewContext(`${compiled.slice(start, end)}\nserializeConstructedInventory`, {
    Buffer, MAX_BYTES: 8 * 1024 * 1024, MAX_VALUES: 500000,
    fail: code => { throw Object.assign(new Error(code), { code }); },
  });
  const nested = depth => {
    let value = 'leaf'; for (let index = 0; index < depth; index++) value = { child: value };
    return value;
  };
  const accepted = serialize({ tasks: [], nested: nested(31) });
  assert.equal(accepted.bytes, Buffer.byteLength(accepted.json));
  assert.throws(() => serialize({ tasks: [], nested: nested(32) }), { code: 'INVENTORY_LIMIT_EXCEEDED' });
  for (const invalid of [undefined, () => {}, 1n, Symbol('private'), NaN, Infinity, -Infinity])
    assert.throws(() => serialize({ tasks: [], invalid }), { code: 'INVENTORY_LIMIT_EXCEEDED' });
});
