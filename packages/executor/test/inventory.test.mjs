import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';

const enrollment = { companyId: 'company', sourceId: 'installation', enrollmentGeneration: 'generation-1' };
const budget = { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100_000.5 };
const task = (id = 'root', extra = {}) => ({ id, tenantId: 'tenant', principalId: 'caller',
  grants: [{ tool: 'read', resources: ['item'] }], budget, ...extra });
const plain = value => JSON.parse(JSON.stringify(value));
function setup(t, extra = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-inventory-')));
  const options = { database: join(directory, 'state.sqlite'), encryptionKey: Buffer.alloc(32, 7),
    clock: () => 1000, inventory: enrollment, ...extra };
  const owners = [];
  const open = (changes = {}) => { const executor = new DurableExecutor({ ...options, ...changes }); owners.push(executor); return executor; };
  t.after(() => { try { for (const owner of owners) owner.close(); } finally { rmSync(directory, { recursive: true, force: true }); } });
  return { executor: open(), open, options };
}
function register(executor, extra = {}) {
  const definition = { name: 'read', description: 'private-description-canary',
    inputSchema: { secret: 'private-schema-canary' }, metadata: { url: 'https://user:private-password@example.invalid/' },
    requiresApproval: true, maxCost: 5,
    resolve: () => ({ resourceId: 'item', tenantId: 'tenant' }), execute: () => ({ value: 'private-result-canary', actualCost: 2 }), ...extra };
  const fingerprint = executor.registerTool(definition);
  executor.approveTool(definition.name, fingerprint);
  return fingerprint;
}

test('inventory reads one revision without callbacks, state mutation or consuming an approval', async t => {
  const counts = { clock: 0, policy: 0, parse: 0, resolve: 0, execute: 0 };
  const { executor } = setup(t, { clock: () => { counts.clock++; return 1000; }, policy: () => { counts.policy++; return 'allow'; } });
  const fingerprint = register(executor, {
    parse: value => { counts.parse++; return value; },
    resolve: () => { counts.resolve++; return { resourceId: 'item', tenantId: 'tenant' }; },
    execute: () => { counts.execute++; return { value: 'private-result-canary', actualCost: 2 }; },
  });
  const credential = executor.createTask(task());
  executor.importMemory({ id: 'private-memory-id', tenantId: 'tenant', origin: 'private-origin', value: 'private-memory-canary' });
  const action = await executor.prepare('root', { tool: 'read', args: { payload: 'private-arguments-canary' } });
  const approvalId = executor.approve(action.id, { approverId: 'private-approver', expiresAt: 2000 });
  const beforeCounts = { ...counts };
  const originalRead = LedgerStore.prototype.read;
  const reads = [];
  const reader = t.mock.method(LedgerStore.prototype, 'read', function () {
    const state = originalRead.call(this); reads.push({ state, before: JSON.stringify(state) }); return state;
  });
  const transaction = t.mock.method(LedgerStore.prototype, 'transaction', () => { assert.fail('inventory wrote the ledger'); });
  const snapshot = executor.inventorySnapshot({ tenantId: 'tenant' });
  assert.equal(reads.length, 1);
  assert.equal(JSON.stringify(reads[0].state), reads[0].before);
  assert.equal(snapshot.ledgerRevision, reads[0].state.revision);
  assert.equal(snapshot.policyEpoch, reads[0].state.epoch);
  assert.deepEqual(counts, beforeCounts);
  reader.mock.restore(); transaction.mock.restore();
  const next = executor.inventorySnapshot({ tenantId: 'tenant' });
  assert.equal(next.ledgerRevision, snapshot.ledgerRevision);
  assert.notEqual(next.snapshotId, snapshot.snapshotId);
  assert.deepEqual(next.tasks, snapshot.tasks);
  assert.deepEqual(next.tools, snapshot.tools);
  assert.equal(snapshot.tools[0].fingerprint, fingerprint.slice('sha256:'.length));
  const serialized = JSON.stringify(snapshot);
  for (const secret of [credential.token, createHash('sha256').update(credential.token).digest('hex'), approvalId, action.id,
    'private-description-canary', 'private-schema-canary', 'private-password', 'private-memory-canary', 'private-memory-id',
    'private-origin', 'private-approver', 'private-arguments-canary', 'private-result-canary', Buffer.alloc(32, 7).toString('hex')]) {
    assert.equal(serialized.includes(secret), false, 'private value reached inventory');
  }
  assert.deepEqual(Object.keys(snapshot).sort(), ['coverage', 'generatedAt', 'ledgerRevision', 'policyEpoch', 'profile', 'schemaVersion', 'snapshotId', 'source', 'tasks', 'tools']);
  assert.deepEqual(Object.keys(snapshot.tasks[0]).sort(), ['allowControlPlane', 'allowedRecipients', 'budget', 'familyId', 'grants', 'id', 'parentTaskId', 'principalId', 'revoked', 'sensitive', 'sourceTaskId', 'tenantId', 'usage']);
  assert.deepEqual(Object.keys(snapshot.tools[0]).sort(), ['approved', 'controlPlane', 'fingerprint', 'maxCost', 'name', 'registered', 'requiresApproval', 'revision']);
  assert.equal(Object.isFrozen(snapshot.tasks[0].grants[0].resources), true);
  assert.throws(() => { snapshot.tasks[0].budget.maxCost = 999; }, TypeError);
  assert.equal(await executor.execute('root', action.id, { approvalId }), 'private-result-canary');
  assert.equal(executor.snapshot('root').spent, 2);
  assert.equal(snapshot.tasks[0].usage.spent, 0);
});

test('complete tenant projection preserves delegation versus independent provenance and historical tasks', t => {
  const { executor } = setup(t, { inventory: { ...enrollment, referenceMode: 'raw' } });
  register(executor);
  register(executor, { name: 'write' });
  register(executor, { name: 'other-tenant-tool' });
  executor.createTask(task('root', { grants: [{ tool: 'read', resources: ['b', 'a', 'a'] }, { tool: 'read', resources: ['a'] },
    { tool: 'unknown', resources: ['*'] }], allowedRecipients: ['z', 'a', 'z'] }));
  executor.delegateTask('root', { id: 'child', grants: [{ tool: 'read', resources: ['a'] }], budget });
  executor.createTask(task('handoff', { principalId: 'different-caller', grants: [{ tool: 'write', resources: ['new'] }],
    budget: { ...budget, maxCost: 100 } }), { sourceTaskId: 'child', sensitive: true });
  executor.createTask(task('foreign', { tenantId: 'foreign-tenant', grants: [{ tool: 'other-tenant-tool', resources: ['foreign-secret'] }] }));
  executor.revokeTask('root');
  // Deadlines are historical at wall-clock observation time; inventory never hides expired tasks.
  const snapshot = executor.inventorySnapshot({ tenantId: 'tenant' });
  assert.deepEqual(snapshot.tasks.map(item => item.id), ['child', 'handoff', 'root']);
  assert.deepEqual(snapshot.tools.map(item => item.name), ['read', 'write']);
  assert.equal(JSON.stringify(snapshot).includes('foreign'), false);
  const [child, handoff, root] = snapshot.tasks;
  assert.equal(child.parentTaskId, 'root'); assert.equal(child.sourceTaskId, null);
  assert.equal(handoff.parentTaskId, null); assert.equal(handoff.sourceTaskId, 'child');
  assert.equal(handoff.principalId, 'different-caller'); assert.equal(handoff.budget.maxCost, 100);
  assert.equal(root.revoked, true); assert.equal(handoff.revoked, false);
  assert.equal(snapshot.tasks.every(item => item.familyId === 'root' && item.sensitive), true);
  assert.deepEqual(plain(root.grants), [{ tool: 'read', resources: ['a', 'b'] }, { tool: 'unknown', resources: ['*'] }]);
  assert.deepEqual(root.allowedRecipients, ['a', 'z']); assert.equal(root.budget.deadline, 100_000.5);
  assert.deepEqual(plain(snapshot.coverage.manifest), { status: 'not_collected' });
  const empty = executor.inventorySnapshot({ tenantId: 'empty' });
  assert.deepEqual(empty.tasks, []); assert.deepEqual(empty.tools, []);
  assert.equal(empty.coverage.tasks.status, 'complete');
});

test('opaque references are stable across restart, tenant separated and exclude credential-bearing URLs', t => {
  const { executor, open } = setup(t);
  const resource = 'https://user:credential-canary@private.invalid/path?token=secret-canary';
  const options = task('root', { grants: [{ tool: 'read', resources: [resource, '*'] }], allowedRecipients: [resource] });
  register(executor);
  executor.createTask(options);
  executor.createTask({ ...options, id: 'same-tenant' });
  executor.createTask({ ...options, id: 'other-tenant', tenantId: 'other' });
  const first = executor.inventorySnapshot({ tenantId: 'tenant' });
  const references = first.tasks[0].grants[0].resources;
  assert.equal(references.includes('*'), true);
  assert.match(references.find(value => value !== '*'), /^opaque:[a-f0-9]{64}$/);
  assert.deepEqual(references, first.tasks[1].grants[0].resources);
  assert.notEqual(first.tasks[0].allowedRecipients[0], references.find(value => value !== '*'));
  assert.notDeepEqual(executor.inventorySnapshot({ tenantId: 'other' }).tasks[0].grants[0].resources, references);
  assert.equal(JSON.stringify(first).includes('canary'), false);
  executor.close();
  const reopened = open();
  const second = reopened.inventorySnapshot({ tenantId: 'tenant' });
  assert.equal(second.source.inventoryInstanceId, first.source.inventoryInstanceId);
  assert.deepEqual(second.tasks[0].grants[0].resources, references);
  assert.ok(second.ledgerRevision > first.ledgerRevision); assert.ok(second.policyEpoch > first.policyEpoch);
  assert.deepEqual(plain(second.tools[0]), { name: 'read', fingerprint: first.tools[0].fingerprint, revision: 1,
    registered: false, approved: false, requiresApproval: null, controlPlane: null, maxCost: null });
  register(reopened, { requiresApproval: false, controlPlane: true, maxCost: 0 });
  const third = reopened.inventorySnapshot({ tenantId: 'tenant' });
  assert.equal(third.tools[0].registered, true); assert.equal(third.tools[0].approved, true);
  assert.equal(third.tools[0].requiresApproval, false); assert.equal(third.tools[0].controlPlane, true); assert.equal(third.tools[0].revision, 2);
  reopened.close();
  const reenrolled = open({ inventory: { ...enrollment, enrollmentGeneration: 'generation-2' } });
  const fourth = reenrolled.inventorySnapshot({ tenantId: 'tenant' });
  assert.equal(fourth.source.inventoryInstanceId, first.source.inventoryInstanceId);
  assert.notDeepEqual(fourth.tasks[0].grants[0].resources, references);
});

test('inventory is opt-in, configuration is detached and scopes cannot filter tasks', t => {
  const disabled = setup(t, { inventory: undefined }).executor;
  assert.throws(() => disabled.inventorySnapshot({ tenantId: 'tenant' }), { code: 'INVENTORY_DISABLED' });
  const mutable = { ...enrollment };
  const { executor } = setup(t, { inventory: mutable });
  mutable.companyId = 'changed';
  assert.equal(executor.inventorySnapshot({ tenantId: 'tenant' }).source.companyId, enrollment.companyId);
  let called = false;
  for (const scope of [null, {}, { tenantId: '' }, { tenantId: ['tenant'] }, { tenantId: 'tenant', taskIds: [] },
    { get tenantId() { called = true; return 'tenant'; } }]) {
    assert.throws(() => executor.inventorySnapshot(scope), { code: 'INVENTORY_SCOPE_INVALID', message: 'INVENTORY_SCOPE_INVALID' });
  }
  for (const config of [{ ...enrollment, referenceMode: 'invalid' }, { ...enrollment, tenantId: 'tenant' }, null,
    { ...enrollment, get companyId() { called = true; return 'secret'; } }]) {
    assert.throws(() => new DurableExecutor({ database: ':memory:', encryptionKey: Buffer.alloc(32), inventory: config }),
      { code: 'INVENTORY_CONFIG_INVALID', message: 'INVENTORY_CONFIG_INVALID' });
  }
  assert.equal(called, false);
  executor.close();
  assert.throws(() => executor.inventorySnapshot({ tenantId: 'tenant' }), { code: 'STORE_CLOSED' });
});

test('a snapshot during an admitted effect keeps its reservation after later settlement', async t => {
  const { executor } = setup(t);
  let finish;
  const started = Promise.withResolvers();
  register(executor, { requiresApproval: false, execute: () => {
    started.resolve(); return new Promise(resolve => { finish = () => resolve({ value: true, actualCost: 2 }); });
  } });
  executor.createTask(task());
  const action = await executor.prepare('root', { tool: 'read', args: null });
  const running = executor.execute('root', action.id);
  await started.promise;
  try {
    const during = executor.inventorySnapshot({ tenantId: 'tenant' });
    assert.deepEqual(plain(during.tasks[0].usage), { calls: 1, concurrent: 1, reserved: 5, spent: 0 });
    finish(); await running;
    const after = executor.inventorySnapshot({ tenantId: 'tenant' });
    assert.deepEqual(plain(after.tasks[0].usage), { calls: 1, concurrent: 0, reserved: 0, spent: 2 });
    assert.equal(during.tasks[0].usage.reserved, 5); assert.ok(after.ledgerRevision > during.ledgerRevision);
  } finally { finish(); await running; }
});
