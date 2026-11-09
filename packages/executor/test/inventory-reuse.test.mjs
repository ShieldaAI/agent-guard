import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '../dist/index.js';
import { createInventoryObservationSession } from '../dist/inventory-observer.js';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function setup(t) {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    inventory: { companyId: 'company', sourceId: 'installation', enrollmentGeneration: 'generation' },
  });
  executor.approveTool(
    'read',
    executor.registerTool({
      name: 'read',
      description: 'fixture',
      maxCost: 0,
      resolve: () => ({ resourceId: 'resource', tenantId: 'alpha' }),
      execute: () => ({ value: null }),
    }),
  );
  const create = (id, tenantId) =>
    executor.createTask({
      id,
      tenantId,
      principalId: `principal-${id}`,
      grants: [{ tool: 'read', resources: ['resource'] }],
      budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
    });
  create('alpha', 'alpha');
  create('beta', 'beta');
  t.after(() => executor.close());
  return { executor, create };
}
const request = (tenantId = 'alpha') => ({
  scope: { tenantId },
  profile: 'core',
  signal: new AbortController().signal,
  deadline: performance.now() + 10_000,
});
const id = observation => JSON.parse(observation.json).snapshotId;

test('an identical poll within the reuse window returns the previous observation', async t => {
  const f = setup(t);
  const session = await createInventoryObservationSession(f.executor, 'default', { reuseUnchangedMs: 60_000 });
  t.after(() => session.close());
  const first = await session.snapshot(request());
  const second = await session.snapshot(request());
  assert.equal(second.json, first.json, 'same ledger, scope and registry: no new projection');
  assert.notEqual(
    id(await session.snapshot(request('beta'))),
    id(first),
    'another tenant scope is projected separately',
  );
  f.create('alpha-2', 'alpha');
  const changed = await session.snapshot(request());
  assert.notEqual(id(changed), id(first), 'a ledger write invalidates reuse');
  assert.equal(JSON.parse(changed.json).tasks.length, JSON.parse(first.json).tasks.length + 1);
});

test('reuse expires after the window and is off by default', async t => {
  const f = setup(t);
  const short = await createInventoryObservationSession(f.executor, 'default', { reuseUnchangedMs: 40 });
  t.after(() => short.close());
  const first = await short.snapshot(request());
  await sleep(60);
  assert.notEqual(id(await short.snapshot(request())), id(first));
  const g = setup(t);
  const off = await createInventoryObservationSession(g.executor);
  t.after(() => off.close());
  assert.notEqual(id(await off.snapshot(request())), id(await off.snapshot(request())));
});

test('the reuse window is validated', async t => {
  const f = setup(t);
  for (const reuseUnchangedMs of [-1, 60_001, 1.5]) {
    await assert.rejects(createInventoryObservationSession(f.executor, 'default', { reuseUnchangedMs }), {
      code: 'INVENTORY_CONFIG_INVALID',
    });
  }
});
