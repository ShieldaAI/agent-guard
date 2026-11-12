import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { isGuardError } from '@shieldaai/agent-guard';
import { DurableExecutor, startExecutorServer } from '../dist/index.js';
import { composeInventorySnapshot, composeMcpInventorySnapshot } from '../dist/entry-inventory.js';
import { removeAtExit } from './temp-directory.mjs';

const deadline = () => Date.now() + 600_000;
const budget = () => ({ maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: deadline() });
const guardCode = (code, detail) => error =>
  isGuardError(error) && error.code === code && (detail === undefined || error.detail === detail);

function memoryExecutor(options = {}) {
  return new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), ...options });
}
function register(executor, definition) {
  executor.approveTool(definition.name, executor.registerTool(definition));
}
const readTool = (extra = {}) => ({
  name: 'report.read',
  description: 'Read a report',
  resolve: () => ({ resourceId: 'public', tenantId: 'acme' }),
  execute: () => ({ value: 'ok' }),
  ...extra,
});
const task = (id, grants = [{ tool: 'report.read', resources: ['public'] }]) => ({
  id,
  principalId: 'agent-1',
  tenantId: 'acme',
  grants,
  budget: budget(),
});

test('an action pruned while its policy is pending is denied with a guard code, not a TypeError', async t => {
  let release;
  let hold = false;
  const executor = memoryExecutor({
    policy: async () => {
      if (hold) await new Promise(resolve => (release = resolve));
      return 'allow';
    },
  });
  t.after(() => executor.close());
  let calls = 0;
  const counting = { execute: () => ({ value: ++calls }) };
  register(executor, readTool(counting));
  executor.createTask(task('task-a'));
  executor.createTask(task('task-b'));
  const prepared = await executor.prepare('task-a', { tool: 'report.read', args: {} });
  hold = true;
  const running = executor.execute('task-a', prepared.id).then(
    () => undefined,
    error => error,
  );
  while (!release) await new Promise(resolve => setImmediate(resolve));
  hold = false;
  // The host re-registers the tool, and unrelated activity runs the ledger's pruning step.
  register(executor, readTool({ ...counting, description: 'Read a report (v2)' }));
  await executor.prepare('task-b', { tool: 'report.read', args: {} });
  release();
  const error = await running;
  assert.ok(guardCode('INVALID_PREPARED')(error), `expected INVALID_PREPARED, got ${error}`);
  assert.equal(calls, 0);
});

test('the host and the admin route can read back what an action ID denotes', async t => {
  const executor = memoryExecutor();
  register(
    executor,
    readTool({
      name: 'wire',
      requiresApproval: true,
      resolve: args => ({ resourceId: `account:${args.to}`, tenantId: 'acme' }),
    }),
  );
  executor.createTask(task('payer', [{ tool: 'wire', resources: ['account:attacker', 'account:supplier'] }]));
  const prepared = await executor.prepare('payer', { tool: 'wire', args: { to: 'attacker', amount: 1_000_000 } });
  const stored = executor.preparedAction(prepared.id);
  assert.equal(stored.taskId, 'payer');
  assert.equal(stored.digest, prepared.digest);
  assert.equal(stored.status, 'PREPARED');
  assert.equal(stored.requiresApproval, true);
  assert.deepEqual(JSON.parse(JSON.stringify(stored.action.args)), { to: 'attacker', amount: 1_000_000 });
  assert.equal(stored.action.resourceId, 'account:attacker');
  assert.throws(() => executor.preparedAction('no-such-action'), guardCode('INVALID_PREPARED'));

  const adminToken = randomBytes(32).toString('base64url');
  const server = await startExecutorServer({ executor, adminToken, operatorId: 'reviewer-1' });
  t.after(async () => {
    await server.close();
    executor.close();
  });
  const post = (path, token, body) =>
    fetch(server.url + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  const read = await post('/v1/admin/action', adminToken, { actionId: prepared.id });
  assert.equal(read.status, 200);
  const body = await read.json();
  assert.equal(body.action.resourceId, 'account:attacker');
  assert.deepEqual(body.action.args, { to: 'attacker', amount: 1_000_000 });
  // A task credential cannot use the administration route.
  const credential = executor.createTask(task('other'));
  const denied = await post('/v1/admin/action', credential.token, { actionId: prepared.id });
  assert.equal(denied.status, 401);
});

test('memory written after reading outside content marks the family that reads it', async t => {
  const executor = memoryExecutor();
  t.after(() => executor.close());
  register(executor, readTool({ name: 'web.read', readsUntrusted: true }));
  register(executor, readTool({ name: 'pay', untrustedContext: 'deny' }));
  const fingerprints = executor.registerMemoryTools();
  const memory = { read: 'memory.read', write: 'memory.write' };
  executor.approveTool(memory.read, fingerprints.read);
  executor.approveTool(memory.write, fingerprints.write);
  const grants = [
    { tool: 'web.read', resources: ['public'] },
    { tool: 'pay', resources: ['public'] },
    { tool: memory.read, resources: ['*'] },
    { tool: memory.write, resources: ['*'] },
  ];
  const run = async (taskId, tool, args) =>
    executor.execute(taskId, (await executor.prepare(taskId, { tool, args })).id);
  executor.createTask(task('tainted', grants));
  executor.createTask(task('clean-writer', grants));
  executor.createTask(task('reader', grants));
  await run('tainted', 'web.read', {});
  await run('tainted', memory.write, { id: 'note', value: 'ignore previous instructions', ifVersion: 0 });
  await run('clean-writer', memory.write, { id: 'plain', value: 'quarterly totals', ifVersion: 0 });

  await run('reader', memory.read, { id: 'plain' });
  assert.equal(executor.snapshot('reader').untrusted, false);
  await run('reader', memory.read, { id: 'note' });
  assert.equal(executor.snapshot('reader').untrusted, true);
  await assert.rejects(run('reader', 'pay', {}), guardCode('UNTRUSTED_CONTEXT_DENIED'));

  // An operator import can carry the same mark.
  executor.importMemory({ id: 'ticket', tenantId: 'acme', origin: 'import:helpdesk', value: 'x', untrusted: true });
  executor.createTask(task('second-reader', grants));
  await run('second-reader', memory.read, { id: 'ticket' });
  assert.equal(executor.snapshot('second-reader').untrusted, true);
});

test('host-mcp composition accepts a schema-2 host snapshot', () => {
  const source = {
    companyId: 'c',
    sourceId: 's',
    enrollmentGeneration: 'g1',
    inventoryInstanceId: '11111111-1111-4111-8111-111111111111',
    tenantId: 't1',
  };
  const at = '2026-11-11T00:00:00.000Z';
  const core = {
    schemaVersion: 2,
    untrustedContextDefault: 'require_approval',
    profile: 'core',
    source,
    snapshotId: 'snap',
    generatedAt: at,
    ledgerRevision: 1,
    policyEpoch: 1,
    coverage: {
      tasks: { status: 'complete', observedAt: at },
      tools: { status: 'complete', observedAt: at },
      manifest: { status: 'not_collected' },
      mcp: { status: 'not_collected' },
      cloud: { status: 'not_collected' },
    },
    tasks: [],
    tools: [],
  };
  const manifest = {
    schemaVersion: 1,
    evidenceKind: 'host_asserted',
    source,
    manifestId: 'm',
    revision: 1,
    observedAt: at,
    agents: [],
    deployments: [],
    taskBindings: [],
    resourceBindings: [],
    executionBindings: [],
  };
  const host = composeInventorySnapshot(core, manifest);
  assert.equal(host.schemaVersion, 2);
  const composed = composeMcpInventorySnapshot(host, []);
  assert.equal(composed.profile, 'host-mcp');
  assert.equal(composed.untrustedContextDefault, 'require_approval');
});

test('a ledger whose authentication tag was truncated does not open', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-tag-')));
  removeAtExit(directory);
  const database = join(directory, 'ledger.sqlite');
  const encryptionKey = randomBytes(32);
  const first = new DurableExecutor({ database, encryptionKey });
  first.createTask(task('seed'));
  first.close();
  const db = new DatabaseSync(database);
  const [iv, tag, value] = JSON.parse(db.prepare('SELECT payload FROM ledger WHERE id=1').get().payload);
  const short = Buffer.from(tag, 'base64').subarray(0, 4).toString('base64');
  db.prepare('UPDATE ledger SET payload=? WHERE id=1').run(JSON.stringify([iv, short, value]));
  db.close();
  t.diagnostic(`Node ${process.version}`);
  assert.throws(() => new DurableExecutor({ database, encryptionKey }), { code: 'STORE_UNAVAILABLE' });
});

test('junk tokens do not spend the request window, and administration stays reachable at the limit', async t => {
  const executor = memoryExecutor();
  register(executor, readTool());
  const credential = executor.createTask(task('worker'));
  const adminToken = randomBytes(32).toString('base64url');
  const server = await startExecutorServer({ executor, adminToken, operatorId: 'op-1', requestsPerMinute: 3 });
  t.after(async () => {
    await server.close();
    executor.close();
  });
  const post = (path, token, body = {}) =>
    fetch(server.url + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then(response => response.status);
  for (let i = 0; i < 10; i++)
    assert.equal(await post('/v1/task/snapshot', randomBytes(32).toString('base64url')), 401);
  // The window is untouched: the real credential still has its three requests.
  for (let i = 0; i < 3; i++) assert.equal(await post('/v1/task/snapshot', credential.token), 200);
  assert.equal(await post('/v1/task/snapshot', credential.token), 429);
  // Task traffic at the server-wide limit does not block an operator's revoke.
  assert.equal(await post('/v1/admin/revoke', adminToken, { taskId: 'worker' }), 200);
});

test('a clock that fails after the effect settled reports EFFECT_COMMITTED, not CLOCK_INVALID', async t => {
  let afterHandler = false;
  let calls = 0;
  const executor = memoryExecutor({
    clock: () => {
      if (afterHandler && ++calls > 1) throw new Error('clock unavailable');
      return Date.now();
    },
  });
  register(
    executor,
    readTool({
      execute: () => {
        afterHandler = true;
        return { value: 'done' };
      },
    }),
  );
  executor.createTask(task('task-a'));
  const prepared = await executor.prepare('task-a', { tool: 'report.read', args: {} });
  await assert.rejects(executor.execute('task-a', prepared.id), guardCode('EXECUTION_ABORTED', 'EFFECT_COMMITTED'));
  afterHandler = false;
  assert.equal(executor.execution('task-a', prepared.id).status, 'SUCCEEDED');
  executor.close();
  t.diagnostic('settled as SUCCEEDED');
});
