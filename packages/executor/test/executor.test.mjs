import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { DurableExecutor, startExecutorServer } from '../dist/index.js';

const key = Buffer.alloc(32, 7);
const task = (id = 'task', extra = {}) => ({ id, principalId: 'operator', tenantId: 'tenant',
  grants: [{ tool: 'test', resources: ['item'] }], budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100_000 }, ...extra });
function setup(t, options = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-test-')));
  const config = { database: join(directory, 'ledger.sqlite'), encryptionKey: key, clock: () => 1000, ...options };
  const executor = new DurableExecutor(config);
  const owners = [executor];
  t.after(() => { try { for (const owner of owners) owner.close(); } finally { rmSync(directory, { recursive: true, force: true }); } });
  return { executor, config, reopen() { const next = new DurableExecutor(config); owners.push(next); return next; } };
}
function tool(executor, execute, extra = {}) {
  const fingerprint = executor.registerTool({ name: 'test', description: 'test', maxCost: 5,
    resolve: () => ({ resourceId: 'item', tenantId: 'tenant' }), execute, ...extra });
  executor.approveTool('test', fingerprint);
}
test('normalized arguments and resource version are immutable; one approval permits one effect', async t => {
  const { executor } = setup(t); let effects = 0;
  tool(executor, args => { effects++; return { value: args, actualCost: 3 }; }, {
    requiresApproval: true,
    parse: value => { if (typeof value?.name !== 'string') throw Error(); return { name: value.name.trim() }; },
    resolve: () => ({ resourceId: 'item', tenantId: 'tenant', resourceVersion: 'v1' }),
  });
  executor.createTask(task());
  await assert.rejects(executor.prepare('task', { tool: 'test', args: {} }), { code: 'ARGUMENT_INVALID' });
  const action = await executor.prepare('task', { tool: 'test', args: { name: ' safe ' } });
  assert.equal(action.action.args.name, 'safe'); assert.equal(action.action.resourceVersion, 'v1');
  await assert.rejects(executor.execute('task', action.id), { code: 'APPROVAL_REQUIRED' });
  const approvalId = executor.approve(action.id, { approverId: 'reviewer', expiresAt: 2000 });
  const results = await Promise.allSettled([executor.execute('task', action.id, { approvalId }), executor.execute('task', action.id, { approvalId })]);
  assert.equal(results.filter(item => item.status === 'fulfilled').length, 1); assert.equal(effects, 1);
  assert.equal(executor.snapshot('task').spent, 3); assert.equal(executor.snapshot('task').reserved, 0);
});
test('uncertain effects retain ancestor reservations and require one evidence-backed reconciliation', async t => {
  const { executor } = setup(t);
  tool(executor, () => { throw Error('secret backend exception'); });
  executor.createTask(task('parent', { budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 5, deadline: 100_000 } }));
  const child = executor.delegateTask('parent', { id: 'child', grants: task().grants, budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 5, deadline: 100_000 } });
  const action = await executor.prepare(child.taskId, { tool: 'test', args: null });
  await assert.rejects(executor.execute(child.taskId, action.id), { code: 'TOOL_FAILED', message: 'TOOL_FAILED' });
  assert.equal(executor.execution(child.taskId, action.id).status, 'UNKNOWN');
  assert.equal(executor.snapshot('parent').reserved, 5); assert.equal(executor.snapshot('parent').concurrent, 1);
  await assert.rejects(executor.prepare(child.taskId, { tool: 'test', args: null }), { code: 'CONCURRENCY_EXCEEDED' });
  executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 2, reference: 'provider-receipt-17' });
  assert.equal(executor.snapshot('parent').spent, 2); assert.equal(executor.snapshot('parent').concurrent, 0);
  assert.throws(() => executor.reconcile(action.id, { outcome: 'FAILED', actualCost: 2, reference: 'same' }), { code: 'RECONCILIATION_INVALID' });
});
test('restart preserves revocation, rejects stale preparations and keeps the store encrypted/exclusive', async t => {
  const { executor, config, reopen } = setup(t);
  tool(executor, () => ({ value: true }));
  const credential = executor.createTask(task());
  const action = await executor.prepare('task', { tool: 'test', args: { secret: 'synthetic-persistent-secret' } });
  executor.createTask(task('still-live'));
  const stale = await executor.prepare('still-live', { tool: 'test', args: null });
  assert.throws(() => new DurableExecutor(config), { code: 'STORE_UNAVAILABLE' });
  executor.revokeTask('task'); executor.close();
  assert.equal(readFileSync(config.database).includes(Buffer.from('synthetic-persistent-secret')), false);
  assert.throws(() => new DurableExecutor({ ...config, encryptionKey: Buffer.alloc(32, 8) }), { code: 'STORE_UNAVAILABLE' });
  const reopened = reopen();
  tool(reopened, () => ({ value: true }));
  assert.throws(() => reopened.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
  await assert.rejects(reopened.execute('task', action.id), { code: 'TASK_REVOKED' });
  await assert.rejects(reopened.execute('still-live', stale.id), { code: 'POLICY_CHANGED' });
});
test('transitive provenance revocation survives restart and blocks derived roots', async t => {
  const { executor, reopen } = setup(t);
  executor.createTask(task('source'));
  executor.createTask(task('second'), { sourceTaskId: 'source' });
  const leaf = executor.createTask(task('third'), { sourceTaskId: 'second' });
  assert.deepEqual(executor.provenanceTaskIds('third'), ['third', 'second', 'source']);
  executor.close();
  const reopened = reopen();
  reopened.revokeTask('source');
  assert.throws(() => reopened.authenticate(leaf.token), { code: 'UNAUTHENTICATED' });
  assert.throws(() => reopened.assertProvenance('third'), { code: 'TASK_REVOKED' });
  assert.throws(() => reopened.createTask(task('fourth'), { sourceTaskId: 'third' }), { code: 'TASK_REVOKED' });
});
test('process exit during a handler recovers UNKNOWN without refunding budget or retrying', async t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-crash-')));
  let executor;
  t.after(() => { executor?.close(); rmSync(directory, { recursive: true, force: true }); });
  const database = join(directory, 'ledger.sqlite');
  const module = new URL('../dist/index.js', import.meta.url).href;
  const script = `import {DurableExecutor} from ${JSON.stringify(module)};
    const e = new DurableExecutor({database:process.argv[1],encryptionKey:Buffer.alloc(32,7),clock:()=>1000});
    const fp=e.registerTool({name:'test',description:'test',maxCost:5,resolve:()=>({resourceId:'item',tenantId:'tenant'}),execute:()=>process.exit(17)});
    e.approveTool('test',fp);e.createTask(${JSON.stringify(task())});
    const a=await e.prepare('task',{tool:'test',args:null});process.stdout.write(a.id+'\\n');await e.execute('task',a.id);`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script, database], { encoding: 'utf8' });
  assert.equal(child.status, 17, child.stderr);
  executor = new DurableExecutor({ database, encryptionKey: key, clock: () => 1000 });
  assert.equal(executor.execution('task', child.stdout.trim()).status, 'UNKNOWN');
  assert.equal(executor.snapshot('task').reserved, 5); assert.equal(executor.snapshot('task').calls, 1);
});
test('clock rollback and policy-time revocation prevent dispatch', async t => {
  let now = 1000; let effects = 0; let revoke;
  const { executor } = setup(t, { clock: () => now, policy: async () => { if (revoke) executor.revokeTask(revoke); return 'allow'; } });
  tool(executor, () => { effects++; return { value: true }; }); executor.createTask(task());
  const action = await executor.prepare('task', { tool: 'test', args: null });
  revoke = 'task'; await assert.rejects(executor.execute('task', action.id)); assert.equal(effects, 0);
  now = 999; assert.throws(() => executor.markSensitive('task'), { code: 'CLOCK_INVALID' });
});
test('HTTP binds task and approver identities and rejects browser/unauthenticated/admin forgery', async t => {
  const { executor } = setup(t); let effects = 0;
  tool(executor, () => { effects++; return { value: 'ok' }; }, { requiresApproval: true });
  const credential = executor.createTask(task());
  const other = executor.createTask(task('other'));
  const admin = 'A'.repeat(43);
  const server = await startExecutorServer({ executor, adminToken: admin, operatorId: 'authenticated-reviewer', maxRequestBytes: 4096 });
  t.after(() => server.close());
  const post = async (path, token, body, headers = {}) => {
    const response = await fetch(`${server.url}/v1/${path}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  assert.equal((await post('task/snapshot', 'unknown', {})).status, 401);
  assert.equal((await post('task/snapshot', credential.token, {}, { origin: 'http://evil.invalid' })).status, 400);
  assert.equal((await post('admin/audit', credential.token, {})).status, 401);
  const prepared = (await post('task/prepare', credential.token, { tool: 'test', args: null })).body;
  assert.equal((await post('task/execute', other.token, { actionId: prepared.id })).body.error, 'INVALID_PREPARED');
  assert.equal((await post('admin/approve', admin, { actionId: prepared.id, expiresAt: 2000, approverId: 'forged' })).status, 400);
  const approval = (await post('admin/approve', admin, { actionId: prepared.id, expiresAt: 2000 })).body;
  assert.equal((await post('task/execute', credential.token, { actionId: prepared.id, approvalId: approval.approvalId })).body.value, 'ok');
  assert.equal(effects, 1);
});
