import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { request } from 'node:http';
import { DurableExecutor, ExecutorClient, ExecutorError, startExecutorServer } from '../dist/index.js';

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
  // The unresolved reservation blocks dispatch; preparation itself is not refused by transient capacity.
  const blocked = await executor.prepare(child.taskId, { tool: 'test', args: null });
  await assert.rejects(executor.execute(child.taskId, blocked.id), { code: 'CONCURRENCY_EXCEEDED' });
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
test('task and approval expiry during the durable commit prevent even a non-cooperative handler from starting', async t => {
  for (const code of ['TASK_EXPIRED', 'APPROVAL_EXPIRED']) {
    let checking = false, effects = 0;
    const deadline = code === 'TASK_EXPIRED' ? 2000 : 3000;
    const { executor } = setup(t, { decisionTraces: {}, clock: () =>
      checking && executor.decisionTraceSnapshot({ tenantId: 'tenant' }).events.some(event => event.event === 'admit') ? 2000 : 1000 });
    tool(executor, () => { effects++; return { value: true }; }, { requiresApproval: true });
    executor.createTask(task('task', { budget: { ...task().budget, deadline } }));
    const action = await executor.prepare('task', { tool: 'test', args: {} });
    const approvalId = executor.approve(action.id, { approverId: 'reviewer', expiresAt: 2000 });
    checking = true;
    await assert.rejects(executor.execute('task', action.id, { approvalId }), { code });
    assert.equal(effects, 0);
    assert.equal(executor.execution('task', action.id).status, 'FAILED');
    const { calls, concurrent, reserved, spent } = executor.snapshot('task');
    assert.deepEqual({ calls, concurrent, reserved, spent }, { calls: 1, concurrent: 0, reserved: 0, spent: 0 });
    await assert.rejects(executor.execute('task', action.id, { approvalId }), { code: 'ACTION_USED' });
  }
});
test('a faulty clock during an uncertain effect preserves a reconcilable reservation', async t => {
  let now = 1000, effects = 0;
  const { executor } = setup(t, { clock: () => now });
  tool(executor, () => { effects++; now = 999; throw Error('backend disconnected after effect'); });
  executor.createTask(task());
  const action = await executor.prepare('task', { tool: 'test', args: {} });
  await assert.rejects(executor.execute('task', action.id), { code: 'TOOL_FAILED' });
  assert.equal(executor.execution('task', action.id).status, 'UNKNOWN');
  assert.equal(executor.snapshot('task').reserved, 5);
  now = 1001;
  executor.reconcile(action.id, { outcome: 'SUCCEEDED', actualCost: 2, reference: 'backend-receipt' });
  assert.equal(executor.snapshot('task').spent, 2); assert.equal(executor.snapshot('task').reserved, 0);
  await assert.rejects(executor.execute('task', action.id), { code: 'ACTION_USED' }); assert.equal(effects, 1);
});
test('unapproved tools and revoked or expired tasks cannot trigger parser or resolver work', async t => {
  let now = 1000, parses = 0, resolutions = 0;
  const { executor } = setup(t, { clock: () => now });
  const fingerprint = executor.registerTool({ name: 'test', description: 'counts preflight work',
    parse: value => { parses++; return value; }, resolve: () => { resolutions++; return { resourceId: 'item', tenantId: 'tenant' }; }, execute: () => ({ value: true }) });
  executor.createTask(task('source')); executor.createTask(task('handoff'), { sourceTaskId: 'source' });
  const prepare = () => executor.prepare('handoff', { tool: 'test', args: null });
  await assert.rejects(prepare(), { code: 'TOOL_UNAPPROVED' });
  executor.approveTool('test', fingerprint);
  await prepare();
  executor.revokeTask('source');
  await assert.rejects(prepare(), { code: 'TASK_REVOKED' });
  executor.createTask(task('short')); now = task().budget.deadline;
  await assert.rejects(executor.prepare('short', { tool: 'test', args: null }), { code: 'TASK_EXPIRED' });
  assert.equal(parses, 1); assert.equal(resolutions, 1);
});
test('revocation between HTTP authentication and the last body byte blocks a task snapshot', async t => {
  const { executor } = setup(t);
  const { token } = executor.createTask(task());
  const service = await startExecutorServer({ executor, adminToken: 'A'.repeat(43), operatorId: 'reviewer' });
  t.after(() => service.close());
  const receivingBody = new Promise(resolve => service.server.once('request', resolve));
  const pending = request(service.url + '/v1/task/snapshot', { method: 'POST', headers: {
    authorization: 'Bearer ' + token, 'content-type': 'application/json', 'content-length': 2 } });
  const response = new Promise((resolve, reject) => {
    pending.once('error', reject);
    pending.once('response', async message => {
      try { const chunks = []; for await (const chunk of message) chunks.push(chunk);
        resolve({ status: message.statusCode, body: JSON.parse(Buffer.concat(chunks)) }); } catch (error) { reject(error); }
    });
  });
  pending.write('{'); await receivingBody;
  executor.revokeTask('task'); pending.end('}');
  assert.deepEqual(await response, { status: 401, body: { error: 'UNAUTHENTICATED', retryable: false } });
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
  assert.equal((await post('task/snapshot', credential.token, {}, { origin: 'http://evil.invalid' })).status, 403);
  assert.equal((await post('admin/audit', credential.token, {})).status, 401);
  const prepared = (await post('task/prepare', credential.token, { tool: 'test', args: null })).body;
  assert.equal((await post('task/execute', other.token, { actionId: prepared.id })).body.error, 'INVALID_PREPARED');
  assert.equal((await post('admin/approve', admin, { actionId: prepared.id, expiresAt: 2000, approverId: 'forged' })).status, 400);
  const approval = (await post('admin/approve', admin, { actionId: prepared.id, expiresAt: 2000 })).body;
  assert.equal((await post('task/execute', credential.token, { actionId: prepared.id, approvalId: approval.approvalId })).body.value, 'ok');
  assert.equal(effects, 1);
});

test('task clients distinguish an approval request from an unknown effect without exposing a backend exception', async t => {
  const { executor } = setup(t);
  let effects = 0;
  tool(executor, () => { effects++; throw new ExecutorError('synthetic backend credential'); }, { requiresApproval: true });
  const { token } = executor.createTask(task());
  const service = await startExecutorServer({ executor, adminToken: 'A'.repeat(43), operatorId: 'reviewer' });
  t.after(() => service.close());
  const client = new ExecutorClient({ endpoint: service.url, token });
  const { id } = await client.prepare('test', null);
  await assert.rejects(client.execute(id), { code: 'APPROVAL_REQUIRED' });
  assert.equal((await client.execution(id)).status, 'PREPARED'); assert.equal(effects, 0);
  const approvalId = executor.approve(id, { approverId: 'reviewer', expiresAt: 2000 });
  // Verify the server's wire response too. Filtering only in the client would still disclose the secret.
  const response = await fetch(service.url + '/v1/task/execute', { method: 'POST',
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify({ actionId: id, approvalId }) });
  assert.deepEqual(await response.json(), { error: 'OPERATION_FAILED', retryable: false });
  assert.equal((await client.execution(id)).status, 'UNKNOWN'); assert.equal(effects, 1);
  await assert.rejects(client.execute(id), { code: 'ACTION_USED' }); assert.equal(effects, 1);
  const untrusted = new ExecutorClient({ endpoint: service.url, token,
    fetch: async () => Response.json({ error: 'synthetic upstream secret' }, { status: 400 }) });
  await assert.rejects(untrusted.snapshot(), { message: 'EXECUTOR_REQUEST_DENIED' });
  const stale = new ExecutorClient({ endpoint: service.url, token, fetch: async () => Response.json({ id: 'other', status: 'FAILED' }) });
  await assert.rejects(stale.execution(id), { code: 'EXECUTOR_RESPONSE_INVALID' });
  let canceled = false;
  const stalled = new ExecutorClient({ endpoint: service.url, token, fetch: async () => new Response(
    new ReadableStream({ cancel() { canceled = true; } }), { status: 400, headers: { 'content-type': 'application/json' } }) });
  await assert.rejects(stalled.snapshot(), { code: 'EXECUTOR_REQUEST_DENIED' }); assert.equal(canceled, true);
});
