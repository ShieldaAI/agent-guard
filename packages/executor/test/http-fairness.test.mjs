import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Agent, request } from 'node:http';
import { performance } from 'node:perf_hooks';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { DurableExecutor, ExecutorClient, startExecutorServer } from '../dist/index.js';

const ADMIN = 'A'.repeat(43);
const task = id => ({ id, principalId: 'host', tenantId: 'tenant',
  grants: [{ tool: 'work', resources: ['record'] }],
  budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: 10000 } });
async function fixture(t, { child = false, approval = false, ...serverOptions } = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'http-fairness-')));
  let now = 1000, effects = 0;
  const events = [], executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 63), clock: () => now });
  const definition = { name: 'work', description: 'synthetic fairness fixture', requiresApproval: approval,
    resolve: () => ({ tenantId: 'tenant', resourceId: 'record' }),
    execute: () => { events.push('effect'); effects++; return { value: 'ok' }; } };
  executor.approveTool('work', executor.registerTool(definition));
  const parent = executor.createTask(task('parent'));
  const credential = child ? executor.delegateTask(parent.taskId, { id: 'child', grants: task('').grants, budget: task('').budget }) : parent;
  const authenticate = executor.authenticate;
  executor.authenticate = function (...args) { events.push('authenticate'); return Reflect.apply(authenticate, this, args); };
  const service = await startExecutorServer({ executor, adminToken: ADMIN, operatorId: 'operator', ...serverOptions });
  t.after(async () => { try { await service.close(); } finally { executor.close(); rmSync(directory, { recursive: true, force: true }); } });
  return { executor, service, credential, parent, events, definition, effects: () => effects, setTime: value => { now = value; } };
}

/** Invoke the real async HTTP request listener with a completely consumed body.
 * The generator schedules a real immediate as it closes, so body Promise
 * continuations alone cannot run the mutation before the old second auth.
 * No production scheduler/clock/auth hook is added to create this boundary.
 */
async function completedRequest(f, route, input, { during = () => {}, afterLastChunk = () => {}, bytes, token = f.credential.token, requestDestroyed = false } = {}) {
  let mutationResolve, mutationReject, bodyStartedAt, destroyCalls = 0;
  const mutation = new Promise((resolve, reject) => { mutationResolve = resolve; mutationReject = reject; });
  const response = { destroyed: false, status: null, payload: null,
    setHeader() {}, writeHead(code) { this.status = code; },
    end(value) { f.events.push('response'); this.payload = JSON.parse(value); } };
  const req = { method: 'POST', url: '/v1/' + route, aborted: false, destroyed: requestDestroyed,
    socket: { destroyed: false }, headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    headersDistinct: { authorization: ['Bearer ' + token] },
    destroy() { destroyCalls++; this.aborted = true; this.socket.destroyed = true; },
    async *[Symbol.asyncIterator]() {
      bodyStartedAt = performance.now();
      try { yield bytes ?? Buffer.from(JSON.stringify(input)); afterLastChunk(); }
      finally {
        setImmediate(() => {
          try { f.events.push('other-callback'); during({ req, response, bodyStartedAt }); mutationResolve(); }
          catch (error) { mutationReject(error); }
        });
      }
    } };
  const handler = f.service.server.listeners('request')[0];
  await Promise.all([Reflect.apply(handler, f.service.server, [req, response]), mutation]);
  return { response, req, destroyCalls };
}

for (const route of ['prepare', 'execute']) {
  test(`task ${route} gives a pending callback an opportunity before fresh second authentication`, async t => {
    const f = await fixture(t);
    const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
    const input = route === 'prepare' ? { tool: 'work', args: null } : { actionId: action.id };
    const { response } = await completedRequest(f, 'task/' + route, input);
    assert.equal(response.status, 200);
    assert.deepEqual(f.events.slice(0, 3), ['authenticate', 'other-callback', 'authenticate']);
    assert.equal(f.events.filter(value => value === 'authenticate').length, 2);
    assert.equal(f.effects(), route === 'execute' ? 1 : 0);
  });
  for (const ancestor of [false, true]) {
    test(`task ${route} refuses ${ancestor ? 'ancestor' : 'task'} revocation during the fairness yield`, async t => {
      const f = await fixture(t, { child: ancestor });
      const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
      const input = route === 'prepare' ? { tool: 'work', args: null } : { actionId: action.id };
      const { response } = await completedRequest(f, 'task/' + route, input, { during: () => f.executor.revokeTask(f.parent.taskId) });
      assert.equal(response.status, 401); assert.deepEqual(response.payload, { error: 'UNAUTHENTICATED' });
      assert.deepEqual(f.events.slice(0, 3), ['authenticate', 'other-callback', 'authenticate']);
      assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
      assert.equal(f.executor.snapshot(f.credential.taskId).reserved, 0);
    });
  }
  test(`task ${route} rechecks expiry after the fairness yield`, async t => {
    const f = await fixture(t);
    const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
    const input = route === 'prepare' ? { tool: 'work', args: null } : { actionId: action.id };
    const { response } = await completedRequest(f, 'task/' + route, input, { during: () => f.setTime(10000) });
    assert.equal(response.status, 401); assert.deepEqual(response.payload, { error: 'UNAUTHENTICATED' });
    assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
  });
  test(`task ${route} observes policy replacement during the fairness yield`, async t => {
    const f = await fixture(t);
    const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
    const input = route === 'prepare' ? { tool: 'work', args: null } : { actionId: action.id };
    const { response } = await completedRequest(f, 'task/' + route, input, { during: () => f.executor.setPolicy(() => 'deny') });
    assert.equal(response.status, 400);
    assert.equal(response.payload.error, route === 'prepare' ? 'POLICY_DENIED' : 'POLICY_CHANGED');
    assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
  });
}

test('execute preserves fresh approval expiry and tool revision checks across the yield', async t => {
  for (const change of ['approval-expiry', 'tool-revision']) {
    const f = await fixture(t, { approval: true });
    const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
    const approvalId = f.executor.approve(action.id, { approverId: 'operator', expiresAt: 2000 });
    const { response } = await completedRequest(f, 'task/execute', { actionId: action.id, approvalId }, { during: () => {
      if (change === 'approval-expiry') f.setTime(2000);
      else f.executor.approveTool('work', f.executor.registerTool({ ...f.definition, description: 'changed registration' }));
    } });
    assert.equal(response.status, 400);
    assert.equal(response.payload.error, change === 'approval-expiry' ? 'APPROVAL_EXPIRED' : 'TOOL_CHANGED');
    assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
  }
});

test('a mutable request URL cannot change task authentication into an administrative dispatch', async t => {
  const f = await fixture(t), victim = f.executor.createTask(task('victim'));
  // Valid admin payload, deliberately invalid for the originally authenticated
  // prepare route. A mutable switch(req.url) would revoke another task here.
  const { response } = await completedRequest(f, 'task/prepare', { taskId: victim.taskId }, {
    during: ({ req }) => { req.url = '/v1/admin/revoke'; },
  });
  assert.equal(response.status, 400); assert.deepEqual(response.payload, { error: 'REQUEST_INVALID' });
  assert.equal(f.executor.authenticate(victim.token), victim.taskId);
  assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(victim.taskId).calls, 0);
});

test('prepare/execute do not dispatch after peer closure while ordinary completed-message destruction is allowed', async t => {
  for (const closed of ['socket', 'response', 'aborted']) {
    const f = await fixture(t);
    const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
    const { response } = await completedRequest(f, 'task/execute', { actionId: action.id }, { during: ({ req, response }) => {
      if (closed === 'socket') req.socket.destroyed = true;
      else if (closed === 'response') response.destroyed = true;
      else req.aborted = true;
    } });
    assert.equal(response.status, null); assert.equal(f.effects(), 0);
    assert.equal(f.events.filter(value => value === 'authenticate').length, 1);
    assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
  }
  const f = await fixture(t);
  const { response } = await completedRequest(f, 'task/prepare', { tool: 'work', args: null }, { requestDestroyed: true });
  assert.equal(response.status, 200);
});

test('yield cannot dispatch after the original monotonic body deadline even before its timer callback', async t => {
  const f = await fixture(t, { requestTimeoutMs: 30 });
  const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
  // Hold only timeout delivery. The immediate and monotonic clock remain real,
  // so host contention cannot turn this into the already-covered timer branch.
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { response, destroyCalls } = await completedRequest(f, 'task/execute', { actionId: action.id }, { during: ({ bodyStartedAt }) => {
    // A previous check-phase callback can occupy the loop past the deadline;
    // the awaiting immediate resumes before the overdue timeout callback.
    while (performance.now() < bodyStartedAt + 50) { /* deterministic deadline fault */ }
  } });
  assert.equal(response.status, 400); assert.deepEqual(response.payload, { error: 'REQUEST_TIMEOUT' });
  assert.equal(destroyCalls, 0); assert.equal(f.effects(), 0);
  assert.equal(f.events.filter(value => value === 'authenticate').length, 1);
  assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
});

test('the original body timeout remains armed through the real immediate', async t => {
  const f = await fixture(t, { requestTimeoutMs: 30 });
  const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { response, destroyCalls } = await completedRequest(f, 'task/execute', { actionId: action.id }, {
    afterLastChunk: () => t.mock.timers.tick(20), during: () => t.mock.timers.tick(10),
  });
  assert.equal(destroyCalls, 1); assert.equal(response.status, 400);
  assert.deepEqual(response.payload, { error: 'REQUEST_TIMEOUT' });
  assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
});

test('malformed and oversized bodies fail before a fairness yield', async t => {
  for (const [bytes, expected] of [[Buffer.from('{'), 'REQUEST_INVALID'], [Buffer.alloc(65, 32), 'REQUEST_TOO_LARGE']]) {
    const f = await fixture(t, { maxRequestBytes: 64 });
    const { response } = await completedRequest(f, 'task/prepare', null, { bytes });
    assert.equal(response.status, 400); assert.deepEqual(response.payload, { error: expected });
    assert.deepEqual(f.events, ['authenticate', 'response', 'other-callback']);
    assert.equal(f.effects(), 0); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
  }
});

test('admin revocation and task cancellation/snapshot remain prompt without the new yield', async t => {
  for (const route of ['admin/revoke', 'task/cancel', 'task/snapshot']) {
    const f = await fixture(t);
    const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
    const input = route === 'admin/revoke' ? { taskId: f.credential.taskId } : route === 'task/cancel' ? { actionId: action.id } : {};
    const { response } = await completedRequest(f, route, input, { token: route.startsWith('admin/') ? ADMIN : f.credential.token });
    assert.equal(response.status, 200);
    assert.ok(f.events.indexOf('response') < f.events.indexOf('other-callback'));
    assert.equal(f.effects(), 0);
  }
});

function post(url, token, value, agent) {
  return new Promise((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(value));
    const req = request(url, { method: 'POST', agent, headers: { authorization: 'Bearer ' + token,
      'content-type': 'application/json', 'content-length': bytes.length } }, res => {
      const chunks = []; res.on('data', value => chunks.push(value));
      res.on('end', () => { try { resolve({ status: res.statusCode, value: JSON.parse(Buffer.concat(chunks)), reused: req.reusedSocket }); } catch (error) { reject(error); } });
    });
    req.on('error', reject); req.end(bytes);
  });
}
test('real complete HTTP bodies succeed on the same keep-alive connection', async t => {
  const f = await fixture(t), agent = new Agent({ keepAlive: true, maxSockets: 1 }); t.after(() => agent.destroy());
  const prepared = await post(f.service.url + '/v1/task/prepare', f.credential.token, { tool: 'work', args: null }, agent);
  assert.equal(prepared.status, 200);
  const executed = await post(f.service.url + '/v1/task/execute', f.credential.token, { actionId: prepared.value.id }, agent);
  assert.equal(executed.status, 200); assert.deepEqual(executed.value, { value: 'ok' }); assert.equal(executed.reused, true);
  assert.equal(f.effects(), 1); assert.equal(f.executor.snapshot(f.credential.taskId).calls, 1);
});

test('a real peer socket closed at the completed-body yield cannot dispatch an effect', async t => {
  const f = await fixture(t);
  const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
  let closed = false;
  f.service.server.prependOnceListener('request', req => {
    req.once('end', () => setImmediate(() => { req.socket.destroy(); closed = true; }));
  });
  await assert.rejects(post(f.service.url + '/v1/task/execute', f.credential.token, { actionId: action.id }), { code: 'ECONNRESET' });
  await nextTurn();
  assert.equal(closed, true); assert.equal(f.effects(), 0);
  assert.equal(f.executor.snapshot(f.credential.taskId).calls, 0);
});

test('the fixed timeout response reaches a task client without retries or arbitrary error disclosure', async () => {
  for (const [error, expected] of [['REQUEST_TIMEOUT', 'REQUEST_TIMEOUT'], ['private-host-detail', 'EXECUTOR_REQUEST_DENIED']]) {
    let calls = 0;
    const client = new ExecutorClient({ endpoint: 'http://127.0.0.1:1', token: 'B'.repeat(43),
      fetch: async () => { calls++; return Response.json({ error }, { status: 400 }); } });
    await assert.rejects(client.prepare('work', null), { code: expected, message: expected });
    assert.equal(calls, 1);
  }
});

test('two yielded executions retain one-use approval and at-most-once accounting', async t => {
  const f = await fixture(t, { approval: true });
  const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
  const approvalId = f.executor.approve(action.id, { approverId: 'operator', expiresAt: 2000 });
  const outcomes = await Promise.all([0, 1].map(() => completedRequest(f, 'task/execute', { actionId: action.id, approvalId })));
  assert.equal(outcomes.filter(x => x.response.status === 200).length, 1); assert.equal(f.effects(), 1);
  const failure = outcomes.find(x => x.response.status !== 200).response.payload.error;
  assert.ok(['ACTION_USED', 'POLICY_STATE_CHANGED', 'APPROVAL_USED'].includes(failure));
  const snapshot = f.executor.snapshot(f.credential.taskId);
  assert.equal(snapshot.calls, 1); assert.equal(snapshot.reserved, 0); assert.equal(snapshot.concurrent, 0);
});

test('executor closed during the yield cannot dispatch and the handler completes', async t => {
  const f = await fixture(t);
  const action = await f.executor.prepare(f.credential.taskId, { tool: 'work', args: null });
  const { response } = await completedRequest(f, 'task/execute', { actionId: action.id }, { during: () => f.executor.close() });
  assert.equal(response.status, 400); assert.equal(f.effects(), 0);
  assert.deepEqual(response.payload, { error: 'OPERATION_FAILED' });
  await nextTurn();
});
