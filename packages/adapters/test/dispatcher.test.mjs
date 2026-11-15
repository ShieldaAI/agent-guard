import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentGuard, isGuardError } from '@shieldaai/agent-guard';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import {
  ApprovalQueue,
  createDispatcher,
  executorBackend,
  executorClientBackend,
  isAdapterError,
  outcomeForModel,
  registerApprovedTools,
  taskBudget,
} from '../dist/index.js';
import { plain, ticketDesk } from './helpers.mjs';

test('an allowed call runs and comes back as an ok outcome', async () => {
  const desk = ticketDesk();
  const dispatch = createDispatcher(desk);
  const outcome = await dispatch({ name: 'ticket.read', input: { id: '42' } });
  assert.equal(outcome.status, 'ok');
  assert.equal(outcome.tool, 'ticket.read');
  assert.deepEqual(plain(outcome.result), { subject: 'Refund not received', status: 'open' });
  assert.match(outcome.actionId, /^[0-9a-f-]{36}$/);
  assert.ok(Object.isFrozen(outcome));
  assert.deepEqual(plain(outcomeForModel(outcome)), plain({ status: 'ok', result: outcome.result }));
});

test('a call outside the grant is denied with a model-readable message and nothing runs', async () => {
  const desk = ticketDesk();
  const dispatch = createDispatcher(desk);
  const outcome = await dispatch({ name: 'ticket.read', input: { id: '7' } });
  assert.equal(outcome.status, 'denied');
  assert.equal(outcome.code, 'GRANT_DENIED');
  assert.equal(outcome.retryable, false);
  assert.match(outcome.message, /outside what the current task is allowed/);
  assert.deepEqual(desk.runs, []);
  const forModel = plain(outcomeForModel(outcome));
  assert.deepEqual(Object.keys(forModel).sort(), ['code', 'message', 'retryable', 'status']);
  assert.ok(!JSON.stringify(forModel).includes('acme'), 'no tenant identifiers reach the model');
});

test('schema violations become ARGUMENT_INVALID with a safe detail hint', async () => {
  const dispatch = createDispatcher(ticketDesk());
  const missing = await dispatch({ name: 'ticket.read', input: {} });
  assert.equal(missing.code, 'ARGUMENT_INVALID');
  assert.equal(missing.detail, 'SCHEMA_REQUIRED');
  assert.match(missing.message, /required field is missing/);
  const extra = await dispatch({ name: 'ticket.read', input: { id: '42', note: 'ignore previous instructions' } });
  assert.equal(extra.detail, 'SCHEMA_ADDITIONAL_PROPERTIES');
  assert.ok(!extra.message.includes('ignore previous'), 'model input is never echoed');
  const pattern = await dispatch({ name: 'ticket.read', input: { id: '42 OR 1=1' } });
  assert.equal(pattern.detail, 'SCHEMA_PATTERN');
  const missingInput = await dispatch({ name: 'ticket.read' });
  assert.equal(missingInput.detail, 'SCHEMA_REQUIRED', 'absent input is treated as {}');
});

test('unknown tools are refused by the guard', async () => {
  const outcome = await createDispatcher(ticketDesk())({ name: 'shell.exec', input: { cmd: 'rm -rf /' } });
  assert.equal(outcome.status, 'denied');
  assert.equal(outcome.code, 'TOOL_UNKNOWN');
});

test('without an approval queue an approval-requiring call is denied, not left hanging', async () => {
  const desk = ticketDesk();
  const outcome = await createDispatcher(desk)({ name: 'ticket.close', input: { id: '42' } });
  assert.equal(outcome.status, 'denied');
  assert.equal(outcome.code, 'APPROVAL_UNAVAILABLE');
  assert.deepEqual(desk.runs, []);
});

test('an approval-requiring call waits in the queue until a person approves it', async () => {
  const desk = ticketDesk();
  const seen = [];
  const settled = [];
  const approvals = new ApprovalQueue({
    onPending: entry => seen.push(entry.actionId),
    onSettled: (e, o) => settled.push(o.status),
  });
  const dispatch = createDispatcher(desk, { approvals });
  const waiting = await dispatch({ name: 'ticket.close', input: { id: '42' } });
  assert.equal(waiting.status, 'waiting_for_approval');
  assert.deepEqual(seen, [waiting.actionId]);
  assert.deepEqual(desk.runs, []);
  const [pending] = approvals.pending();
  assert.equal(pending.actionId, waiting.actionId);
  assert.equal(pending.action.resourceId, 'ticket:42');
  assert.match(pending.digest, /^sha256:/);
  assert.deepEqual(approvals.get(waiting.actionId), pending);

  const done = await approvals.approve(waiting.actionId, { approverId: 'alice' });
  assert.equal(done.status, 'ok');
  assert.deepEqual(plain(done.result), { closed: '42' });
  assert.deepEqual(desk.runs, [['ticket.close', '42']]);
  assert.deepEqual(approvals.pending(), []);
  assert.deepEqual(settled, ['ok']);
  await assert.rejects(approvals.approve(waiting.actionId, { approverId: 'alice' }), error => {
    assert.ok(isAdapterError(error));
    return error.code === 'APPROVAL_NOT_FOUND';
  });
});

test('a rejected action never runs, and a duplicate decision is refused', async () => {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue();
  const waiting = await createDispatcher(desk, { approvals })({ name: 'ticket.close', input: { id: '42' } });
  const rejected = approvals.reject(waiting.actionId);
  assert.equal(rejected.code, 'APPROVAL_REJECTED');
  assert.deepEqual(desk.runs, []);
  assert.throws(() => approvals.reject(waiting.actionId), { code: 'APPROVAL_NOT_FOUND' });
});

test('two reviewers approving at once run the action only once', async () => {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue();
  const waiting = await createDispatcher(desk, { approvals })({ name: 'ticket.close', input: { id: '42' } });
  const results = await Promise.allSettled([
    approvals.approve(waiting.actionId, { approverId: 'alice' }),
    approvals.approve(waiting.actionId, { approverId: 'bob' }),
  ]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.code, 'APPROVAL_NOT_FOUND');
  assert.deepEqual(desk.runs, [['ticket.close', '42']]);
});

test('waitForApproval holds the call open until the decision, then returns the result', async () => {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue({
    onPending: entry => setImmediate(() => approvals.approve(entry.actionId, { approverId: 'alice' })),
  });
  const dispatch = createDispatcher(desk, { approvals, waitForApproval: { timeoutMs: 5_000 } });
  const outcome = await dispatch({ name: 'ticket.close', input: { id: '42' } });
  assert.equal(outcome.status, 'ok');
  assert.deepEqual(plain(outcome.result), { closed: '42' });
});

test('waitForApproval times out with APPROVAL_TIMEOUT and drops the action', async () => {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue();
  const dispatch = createDispatcher(desk, { approvals, waitForApproval: { timeoutMs: 20 } });
  const outcome = await dispatch({ name: 'ticket.close', input: { id: '42' } });
  assert.equal(outcome.code, 'APPROVAL_TIMEOUT');
  assert.deepEqual(approvals.pending(), []);
  assert.deepEqual(desk.runs, []);
});

test('an aborted wait resolves APPROVAL_CANCELLED', async () => {
  const approvals = new ApprovalQueue();
  const dispatch = createDispatcher(ticketDesk(), { approvals, waitForApproval: { timeoutMs: 0 } });
  const controller = new AbortController();
  const pending = dispatch({ name: 'ticket.close', input: { id: '42' } }, { signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  assert.equal((await pending).code, 'APPROVAL_CANCELLED');
  assert.deepEqual(approvals.pending(), []);
});

test('a waiting dispatcher sees a rejection', async () => {
  const approvals = new ApprovalQueue({ onPending: entry => setImmediate(() => approvals.reject(entry.actionId)) });
  const dispatch = createDispatcher(ticketDesk(), { approvals, waitForApproval: { timeoutMs: 5_000 } });
  assert.equal((await dispatch({ name: 'ticket.close', input: { id: '42' } })).code, 'APPROVAL_REJECTED');
});

test('the queue refuses new actions past maxPending', async () => {
  const approvals = new ApprovalQueue({ maxPending: 1 });
  const dispatch = createDispatcher(ticketDesk(), { approvals });
  assert.equal((await dispatch({ name: 'ticket.close', input: { id: '42' } })).status, 'waiting_for_approval');
  const second = await dispatch({ name: 'ticket.close', input: { id: '42' } });
  assert.equal(second.code, 'APPROVAL_QUEUE_FULL');
});

test('approval expiry is capped at the task deadline', async () => {
  let now = 1_000_000;
  const clock = () => now;
  const guard = new AgentGuard({ clock });
  registerApprovedTools(guard, [
    {
      name: 'close',
      description: 'Close',
      requiresApproval: true,
      resolve: () => ({ resourceId: 'r', tenantId: 't' }),
      execute: () => ({ value: 'closed' }),
    },
  ]);
  const task = guard.createTask({
    id: 'short',
    principalId: 'p',
    tenantId: 't',
    grants: [{ tool: 'close', resources: ['r'] }],
    budget: taskBudget({ maxCalls: 2, ttlMs: 5_000, clock }),
  });
  const approvals = new ApprovalQueue({ clock, approvalTtlMs: 3_600_000 });
  const waiting = await createDispatcher({ guard, task }, { approvals })({ name: 'close', input: {} });
  // Without the cap the guard would refuse an approval that outlives the task.
  const outcome = await approvals.approve(waiting.actionId, { approverId: 'alice' });
  assert.equal(outcome.status, 'ok');
  now += 10;
});

test('a handler that throws after starting is a failed outcome: effect unknown, not retryable', async () => {
  const desk = ticketDesk();
  const outcome = await createDispatcher(desk)({ name: 'ticket.explode', input: { id: '42' } });
  assert.equal(outcome.status, 'failed');
  assert.equal(outcome.code, 'TOOL_FAILED');
  assert.equal(outcome.retryable, false);
  assert.match(outcome.message, /do not repeat/);
  assert.ok(outcome.actionId);
});

test('budget exhaustion is reported to the model', async () => {
  const dispatch = createDispatcher(ticketDesk({ maxCalls: 1 }));
  assert.equal((await dispatch({ name: 'ticket.read', input: { id: '42' } })).status, 'ok');
  const outcome = await dispatch({ name: 'ticket.read', input: { id: '42' } });
  assert.equal(outcome.code, 'CALL_BUDGET_EXCEEDED');
  assert.match(outcome.message, /summarize/);
});

test('a revoked task stops every later call', async () => {
  const desk = ticketDesk();
  const dispatch = createDispatcher(desk);
  desk.guard.revokeTask(desk.task);
  assert.equal((await dispatch({ name: 'ticket.read', input: { id: '42' } })).code, 'TASK_REVOKED');
});

test('onOutcome observes every outcome, and a throwing hook changes nothing', async () => {
  const seen = [];
  const dispatch = createDispatcher(ticketDesk(), {
    onOutcome: (outcome, call) => {
      seen.push([outcome.status, call.id]);
      throw new Error('broken hook');
    },
  });
  assert.equal((await dispatch({ id: 'c1', name: 'ticket.read', input: { id: '42' } })).status, 'ok');
  assert.equal((await dispatch({ id: 'c2', name: 'ticket.read', input: { id: '7' } })).status, 'denied');
  assert.deepEqual(seen, [
    ['ok', 'c1'],
    ['denied', 'c2'],
  ]);
});

test('host errors go to onHostError; the model gets HOST_ERROR with no detail', async () => {
  const reported = [];
  const onHostError = (error, call) => reported.push([error.message, call.name]);
  const failing = phase => ({
    prepare: async () => {
      if (phase === 'prepare') throw new TypeError('connect ECONNREFUSED 10.0.0.5:8443');
      return { id: 'a1', digest: 'sha256:x', action: { tool: 'x' }, requiresApproval: false };
    },
    execute: async () => {
      throw new TypeError('connect ECONNREFUSED 10.0.0.5:8443');
    },
  });
  const before = await createDispatcher(failing('prepare'), { onHostError })({ name: 'x', input: {} });
  assert.equal(before.status, 'denied', 'nothing ran');
  assert.equal(before.code, 'HOST_ERROR');
  const during = await createDispatcher(failing('execute'), { onHostError })({ name: 'x', input: {} });
  assert.equal(during.status, 'failed', 'the effect is unknown');
  assert.equal(during.actionId, 'a1');
  assert.match(during.message, /do not repeat/);
  for (const outcome of [before, during])
    assert.doesNotMatch(JSON.stringify(outcomeForModel(outcome)), /ECONNREFUSED|10\.0\.0\.5/);
  assert.deepEqual(reported, [
    ['connect ECONNREFUSED 10.0.0.5:8443', 'x'],
    ['connect ECONNREFUSED 10.0.0.5:8443', 'x'],
  ]);
  await assert.rejects(createDispatcher(failing('prepare'))(null), { code: 'INVALID_TOOL_CALL' });
});

test('without onHostError, a host error becomes a process warning', async () => {
  const warnings = [];
  const listener = warning => warnings.push(warning.code);
  process.on('warning', listener);
  try {
    const backend = { prepare: async () => Promise.reject(new Error('boom')), execute: async () => null };
    assert.equal((await createDispatcher(backend)({ name: 'x' })).code, 'HOST_ERROR');
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(warnings, ['AGENT_GUARD_HOST_ERROR']);
  } finally {
    process.off('warning', listener);
  }
});

test('options are validated', () => {
  const desk = ticketDesk();
  assert.throws(() => createDispatcher(null), { code: 'INVALID_OPTIONS' });
  assert.throws(() => createDispatcher(desk, { approvals: {} }), { code: 'INVALID_OPTIONS' });
  assert.throws(() => createDispatcher(desk, { waitForApproval: { timeoutMs: -1 } }), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new ApprovalQueue({ maxPending: 0 }), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new ApprovalQueue({ approvalTtlMs: 10 }), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new ApprovalQueue({ clock: 5 }), { code: 'INVALID_OPTIONS' });
});

test('the durable executor works through executorBackend, approvals included', async t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'adapters-executor-')));
  const executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: randomBytes(32) });
  // Close before removing: Windows cannot delete the open ledger file.
  t.after(() => {
    try {
      executor.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  let refunds = 0;
  registerApprovedTools(executor, [
    {
      name: 'refund.send',
      description: 'Send one refund',
      requiresApproval: true,
      resolve: () => ({ resourceId: 'order-17', tenantId: 'acme' }),
      execute: () => ({ value: `refund ${++refunds}` }),
    },
    {
      name: 'order.read',
      description: 'Read one order',
      resolve: args => ({ resourceId: `order-${args.id}`, tenantId: 'acme' }),
      execute: args => ({ value: { order: args.id } }),
    },
  ]);
  executor.createTask({
    id: 'refund-task',
    principalId: 'user-7',
    tenantId: 'acme',
    grants: [
      { tool: 'refund.send', resources: ['order-17'] },
      { tool: 'order.read', resources: ['order-17'] },
    ],
    budget: taskBudget({ maxCalls: 5, ttlMs: 600_000 }),
  });
  const approvals = new ApprovalQueue();
  const dispatch = createDispatcher(executorBackend(executor, 'refund-task'), { approvals });
  assert.deepEqual(plain((await dispatch({ name: 'order.read', input: { id: '17' } })).result), { order: '17' });
  assert.equal((await dispatch({ name: 'order.read', input: { id: '18' } })).code, 'GRANT_DENIED');
  const waiting = await dispatch({ name: 'refund.send', input: {} });
  assert.equal(waiting.status, 'waiting_for_approval');
  const done = await approvals.approve(waiting.actionId, { approverId: 'reviewer-2' });
  assert.equal(done.result, 'refund 1');
});

test('a backend that cannot approve uses complete() with an approval issued elsewhere', async () => {
  const desk = ticketDesk();
  const handles = new Map();
  const client = {
    async prepare(tool, args) {
      const prepared = await desk.guard.prepare(desk.task, { tool, args });
      handles.set(prepared.id, prepared);
      return prepared;
    },
    execute: (actionId, options) => desk.guard.execute(handles.get(actionId), options),
  };
  const approvals = new ApprovalQueue();
  const dispatch = createDispatcher(executorClientBackend(client), { approvals });
  const waiting = await dispatch({ name: 'ticket.close', input: { id: '42' } });
  await assert.rejects(approvals.approve(waiting.actionId, { approverId: 'alice' }), { code: 'APPROVAL_UNAVAILABLE' });
  // The admin API issues the approval; here the guard stands in for it.
  const approvalId = desk.guard.approve(handles.get(waiting.actionId), {
    approverId: 'admin',
    expiresAt: Date.now() + 10_000,
  });
  const done = await approvals.complete(waiting.actionId, { approvalId });
  assert.deepEqual(plain(done.result), { closed: '42' });
});

test('executor client errors become outcomes using only server-confirmed retryability', async () => {
  const error = Object.assign(new Error('EXECUTOR_RATE_LIMITED'), {
    name: 'ExecutorError',
    code: 'EXECUTOR_RATE_LIMITED',
  });
  Object.defineProperty(error, 'retryable', { value: true, enumerable: true });
  const client = { prepare: async () => Promise.reject(error), execute: async () => null };
  const outcome = await createDispatcher(executorClientBackend(client))({ name: 'x', input: {} });
  assert.equal(outcome.code, 'EXECUTOR_RATE_LIMITED');
  assert.equal(outcome.retryable, true);
  const fake = { name: 'ExecutorError', code: 'lowercase not allowed' };
  const client2 = { prepare: async () => Promise.reject(fake), execute: async () => null };
  const odd = await createDispatcher(executorClientBackend(client2), { onHostError: () => {} })({
    name: 'x',
    input: {},
  });
  assert.equal(odd.code, 'HOST_ERROR');
});

test('a remote execute that fails with a transport or response code is failed, not denied', async () => {
  for (const code of ['EXECUTOR_RESPONSE_INVALID', 'EXECUTOR_RESPONSE_LIMIT', 'OPERATION_FAILED', 'REQUEST_TIMEOUT']) {
    const error = Object.assign(new Error(code), { name: 'ExecutorError', code });
    const client = {
      prepare: async () => ({ id: 'a1', digest: 'sha256:x', action: { tool: 'pay' }, requiresApproval: false }),
      execute: async () => Promise.reject(error),
    };
    const outcome = await createDispatcher(executorClientBackend(client))({ name: 'pay' });
    assert.equal(outcome.status, 'failed', code);
    assert.equal(outcome.retryable, false);
    assert.match(outcome.message, /effect is unknown/);
  }
  // A known guard denial from a remote execute still proves nothing ran.
  const denial = Object.assign(new Error('APPROVAL_REQUIRED'), { name: 'ExecutorError', code: 'APPROVAL_REQUIRED' });
  const client = {
    prepare: async () => ({ id: 'a1', digest: 'sha256:x', action: { tool: 'pay' }, requiresApproval: false }),
    execute: async () => Promise.reject(denial),
  };
  assert.equal((await createDispatcher(executorClientBackend(client))({ name: 'pay' })).status, 'denied');
});

test('one task cannot fill a shared queue, and actions of a revoked or expired task are dropped', async () => {
  const a = ticketDesk({ taskId: 'a' });
  const b = ticketDesk({ taskId: 'b' });
  const approvals = new ApprovalQueue({ maxPending: 5, maxPendingPerTask: 2 });
  const dispatchA = createDispatcher(a, { approvals });
  const dispatchB = createDispatcher(b, { approvals });
  const close = { name: 'ticket.close', input: { id: '42' } };
  assert.equal((await dispatchA(close)).status, 'waiting_for_approval');
  assert.equal((await dispatchA(close)).status, 'waiting_for_approval');
  assert.equal((await dispatchA(close)).code, 'APPROVAL_QUEUE_FULL');
  assert.equal((await dispatchB(close)).status, 'waiting_for_approval', 'another task still has room');
  const settled = [];
  const watched = new ApprovalQueue({ onSettled: (entry, outcome) => settled.push(outcome.code) });
  const c = ticketDesk({ taskId: 'c' });
  await createDispatcher(c, { approvals: watched })(close);
  c.guard.revokeTask(c.task);
  assert.deepEqual(watched.pending(), []);
  assert.deepEqual(settled, ['TASK_REVOKED']);
  a.guard.revokeTask(a.task);
  assert.equal(approvals.pending().length, 1, "only task b's action is left");
});

test('actions are dropped after maxWaitMs and at the task deadline', async () => {
  let now = 1_000_000;
  const clock = () => now;
  const guard = new AgentGuard({ clock });
  registerApprovedTools(guard, [
    {
      name: 'close',
      description: 'c',
      requiresApproval: true,
      resolve: () => ({ resourceId: 'r', tenantId: 't' }),
      execute: () => ({ value: 1 }),
    },
  ]);
  const make = (id, ttlMs) =>
    guard.createTask({
      id,
      principalId: 'p',
      tenantId: 't',
      grants: [{ tool: 'close', resources: ['r'] }],
      budget: taskBudget({ maxCalls: 3, ttlMs, clock }),
    });
  const approvals = new ApprovalQueue({ clock, maxWaitMs: 10_000 });
  const long = await createDispatcher({ guard, task: make('long', 3_600_000) }, { approvals })({ name: 'close' });
  const short = await createDispatcher({ guard, task: make('short', 5_000) }, { approvals })({ name: 'close' });
  now += 6_000;
  assert.deepEqual(
    approvals.pending().map(entry => entry.actionId),
    [long.actionId],
    'the short task expired',
  );
  assert.equal(approvals.get(short.actionId), undefined);
  now += 5_000;
  assert.deepEqual(approvals.pending(), [], 'waited longer than maxWaitMs');
});

test('an onPending hook that decides at once is seen by the dispatcher', async () => {
  const approvals = new ApprovalQueue({ onPending: entry => approvals.reject(entry.actionId) });
  const waiting = createDispatcher(ticketDesk(), { approvals, waitForApproval: { timeoutMs: 1_000 } });
  assert.equal((await waiting({ name: 'ticket.close', input: { id: '42' } })).code, 'APPROVAL_REJECTED');
  const settled = [];
  const quick = new ApprovalQueue({
    onPending: entry => quick.reject(entry.actionId),
    onSettled: (e, o) => settled.push(o.code),
  });
  const returning = await createDispatcher(ticketDesk(), { approvals: quick })({
    name: 'ticket.close',
    input: { id: '42' },
  });
  assert.equal(returning.status, 'waiting_for_approval');
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(settled, ['APPROVAL_REJECTED']);
});

test('a host mistake when approving keeps the action waiting', async () => {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue();
  const waiting = await createDispatcher(desk, { approvals })({ name: 'ticket.close', input: { id: '42' } });
  await assert.rejects(approvals.approve(waiting.actionId, {}), { code: 'INVALID_OPTIONS' });
  await assert.rejects(approvals.approve(waiting.actionId, { approverId: 'alice', expiresAt: 1 }), {
    code: 'APPROVAL_NOT_ACCEPTED',
    detail: 'APPROVAL_INVALID',
  });
  await assert.rejects(approvals.complete(waiting.actionId, { approvalId: 'not-a-real-approval' }), {
    code: 'APPROVAL_NOT_ACCEPTED',
  });
  assert.equal(approvals.pending().length, 1);
  assert.deepEqual(desk.runs, []);
  assert.equal((await approvals.approve(waiting.actionId, { approverId: 'alice' })).status, 'ok');
  assert.deepEqual(desk.runs, [['ticket.close', '42']]);
});

test('guard denials stay GuardErrors at the guard boundary', async () => {
  const desk = ticketDesk();
  await assert.rejects(desk.guard.prepare(desk.task, { tool: 'ticket.read', args: { id: '7' } }), isGuardError);
});

test('a wait that runs out while an approval is being refused still ends', async () => {
  const desk = ticketDesk();
  const approvals = new ApprovalQueue();
  const handles = new Map();
  let releaseExecute;
  const client = {
    async prepare(tool, args) {
      const prepared = await desk.guard.prepare(desk.task, { tool, args });
      handles.set(prepared.id, prepared);
      return prepared;
    },
    async execute(actionId, options) {
      await new Promise(resolve => (releaseExecute = resolve)); // a slow round trip
      return desk.guard.execute(handles.get(actionId), options);
    },
  };
  const dispatch = createDispatcher(executorClientBackend(client), { approvals, waitForApproval: { timeoutMs: 20 } });
  const pending = dispatch({ name: 'ticket.close', input: { id: '42' } });
  await new Promise(resolve => setImmediate(resolve));
  const [entry] = approvals.pending();
  const completing = approvals.complete(entry.actionId, { approvalId: 'wrong' });
  await new Promise(resolve => setTimeout(resolve, 40)); // the dispatcher's wait runs out meanwhile
  releaseExecute();
  await assert.rejects(completing, { code: 'APPROVAL_NOT_ACCEPTED' });
  const outcome = await Promise.race([pending, new Promise(resolve => setTimeout(() => resolve('hung'), 500))]);
  assert.equal(outcome.code, 'APPROVAL_TIMEOUT');
  assert.deepEqual(approvals.pending(), []);
  assert.deepEqual(desk.runs, []);
});

test('a throwing custom backend hook affects only its own actions', async () => {
  const reported = [];
  const approvals = new ApprovalQueue({ onHostError: error => reported.push(error.message) });
  const good = createDispatcher(ticketDesk({ taskId: 'good' }), { approvals });
  const desk = ticketDesk({ taskId: 'bad' });
  const broken = {
    prepare: request => desk.guard.prepare(desk.task, request),
    execute: (prepared, options) => desk.guard.execute(prepared, options),
    approve: (prepared, options) => desk.guard.approve(prepared, options),
    active: () => {
      throw new Error('backend bug');
    },
  };
  const close = { name: 'ticket.close', input: { id: '42' } };
  assert.equal((await createDispatcher(broken, { approvals })(close)).status, 'waiting_for_approval');
  const waiting = await good(close);
  assert.equal(waiting.status, 'waiting_for_approval');
  assert.deepEqual(
    approvals.pending().map(e => e.actionId),
    [waiting.actionId],
  );
  assert.ok(reported.includes('backend bug'));
});

test('an approval the executor refuses after admission is final', async () => {
  const approvals = new ApprovalQueue();
  const expired = Object.assign(new Error('APPROVAL_EXPIRED'), { name: 'ExecutorError', code: 'APPROVAL_EXPIRED' });
  const client = {
    prepare: async () => ({
      id: 'a1',
      digest: 'sha256:x',
      action: { tool: 'pay', resourceId: 'r' },
      requiresApproval: true,
    }),
    execute: async () => Promise.reject(expired),
  };
  await createDispatcher(executorClientBackend(client), { approvals })({ name: 'pay' });
  const outcome = await approvals.complete('a1', { approvalId: 'id' });
  assert.equal(outcome.code, 'APPROVAL_EXPIRED');
  assert.deepEqual(approvals.pending(), [], 'not put back: the executor may have spent the action');
});

test('a handler code reaches the host, not the model', async () => {
  const desk = ticketDesk();
  desk.guard.registerTool({
    name: 'net',
    description: 'net',
    resolve: () => ({ resourceId: 'ticket:42', tenantId: 'acme' }),
    execute: () => {
      throw Object.assign(new Error('x'), { code: 'ECONNREFUSED' });
    },
  });
  desk.guard.approveTool('net', desk.guard.toolChanges('net').fingerprint);
  const task = desk.guard.createTask({
    id: 'n',
    principalId: 'p',
    tenantId: 'acme',
    grants: [{ tool: 'net', resources: ['ticket:42'] }],
    budget: taskBudget({ maxCalls: 2, ttlMs: 10_000 }),
  });
  const outcome = await createDispatcher({ guard: desk.guard, task })({ name: 'net' });
  assert.equal(outcome.detail, 'ECONNREFUSED');
  assert.equal(outcomeForModel(outcome).detail, undefined);
});
