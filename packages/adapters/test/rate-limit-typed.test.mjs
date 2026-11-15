import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentGuard } from '@shieldaai/agent-guard';
import {
  ApprovalQueue,
  RateLimiter,
  combineDecisionHooks,
  combinePolicies,
  createDispatcher,
  defineTool,
  jsonSchemaParser,
  registerApprovedTools,
  taskBudget,
} from '../dist/index.js';

function mailroom({ rules, clock }) {
  const limiter = new RateLimiter(rules, { clock });
  const guard = new AgentGuard({
    clock,
    policy: combinePolicies(limiter.policy),
    onDecision: combineDecisionHooks(limiter.hook),
  });
  let sent = 0;
  registerApprovedTools(guard, [
    {
      name: 'mail.send',
      description: 'Send one email',
      resolve: () => ({ resourceId: 'outbox', tenantId: 'acme' }),
      execute: () => ({ value: ++sent }),
    },
    {
      name: 'mail.read',
      description: 'Read the inbox',
      resolve: () => ({ resourceId: 'inbox', tenantId: 'acme' }),
      execute: () => ({ value: 'inbox' }),
    },
  ]);
  const task = id =>
    guard.createTask({
      id,
      principalId: `agent-${id}`,
      tenantId: 'acme',
      grants: [
        { tool: 'mail.send', resources: ['outbox'] },
        { tool: 'mail.read', resources: ['inbox'] },
      ],
      budget: taskBudget({ maxCalls: 100, ttlMs: 10 * 3_600_000, clock }),
    });
  return { guard, limiter, task, sent: () => sent };
}

test('a tenant-wide limit holds across tasks and frees up as the window slides', async () => {
  let now = 1_000_000;
  const clock = () => now;
  const room = mailroom({ rules: [{ tools: ['mail.send'], max: 2, windowMs: 60_000 }], clock });
  const first = createDispatcher({ guard: room.guard, task: room.task('a') });
  const second = createDispatcher({ guard: room.guard, task: room.task('b') });
  assert.equal((await first({ name: 'mail.send' })).status, 'ok');
  now += 10_000;
  assert.equal((await second({ name: 'mail.send' })).status, 'ok');
  const over = await second({ name: 'mail.send' });
  assert.equal(over.code, 'POLICY_DENIED');
  assert.equal(room.sent(), 2);
  assert.equal((await first({ name: 'mail.read' })).status, 'ok', 'other tools are not counted');
  assert.equal(room.limiter.usage(0, { tenantId: 'acme' }), 2);
  now += 50_001; // the first send leaves the window
  assert.equal((await first({ name: 'mail.send' })).status, 'ok');
  assert.equal(room.sent(), 3);
});

test('denied calls never use the allowance', async () => {
  const room = mailroom({ rules: [{ max: 1, windowMs: 60_000 }], clock: Date.now });
  const dispatch = createDispatcher({ guard: room.guard, task: room.task('a') });
  assert.equal((await dispatch({ name: 'mail.unknown' })).code, 'TOOL_UNKNOWN');
  assert.equal((await dispatch({ name: 'mail.send' })).status, 'ok');
  assert.equal((await dispatch({ name: 'mail.read' })).code, 'POLICY_DENIED', 'no tools list: every tool counts');
});

test('per principal, and require_approval instead of deny', async () => {
  const room = mailroom({
    rules: [{ tools: ['mail.send'], max: 1, windowMs: 60_000, per: 'principal', over: 'require_approval' }],
    clock: Date.now,
  });
  const approvals = new ApprovalQueue();
  const a = createDispatcher({ guard: room.guard, task: room.task('a') }, { approvals });
  const b = createDispatcher({ guard: room.guard, task: room.task('b') }, { approvals });
  assert.equal((await a({ name: 'mail.send' })).status, 'ok');
  assert.equal((await b({ name: 'mail.send' })).status, 'ok', 'another principal has its own allowance');
  const waiting = await a({ name: 'mail.send' });
  assert.equal(waiting.status, 'waiting_for_approval');
  assert.equal((await approvals.approve(waiting.actionId, { approverId: 'alice' })).status, 'ok');
});

test('RateLimiter options are validated', () => {
  assert.throws(() => new RateLimiter([]), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new RateLimiter([{ max: 0, windowMs: 60_000 }]), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new RateLimiter([{ max: 1, windowMs: 10 }]), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new RateLimiter([{ max: 1, windowMs: 60_000, per: 'task' }]), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new RateLimiter([{ max: 1, windowMs: 60_000, tools: 'mail.send' }]), { code: 'INVALID_OPTIONS' });
  assert.throws(() => new RateLimiter([{ max: 1, windowMs: 60_000 }]).usage(3), { code: 'INVALID_OPTIONS' });
});

test('defineTool is the identity at runtime and types the arguments', async () => {
  const schema = { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] };
  const definition = {
    name: 'ticket.read',
    description: 'Read one ticket',
    inputSchema: schema,
    parse: jsonSchemaParser(schema),
    resolve: args => ({ resourceId: `ticket:${args.id}`, tenantId: 'acme' }),
    execute: args => ({ value: args.id }),
  };
  assert.equal(defineTool(definition), definition);
});
