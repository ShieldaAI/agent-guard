import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { AgentGuard, GuardErrorCatalog } from '@shieldaai/agent-guard';
import {
  DecisionStats,
  combineDecisionHooks,
  combinePolicies,
  createDispatcher,
  denyTools,
  denyWhen,
  explainCode,
  jsonLinesDecisionLogger,
  knownCodes,
  modelMessage,
  openTelemetryDecisionHook,
  registerApprovedTools,
  requireApprovalAfterUntrusted,
  requireApprovalForExternal,
  requireApprovalForTools,
  requireApprovalWhen,
  taskBudget,
  withinHours,
} from '../dist/index.js';

const action = (overrides = {}) => ({
  tool: 'mail.send',
  args: {},
  resourceId: 'r',
  tenantId: 't',
  toolFingerprint: 'f',
  policyVersion: 1,
  ...overrides,
});
const task = (overrides = {}) => ({
  id: 'k',
  principalId: 'p',
  tenantId: 't',
  sensitive: false,
  untrusted: false,
  calls: 0,
  concurrent: 0,
  spent: 0,
  reserved: 0,
  ...overrides,
});

test('combinePolicies returns the most restrictive answer and stops at deny', async () => {
  let reached = false;
  const late = () => {
    reached = true;
    return 'allow';
  };
  assert.equal(
    await combinePolicies(
      () => 'allow',
      () => 'require_approval',
    )(action(), task()),
    'require_approval',
  );
  assert.equal(
    await combinePolicies(
      () => 'require_approval',
      async () => 'deny',
      late,
    )(action(), task()),
    'deny',
  );
  assert.equal(reached, false);
  assert.equal(await combinePolicies()(action(), task()), 'allow');
  await assert.rejects(combinePolicies(() => 'maybe')(action(), task()));
  await assert.rejects(combinePolicies(() => ({ toString: () => 'allow' }))(action(), task()));
  assert.throws(() => combinePolicies('nope'), { code: 'INVALID_OPTIONS' });
});

test('the small policies', () => {
  assert.equal(denyTools(['mail.send'])(action(), task()), 'deny');
  assert.equal(denyTools(['other'])(action(), task()), 'allow');
  assert.equal(requireApprovalForTools(['mail.send'])(action(), task()), 'require_approval');
  assert.equal(requireApprovalForExternal()(action({ external: true }), task()), 'require_approval');
  assert.equal(requireApprovalForExternal()(action(), task()), 'allow');
  assert.equal(
    requireApprovalAfterUntrusted({ except: ['web.read'] })(action(), task({ untrusted: true })),
    'require_approval',
  );
  assert.equal(requireApprovalAfterUntrusted({ except: ['mail.send'] })(action(), task({ untrusted: true })), 'allow');
  assert.equal(requireApprovalAfterUntrusted()(action(), task()), 'allow');
  assert.equal(denyWhen(a => a.resourceId === 'r')(action(), task()), 'deny');
  assert.equal(requireApprovalWhen((a, t) => t.spent > 10)(action(), task({ spent: 11 })), 'require_approval');
  assert.throws(() => denyTools('mail.send'), { code: 'INVALID_OPTIONS' });
  assert.throws(() => denyWhen(null), { code: 'INVALID_OPTIONS' });
});

test('withinHours uses the configured time zone', () => {
  // Wednesday 2026-11-18 15:30 UTC is 10:30 in New York and 00:30 Thursday in Tokyo.
  const clock = () => Date.UTC(2026, 10, 18, 15, 30);
  const ny = withinHours({ timeZone: 'America/New_York', from: 9, to: 17, clock });
  const tokyo = withinHours({ timeZone: 'Asia/Tokyo', from: 9, to: 17, clock, outside: 'require_approval' });
  assert.equal(ny(action(), task()), 'allow');
  assert.equal(tokyo(action(), task()), 'require_approval');
  const weekend = withinHours({ timeZone: 'UTC', days: [0, 6], from: 0, to: 24, clock });
  assert.equal(weekend(action(), task()), 'deny');
  assert.equal(withinHours({ timeZone: 'UTC', from: 0, to: 1, clock, tools: ['other'] })(action(), task()), 'allow');
  assert.throws(() => withinHours({ timeZone: 'Mars/Olympus', from: 9, to: 17 }), { code: 'INVALID_OPTIONS' });
  assert.throws(() => withinHours({ timeZone: 'UTC', from: 17, to: 9 }), { code: 'INVALID_OPTIONS' });
  assert.throws(() => withinHours({ from: 9, to: 17 }), { code: 'INVALID_OPTIONS' }, 'no silent host time zone');
});

test('combined policies plug into the guard', async () => {
  const guard = new AgentGuard({
    policy: combinePolicies(denyTools(['mail.send']), requireApprovalForTools(['ticket.close'])),
  });
  registerApprovedTools(
    guard,
    ['mail.send', 'ticket.close', 'ticket.read'].map(name => ({
      name,
      description: name,
      resolve: () => ({ resourceId: 'r', tenantId: 't' }),
      execute: () => ({ value: name }),
    })),
  );
  const handle = guard.createTask({
    id: 'k',
    principalId: 'p',
    tenantId: 't',
    grants: ['mail.send', 'ticket.close', 'ticket.read'].map(tool => ({ tool, resources: ['r'] })),
    budget: taskBudget({ maxCalls: 5, ttlMs: 10_000 }),
  });
  const dispatch = createDispatcher({ guard, task: handle });
  assert.equal((await dispatch({ name: 'mail.send' })).code, 'POLICY_DENIED');
  assert.equal((await dispatch({ name: 'ticket.read' })).status, 'ok');
  // The policy requires approval, and this dispatcher has no queue.
  assert.equal((await dispatch({ name: 'ticket.close' })).code, 'APPROVAL_UNAVAILABLE');
});

test('decision hooks: JSON lines, OpenTelemetry and in-memory stats, combined', async () => {
  const lines = [];
  const counts = [];
  const events = [];
  const meter = {
    createCounter: (name, options) => ({
      add: (value, attributes) => counts.push([name, value, attributes, options.unit]),
    }),
  };
  const span = { addEvent: (name, attributes) => events.push([name, attributes]) };
  const stats = new DecisionStats();
  const guard = new AgentGuard({
    onDecision: combineDecisionHooks(
      () => {
        throw new Error('broken sink');
      },
      jsonLinesDecisionLogger({ write: line => lines.push(line), clock: () => 0, fields: { service: 'support' } }),
      openTelemetryDecisionHook({ meter, activeSpan: () => span }),
      stats.hook,
      undefined,
    ),
  });
  registerApprovedTools(guard, [
    {
      name: 'read',
      description: 'r',
      resolve: a => ({ resourceId: a.id, tenantId: 't' }),
      execute: () => ({ value: 1 }),
    },
  ]);
  const handle = guard.createTask({
    id: 'k',
    principalId: 'p',
    tenantId: 't',
    grants: [{ tool: 'read', resources: ['a'] }],
    budget: taskBudget({ maxCalls: 5, ttlMs: 10_000 }),
  });
  const dispatch = createDispatcher({ guard, task: handle });
  await dispatch({ name: 'read', input: { id: 'a' } });
  await dispatch({ name: 'read', input: { id: 'b' } });

  assert.equal(lines.length, 3, 'prepare + execute, then one denied prepare');
  const first = JSON.parse(lines[0]);
  assert.equal(first.service, 'support');
  assert.equal(first.time, '1970-01-01T00:00:00.000Z');
  assert.equal(first.event, 'agent_guard.decision');
  assert.equal(JSON.parse(lines[2]).code, 'GRANT_DENIED');
  assert.ok(!lines.join('').includes('"args"'));

  assert.equal(counts.length, 3);
  assert.equal(counts[0][0], 'agent_guard.decisions');
  assert.equal(counts[0][3], '{decision}');
  assert.deepEqual(Object.keys(counts[2][2]).sort(), [
    'agent_guard.code',
    'agent_guard.operation',
    'agent_guard.outcome',
    'agent_guard.tool',
    'agent_guard.untrusted',
  ]);
  assert.ok(
    events.every(([name, attributes]) => name === 'agent_guard.decision' && attributes['agent_guard.task_id'] === 'k'),
  );
  assert.ok(
    events.every(([, attributes]) => !('agent_guard.resource_id' in attributes)),
    'identifiers are opt-in',
  );

  const snapshot = stats.snapshot();
  assert.equal(snapshot.total, 3);
  assert.deepEqual({ ...snapshot.byOutcome }, { allowed: 1, succeeded: 1, denied: 1 });
  assert.deepEqual({ ...snapshot.byCode }, { GRANT_DENIED: 1 });
  assert.deepEqual({ ...snapshot.byTool.read }, { allowed: 2, refused: 1 });
  stats.reset();
  assert.equal(stats.snapshot().total, 0);
});

test('openTelemetryDecisionHook can include identifiers on span events', () => {
  const events = [];
  const hook = openTelemetryDecisionHook({
    activeSpan: () => ({ addEvent: (n, a) => events.push(a) }),
    includeIdentifiers: true,
  });
  hook({
    operation: 'approve',
    outcome: 'allowed',
    taskId: 'k',
    tenantId: 't',
    principalId: 'p',
    resourceId: 'r',
    approverId: 'alice',
    untrusted: false,
  });
  assert.equal(events[0]['agent_guard.approver_id'], 'alice');
  assert.equal(events[0]['agent_guard.resource_id'], 'r');
  openTelemetryDecisionHook({})({
    operation: 'prepare',
    outcome: 'allowed',
    taskId: 'k',
    tenantId: 't',
    principalId: 'p',
    untrusted: false,
  });
});

test('every guard code has a model message and an explanation', () => {
  for (const code of Object.keys(GuardErrorCatalog)) {
    assert.doesNotMatch(
      modelMessage(code),
      /^The call was refused\. Do not retry it with other values/,
      `${code} has its own message`,
    );
    const info = explainCode(code);
    assert.equal(info.source, 'guard');
    assert.equal(info.retryable, GuardErrorCatalog[code].retryable);
  }
  for (const code of [
    'INPUT_NOT_JSON',
    'APPROVAL_QUEUE_FULL',
    'APPROVAL_REJECTED',
    'APPROVAL_TIMEOUT',
    'APPROVAL_UNAVAILABLE',
    'APPROVAL_CANCELLED',
  ])
    assert.equal(explainCode(code).source, 'adapter');
  assert.equal(explainCode('NOPE'), undefined);
  assert.equal(knownCodes().length, Object.keys(GuardErrorCatalog).length + 7);
});

test('the agent-guard-explain command', () => {
  const cli = fileURLToPath(new URL('../dist/explain-cli.js', import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  const one = run('grant_denied');
  assert.equal(one.status, 0);
  assert.match(one.stdout, /^GRANT_DENIED \(guard\)/);
  assert.match(one.stdout, /Retryable: no/);
  const json = JSON.parse(run('--json', 'APPROVAL_TIMEOUT').stdout);
  assert.equal(json.source, 'adapter');
  assert.equal(run('--list').stdout.trim().split('\n').length, knownCodes().length);
  // Anything outside A-Z, 0-9 and _ is printed as "?", so the input is never echoed.
  const unknown = run('<b>');
  assert.equal(unknown.status, 1);
  assert.equal(unknown.stderr, 'Unknown code: ?B?. Run with --list to see every code.\n');
  assert.equal(run().status, 2);
  assert.equal(run('--help').status, 0);
});
