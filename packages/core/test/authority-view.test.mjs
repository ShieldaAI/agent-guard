import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard } from '@shieldaai/agent-guard';
import { assertActionAuthority } from '@shieldaai/agent-guard/internal';

const identity = { id: 'task', principalId: 'alice', tenantId: 'acme' };
const budget = { maxCalls: 2, maxConcurrent: 1, maxCost: 10, deadline: 1_000 };
const usage = { calls: 0, concurrent: 0, spent: 0, reserved: 0 };

/** The same authority in both accepted forms: arrays, and precomputed lookups. */
function forms({ grants, recipients = [], ...rest }) {
  const base = { identity, allowControlPlane: false, budget, snapshot: { ...identity, ...usage }, revoked: false };
  const lookup = new Map();
  for (const grant of grants) lookup.set(grant.tool, new Set([...(lookup.get(grant.tool) ?? []), ...grant.resources]));
  return [
    { ...base, grants, allowedRecipients: recipients, ...rest },
    { ...base, grants: lookup, allowedRecipients: new Set(recipients), ...rest },
  ];
}
function decide(action, ancestors, options = {}) {
  try {
    assertActionAuthority(action, ancestors, {
      now: 10,
      maxCost: 1,
      controlPlane: false,
      sensitive: false,
      secretValues: [],
      ...options,
    });
    return 'allowed';
  } catch (error) {
    return error.code;
  }
}
const action = (extra = {}) => ({
  tool: 'read',
  args: {},
  resourceId: 'doc',
  tenantId: 'acme',
  toolFingerprint: 'sha256:x',
  policyVersion: 1,
  ...extra,
});

test('array and lookup authorities decide every gate the same way', () => {
  const external = { external: true, recipient: 'a@example.test' };
  const cases = [
    ['allowed', action(), { grants: [{ tool: 'read', resources: ['doc'] }] }],
    ['allowed', action(), { grants: [{ tool: 'read', resources: ['*'] }] }],
    [
      'allowed',
      action(),
      {
        grants: [
          { tool: 'read', resources: ['other'] },
          { tool: 'read', resources: ['doc'] },
        ],
      },
    ],
    ['GRANT_DENIED', action(), { grants: [{ tool: 'read', resources: ['other'] }] }],
    ['GRANT_DENIED', action(), { grants: [{ tool: 'write', resources: ['*'] }] }],
    ['GRANT_DENIED', action(), { grants: [] }],
    ['GRANT_DENIED', action({ resourceId: '*' }), { grants: [{ tool: 'read', resources: ['doc'] }] }],
    ['TENANT_DENIED', action({ tenantId: 'other' }), { grants: [{ tool: 'read', resources: ['doc'] }] }],
    ['allowed', action(external), { grants: [{ tool: 'read', resources: ['doc'] }], recipients: ['a@example.test'] }],
    [
      'RECIPIENT_DENIED',
      action(external),
      { grants: [{ tool: 'read', resources: ['doc'] }], recipients: ['b@example.test'] },
    ],
    ['RECIPIENT_DENIED', action({ external: true }), { grants: [{ tool: 'read', resources: ['doc'] }] }],
    ['TASK_REVOKED', action(), { grants: [{ tool: 'read', resources: ['doc'] }], revoked: true }],
    [
      'CALL_BUDGET_EXCEEDED',
      action(),
      { grants: [{ tool: 'read', resources: ['doc'] }], snapshot: { ...identity, ...usage, calls: 2 } },
    ],
    [
      'COST_BUDGET_EXCEEDED',
      action(),
      { grants: [{ tool: 'read', resources: ['doc'] }], snapshot: { ...identity, ...usage, spent: 10 } },
    ],
  ];
  for (const [expected, candidate, authority] of cases) {
    const [arrays, lookups] = forms(authority);
    assert.equal(decide(candidate, [arrays]), expected, `array form: ${expected}`);
    assert.equal(decide(candidate, [lookups]), expected, `lookup form: ${expected}`);
    // A chain may mix both forms; a permissive parent never widens the child.
    const [parentArrays, parentLookups] = forms({
      grants: [{ tool: 'read', resources: ['*'] }],
      recipients: ['a@example.test'],
    });
    assert.equal(decide(candidate, [arrays, parentLookups]), expected);
    assert.equal(decide(candidate, [lookups, parentArrays]), expected);
  }
});

test('a lookup view may expose live counters and revocation through getters', () => {
  const live = { ...usage, revoked: false };
  const view = Object.freeze({
    identity,
    grants: new Map([['read', new Set(['doc'])]]),
    allowedRecipients: new Set(),
    allowControlPlane: false,
    budget,
    snapshot: Object.freeze({
      get calls() {
        return live.calls;
      },
      get concurrent() {
        return live.concurrent;
      },
      get spent() {
        return live.spent;
      },
      get reserved() {
        return live.reserved;
      },
    }),
    get revoked() {
      return live.revoked;
    },
  });
  assert.equal(decide(action(), [view]), 'allowed');
  live.concurrent = 1;
  assert.equal(decide(action(), [view]), 'CONCURRENCY_EXCEEDED');
  assert.equal(decide(action(), [view], { phase: 'prepare' }), 'allowed');
  live.concurrent = 0;
  live.reserved = 10;
  assert.equal(decide(action(), [view]), 'COST_BUDGET_EXCEEDED');
  live.reserved = 0;
  live.revoked = true;
  assert.equal(decide(action(), [view]), 'TASK_REVOKED');
});

/** Counts Map and Set iterations (spreads, for-of) while `run` executes. */
async function iterations(run) {
  const mapIterator = Map.prototype[Symbol.iterator];
  const mapEntries = Map.prototype.entries;
  const setIterator = Set.prototype[Symbol.iterator];
  const setValues = Set.prototype.values;
  let count = 0;
  const counted = original =>
    function (...args) {
      count++;
      return original.apply(this, args);
    };
  Map.prototype[Symbol.iterator] = counted(mapIterator);
  Map.prototype.entries = counted(mapEntries);
  Set.prototype[Symbol.iterator] = counted(setIterator);
  Set.prototype.values = counted(setValues);
  try {
    await run();
  } finally {
    Map.prototype[Symbol.iterator] = mapIterator;
    Map.prototype.entries = mapEntries;
    Set.prototype[Symbol.iterator] = setIterator;
    Set.prototype.values = setValues;
  }
  return count;
}

test('a check does not rebuild grant tables: its cost in copies is the same at any delegation depth', async () => {
  async function copiesAt(depth) {
    const guard = new AgentGuard();
    guard.approveTool(
      'read',
      guard.registerTool({
        name: 'read',
        description: 'fixture',
        resolve: () => ({ resourceId: 'doc-7', tenantId: 'acme' }),
        execute: () => ({ value: 'ok' }),
      }),
    );
    const grants = [{ tool: 'read', resources: Array.from({ length: 200 }, (_, index) => `doc-${index}`) }];
    const budgetFor = { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 };
    let task = guard.createTask({ id: 'root', principalId: 'alice', tenantId: 'acme', grants, budget: budgetFor });
    for (let level = 1; level < depth; level++)
      task = guard.delegateTask(task, { id: `child-${level}`, grants, budget: budgetFor });
    let value;
    const copies = await iterations(async () => {
      value = await guard.execute(await guard.prepare(task, { tool: 'read', args: {} }));
    });
    assert.equal(value, 'ok');
    assert.equal(guard.snapshot(task).calls, 1);
    return copies;
  }
  const shallow = await copiesAt(1);
  const deep = await copiesAt(12);
  assert.equal(deep, shallow, 'prepare and execute iterate no grant or recipient table per ancestor');
});
