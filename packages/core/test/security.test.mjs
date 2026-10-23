import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, GuardError, GuardErrorCode } from '../dist/index.js';

const defaultBudget = () => ({ maxCalls: 20, maxConcurrent: 4, maxCost: 20, deadline: Date.now() + 60_000 });
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
function fixture({ options = {}, tool = {}, task = {}, approved = true } = {}) {
  const effects = [];
  const guard = new AgentGuard(options);
  const definition = {
    name: 'record.write', description: 'Write a record', maxCost: 1,
    resolve: (_args, identity) => ({ resourceId: 'record:1', tenantId: identity.tenantId }),
    execute: args => { effects.push(args); return { value: 'ok', actualCost: 1 }; },
    ...tool,
  };
  const fingerprint = guard.registerTool(definition);
  if (approved) guard.approveTool(definition.name, fingerprint);
  const handle = guard.createTask({
    id: 'task:1', principalId: 'user:1', tenantId: 'tenant:1',
    grants: [{ tool: definition.name, resources: ['record:1'] }], budget: defaultBudget(), ...task,
  });
  const prepare = (args = {}) => guard.prepare(handle, { tool: definition.name, args });
  return { guard, handle, definition, fingerprint, effects, prepare };
}
const code = expected => error => {
  assert.ok(error instanceof GuardError);
  assert.equal(error.code, expected);
  assert.equal(error.message, expected);
  assert.equal(GuardErrorCode[error.code], error.code);
  return true;
};

test('default-deny grants, tenant, control plane, recipients and tool approval precede effects', async t => {
  for (const [name, setup, expected] of [
    ['missing grant', { task: { grants: [] } }, 'GRANT_DENIED'],
    ['tool names have no wildcard', { task: { grants: [{ tool: '*', resources: ['*'] }] } }, 'GRANT_DENIED'],
    ['wrong resource', { task: { grants: [{ tool: 'record.write', resources: ['record:2'] }] } }, 'GRANT_DENIED'],
    ['wrong tenant', { tool: { resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:2' }) } }, 'TENANT_DENIED'],
    ['control plane', { tool: { controlPlane: true } }, 'CONTROL_PLANE_DENIED'],
    ['external without recipient permission', { tool: { resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', external: true, recipient: 'service:a' }) } }, 'RECIPIENT_DENIED'],
    ['unapproved metadata', { approved: false }, 'TOOL_UNAPPROVED'],
  ]) {
    await t.test(name, async () => {
      const f = fixture(setup);
      await assert.rejects(f.prepare(), code(expected));
      assert.deepEqual(f.effects, []);
      assert.equal(f.guard.snapshot(f.handle).calls, 0);
    });
  }
  const f = fixture({ task: { grants: [{ tool: 'record.write', resources: ['*'] }], allowControlPlane: true }, tool: { controlPlane: true } });
  assert.equal(await f.guard.execute(await f.prepare()), 'ok');
  assert.equal(f.effects.length, 1);
});

test('opaque object identity rejects copied, serialized and cross-guard handles', async () => {
  const f = fixture();
  await assert.rejects(f.guard.prepare({ ...f.handle }, { tool: 'record.write', args: {} }), code('INVALID_TASK'));
  const prepared = await f.prepare();
  await assert.rejects(f.guard.execute({ ...prepared }), code('INVALID_PREPARED'));
  await assert.rejects(f.guard.execute(JSON.parse(JSON.stringify(prepared))), code('INVALID_PREPARED'));
  await assert.rejects(new AgentGuard().execute(prepared), code('INVALID_PREPARED'));
  assert.throws(() => f.guard.snapshot({ id: 'task:1' }), code('INVALID_TASK'));
  assert.ok(Object.isFrozen(f.handle));
  f.guard.revokeTask(f.handle);
  assert.throws(() => f.guard.createTask({ id: 'task:1', principalId: 'user:1', tenantId: 'tenant:1', grants: [], budget: defaultBudget() }), code('DUPLICATE_TASK'));
  assert.deepEqual(f.effects, []);
});

test('canonical metadata fingerprint covers schema, metadata and security configuration', () => {
  const f = fixture();
  const register = fields => f.guard.registerTool({ ...f.definition, ...fields });
  const first = register({ inputSchema: { b: 2, a: 1 }, metadata: { annotations: { readOnlyHint: true } } });
  const reordered = register({ inputSchema: { a: 1, b: 2 }, metadata: { annotations: { readOnlyHint: true } } });
  assert.equal(first, reordered);
  assert.notEqual(first, register({ inputSchema: { a: 1, b: 2 }, metadata: { annotations: { readOnlyHint: false } } }));
  assert.notEqual(f.fingerprint, register({ requiresApproval: true }));
  assert.notEqual(f.fingerprint, register({ controlPlane: true }));
  assert.notEqual(f.fingerprint, register({ maxCost: 2 }));
  assert.throws(() => f.guard.approveTool('record.write', f.fingerprint), code('TOOL_CHANGED'));
});

test('re-registering identical metadata invalidates prepared execution and needs explicit approval', async () => {
  const f = fixture();
  const prepared = await f.prepare();
  const fingerprint = f.guard.registerTool({ ...f.definition, execute: () => ({ value: 'replacement' }) });
  assert.equal(fingerprint, f.fingerprint);
  await assert.rejects(f.guard.execute(prepared), code('TOOL_CHANGED'));
  await assert.rejects(f.prepare(), code('TOOL_UNAPPROVED'));
  f.guard.approveTool('record.write', fingerprint);
  assert.equal(await f.guard.execute(await f.prepare()), 'replacement');
  assert.deepEqual(f.effects, []);
});

test('invocation is copied before async policy and deeply frozen through dispatch', async () => {
  const entered = deferred();
  const release = deferred();
  let first = true;
  let resolved;
  let executed;
  const f = fixture({
    options: { policy: async (action, snapshot) => {
      assert.ok(Object.isFrozen(snapshot));
      assert.ok(Object.isFrozen(action));
      if (first) { first = false; entered.resolve(); await release.promise; }
      return 'allow';
    } },
    tool: {
      resolve(args, task) { assert.equal(this, undefined); resolved = args; return { resourceId: 'record:1', tenantId: task.tenantId }; },
      execute(args, context) { assert.equal(this, undefined); executed = args; assert.equal(args, context.action.args); return { value: args }; },
    },
  });
  const args = { nested: [{ text: 'approved' }], other: { number: 2 } };
  const waiting = f.prepare(args);
  await entered.promise;
  args.nested[0].text = 'mutated';
  args.other.number = 999;
  release.resolve();
  const prepared = await waiting;
  assert.ok(Object.isFrozen(prepared));
  assert.ok(Object.isFrozen(prepared.action.args.nested[0]));
  assert.throws(() => { prepared.action.args.nested[0].text = 'attack'; }, TypeError);
  assert.throws(() => { prepared.action.resourceId = 'record:2'; }, TypeError);
  const returned = await f.guard.execute(prepared);
  assert.equal(executed, resolved);
  assert.equal(returned.nested[0].text, 'approved');
  assert.equal(returned.other.number, 2);
  assert.ok(Object.isFrozen(returned));
});

test('JSON rejects accessors without running them, exotic objects, cycles and lossy values', async t => {
  let reads = 0;
  const accessor = Object.defineProperty({}, 'payload', { enumerable: true, get() { reads++; return 'secret'; } });
  const hiddenArray = [1];
  Object.defineProperty(hiddenArray, 'hidden', { value: 1 });
  const arrayAccessor = [1];
  Object.defineProperty(arrayAccessor, '0', { enumerable: true, get() { reads++; return 1; } });
  const cycle = {}; cycle.self = cycle;
  let deep = {}; for (let i = 0; i < 70; i++) deep = { child: deep };
  class FancyArray extends Array {}
  const invalid = [accessor, hiddenArray, arrayAccessor, cycle, deep, new Date(), new Map(), new FancyArray(1),
    { number: NaN }, { number: Infinity }, { missing: undefined }, { value: 1n }, { value: () => 1 },
    { value: Symbol('x') }, { [Symbol('x')]: 1 }, new Array(2), 'x'.repeat(1_048_577)];
  const f = fixture();
  for (const [i, args] of invalid.entries()) {
    await t.test(`invalid shape ${i}`, async () => { await assert.rejects(f.prepare(args), code('INVALID_JSON')); });
  }
  assert.equal(reads, 0);
  assert.deepEqual(f.effects, []);
  const prepared = await f.prepare(JSON.parse('{"__proto__":{"admin":true},"constructor":"data","a":-0}'));
  assert.equal(Object.getPrototypeOf(prepared.action.args), null);
  assert.equal(prepared.action.args.__proto__.admin, true);
  assert.equal(Object.is(prepared.action.args.a, -0), false);
  assert.equal({}.admin, undefined);
});

test('resolver failure, invalid metadata and invalid policy results fail closed without leaking text', async t => {
  const secret = 'SENSITIVE-ERROR-TEXT';
  for (const [name, tool] of [
    ['exception', { resolve() { throw new Error(secret); } }],
    ['missing tenant', { resolve: () => ({ resourceId: 'record:1' }) }],
    ['async resolver', { resolve: async () => ({ resourceId: 'record:1', tenantId: 'tenant:1' }) }],
    ['truthy external', { resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', external: 'false' }) }],
    ['unknown fields', { resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', untrusted: true }) }],
  ]) await t.test(name, async () => {
    const f = fixture({ tool }); await assert.rejects(f.prepare(), code('RESOLUTION_FAILED')); assert.deepEqual(f.effects, []);
  });
  for (const policy of [() => undefined, () => true, () => 'ALLOW', () => { throw new Error(secret); }, async () => { throw new Error(secret); }]) {
    const f = fixture({ options: { policy } });
    await assert.rejects(f.prepare(), code('POLICY_ERROR'));
    assert.deepEqual(f.effects, []);
  }
  const denied = fixture({ options: { policy: () => 'deny' } });
  await assert.rejects(denied.prepare(), code('POLICY_DENIED'));
});

test('approval binds an exact prepared action, expires, and concurrent replay dispatches once', async () => {
  let now = 1_000;
  const f = fixture({ options: { clock: () => now }, tool: { requiresApproval: true }, task: { budget: { ...defaultBudget(), deadline: 10_000 } } });
  const a = await f.prepare({ operation: 'one' });
  const b = await f.prepare({ operation: 'two' });
  const approvalId = f.guard.approve(a, { approverId: 'reviewer:1', expiresAt: 5_000 });
  await assert.rejects(f.guard.execute(a), code('APPROVAL_REQUIRED'));
  await assert.rejects(f.guard.execute(b, { approvalId }), code('APPROVAL_INVALID'));
  assert.throws(() => f.guard.approve(a, { approverId: 'reviewer:1', expiresAt: 10_001 }), code('APPROVAL_INVALID'));
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => f.guard.execute(a, { approvalId })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  for (const result of results.filter(result => result.status === 'rejected')) code('ACTION_USED')(result.reason);
  assert.equal(f.effects.length, 1);
  assert.equal(f.effects[0].operation, 'one');
  const expired = f.guard.approve(b, { approverId: 'reviewer:1', expiresAt: 5_000 });
  now = 5_000;
  await assert.rejects(f.guard.execute(b, { approvalId: expired }), code('APPROVAL_EXPIRED'));
  assert.equal(f.effects.length, 1);
});

test('policy can tighten approval at execution without changing version', async () => {
  let needsApproval = false;
  const f = fixture({ options: { policy: () => needsApproval ? 'require_approval' : 'allow' } });
  const prepared = await f.prepare();
  assert.equal(prepared.requiresApproval, false);
  needsApproval = true;
  await assert.rejects(f.guard.execute(prepared), code('APPROVAL_REQUIRED'));
  const approvalId = f.guard.approve(prepared, { approverId: 'reviewer:1', expiresAt: Date.now() + 10_000 });
  assert.equal(await f.guard.execute(prepared, { approvalId }), 'ok');
});

test('final checks reject state changes while execution policy is pending', async t => {
  for (const change of ['revoke', 'policy', 'tool', 'deadline', 'approval-expiry']) {
    await t.test(change, async () => {
      let now = 1_000;
      let pause = false;
      const entered = deferred(); const release = deferred();
      const f = fixture({
        options: { clock: () => now, policy: async () => { if (pause) { entered.resolve(); await release.promise; } return 'allow'; } },
        tool: { requiresApproval: change === 'approval-expiry' },
        task: { budget: { ...defaultBudget(), deadline: 10_000 } },
      });
      const prepared = await f.prepare();
      const approvalId = change === 'approval-expiry' ? f.guard.approve(prepared, { approverId: 'reviewer:1', expiresAt: 5_000 }) : undefined;
      pause = true;
      const pending = f.guard.execute(prepared, approvalId ? { approvalId } : {});
      await entered.promise;
      if (change === 'revoke') f.guard.revokeTask(f.handle);
      if (change === 'policy') f.guard.setPolicy(() => 'allow');
      if (change === 'tool') f.guard.registerTool(f.definition);
      if (change === 'deadline') now = 10_000;
      if (change === 'approval-expiry') now = 5_000;
      release.resolve();
      const expected = { revoke: 'TASK_REVOKED', policy: 'POLICY_CHANGED', tool: 'TOOL_CHANGED', deadline: 'TASK_EXPIRED', 'approval-expiry': 'APPROVAL_EXPIRED' }[change];
      await assert.rejects(pending, code(expected));
      assert.deepEqual(f.effects, []);
      assert.equal(f.guard.snapshot(f.handle).calls, 0);
    });
  }
});

test('preparation also rechecks revocation after asynchronous policy', async () => {
  const entered = deferred(); const release = deferred();
  const f = fixture({ options: { policy: async () => { entered.resolve(); await release.promise; return 'allow'; } } });
  const pending = f.prepare();
  await entered.promise;
  f.guard.revokeTask(f.handle);
  release.resolve();
  await assert.rejects(pending, code('TASK_REVOKED'));
  assert.deepEqual(f.effects, []);
});

test('delegation cannot widen resource, recipient, control plane or budget scope', async () => {
  const budget = defaultBudget();
  const f = fixture({ task: { budget, allowedRecipients: ['service:a'] } });
  const base = { id: 'child', grants: [{ tool: 'record.write', resources: ['record:1'] }], budget };
  for (const changes of [
    { grants: [{ tool: 'record.write', resources: ['*'] }] },
    { grants: [{ tool: 'record.write', resources: ['record:2'] }] },
    { grants: [{ tool: 'other', resources: ['record:1'] }] },
    { allowedRecipients: ['service:b'] }, { allowControlPlane: true },
    ...['maxCalls', 'maxConcurrent', 'maxCost', 'deadline'].map(key => ({ budget: { ...budget, [key]: budget[key] + 1 } })),
  ]) assert.throws(() => f.guard.delegateTask(f.handle, { ...base, ...changes }), code('DELEGATION_DENIED'));
  const child = f.guard.delegateTask(f.handle, { ...base, principalId: 'forged', tenantId: 'forged' });
  const snapshot = f.guard.snapshot(child);
  assert.equal(snapshot.principalId, 'user:1');
  assert.equal(snapshot.tenantId, 'tenant:1');
  await f.guard.execute(await f.guard.prepare(child, { tool: 'record.write', args: {} }));
  assert.equal(f.guard.snapshot(f.handle).calls, 1);
  assert.equal(f.guard.snapshot(child).calls, 1);
  f.guard.revokeTask(f.handle);
  await assert.rejects(f.guard.prepare(child, { tool: 'record.write', args: {} }), code('TASK_REVOKED'));
});

test('literal canaries are scanned recursively in outbound strings and object keys', async () => {
  const f = fixture({
    options: { secretValues: ['canary-123'] }, task: { allowedRecipients: ['service:a'] },
    tool: { resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', external: true, recipient: 'service:a' }) },
  });
  for (const args of [{ nested: [{ message: 'prefix-canary-123-suffix' }] }, { 'canary-123': 'value' }]) {
    await assert.rejects(f.prepare(args), code('SECRET_EGRESS_DENIED'));
  }
  assert.equal(await f.guard.execute(await f.prepare({ nested: [{ message: 'public' }] })), 'ok');
  assert.equal(f.effects.length, 1);
});

test('sensitivity is family-wide, monotonic and visible before read handler starts', async () => {
  const effects = [];
  const guard = new AgentGuard();
  const budget = defaultBudget();
  for (const [name, resolved, execute] of [
    ['send', { external: true, recipient: 'service:a' }, () => { effects.push('sent'); return { value: 'sent' }; }],
    ['read', { sensitive: true }, () => { effects.push('read'); return { value: 'sensitive' }; }],
  ]) {
    const fp = guard.registerTool({ name, description: name, resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', ...resolved }), execute });
    guard.approveTool(name, fp);
  }
  const grants = ['send', 'read'].map(tool => ({ tool, resources: ['record:1'] }));
  const parent = guard.createTask({ id: 'parent', principalId: 'user:1', tenantId: 'tenant:1', grants, budget, allowedRecipients: ['service:a'] });
  const child = guard.delegateTask(parent, { id: 'child', grants, budget, allowedRecipients: ['service:a'] });
  const sibling = guard.delegateTask(parent, { id: 'sibling', grants, budget, allowedRecipients: ['service:a'] });
  const send = await guard.prepare(sibling, { tool: 'send', args: 'public' });
  await guard.execute(await guard.prepare(child, { tool: 'read', args: {} }));
  for (const task of [parent, child, sibling]) assert.equal(guard.snapshot(task).sensitive, true);
  await assert.rejects(guard.execute(send), code('SENSITIVE_EGRESS_DENIED'));
  assert.deepEqual(effects, ['read']);
});

test('pending outbound policy is denied if another family action marks sensitivity', async () => {
  let blockSend = false; const entered = deferred(); const release = deferred();
  const f = fixture({
    options: { policy: async action => { if (blockSend && action.tool === 'record.write') { entered.resolve(); await release.promise; } return 'allow'; } },
    task: { grants: [{ tool: 'record.write', resources: ['record:1'] }, { tool: 'read', resources: ['record:1'] }], allowedRecipients: ['service:a'] },
    tool: { resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', external: true, recipient: 'service:a' }) },
  });
  const fp = f.guard.registerTool({ name: 'read', description: 'read', resolve: () => ({ resourceId: 'record:1', tenantId: 'tenant:1', sensitive: true }), execute: () => ({ value: 'sensitive' }) });
  f.guard.approveTool('read', fp);
  const send = await f.prepare();
  const read = await f.guard.prepare(f.handle, { tool: 'read', args: {} });
  blockSend = true;
  const pending = f.guard.execute(send);
  await entered.promise;
  await f.guard.execute(read);
  release.resolve();
  await assert.rejects(pending, code('SENSITIVE_EGRESS_DENIED'));
  assert.deepEqual(f.effects, []);
});

test('invalid trusted configuration rejects finite, integer and deadline violations', () => {
  for (const clock of [() => NaN, () => -1, () => { throw new Error('clock secret'); }]) assert.throws(() => new AgentGuard({ clock }), code('CLOCK_INVALID'));
  for (const budget of [
    { ...defaultBudget(), maxCalls: 0.5 }, { ...defaultBudget(), maxConcurrent: -1 },
    { ...defaultBudget(), maxCost: Infinity }, { ...defaultBudget(), deadline: NaN },
  ]) assert.throws(() => fixture({ task: { budget } }), error => error instanceof GuardError);
  assert.throws(() => fixture({ task: { budget: { ...defaultBudget(), deadline: 1 } } }), code('TASK_EXPIRED'));
  assert.throws(() => fixture({ options: { secretValues: [''] } }), code('INVALID_INPUT'));
  assert.throws(() => fixture({ tool: { maxCost: -1 } }), code('INVALID_INPUT'));
});
