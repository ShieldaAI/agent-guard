import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentGuard, isGuardError } from '@shieldaai/agent-guard';

const deadline = Date.now() + 60_000;
const budget = { maxCalls: 4, maxConcurrent: 2, maxCost: 10, deadline };

function fixture() {
  const guard = new AgentGuard();
  const fingerprint = guard.registerTool({
    name: 'read',
    description: 'Read one record',
    resolve: args => ({ resourceId: String(args.id), tenantId: 'acme' }),
    execute: () => ({ value: 'ok' }),
  });
  guard.approveTool('read', fingerprint);
  const parent = guard.createTask({
    id: 'parent',
    principalId: 'agent-1',
    tenantId: 'acme',
    grants: [{ tool: 'read', resources: ['a'] }],
    allowedRecipients: ['ops@acme.example'],
    budget,
  });
  return { guard, parent };
}

function denied(detail) {
  return error => isGuardError(error) && error.code === 'DELEGATION_DENIED' && error.detail === detail;
}

test('DELEGATION_DENIED names the limit the child exceeded', () => {
  const { guard, parent } = fixture();
  const child = (id, options) => guard.delegateTask(parent, { id, grants: [], budget, ...options });
  assert.throws(() => child('c1', { grants: [{ tool: 'read', resources: ['b'] }] }), denied('GRANT_EXCEEDS_PARENT'));
  assert.throws(() => child('c2', { grants: [{ tool: 'read', resources: ['*'] }] }), denied('GRANT_EXCEEDS_PARENT'));
  assert.throws(() => child('c3', { allowedRecipients: ['evil@x.example'] }), denied('RECIPIENT_EXCEEDS_PARENT'));
  assert.throws(() => child('c4', { allowControlPlane: true }), denied('CONTROL_PLANE_EXCEEDS_PARENT'));
  assert.throws(() => child('c5', { budget: { ...budget, maxCalls: 5 } }), denied('BUDGET_EXCEEDS_PARENT'));
  assert.throws(() => child('c6', { budget: { ...budget, maxCost: 11 } }), denied('BUDGET_EXCEEDS_PARENT'));
  // The common mistake: a fresh `Date.now() + n` for the child is later than the parent's deadline.
  assert.throws(
    () => child('c7', { budget: { ...budget, deadline: deadline + 1 } }),
    denied('DEADLINE_EXCEEDS_PARENT'),
  );
  assert.equal(child('c8', { grants: [{ tool: 'read', resources: ['a'] }] }).id, 'c8');
});

test('an aborted call whose handler finished reports EFFECT_COMMITTED', async () => {
  const { guard } = fixture();
  const effects = [];
  let task;
  const fingerprint = guard.registerTool({
    name: 'write',
    description: 'Write one record',
    resolve: () => ({ resourceId: 'a', tenantId: 'acme' }),
    execute: () => {
      effects.push('written');
      // Revocation aborts the running call after the handler has had its effect.
      guard.revokeTask(task);
      return { value: 'done' };
    },
  });
  guard.approveTool('write', fingerprint);
  task = guard.createTask({
    id: 'writer',
    principalId: 'agent-1',
    tenantId: 'acme',
    grants: [{ tool: 'write', resources: ['a'] }],
    budget,
  });
  const prepared = await guard.prepare(task, { tool: 'write', args: {} });
  await assert.rejects(
    guard.execute(prepared),
    error => isGuardError(error) && error.code === 'EXECUTION_ABORTED' && error.detail === 'EFFECT_COMMITTED',
  );
  assert.deepEqual(effects, ['written']);
});

test('a handler aborted before its effect throws, and the call reports no EFFECT_COMMITTED', async () => {
  const { guard } = fixture();
  const effects = [];
  for (const [name, honour] of [
    // The contract: throw when aborted before the effect.
    ['write-throws', signal => signal.throwIfAborted()],
    // Returning instead is taken as "the effect happened", although nothing was written.
    ['write-returns', () => {}],
  ]) {
    const fingerprint = guard.registerTool({
      name,
      description: 'Write one record unless aborted first',
      resolve: () => ({ resourceId: 'a', tenantId: 'acme' }),
      execute: async (_args, { signal }) => {
        await new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
        honour(signal);
        if (signal.aborted) return { value: null };
        effects.push(name);
        return { value: 'done' };
      },
    });
    guard.approveTool(name, fingerprint);
    const task = guard.createTask({
      id: name,
      principalId: 'agent-1',
      tenantId: 'acme',
      grants: [{ tool: name, resources: ['a'] }],
      budget,
    });
    const running = guard.execute(await guard.prepare(task, { tool: name, args: {} }));
    await new Promise(resolve => setImmediate(resolve));
    guard.revokeTask(task);
    await assert.rejects(
      running,
      error =>
        isGuardError(error) &&
        error.code === 'EXECUTION_ABORTED' &&
        error.detail === (name === 'write-throws' ? undefined : 'EFFECT_COMMITTED'),
      name,
    );
  }
  assert.deepEqual(effects, []);
});
