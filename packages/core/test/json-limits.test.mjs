import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard, GuardErrorCatalog } from '@shieldaai/agent-guard';
import { canonicalJson, digestJson, immutableJson } from '@shieldaai/agent-guard/internal';

const MIB = 1_048_576;

function fixture(options = {}, tool = {}) {
  const calls = { resolve: 0, policy: 0, execute: 0 };
  const guard = new AgentGuard({
    policy: () => {
      calls.policy++;
      return 'allow';
    },
    ...options,
  });
  guard.approveTool(
    'store',
    guard.registerTool({
      name: 'store',
      description: 'fixture',
      resolve: () => {
        calls.resolve++;
        return { resourceId: 'doc', tenantId: 'acme' };
      },
      execute: args => {
        calls.execute++;
        return { value: args };
      },
      ...tool,
    }),
  );
  const task = (id = 'task') =>
    guard.createTask({
      id,
      principalId: 'alice',
      tenantId: 'acme',
      grants: [{ tool: 'store', resources: ['doc'] }],
      budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
    });
  return { guard, calls, task };
}
/** Arguments whose `prepare` request is exactly `bytes` long as compact JSON. */
function argsForRequestBytes(bytes) {
  const empty = Buffer.byteLength(JSON.stringify({ args: { text: '' }, tool: 'store' }));
  return { text: 'x'.repeat(bytes - empty) };
}

test('arguments that fit the limit are prepared: the digest does not measure them again', async () => {
  const f = fixture();
  const args = argsForRequestBytes(MIB);
  // The request is exactly at the limit; the digest envelope around it is larger.
  assert.doesNotThrow(() => immutableJson({ tool: 'store', args }));
  const prepared = await f.guard.prepare(f.task(), { tool: 'store', args });
  assert.match(prepared.digest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(f.calls, { resolve: 1, policy: 1, execute: 0 });
  assert.equal((await f.guard.execute(prepared)).text.length, args.text.length);
});

test('arguments one byte over the limit fail INVALID_JSON before resolve and the policy run', async () => {
  const f = fixture();
  await assert.rejects(f.guard.prepare(f.task(), { tool: 'store', args: argsForRequestBytes(MIB + 1) }), {
    code: 'INVALID_JSON',
  });
  assert.deepEqual(f.calls, { resolve: 0, policy: 0, execute: 0 });
});

test('arguments nested to the depth limit are prepared', async () => {
  const f = fixture();
  // The request holds `args` one level down, so 63 further levels reach the limit of 64.
  let args = 'leaf';
  for (let level = 0; level < 63; level++) args = [args];
  assert.doesNotThrow(() => immutableJson({ tool: 'store', args }));
  assert.throws(() => immutableJson({ tool: 'store', args: [args] }));
  await f.guard.prepare(f.task(), { tool: 'store', args });
  await assert.rejects(f.guard.prepare(f.task('deeper'), { tool: 'store', args: [args] }), { code: 'INVALID_JSON' });
  assert.equal(f.calls.resolve, 1);
});

test('the digest is the sha256 of the ID, task identity, action and tool revision', async () => {
  const f = fixture();
  const prepared = await f.guard.prepare(f.task(), { tool: 'store', args: { b: [1, { z: null, a: 'é' }], a: -0 } });
  const expected = digestJson(
    immutableJson({
      preparedId: prepared.id,
      task: { id: 'task', principalId: 'alice', tenantId: 'acme' },
      action: prepared.action,
      toolRevision: 1,
    }),
  );
  assert.equal(prepared.digest, `sha256:${expected}`);
});

test('the canonical form behind fingerprints and digests is pinned to literal values', async () => {
  // Stored fingerprints and recorded digests must keep matching: a change to the canonical
  // JSON form, to the fingerprinted fields or to the action shape fails here.
  const fingerprint = 'sha256:3a663d7b6f1facc6c2f21e3ac482a90c0108596f40c7366466eb2ca6d5bc84e4';
  const guard = new AgentGuard();
  const definition = {
    name: 'store',
    description: 'fixture',
    resolve: () => ({ resourceId: 'doc', tenantId: 'acme' }),
    execute: args => ({ value: args }),
  };
  assert.equal(guard.registerTool(definition), fingerprint);
  guard.approveTool('store', fingerprint);
  const task = guard.createTask({
    id: 'task',
    principalId: 'alice',
    tenantId: 'acme',
    grants: [{ tool: 'store', resources: ['doc'] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  const prepared = await guard.prepare(task, { tool: 'store', args: { b: [1, { z: null, a: 'é' }], a: -0 } });
  // The prepared ID is random, so the envelope is rebuilt around a fixed one.
  const envelope = {
    preparedId: '00000000-0000-4000-8000-000000000000',
    task: { id: 'task', principalId: 'alice', tenantId: 'acme' },
    action: prepared.action,
    toolRevision: 1,
  };
  assert.equal(
    canonicalJson(envelope),
    '{"action":{"args":{"a":0,"b":[1,{"a":"é","z":null}]},"external":false,"policyVersion":1,"resourceId":"doc",' +
      `"sensitive":false,"tenantId":"acme","tool":"store","toolFingerprint":"${fingerprint}"},` +
      '"preparedId":"00000000-0000-4000-8000-000000000000",' +
      '"task":{"id":"task","principalId":"alice","tenantId":"acme"},"toolRevision":1}',
  );
  assert.equal(digestJson(envelope), '690486edb239d89de335a6f42902e9f2ad476aad300be4f0b10cf87f43854bf5');
  // The real digest is the same computation with the real ID.
  assert.equal(prepared.digest, `sha256:${digestJson({ ...envelope, preparedId: prepared.id })}`);
});

test('limits.maxJsonBytes raises the limit for arguments and results', async () => {
  const large = 3 * MIB;
  const standard = fixture();
  await assert.rejects(standard.guard.prepare(standard.task(), { tool: 'store', args: { text: 'x'.repeat(large) } }), {
    code: 'INVALID_JSON',
  });
  const raised = fixture({ limits: { maxJsonBytes: 4 * MIB } });
  const prepared = await raised.guard.prepare(raised.task(), { tool: 'store', args: { text: 'x'.repeat(large) } });
  assert.equal((await raised.guard.execute(prepared)).text.length, large);
});

test('limits.maxJsonBytes lowers the limit for arguments, tool metadata and task options', async () => {
  const f = fixture({ limits: { maxJsonBytes: 65_536 } });
  await f.guard.prepare(f.task(), { tool: 'store', args: { text: 'x'.repeat(60_000) } });
  await assert.rejects(f.guard.prepare(f.task('second'), { tool: 'store', args: { text: 'x'.repeat(70_000) } }), {
    code: 'INVALID_JSON',
  });
  assert.throws(
    () =>
      f.guard.registerTool({
        name: 'big',
        description: 'x'.repeat(70_000),
        resolve: () => ({ resourceId: 'doc', tenantId: 'acme' }),
        execute: () => ({ value: null }),
      }),
    { code: 'INVALID_JSON' },
  );
  assert.throws(
    () =>
      f.guard.createTask({
        id: 'wide',
        principalId: 'alice',
        tenantId: 'acme',
        grants: [{ tool: 'store', resources: Array.from({ length: 8_000 }, (_, index) => `resource-${index}`) }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
      }),
    { code: 'INVALID_JSON' },
  );
});

test('limits.maxJsonNodes bounds the number of values', async () => {
  const many = Array.from({ length: 2_000 }, (_, index) => index);
  const standard = fixture();
  await standard.guard.prepare(standard.task(), { tool: 'store', args: many });
  const lowered = fixture({ limits: { maxJsonNodes: 1_000 } });
  await assert.rejects(lowered.guard.prepare(lowered.task(), { tool: 'store', args: many }), { code: 'INVALID_JSON' });
  const wide = Array.from({ length: 150_000 }, () => 0);
  await assert.rejects(standard.guard.prepare(standard.task('wide'), { tool: 'store', args: wide }), {
    code: 'INVALID_JSON',
  });
  const raised = fixture({ limits: { maxJsonNodes: 200_000 } });
  await raised.guard.prepare(raised.task(), { tool: 'store', args: wide });
});

test('a result over the limit fails RESULT_INVALID after the handler ran and revokes the task', async () => {
  for (const [limits, size] of [
    [undefined, MIB + 1],
    [{ maxJsonBytes: 2 * MIB }, 2 * MIB + 1],
  ]) {
    const f = fixture(limits ? { limits } : {}, { execute: () => ({ value: 'x'.repeat(size) }) });
    let executed = 0;
    const task = f.task();
    const prepared = await f.guard.prepare(task, { tool: 'store', args: {} });
    await assert.rejects(
      f.guard.execute(prepared).finally(() => executed++),
      { code: 'RESULT_INVALID' },
    );
    assert.equal(executed, 1);
    const status = f.guard.snapshot(task);
    assert.equal(status.revoked, true);
    assert.equal(status.calls, 1, 'the call is counted: the handler ran');
    await assert.rejects(f.guard.prepare(task, { tool: 'store', args: {} }), { code: 'TASK_REVOKED' });
  }
  // The same result is delivered when the limit admits it.
  const fits = fixture({ limits: { maxJsonBytes: 2 * MIB } }, { execute: () => ({ value: 'x'.repeat(MIB + 1) }) });
  const task = fits.task();
  assert.equal((await fits.guard.execute(await fits.guard.prepare(task, { tool: 'store', args: {} }))).length, MIB + 1);
  assert.equal(fits.guard.snapshot(task).revoked, false);
});

test('JSON limits outside their range are refused at construction', () => {
  for (const limits of [
    { maxJsonBytes: 65_535 },
    { maxJsonBytes: 64 * MIB + 1 },
    { maxJsonBytes: 1.5 * MIB + 0.5 },
    { maxJsonBytes: '1048576' },
    { maxJsonNodes: 999 },
    { maxJsonNodes: 10_000_001 },
    { maxJsonNodes: Infinity },
  ])
    assert.throws(() => new AgentGuard({ limits }), { code: 'INVALID_INPUT' }, JSON.stringify(limits));
  for (const limits of [
    { maxJsonBytes: 65_536 },
    { maxJsonBytes: 64 * MIB },
    { maxJsonNodes: 1_000 },
    { maxJsonNodes: 10_000_000 },
  ])
    assert.doesNotThrow(() => new AgentGuard({ limits }), JSON.stringify(limits));
});

test('the error catalog names the current remedies', () => {
  assert.match(GuardErrorCatalog.INVALID_TASK.cause, /retireTask\(\)/);
  assert.match(GuardErrorCatalog.TOOL_UNAPPROVED.cause, /unapproveTool\(\)/);
  assert.match(GuardErrorCatalog.TOOL_CHANGED.cause, /unregisterTool\(\)/);
  assert.doesNotMatch(GuardErrorCatalog.INVALID_PREPARED.cause, /^The action was never prepared here, belongs/);
  assert.match(GuardErrorCatalog.APPROVAL_USED.cause, /only the executor/);
  assert.match(GuardErrorCatalog.INVALID_JSON.cause, /maxJsonBytes/);
  for (const [code, info] of Object.entries(GuardErrorCatalog)) {
    assert.ok(info.cause.split('. ').length >= 2 || /;/.test(info.cause), `${code} says what happened and what to do`);
    assert.equal(/\balpha|\bpreviously\b|\bas before\b/i.test(info.cause + info.meaning), false, code);
  }
});

test('the in-memory guard reports a second run as ACTION_USED, never APPROVAL_USED', async () => {
  const f = fixture({}, { requiresApproval: true });
  const prepared = await f.guard.prepare(f.task(), { tool: 'store', args: {} });
  const approvalId = f.guard.approve(prepared, { approverId: 'bob', expiresAt: Date.now() + 10_000 });
  await f.guard.execute(prepared, { approvalId });
  await assert.rejects(f.guard.execute(prepared, { approvalId }), { code: 'ACTION_USED' });
});
