import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor, startExecutorServer } from '../dist/index.js';
import { removeAtExit } from './temp-directory.mjs';

function open(t, database) {
  const executor = new DurableExecutor({ database, encryptionKey: Buffer.alloc(32, 23), clock: () => 1000 });
  executor.approveTool(
    'read',
    executor.registerTool({
      name: 'read',
      description: 'fixture',
      resolve: () => ({ resourceId: 'doc', tenantId: 'acme' }),
      execute: () => ({ value: 'ok' }),
    }),
  );
  return executor;
}
function task(executor, id) {
  return executor.createTask({
    id,
    principalId: 'p',
    tenantId: 'acme',
    grants: [{ tool: 'read', resources: ['doc'] }],
    budget: { maxCalls: 1000, maxConcurrent: 4, maxCost: 0, deadline: 100_000 },
  });
}
function directory(t) {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'executor-limits-')));
  removeAtExit(path);
  return path;
}

test('unknown and malformed tokens are refused without reading the ledger', t => {
  const executor = open(t, join(directory(t), 'ledger.sqlite'));
  const { token, taskId } = task(executor, 'task');
  assert.equal(executor.authenticate(token), taskId);
  executor.close();
  // The store is closed: any ledger read would fail with a store error, not UNAUTHENTICATED.
  for (const candidate of ['A'.repeat(43), 'short', 'x'.repeat(300), 'A'.repeat(42) + '!']) {
    assert.throws(() => executor.authenticate(candidate), { code: 'UNAUTHENTICATED' }, candidate);
  }
  assert.throws(
    () => executor.authenticate(token),
    error => error.code !== 'UNAUTHENTICATED',
    'a known token still reads the ledger',
  );
});

test('the token index survives a restart and an archived task is refused', t => {
  const database = join(directory(t), 'ledger.sqlite');
  let executor = open(t, database);
  const { token, taskId } = task(executor, 'task');
  executor.close();
  executor = open(t, database);
  t.after(() => executor.close());
  assert.equal(executor.authenticate(token), taskId);
  const scope = { tenantId: 'acme', taskId: 'task' };
  executor.retireTaskFamily({ ...scope, expectedDigest: executor.previewTaskFamilyRetirement(scope).reviewDigest });
  executor.archiveTaskFamily({ ...scope, expectedDigest: executor.previewTaskFamilyRetirement(scope).reviewDigest });
  assert.throws(() => executor.authenticate(token), { code: 'UNAUTHENTICATED' });
});

test('the task server rate-limits per credential and across the server', async t => {
  const executor = open(t, join(directory(t), 'ledger.sqlite'));
  const first = task(executor, 'first'),
    second = task(executor, 'second');
  const service = await startExecutorServer({
    executor,
    adminToken: 'A'.repeat(43),
    operatorId: 'reviewer',
    requestsPerMinutePerCredential: 3,
    requestsPerMinute: 5,
  });
  t.after(async () => {
    await service.close();
    executor.close();
  });
  const snapshot = async token => {
    const response = await fetch(`${service.url}/v1/task/snapshot`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: '{}',
    });
    return [response.status, (await response.json()).error];
  };
  assert.deepEqual(await Promise.all([1, 2, 3].map(() => snapshot(first.token))), [
    [200, undefined],
    [200, undefined],
    [200, undefined],
  ]);
  assert.deepEqual(await snapshot(first.token), [429, 'REQUEST_RATE_LIMITED'], 'per-credential window');
  assert.deepEqual(await snapshot(second.token), [200, undefined], 'another credential has its own window');
  assert.deepEqual(await snapshot(second.token), [429, 'REQUEST_RATE_LIMITED'], 'the server-wide window is shared');
});

test('in-flight requests beyond the active limit are refused, and limits are validated', async t => {
  const executor = open(t, join(directory(t), 'ledger.sqlite'));
  let release;
  const gate = new Promise(resolve => {
    release = resolve;
  });
  executor.approveTool(
    'slow',
    executor.registerTool({
      name: 'slow',
      description: 'fixture',
      resolve: () => ({ resourceId: 'doc', tenantId: 'acme' }),
      execute: async () => {
        await gate;
        return { value: 'ok' };
      },
    }),
  );
  const { token } = executor.createTask({
    id: 'busy',
    principalId: 'p',
    tenantId: 'acme',
    grants: [{ tool: 'slow', resources: ['doc'] }],
    budget: { maxCalls: 10, maxConcurrent: 4, maxCost: 0, deadline: 100_000 },
  });
  const service = await startExecutorServer({
    executor,
    adminToken: 'A'.repeat(43),
    operatorId: 'reviewer',
    maxActiveRequests: 1,
  });
  t.after(async () => {
    await service.close();
    executor.close();
  });
  const post = (path, body) =>
    fetch(`${service.url}/v1/task/${path}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  const prepared = await (await post('prepare', { tool: 'slow', args: {} })).json();
  const running = post('execute', { actionId: prepared.id });
  await new Promise(resolve => setTimeout(resolve, 50));
  const refused = await post('snapshot', {});
  assert.equal(refused.status, 429);
  assert.deepEqual(await refused.json(), { error: 'REQUEST_RATE_LIMITED', retryable: true });
  release();
  assert.equal((await running).status, 200);
  for (const options of [
    { maxConnections: 0 },
    { maxActiveRequests: 1025 },
    { requestsPerMinute: 1.5 },
    { requestsPerMinutePerCredential: 0 },
  ]) {
    await assert.rejects(
      startExecutorServer({ executor, adminToken: 'A'.repeat(43), operatorId: 'reviewer', ...options }),
      { code: 'SERVER_CONFIG_INVALID' },
    );
  }
});
