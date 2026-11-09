import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor, ExecutorClient, startExecutorServer } from '../dist/index.js';

async function setup(t) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'executor-status-')));
  const executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 21), clock: () => 1000 });
  const fingerprint = executor.registerTool({ name: 'write', description: 'fixture', maxCost: 1,
    resolve: args => ({ resourceId: args.id, tenantId: 'acme' }), execute: () => ({ value: 'ok' }) });
  executor.approveTool('write', fingerprint);
  const { token } = executor.createTask({ id: 'task', principalId: 'p', tenantId: 'acme', grants: [{ tool: 'write', resources: ['allowed'] }],
    budget: { maxCalls: 2, maxConcurrent: 1, maxCost: 10, deadline: 100_000 } });
  const service = await startExecutorServer({ executor, adminToken: 'A'.repeat(43), operatorId: 'reviewer' });
  t.after(async () => { await service.close(); executor.close(); rmSync(directory, { recursive: true, force: true }); });
  const post = async (path, body, bearer = token) => {
    const response = await fetch(`${service.url}/v1/task/${path}`, { method: 'POST',
      headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  return { executor, service, token, post };
}

test('the task server maps codes to statuses and says whether a retry is safe', async t => {
  const f = await setup(t);
  assert.deepEqual(await f.post('snapshot', {}, 'B'.repeat(43)), { status: 401, body: { error: 'UNAUTHENTICATED', retryable: false } });
  assert.deepEqual(await f.post('prepare', { tool: 'write', args: { id: 'other' } }), { status: 403, body: { error: 'GRANT_DENIED', retryable: false } });
  assert.deepEqual(await f.post('execute', { actionId: 'missing' }), { status: 404, body: { error: 'INVALID_PREPARED', retryable: false } });
  const prepared = (await f.post('prepare', { tool: 'write', args: { id: 'allowed' } })).body;
  assert.equal((await f.post('execute', { actionId: prepared.id })).status, 200);
  assert.deepEqual(await f.post('execute', { actionId: prepared.id }), { status: 409, body: { error: 'ACTION_USED', retryable: false } });
  assert.deepEqual(await f.post('prepare', { tool: 'write' }), { status: 400, body: { error: 'REQUEST_INVALID', retryable: false } });
});

test('the task client keeps the code and a server-confirmed retryable flag', async t => {
  const f = await setup(t);
  const client = new ExecutorClient({ endpoint: f.service.url, token: f.token });
  const denied = await client.prepare('write', { id: 'other' }).catch(error => error);
  assert.equal(denied.code, 'GRANT_DENIED'); assert.equal(denied.retryable, false);
  const busy = new ExecutorClient({ endpoint: f.service.url, token: f.token,
    fetch: async () => Response.json({ error: 'CONCURRENCY_EXCEEDED', retryable: true }, { status: 429 }) });
  const error = await busy.snapshot().catch(caught => caught);
  assert.equal(error.code, 'CONCURRENCY_EXCEEDED'); assert.equal(error.retryable, true);
  const forged = new ExecutorClient({ endpoint: f.service.url, token: f.token,
    fetch: async () => Response.json({ error: 'not a code', retryable: true }, { status: 429 }) });
  const unknown = await forged.snapshot().catch(caught => caught);
  assert.equal(unknown.code, 'EXECUTOR_REQUEST_DENIED'); assert.equal(unknown.retryable, false);
});
