// Synthetic HTTP-to-consumer fixture. Never reads host ledgers or credentials.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor, createInventoryObserverToken, startInventoryServer } from '../../../../packages/executor/dist/index.js';

const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-observer-contract-')));
const servers = [];
let executor;
try {
  executor = new DurableExecutor({
    database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 7), clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'observer-executor', enrollmentGeneration: 'generation' },
  });
  const fingerprint = executor.registerTool({
    name: 'records.read', description: 'canary-private-description', requiresApproval: true, maxCost: 2,
    metadata: { private: 'canary-private-metadata' },
    resolve: () => { throw new Error('Observation called a resolver'); },
    execute: () => { throw new Error('Observation called a handler'); },
  });
  executor.approveTool('records.read', fingerprint);
  const budget = { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100000.5 };
  const task = executor.createTask({
    id: 'alpha-task', tenantId: 'alpha', principalId: 'caller', budget,
    grants: [{ tool: 'records.read', resources: ['https://user:canary-private-password@private.invalid/?token=canary-private-token'] }],
    allowedRecipients: ['canary-private-recipient'],
  });
  executor.createTask({
    id: 'beta-private-task', tenantId: 'beta', principalId: 'beta-private-caller', budget,
    grants: [{ tool: 'beta.private-tool', resources: ['beta-private-resource'] }],
  });
  executor.importMemory({ id: 'canary-private-memory-id', tenantId: 'alpha', origin: 'fixture', value: 'canary-private-memory' });
  const observerToken = createInventoryObserverToken();
  const server = await startInventoryServer({
    executor, observers: [{ token: observerToken, tenantIds: ['alpha', 'empty'], profile: 'core' }],
  });
  servers.push(server);
  const request = async (service, token, body) => {
    const response = await fetch(`${service.url}/v1/inventory/snapshot`, {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(5000),
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    return { status: response.status, cacheControl: response.headers.get('cache-control'),
      contentLength: response.headers.get('content-length'), byteLength: bytes.byteLength,
      body: JSON.parse(bytes.toString('utf8')) };
  };
  const direct = executor.inventorySnapshot({ tenantId: 'alpha' });
  const observed = await request(server, observerToken, { tenantId: 'alpha' });
  const empty = await request(server, observerToken, { tenantId: 'empty' });
  const forbidden = await request(server, observerToken, { tenantId: 'beta' });
  const taskCredential = await request(server, task.token, { tenantId: 'alpha' });
  const unknownCredential = await request(server, createInventoryObserverToken(), { tenantId: 'alpha' });
  const filtered = await request(server, observerToken, { tenantId: 'alpha', taskIds: ['alpha-task'] });
  const limitedServer = await startInventoryServer({
    executor, observers: [{ token: observerToken, tenantIds: ['alpha'] }], maxResponseBytes: 128,
  });
  servers.push(limitedServer);
  const limited = await request(limitedServer, observerToken, { tenantId: 'alpha' });
  const after = executor.inventorySnapshot({ tenantId: 'alpha' });
  const output = JSON.stringify({ direct, observed, empty, forbidden, taskCredential, unknownCredential, filtered, limited, after });
  for (const secret of [observerToken, task.token, createHash('sha256').update(task.token).digest('hex'),
    'canary-private-', 'beta-private-', 'beta.private-tool']) {
    assert.equal(output.includes(secret), false, 'Private value reached observer fixture output');
  }
  process.stdout.write(output);
} finally {
  try { for (const server of servers) await server.close(); }
  finally { executor?.close(); rmSync(directory, { recursive: true, force: true }); }
}
