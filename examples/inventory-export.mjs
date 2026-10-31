// Run after npm run build. Synthetic ephemeral enrollment; no production ledger is read.
// Real hosts reuse their protected database/key and enroll the collector independently.
import { randomBytes } from 'node:crypto';
import { DurableExecutor, createInventoryObserverToken, startInventoryServer } from '../packages/executor/dist/index.js';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
  inventory: { companyId: 'example-company', sourceId: 'example-executor', enrollmentGeneration: 'demo-1' } });
let observer;
try {
  executor.createTask({ id: 'report-task', principalId: 'report-agent', tenantId: 'example-tenant',
    grants: [{ tool: 'reports.read', resources: ['public-report'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
  // The absent tool registration remains unresolved in inventory; a grant proves no availability.
  const token = createInventoryObserverToken();
  observer = await startInventoryServer({ executor,
    observers: [{ token, tenantIds: ['example-tenant'], profile: 'core' }] });
  const response = await fetch(`${observer.url}/v1/inventory/snapshot`, {
    method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'example-tenant' }),
  });
  if (!response.ok) throw new Error('Inventory example failed');
  // Output only the minimized snapshot. Never log or place observer credentials in a URL.
  process.stdout.write(`${JSON.stringify(await response.json())}\n`);
} finally {
  await observer?.close();
  executor.close();
}
