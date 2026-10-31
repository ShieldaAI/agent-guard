// Run after npm run build. Synthetic host assertions; no AWS credentials or API calls.
// A deployed host uses its existing protected ledger/key and operator-reviewed manifest file.
import { randomBytes } from 'node:crypto';
import { DurableExecutor, validateInventoryManifest, composeInventorySnapshot,
  createInventoryObserverToken, startInventoryServer } from '../packages/executor/dist/index.js';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
  inventory: { companyId: 'example-company', sourceId: 'example-executor', enrollmentGeneration: 'host-demo-1' } });
let observer;
try {
  const fingerprint = executor.registerTool({ name: 'reports.read', description: 'Synthetic report reader',
    resolve: () => ({ resourceId: 'report-alias', tenantId: 'example-tenant' }), execute: () => ({ value: 'example' }) });
  executor.approveTool('reports.read', fingerprint);
  executor.createTask({ id: 'report-task', principalId: 'application-caller', tenantId: 'example-tenant',
    grants: [{ tool: 'reports.read', resources: ['report-alias'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
  const core = executor.inventorySnapshot({ tenantId: 'example-tenant' });
  // Host authors bind the exported selector, which stays opaque and stable within this enrollment.
  // The AWS target and execution identity below are independent reviewed assertions, not discovered permissions.
  const manifest = validateInventoryManifest({
    schemaVersion: 1, evidenceKind: 'host_asserted', source: core.source,
    manifestId: 'host-configuration', revision: 1, observedAt: new Date().toISOString(),
    agents: [{ id: 'report-agent', name: 'Report agent', ownerId: 'example-owner', teamId: 'example-team' }],
    deployments: [{ id: 'report-deployment', agentId: 'report-agent', environment: 'demo' }],
    taskBindings: [{ taskId: 'report-task', deploymentId: 'report-deployment' }],
    resourceBindings: [{ id: 'report-object', tool: 'reports.read', resourceRef: core.tasks[0].grants[0].resources[0],
      target: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
        arn: 'arn:aws:s3:::example-reports/report.txt', kind: 'object' }, actions: ['s3:GetObject'], scope: 'exact' }],
    executionBindings: [{ id: 'report-runtime', tool: 'reports.read', deploymentId: 'report-deployment', connectionId: null,
      identitySelection: 'static', identity: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
        arn: 'arn:aws:iam::111122223333:role/report-reader' } }],
  });
  const composed = composeInventorySnapshot(core, manifest);
  if (composed.ledgerRevision !== core.ledgerRevision) throw new Error('Composition changed authority revision');
  const token = createInventoryObserverToken();
  observer = await startInventoryServer({ executor, manifests: [manifest],
    observers: [{ token, tenantIds: ['example-tenant'], profile: 'host' }] });
  const response = await fetch(`${observer.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'example-tenant' }) });
  if (!response.ok) throw new Error('Manifest example failed');
  process.stdout.write(`${JSON.stringify(await response.json())}\n`);
} finally { await observer?.close(); executor.close(); }
