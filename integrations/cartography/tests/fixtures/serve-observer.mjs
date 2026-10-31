// Disposable real observer for Python collector tests. Credentials travel only over parent IPC.
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';
import { DurableExecutor, startInventoryServer, createInventoryObserverToken } from '../../../../packages/executor/dist/index.js';

const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32),
  inventory: { companyId: 'collector-company', sourceId: 'collector-executor', enrollmentGeneration: 'generation-one' } });
const tool = 'storage.read';
const fingerprint = executor.registerTool({ name: tool, description: 'private-description-canary',
  resolve() { throw new Error('Collector resolved an operation'); },
  execute() { throw new Error('Collector executed an operation'); } });
executor.approveTool(tool, fingerprint);
executor.createTask({ id: 'reader-task', tenantId: 'alpha', principalId: 'application',
  grants: [{ tool, resources: ['private-alias-canary'] }],
  budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 3_600_000 } });
const core = executor.inventorySnapshot({ tenantId: 'alpha' });
const manifest = { schemaVersion: 1, evidenceKind: 'host_asserted', source: core.source,
  manifestId: 'collector-config', revision: 1, observedAt: new Date().toISOString(),
  agents: [{ id: 'reader', name: 'Reader', ownerId: null, teamId: 'reports' }],
  deployments: [{ id: 'reader-deployment', agentId: 'reader', environment: 'test' }],
  taskBindings: [{ taskId: 'reader-task', deploymentId: 'reader-deployment' }],
  resourceBindings: [{ id: 'report-binding', tool, resourceRef: core.tasks[0].grants[0].resources[0],
    target: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
      arn: 'arn:aws:s3:::collector-reports/report.txt', kind: 'object' }, actions: ['s3:GetObject'], scope: 'exact' }],
  executionBindings: [{ id: 'reader-identity', tool, deploymentId: 'reader-deployment', connectionId: null,
    identitySelection: 'static', identity: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
      arn: 'arn:aws:iam::111122223333:role/CollectorReader' } }] };
const token = createInventoryObserverToken();
const observer = await startInventoryServer({ executor, observers: [{ token, tenantIds: ['alpha'], profile: 'host' }],
  manifests: [manifest] });
process.stdout.write(`${JSON.stringify({ endpoint: `${observer.url}/v1/inventory/snapshot`, token, source: core.source, profile: 'host' })}\n`);
const lines = createInterface({ input: process.stdin });
try {
  for await (const line of lines) {
    if (line === 'close') break;
    if (line === 'revoke') executor.revokeTask('reader-task');
    process.stdout.write(`${JSON.stringify({ status: 'ok' })}\n`);
  }
} finally {
  lines.close(); await observer.close(); executor.close();
}
