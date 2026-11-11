// Synthetic, disposable company catalog. Run after npm run build.
// An installed company host retains its own source enrollment and reference key.
import { createHmac, randomBytes } from 'node:crypto';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import {
  validateInventoryManifest,
  composeInventorySnapshot,
  createInventoryObserverToken,
  startInventoryServer,
} from '@shieldaai/agent-guard-executor/inventory';

const referenceKey = randomBytes(32);
const reference = (kind, id) =>
  `opaque:${createHmac('sha256', referenceKey)
    .update(JSON.stringify(['example-tenant', kind, id]))
    .digest('hex')}`;
const executor = new DurableExecutor({
  database: ':memory:',
  encryptionKey: randomBytes(32),
  inventory: { companyId: 'example-company', sourceId: 'company-host', enrollmentGeneration: 'catalog-demo-1' },
});
let observer;
try {
  const fingerprint = executor.registerTool({
    name: 'reports.read',
    description: 'Synthetic report reader',
    resolve: () => {
      throw new Error('Inventory must not resolve an action');
    },
    execute: () => {
      throw new Error('Inventory must not execute an action');
    },
  });
  executor.approveTool('reports.read', fingerprint);
  executor.createTask({
    id: 'report-task',
    principalId: 'application-caller',
    tenantId: 'example-tenant',
    grants: [{ tool: 'reports.read', resources: ['private-company-database-selector'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  const core = executor.inventorySnapshot({ tenantId: 'example-tenant' });
  const credentialId = reference('credential', 'reports-workload');
  const manifest = validateInventoryManifest({
    schemaVersion: 2,
    evidenceKind: 'host_asserted',
    source: core.source,
    authorityId: 'company-directory',
    manifestId: 'company-catalog',
    revision: 1,
    observedAt: new Date().toISOString(),
    owners: [{ id: 'reports-team', name: 'Reports team', kind: 'team' }],
    agents: [
      {
        id: 'report-agent',
        name: 'Report assistant',
        ownerId: 'reports-team',
        teamId: 'reports',
        purpose: 'Prepare reviewed company reports',
        lifecycleState: 'active',
        ownershipStatus: 'assigned',
        ownershipSource: 'company-directory',
      },
    ],
    deployments: [
      {
        id: 'report-deployment',
        agentId: 'report-agent',
        environment: 'demo',
        runtimeRef: reference('runtime', 'reports'),
        workloadGeneration: 'generation-1',
        buildRef: reference('build', 'reviewed-build'),
        bindingAuthority: 'company-deployment-controller',
        credentialReferenceIds: [credentialId],
      },
    ],
    taskBindings: [{ taskId: 'report-task', deploymentId: 'report-deployment' }],
    resourceBindings: [
      {
        id: 'reports-db',
        tool: 'reports.read',
        resourceRef: core.tasks[0].grants[0].resources[0],
        target: {
          provider: 'host',
          id: reference('resource', 'reports-db'),
          name: 'Company reports database',
          kind: 'database',
        },
        actions: ['record.read'],
        scope: 'exact',
        displayName: 'Reviewed reports',
        ownerId: 'reports-team',
        ownershipStatus: 'assigned',
        ownershipSource: 'company-directory',
        sensitivity: 'internal',
        approvedDestinations: [reference('destination', 'reports')],
        dependsOn: [],
      },
    ],
    executionBindings: [
      {
        id: 'reports-runtime',
        tool: 'reports.read',
        deploymentId: 'report-deployment',
        connectionId: null,
        identitySelection: 'dynamic',
        identity: null,
      },
    ],
    credentialReferences: [
      {
        id: credentialId,
        name: 'Reports workload identity',
        issuerRef: reference('issuer', 'company-provider'),
        audienceRefs: [reference('audience', 'reports')],
        recipientRefs: [reference('recipient', 'reports')],
        lifecycleState: 'active',
        expiresAt: null,
        rotationStatus: 'unknown',
      },
    ],
  });
  const composed = composeInventorySnapshot(core, manifest);
  if (composed.ledgerRevision !== core.ledgerRevision) throw new Error('Inventory changed authority');
  const token = createInventoryObserverToken();
  observer = await startInventoryServer({
    executor,
    manifests: [manifest],
    observers: [{ token, tenantIds: ['example-tenant'], profile: 'host' }],
  });
  const response = await fetch(`${observer.url}/v1/inventory/snapshot`, {
    method: 'POST',
    redirect: 'error',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId: 'example-tenant' }),
  });
  if (!response.ok) throw new Error('Company catalog observation failed');
  process.stdout.write(`${JSON.stringify(await response.json())}\n`);
} finally {
  await observer?.close();
  executor.close();
  referenceKey.fill(0);
}
