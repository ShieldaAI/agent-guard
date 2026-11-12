// Synthetic host manifest -> observer -> consumer fixture. No production state or credentials.
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../../../../packages/executor/dist/index.js';
import { composeInventorySnapshot, validateInventoryManifest, createInventoryObserverToken, startInventoryServer } from '../../../../packages/executor/dist/entry-inventory.js';

const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-manifest-contract-')));
let executor;
let server;
try {
  executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 7),
    clock: () => 1000,
    inventory: { companyId: 'company', sourceId: 'manifest-executor', enrollmentGeneration: 'generation' } });
  const fingerprint = executor.registerTool({ name: 'records.read', description: 'private-descriptor-canary',
    metadata: { secret: 'private-metadata-canary' }, requiresApproval: true,
    resolve: () => { throw new Error('Composition called a resolver'); },
    execute: () => { throw new Error('Composition called an executor'); } });
  executor.approveTool('records.read', fingerprint);
  const rawResources = ['https://user:private-password-canary@private.invalid/report', 'private-prefix-canary'];
  const budget = { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100_000.5 };
  const root = executor.createTask({ id: 'root', tenantId: 'alpha', principalId: 'shared-caller', budget,
    grants: [{ tool: 'records.read', resources: rawResources }, { tool: 'future.tool', resources: ['*'] }] });
  executor.delegateTask('root', { id: 'child', budget,
    grants: [{ tool: 'records.read', resources: rawResources }] });
  executor.createTask({ id: 'unassigned', tenantId: 'alpha', principalId: 'unassigned-caller', budget,
    grants: [{ tool: 'future.tool', resources: ['*'] }] });
  executor.createTask({ id: 'beta-private-task', tenantId: 'beta', principalId: 'beta-private-caller', budget,
    grants: [{ tool: 'beta-private-tool', resources: ['beta-private-resource'] }] });
  const core = executor.inventorySnapshot({ tenantId: 'alpha' });
  const refs = core.tasks.find(task => task.id === 'root').grants.find(grant => grant.tool === 'records.read').resources;
  const source = { ...core.source };
  const manifest = {
    schemaVersion: 1, evidenceKind: 'host_asserted', source, manifestId: 'manifest-one', revision: 1,
    observedAt: '2026-10-30T00:00:00Z',
    agents: [
      { id: 'agent-research', name: 'Research worker', ownerId: 'owner-research', teamId: 'team-research' },
      { id: 'agent-review', name: 'Review worker', ownerId: null, teamId: 'team-review' },
    ],
    deployments: [
      { id: 'deployment-static', agentId: 'agent-research', environment: 'test' },
      { id: 'deployment-dynamic', agentId: 'agent-review', environment: null },
    ],
    taskBindings: [{ taskId: 'root', deploymentId: 'deployment-static' }, { taskId: 'child', deploymentId: 'deployment-dynamic' }],
    resourceBindings: [
      { id: 'object-binding', tool: 'records.read', resourceRef: refs[0],
        target: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
          arn: 'arn:aws:s3:::manifest-fixture/reports/report.json', kind: 'object' },
        actions: ['s3:GetObject'], scope: 'exact' },
      { id: 'prefix-binding', tool: 'records.read', resourceRef: refs[1],
        target: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '',
          arn: 'arn:aws:s3:::manifest-fixture/reports/', kind: 'prefix' },
        actions: ['s3:GetObject'], scope: 'prefix' },
    ],
    executionBindings: [
      { id: 'static-execution', tool: 'records.read', deploymentId: 'deployment-static', connectionId: null,
        identitySelection: 'static', identity: { provider: 'aws', partition: 'aws', accountId: '111122223333',
          region: '', arn: 'arn:aws:iam::111122223333:role/ManifestReader' } },
      { id: 'dynamic-execution', tool: 'records.read', deploymentId: 'deployment-dynamic',
        connectionId: 'declared-mcp-reference', identitySelection: 'dynamic', identity: null },
    ],
  };
  const v3 = process.argv.includes('--v3');
  if (v3 || process.argv.includes('--v2')) {
    const opaque = character => `opaque:${character.repeat(64)}`;
    Object.assign(manifest, { schemaVersion: 2, authorityId: 'company-directory',
      owners: [{ id: 'owner-research', name: 'Research team', kind: 'team' },
        { id: 'owner-review', name: 'Review team', kind: 'team' }],
      credentialReferences: ['a', 'b'].map((character, index) => ({ id: opaque(character),
        name: index ? 'Review credential' : 'Research credential', issuerRef: opaque('c'),
        audienceRefs: [opaque('d')], recipientRefs: [opaque('e')], lifecycleState: 'active',
        expiresAt: '2026-12-01T00:00:00Z', rotationStatus: 'current' })) });
    manifest.agents.forEach(agent => Object.assign(agent, {
      purpose: 'Reviewed records workflow', lifecycleState: 'active',
      ownershipStatus: agent.ownerId === null ? 'unassigned' : 'assigned',
      ownershipSource: 'company-directory' }));
    manifest.deployments.forEach((deployment, index) => Object.assign(deployment, {
      runtimeRef: opaque(index ? 'f' : '0'), workloadGeneration: 'generation-1', buildRef: opaque('1'),
      bindingAuthority: 'deployment-controller', credentialReferenceIds: [opaque(index ? 'b' : 'a')] }));
    manifest.resourceBindings.forEach((binding, index) => Object.assign(binding, {
      displayName: index ? 'Company records' : 'Reviewed report', ownerId: index ? 'owner-review' : 'owner-research',
      ownershipStatus: 'assigned', ownershipSource: 'company-directory', sensitivity: 'internal',
      approvedDestinations: [opaque('2')], dependsOn: index ? ['object-binding'] : [] }));
    Object.assign(manifest.resourceBindings[1], {
      target: { provider: 'host', id: opaque('3'), name: 'Company records', kind: 'database' },
      actions: ['read'], scope: 'exact' });
    // v3: one declared path outside the guard for the static deployment, none for the dynamic one.
    if (v3) Object.assign(manifest, { schemaVersion: 3, directAccess: [{ id: opaque('4'),
      deploymentId: 'deployment-static', kind: 'database', targetRef: opaque('3'),
      description: 'Reporting job connects to the records database directly' }] });
  }
  const validated = validateInventoryManifest(manifest);
  assert.equal(Object.isFrozen(validated.resourceBindings[0].target), true);
  const composed = composeInventorySnapshot(core, validated);
  // Manifest v3 lifts a v1 core to the v2 snapshot shape; nothing else changes.
  const lifted = ({ untrusted: _u, readsUntrusted: _r, untrustedContext: _c, sendsExternal: _s, ...rest }) => rest;
  const plain = value => JSON.parse(JSON.stringify(value));
  assert.deepEqual(v3 ? plain(composed.tasks.map(lifted)) : composed.tasks, v3 ? plain(core.tasks) : core.tasks);
  assert.deepEqual(v3 ? plain(composed.tools.map(lifted)) : composed.tools, v3 ? plain(core.tools) : core.tools);
  assert.equal(composed.ledgerRevision, core.ledgerRevision);
  assert.equal(composed.policyEpoch, core.policyEpoch);
  assert.notEqual(composed.snapshotId, core.snapshotId);
  assert.equal(Object.isFrozen(composed.manifest.executionBindings), true);
  assert.throws(() => { composed.manifest.agents[0].name = 'changed'; }, TypeError);
  const failures = [];
  for (const [label, operation] of [
    ['extra-field', () => validateInventoryManifest({ ...manifest, token: 'private-error-canary' })],
    ['wrong-source', () => composeInventorySnapshot(core, { ...manifest, source: { ...source, tenantId: 'beta' } })],
    ['wrong-account', () => validateInventoryManifest({ ...manifest, executionBindings: [
      { ...manifest.executionBindings[0], identity: { ...manifest.executionBindings[0].identity, accountId: '999988887777' } },
    ] })],
    ['wildcard-binding', () => validateInventoryManifest({ ...manifest, resourceBindings: [
      { ...manifest.resourceBindings[0], resourceRef: '*' },
    ] })],
    ['raw-alias', () => composeInventorySnapshot(core, { ...manifest, resourceBindings: [
      { ...manifest.resourceBindings[0], resourceRef: rawResources[0] },
    ] })],
    ['poisoned-core', () => composeInventorySnapshot({ ...core, token: 'private-error-canary' }, manifest)],
  ]) {
    let failed = false;
    try { operation(); }
    catch (error) {
      failed = true;
      assert.match(error.code, /^INVENTORY_[A-Z_]+$/);
      assert.equal(error.message, error.code);
      failures.push({ label, code: error.code });
    }
    assert.equal(failed, true, label);
  }
  const hostToken = createInventoryObserverToken(), coreToken = createInventoryObserverToken();
  server = await startInventoryServer({ executor, manifests: [manifest], observers: [
    { token: hostToken, tenantIds: ['alpha'], profile: 'host' },
    { token: coreToken, tenantIds: ['alpha'], profile: 'core' },
  ] });
  // Configuration must be detached from mutable host input once the listener starts.
  manifest.agents[0].name = 'mutated-after-start';
  const request = async (token, input) => {
    const response = await fetch(`${server.url}/v1/inventory/snapshot`, { method: 'POST', redirect: 'error',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(input), signal: AbortSignal.timeout(5000) });
    const bytes = Buffer.from(await response.arrayBuffer());
    return { status: response.status, cacheControl: response.headers.get('cache-control'),
      contentLength: response.headers.get('content-length'), byteLength: bytes.byteLength,
      body: JSON.parse(bytes.toString('utf8')) };
  };
  const observedHost = await request(hostToken, { tenantId: 'alpha' });
  const observedCore = await request(coreToken, { tenantId: 'alpha' });
  const forbidden = await request(hostToken, { tenantId: 'beta' });
  const override = await request(coreToken, { tenantId: 'alpha', profile: 'host' });
  const after = executor.inventorySnapshot({ tenantId: 'alpha' });
  const output = JSON.stringify({ core, validated, composed, observedHost, observedCore, forbidden, override, after, failures });
  for (const privateValue of [root.token, hostToken, coreToken, 'private-', 'beta-private-', 'mutated-after-start']) {
    assert.equal(output.includes(privateValue), false, 'Private or mutable value reached composition output');
  }
  process.stdout.write(output);
} finally {
  try { await server?.close(); }
  finally { executor?.close(); rmSync(directory, { recursive: true, force: true }); }
}
