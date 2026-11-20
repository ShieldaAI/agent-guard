import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { AgentGuard } from '@shieldaai/agent-guard';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import { createInventoryObserverToken, startInventoryServer } from '@shieldaai/agent-guard-executor/inventory';
import { MemorySource, parseConfig, scan } from '@shieldaai/agent-guard-check';
import { findingsFor, json, mcp, ruleIds, scanFiles } from './helpers.mjs';

const tool = (name, extra = {}) => ({
  name,
  description: name,
  resolve: () => ({ resourceId: 'r', tenantId: 'acme' }),
  execute: () => ({ value: 1 }),
  ...extra,
});
const HOUR = 3_600_000;
const AT = '2026-11-16T00:00:00.000Z';
const NOW = Date.parse(AT);

/** A synthetic inventory snapshot in the executor's v2 shape (resources are opaque in real ones). */
function inventory({ tools = [], tasks = [], untrustedContextDefault = 'allow', mcpConnections, manifest } = {}) {
  return json({
    schemaVersion: 2,
    profile: mcpConnections ? 'host-mcp' : manifest ? 'host' : 'core',
    snapshotId: '00000000-0000-4000-8000-000000000001',
    generatedAt: AT,
    source: { companyId: 'c', sourceId: 's', tenantId: 'acme' },
    untrustedContextDefault,
    tools: tools.map(item => ({
      registered: true,
      approved: true,
      requiresApproval: false,
      controlPlane: false,
      maxCost: 0,
      revision: 1,
      fingerprint: 'a'.repeat(64),
      readsUntrusted: null,
      sendsExternal: null,
      untrustedContext: null,
      ...item,
    })),
    tasks: tasks.map(item => ({
      principalId: 'agent-a',
      tenantId: 'acme',
      parentTaskId: null,
      revoked: false,
      sensitive: false,
      untrusted: false,
      allowedRecipients: ['opaque:1'],
      budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: NOW + HOUR },
      ...item,
    })),
    ...(mcpConnections
      ? {
          mcp: {
            observedAt: AT,
            connections: mcpConnections.map((serverId, i) => ({
              connectionId: `c${i}`,
              status: 'observed',
              inventory: { identity: { serverId, principalId: 'p', tenantId: 'acme' }, state: 'ready' },
            })),
          },
        }
      : {}),
    ...(manifest ? { manifest } : {}),
  });
}

const reader = { name: 'web.read', readsUntrusted: true, sendsExternal: false };
const sender = { name: 'mail.send', sendsExternal: true, readsUntrusted: false };
const exposedTask = {
  id: 'task-1',
  grants: [
    { tool: 'web.read', resources: ['opaque:a'] },
    { tool: 'mail.send', resources: ['opaque:b'] },
  ],
};
/** A host manifest (embedded in host inventories) marking the task's web.read resource confidential. */
const confidential = {
  schemaVersion: 3,
  evidenceKind: 'host_asserted',
  agents: [],
  resourceBindings: [
    { id: 'opaque:rb1', tool: 'web.read', resourceRef: 'opaque:a', scope: 'exact', sensitivity: 'confidential' },
  ],
};
const exposed = (tools, extra = {}) => inventory({ tools, tasks: [exposedTask], manifest: confidential, ...extra });

test('Agent Guard files are recognised by content and listed in the result', () => {
  const result = scanFiles({ 'agent-guard-inventory.json': inventory({ tools: [sender] }), 'README.md': '# x' });
  assert.deepEqual(result.modes.agentGuard, [{ path: 'agent-guard-inventory.json', kind: 'inventory' }]);
  assert.equal(result.modes.live, null);
  assert.deepEqual(result.errors, []);
});

test('a repository without Agent Guard records triggers no AGX rule', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.0.0'] } }),
  });
  assert.ok(!ruleIds(result).some(id => id.startsWith('AGC-AGX')));
  assert.deepEqual(result.modes.agentGuard, []);
});

test('a malformed Agent Guard file is an error, not a guess', () => {
  const broken = JSON.parse(inventory({ tools: [sender] }));
  broken.tools[0].approved = 'yes';
  const result = scanFiles({ 'agent-guard-inventory.json': json(broken) });
  assert.match(result.errors[0].message, /tools\[0\]\.approved must be a boolean/);
  assert.deepEqual(result.modes.agentGuard, []);
  const future = scanFiles({
    'agent-guard-description.json': json({ kind: 'agent-guard-description', schemaVersion: 9, tools: [] }),
  });
  assert.match(future.errors[0].message, /unsupported describe\(\) schemaVersion 9/);
});

test('AGX-003: a live task with all three legs and a sender on allow is critical', () => {
  const result = scanFiles({
    'agent-guard-inventory.json': exposed([reader, sender]),
  });
  const [finding] = findingsFor(result, 'AGC-AGX-003');
  assert.equal(finding.severity, 'critical');
  assert.match(finding.message, /task-1.*exposed.*mail\.send/s);
  assert.equal(finding.location.file, 'agent-guard-inventory.json');
  assert.ok(finding.location.line > 1);
});

test('AGX-003: requiring approval after untrusted content mitigates the task', () => {
  const guarded = { ...sender, untrustedContext: 'require_approval' };
  const result = scanFiles({
    'agent-guard-inventory.json': exposed([reader, guarded]),
  });
  assert.deepEqual(findingsFor(result, 'AGC-AGX-003'), []);
  const byDefault = scanFiles({
    'agent-guard-inventory.json': exposed([reader, sender], { untrustedContextDefault: 'deny' }),
  });
  assert.deepEqual(findingsFor(byDefault, 'AGC-AGX-003'), []);
});

test('AGX-003: the core refuses sends from sensitive tasks and tasks without recipients', () => {
  for (const change of [{ allowedRecipients: [] }, { sensitive: true }]) {
    const task = { ...exposedTask, ...change };
    const result = scanFiles({
      'agent-guard-inventory.json': inventory({ tools: [reader, sender], tasks: [task], manifest: confidential }),
    });
    assert.deepEqual(findingsFor(result, 'AGC-AGX-003'), [], JSON.stringify(change));
  }
});

test('AGX-003: unknown recipients or sensitivity keep the send leg unknown', () => {
  const task = { ...exposedTask, allowedRecipients: null };
  const result = scanFiles({
    'agent-guard-inventory.json': inventory({ tools: [reader, sender], tasks: [task], manifest: confidential }),
  });
  const [finding] = findingsFor(result, 'AGC-AGX-003');
  assert.equal(finding.severity, 'medium');
});

test('AGX-003: undeclared labels with two present legs give a medium finding', () => {
  const unlabeled = { name: 'mail.send' };
  const result = scanFiles({
    'agent-guard-inventory.json': exposed([reader, unlabeled]),
  });
  const [finding] = findingsFor(result, 'AGC-AGX-003');
  assert.equal(finding.severity, 'medium');
  assert.match(finding.message, /externalSend cannot be determined/);
});

test('AGX-003: revoked tasks, expired tasks and tasks under a revoked parent are ignored', () => {
  const revoked = { ...exposedTask, revoked: true };
  const expired = {
    ...exposedTask,
    id: 'task-2',
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: NOW - 1 },
  };
  const parent = { id: 'parent', revoked: true, grants: [] };
  const child = { ...exposedTask, id: 'child', parentTaskId: 'parent' };
  const result = scanFiles({
    'agent-guard-inventory.json': inventory({
      tools: [reader, sender],
      tasks: [revoked, expired, parent, child],
      manifest: confidential,
    }),
  });
  assert.deepEqual(findingsFor(result, 'AGC-AGX-003'), []);
});

test('AGX-003 from describe() alone judges the registry at medium', () => {
  const guard = new AgentGuard();
  guard.registerTool(tool('web.read', { readsUntrusted: true, sendsExternal: false }));
  guard.registerTool(tool('mail.send', { sendsExternal: true }));
  const result = scanFiles({ 'agent-guard-description.json': json(guard.describe()) });
  const [finding] = findingsFor(result, 'AGC-AGX-003');
  assert.equal(finding.severity, 'medium');
  assert.match(finding.message, /mail\.send can send data out without approval after web\.read/);

  const safe = new AgentGuard({ untrustedContextDefault: 'require_approval' });
  safe.registerTool(tool('web.read', { readsUntrusted: true, sendsExternal: false }));
  safe.registerTool(tool('mail.send', { sendsExternal: true }));
  assert.deepEqual(
    findingsFor(scanFiles({ 'agent-guard-description.json': json(safe.describe()) }), 'AGC-AGX-003'),
    [],
  );
});

test('AGX-005 and AGX-008 read real describe() output', () => {
  const guard = new AgentGuard();
  const approved = guard.registerTool(tool('docs.read', { sendsExternal: false }));
  guard.approveTool('docs.read', approved);
  guard.registerTool(tool('shell.run'));
  const result = scanFiles({ 'agent-guard-description.json': json(guard.describe()) });
  const unapproved = findingsFor(result, 'AGC-AGX-005');
  assert.deepEqual(
    unapproved.map(finding => finding.message.split(' ')[1]),
    ['shell.run'],
  );
  const undeclared = findingsFor(result, 'AGC-AGX-008');
  assert.equal(undeclared.length, 1);
  assert.equal(undeclared[0].severity, 'low');
  assert.match(undeclared[0].message, /shell\.run does not declare sendsExternal/);
});

test('AGX-008: an outbound tool on allow next to an untrusted reader is medium', () => {
  const result = scanFiles({ 'agent-guard-inventory.json': inventory({ tools: [reader, sender] }) });
  const finding = findingsFor(result, 'AGC-AGX-008').find(item => item.message.includes('allow'));
  assert.equal(finding.severity, 'medium');
});

test('AGX-006: a wildcard grant on a sending tool, and grants to unregistered tools', () => {
  const task = {
    id: 'wide',
    grants: [
      { tool: 'mail.send', resources: ['*'] },
      { tool: 'ghost.tool', resources: ['opaque:x'] },
    ],
  };
  const result = scanFiles({ 'agent-guard-inventory.json': inventory({ tools: [sender], tasks: [task] }) });
  const findings = findingsFor(result, 'AGC-AGX-006');
  assert.deepEqual(findings.map(finding => finding.severity).sort(), ['low', 'medium']);
  assert.ok(findings.some(finding => /every resource/.test(finding.message)));
  assert.ok(findings.some(finding => /ghost\.tool, which is not registered/.test(finding.message)));
});

test('AGX-007: budgets above the default and configured ceilings', () => {
  const task = {
    id: 'long',
    grants: [],
    budget: { maxCalls: 5000, maxConcurrent: 1, maxCost: 900, deadline: NOW + 72 * HOUR },
  };
  const files = { 'agent-guard-inventory.json': inventory({ tasks: [task] }) };
  const [finding] = findingsFor(scanFiles(files), 'AGC-AGX-007');
  assert.match(finding.message, /deadline 72 h away \(ceiling 24 h\), maxCalls 5000 \(ceiling 1000\)/);
  const config = parseConfig('agent_guard:\n  max_deadline_hours: 168\n  max_calls: 10000\n  max_cost: 100\n');
  const [custom] = findingsFor(scanFiles(files, { config }), 'AGC-AGX-007');
  assert.match(custom.message, /^Task long has a budget above the ceiling: maxCost 900 \(ceiling 100\)\.$/);
});

test('AGX-001: an MCP server the guard mediates is also configured directly', () => {
  const files = {
    'agent-guard-inventory.json': inventory({ mcpConnections: ['github'] }),
    '.mcp.json': mcp({
      gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.0.0'] },
      notes: { command: 'npx', args: ['-y', 'some-notes-server@1.0.0'] },
    }),
  };
  const findings = findingsFor(scanFiles(files), 'AGC-AGX-001');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /"gh".*mediates it as "github"/);
});

test('AGX-002 and AGX-004 read manifest declarations', () => {
  const manifest = {
    schemaVersion: 3,
    evidenceKind: 'host_asserted',
    source: { companyId: 'c', sourceId: 's', tenantId: 'acme' },
    agents: [
      {
        id: 'invoice',
        name: 'Invoice agent',
        ownerId: 'finance',
        lifecycleState: 'active',
        ownershipStatus: 'assigned',
      },
      { id: 'legacy', name: 'Legacy agent', ownerId: null, lifecycleState: 'retired', ownershipStatus: 'unassigned' },
    ],
    deployments: [
      { id: 'd1', agentId: 'invoice' },
      { id: 'd2', agentId: 'legacy' },
    ],
    taskBindings: [{ taskId: 'old-task', deploymentId: 'd2' }],
    resourceBindings: [],
    directAccess: [
      { id: 'opaque:da1', deploymentId: 'd1', kind: 'shell', targetRef: null, description: 'Runs report scripts' },
      { id: 'opaque:da2', deploymentId: 'd1', kind: 'sdk', targetRef: null, description: '' },
    ],
  };
  const result = scanFiles({
    'agent-guard-manifest.json': json(manifest),
    'agent-guard-inventory.json': inventory({ tasks: [{ id: 'old-task', grants: [] }] }),
  });
  assert.deepEqual(
    findingsFor(result, 'AGC-AGX-002').map(finding => finding.severity),
    ['high', 'medium'],
  );
  const owners = findingsFor(result, 'AGC-AGX-004');
  assert.deepEqual(owners.map(finding => finding.severity).sort(), ['high', 'medium']);
  assert.ok(owners.some(finding => /Legacy agent is retired but still has 1 live task/.test(finding.message)));
  assert.equal(owners.find(finding => finding.severity === 'medium').location.file, 'agent-guard-manifest.json');
});

test('a manifest v4 file is read like v3; its network isolation adds no finding', () => {
  const manifest = {
    schemaVersion: 4,
    evidenceKind: 'host_asserted',
    source: { companyId: 'c', sourceId: 's', tenantId: 'acme' },
    agents: [{ id: 'invoice', name: 'Invoice agent', ownerId: 'finance', ownershipStatus: 'assigned' }],
    deployments: [{ id: 'd1', agentId: 'invoice' }],
    taskBindings: [],
    resourceBindings: [],
    directAccess: [
      { id: 'opaque:da1', deploymentId: 'd1', kind: 'shell', targetRef: null, description: 'Runs report scripts' },
    ],
    networkIsolation: [{ deploymentId: 'd1', segmentId: null, egress: 'none', egressTargets: [], sandbox: 'vm' }],
  };
  const result = scanFiles({ 'agent-guard-manifest.json': json(manifest) });
  assert.deepEqual(result.errors, []);
  assert.equal(findingsFor(result, 'AGC-AGX-002').length, 1, 'the v3 part is still read');
  const future = scanFiles({ 'agent-guard-manifest.json': json({ ...manifest, schemaVersion: 5 }) });
  assert.match(future.errors[0].message, /unsupported manifest schemaVersion 5/);
});

test('a real executor inventory snapshot is read without errors', async () => {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    inventory: { companyId: 'c', sourceId: 's', enrollmentGeneration: 'g' },
  });
  let observer;
  try {
    const fingerprint = executor.registerTool(tool('mail.send', { sendsExternal: true }));
    executor.approveTool('mail.send', fingerprint);
    executor.registerTool(tool('web.read', { readsUntrusted: true, sendsExternal: false }));
    executor.createTask({
      id: 'task-1',
      principalId: 'agent-a',
      tenantId: 'acme',
      grants: [
        { tool: 'mail.send', resources: ['*'] },
        { tool: 'web.read', resources: ['page'] },
      ],
      allowedRecipients: ['someone@example.com'],
      budget: { maxCalls: 5000, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 72 * HOUR },
    });
    const token = createInventoryObserverToken();
    observer = await startInventoryServer({ executor, observers: [{ token, tenantIds: ['acme'], profile: 'core' }] });
    const response = await fetch(`${observer.url}/v1/inventory/snapshot`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ tenantId: 'acme' }),
    });
    const snapshot = await response.text();
    const result = scan({
      root: '/repo',
      source: new MemorySource({}),
      agentGuardFiles: [{ path: 'snapshot.json', text: snapshot }],
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.modes.agentGuard, [{ path: 'snapshot.json', kind: 'inventory' }]);
    const ids = new Set(ruleIds(result));
    for (const id of ['AGC-AGX-005', 'AGC-AGX-006', 'AGC-AGX-007', 'AGC-AGX-008']) assert.ok(ids.has(id), id);
    // The task is not sensitive, so the dangerous three are not all present.
    assert.ok(
      !ids.has('AGC-AGX-003') || findingsFor(result, 'AGC-AGX-003').every(finding => finding.severity !== 'critical'),
    );
  } finally {
    await observer?.close();
    executor.close();
  }
});

test('agent_guard.files reads named records; a missing one is reported', () => {
  const config = 'agent_guard:\n  files: [build/guard.json, build/missing.json]\n';
  const result = scanFiles({ '.agc.yaml': config, 'build/guard.json': inventory({ tools: [sender] }) });
  assert.deepEqual(result.modes.agentGuard, [{ path: 'build/guard.json', kind: 'inventory' }]);
  assert.match(result.errors.map(error => error.message).join('\n'), /build\/missing\.json was not found/);
});
