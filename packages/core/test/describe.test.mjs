import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuard } from '@shieldaai/agent-guard';

const tool = (name, extra = {}) => ({
  name,
  description: `The ${name} tool`,
  resolve: () => ({ resourceId: 'r', tenantId: 'acme' }),
  execute: () => ({ value: 'done' }),
  ...extra,
});
const plain = value => JSON.parse(JSON.stringify(value));

test('describe lists registered tools by name with their declared labels', () => {
  const guard = new AgentGuard({ untrustedContextDefault: 'require_approval' });
  const sendPrint = guard.registerTool(
    tool('mail.send', { sendsExternal: true, readsUntrusted: false, untrustedContext: 'deny', requiresApproval: true }),
  );
  guard.registerTool(tool('docs.read', { readsUntrusted: true, maxCost: 3 }));
  guard.approveTool('mail.send', sendPrint);
  const description = guard.describe();
  assert.equal(description.kind, 'agent-guard-description');
  assert.equal(description.schemaVersion, 1);
  assert.equal(description.untrustedContextDefault, 'require_approval');
  assert.deepEqual(
    description.tools.map(item => item.name),
    ['docs.read', 'mail.send'],
  );
  const [docs, mail] = plain(description.tools);
  assert.deepEqual(docs, {
    name: 'docs.read',
    fingerprint: docs.fingerprint,
    revision: docs.revision,
    approved: false,
    requiresApproval: false,
    controlPlane: false,
    maxCost: 3,
    readsUntrusted: true,
    untrustedContext: null,
    sendsExternal: null,
  });
  assert.match(docs.fingerprint, /^sha256:/);
  assert.equal(mail.fingerprint, sendPrint);
  assert.deepEqual(
    [mail.approved, mail.requiresApproval, mail.readsUntrusted, mail.untrustedContext, mail.sendsExternal],
    [true, true, false, 'deny', true],
  );
});

test('undeclared labels are null, never a guessed false', () => {
  const guard = new AgentGuard();
  guard.registerTool(tool('plain'));
  const [plainTool] = guard.describe().tools;
  assert.deepEqual([plainTool.readsUntrusted, plainTool.untrustedContext, plainTool.sendsExternal], [null, null, null]);
  assert.equal(guard.describe().untrustedContextDefault, 'allow');
});

test('describe is frozen, JSON-safe and tracks registration changes', () => {
  const guard = new AgentGuard();
  const first = guard.registerTool(tool('a'));
  guard.approveTool('a', first);
  const before = guard.describe();
  assert.ok(Object.isFrozen(before) && Object.isFrozen(before.tools) && Object.isFrozen(before.tools[0]));
  assert.throws(() => {
    before.tools[0].approved = false;
  }, TypeError);
  assert.deepEqual(plain(before), before);
  // Registering again withdraws approval; unregistering removes the tool.
  guard.registerTool(tool('a', { description: 'changed' }));
  const after = guard.describe();
  assert.equal(after.tools[0].approved, false);
  assert.notEqual(after.tools[0].fingerprint, before.tools[0].fingerprint);
  assert.ok(after.tools[0].revision > before.tools[0].revision);
  guard.unregisterTool('a');
  assert.deepEqual(guard.describe().tools, []);
});

test('describe carries no functions, arguments or secret values', () => {
  const guard = new AgentGuard({ secretValues: ['s3cr3t-value-123'] });
  guard.registerTool(tool('x', { metadata: { owner: 'team' } }));
  const text = JSON.stringify(guard.describe());
  assert.ok(!text.includes('s3cr3t'));
  const keys = Object.keys(guard.describe().tools[0]);
  for (const key of ['description', 'metadata', 'inputSchema', 'resolve', 'execute'])
    assert.ok(!keys.includes(key), key);
  assert.ok(!text.includes('owner'));
});
