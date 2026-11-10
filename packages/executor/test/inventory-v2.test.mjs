import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '../dist/index.js';
import { composeInventorySnapshot } from '../dist/entry-inventory.js';

const enrollment = { companyId: 'company', sourceId: 'installation', enrollmentGeneration: 'generation' };
const plain = value => JSON.parse(JSON.stringify(value));
function boundaryExecutor(labels = true) {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    inventory: enrollment,
  });
  const tool = definition => executor.approveTool(definition.name, executor.registerTool(definition));
  tool({
    name: 'email.read',
    description: 'inbox',
    ...(labels ? { readsUntrusted: true, sendsExternal: false } : {}),
    resolve: () => ({ resourceId: 'inbox', tenantId: 'acme' }),
    execute: () => ({ value: 'outside text' }),
  });
  tool({
    name: 'email.send',
    description: 'send',
    ...(labels ? { sendsExternal: true, untrustedContext: 'require_approval' } : {}),
    resolve: () => ({ resourceId: 'outbox', tenantId: 'acme', external: true, recipient: 'partner' }),
    execute: () => ({ value: 'sent' }),
  });
  tool({
    name: 'docs.read',
    description: 'plain',
    resolve: () => ({ resourceId: 'handbook', tenantId: 'acme' }),
    execute: () => ({ value: 1 }),
  });
  const grants = ['email.read', 'email.send', 'docs.read'].map((name, index) => ({
    tool: name,
    resources: [['inbox', 'outbox', 'handbook'][index]],
  }));
  const budget = { maxCalls: 9, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 };
  executor.createTask({
    id: 'reader',
    principalId: 'agent',
    tenantId: 'acme',
    grants,
    budget,
    allowedRecipients: ['partner'],
  });
  executor.delegateTask('reader', { id: 'helper', grants, budget, allowedRecipients: ['partner'] });
  executor.createTask({
    id: 'other',
    principalId: 'agent',
    tenantId: 'acme',
    grants,
    budget,
    allowedRecipients: ['partner'],
  });
  return executor;
}

test('without outside-content labels the snapshot stays exactly v1', t => {
  const executor = boundaryExecutor(false);
  t.after(() => executor.close());
  const snapshot = plain(executor.inventorySnapshot({ tenantId: 'acme' }));
  assert.equal(snapshot.schemaVersion, 1);
  assert.ok(snapshot.tasks.every(task => !('untrusted' in task)));
  assert.equal('untrustedContextDefault' in snapshot, false);
  assert.ok(
    snapshot.tools.every(
      tool => !('readsUntrusted' in tool) && !('sendsExternal' in tool) && !('untrustedContext' in tool),
    ),
  );
});

test('declared labels and the family flag produce a v2 snapshot with every v2 field present', async t => {
  const executor = boundaryExecutor();
  t.after(() => executor.close());
  let snapshot = plain(executor.inventorySnapshot({ tenantId: 'acme' }));
  assert.equal(snapshot.schemaVersion, 2);
  assert.equal(snapshot.untrustedContextDefault, 'allow', 'the executor default travels with v2');
  assert.ok(snapshot.tasks.every(task => task.untrusted === false));
  const tools = Object.fromEntries(snapshot.tools.map(tool => [tool.name, tool]));
  assert.deepEqual(
    [tools['email.read'].readsUntrusted, tools['email.read'].sendsExternal, tools['email.read'].untrustedContext],
    [true, false, null],
  );
  assert.deepEqual(
    [tools['email.send'].readsUntrusted, tools['email.send'].sendsExternal, tools['email.send'].untrustedContext],
    [null, true, 'require_approval'],
  );
  assert.deepEqual(
    [tools['docs.read'].readsUntrusted, tools['docs.read'].sendsExternal, tools['docs.read'].untrustedContext],
    [null, null, null],
    'undeclared means unknown',
  );
  await executor.execute('helper', (await executor.prepare('helper', { tool: 'email.read', args: {} })).id);
  snapshot = plain(executor.inventorySnapshot({ tenantId: 'acme' }));
  const untrusted = Object.fromEntries(snapshot.tasks.map(task => [task.id, task.untrusted]));
  assert.deepEqual(untrusted, { reader: true, helper: true, other: false }, 'family-wide, other families unaffected');
});

test('the composers accept v2 and reject a v2 family that disagrees about the flag', t => {
  const executor = boundaryExecutor();
  t.after(() => executor.close());
  const snapshot = plain(executor.inventorySnapshot({ tenantId: 'acme' }));
  const probe = core => {
    try {
      composeInventorySnapshot(core, { not: 'a manifest' });
    } catch (error) {
      return error.code;
    }
    return 'ACCEPTED';
  };
  assert.notEqual(
    probe(snapshot),
    'INVENTORY_SNAPSHOT_INVALID',
    'a valid v2 core passes core validation (then the bogus manifest fails)',
  );
  const split = structuredClone(snapshot);
  split.tasks.find(task => task.id === 'helper').untrusted = true;
  assert.equal(probe(split), 'INVENTORY_SNAPSHOT_INVALID');
  const unregistered = structuredClone(snapshot);
  Object.assign(
    unregistered.tools.find(tool => tool.name === 'email.read'),
    {
      registered: false,
      requiresApproval: null,
      controlPlane: null,
      maxCost: null,
    },
  );
  assert.equal(probe(unregistered), 'INVENTORY_SNAPSHOT_INVALID', 'labels are only known for registered tools');
  const v1Shape = structuredClone(snapshot);
  v1Shape.schemaVersion = 1;
  assert.equal(probe(v1Shape), 'INVENTORY_SNAPSHOT_INVALID', 'v2 fields under a v1 version are refused');
});

test('the reported default follows the executor option and a malformed core value is refused', t => {
  const executor = new DurableExecutor({
    database: ':memory:',
    encryptionKey: randomBytes(32),
    inventory: enrollment,
    untrustedContextDefault: 'require_approval',
  });
  t.after(() => executor.close());
  executor.approveTool(
    'mail.read',
    executor.registerTool({
      name: 'mail.read',
      description: 'inbox',
      readsUntrusted: true,
      resolve: () => ({ resourceId: 'inbox', tenantId: 'acme' }),
      execute: () => ({ value: 1 }),
    }),
  );
  // A snapshot lists the tools its tenant's tasks reference.
  executor.createTask({
    id: 'reader',
    principalId: 'agent',
    tenantId: 'acme',
    grants: [{ tool: 'mail.read', resources: ['inbox'] }],
    budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  const snapshot = plain(executor.inventorySnapshot({ tenantId: 'acme' }));
  assert.equal(snapshot.untrustedContextDefault, 'require_approval');
  const probe = core => {
    try {
      composeInventorySnapshot(core, { not: 'a manifest' });
    } catch (error) {
      return error.code;
    }
    return 'ACCEPTED';
  };
  assert.notEqual(probe(snapshot), 'INVENTORY_SNAPSHOT_INVALID');
  assert.equal(probe({ ...snapshot, untrustedContextDefault: 'sometimes' }), 'INVENTORY_SNAPSHOT_INVALID');
  const { untrustedContextDefault: _missing, ...without } = snapshot;
  assert.equal(probe(without), 'INVENTORY_SNAPSHOT_INVALID');
  assert.equal(
    probe({ ...snapshot, schemaVersion: 1, tasks: [], tools: [] }),
    'INVENTORY_SNAPSHOT_INVALID',
    'v1 has no default field',
  );
});
