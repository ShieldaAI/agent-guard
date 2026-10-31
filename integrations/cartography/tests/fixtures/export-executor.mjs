// Synthetic cross-language contract fixture. Never reads a host ledger or credentials.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../../../../packages/executor/dist/index.js';

const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-inventory-contract-')));
const options = {
  database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.alloc(32, 7),
  clock: () => 1000,
  inventory: { companyId: 'company', sourceId: 'executor', enrollmentGeneration: 'generation' },
};
const budget = { maxCalls: 10, maxConcurrent: 2, maxCost: 20, deadline: 100000.5 };
let executor;
try {
  // Python's Unicode whitespace set is wider than JavaScript trim().
  for (const sourceId of ['\u0085', '\u001c', '\u001d', '\u001e', '\u001f', ' \u0085\t']) {
    assert.throws(() => new DurableExecutor({
      ...options, database: ':memory:', inventory: { ...options.inventory, sourceId },
    }), { code: 'INVENTORY_CONFIG_INVALID' });
  }
  executor = new DurableExecutor(options);
  const fingerprint = executor.registerTool({
    name: 'records.read', description: 'canary-description-do-not-export',
    metadata: { secret: 'canary-metadata-do-not-export' },
    inputSchema: { type: 'object', title: 'canary-schema-do-not-export' },
    requiresApproval: true, maxCost: 2,
    resolve: () => { throw new Error('Inventory called a resolver'); },
    execute: () => { throw new Error('Inventory called an executor'); },
  });
  executor.approveTool('records.read', fingerprint);
  executor.registerTool({
    name: 'beta.private', description: 'other tenant tool',
    resolve: () => { throw new Error('Inventory called a resolver'); },
    execute: () => { throw new Error('Inventory called an executor'); },
  });
  const credential = executor.createTask({
    id: 'root', tenantId: 'alpha', principalId: 'researcher', budget,
    grants: [
      { tool: 'records.read', resources: ['report-a', 'report-a'] },
      { tool: 'records.read', resources: ['report-b'] },
      { tool: 'future.tool', resources: ['*'] },
    ],
    allowedRecipients: ['reviewer', 'reviewer'],
  }, { sensitive: true });
  executor.delegateTask('root', {
    id: 'child', budget, grants: [{ tool: 'records.read', resources: ['report-a'] }],
  });
  executor.createTask({
    id: 'handoff', tenantId: 'alpha', principalId: 'reviewer', budget,
    grants: [{ tool: 'future.tool', resources: ['*'] }],
  }, { sourceTaskId: 'child' });
  executor.createTask({
    id: 'beta-secret-task', tenantId: 'beta', principalId: 'beta-secret-principal', budget,
    grants: [{ tool: 'beta.private', resources: ['beta-secret-resource'] }],
  });
  executor.importMemory({
    id: 'canary-memory-id', tenantId: 'alpha', origin: 'canary-memory-origin',
    value: 'canary-memory-body-do-not-export',
  });
  const live = executor.inventorySnapshot({ tenantId: 'alpha' });
  const repeated = executor.inventorySnapshot({ tenantId: 'alpha' });
  executor.revokeTask('root');
  const revoked = executor.inventorySnapshot({ tenantId: 'alpha' });
  executor.close();
  executor = new DurableExecutor(options);
  const reopened = executor.inventorySnapshot({ tenantId: 'alpha' });
  const empty = executor.inventorySnapshot({ tenantId: 'empty' });
  const output = JSON.stringify({ live, repeated, revoked, reopened, empty });
  assert(!output.includes(credential.token));
  assert(!output.includes(createHash('sha256').update(credential.token).digest('hex')));
  assert(!output.includes('canary-'));
  assert(!output.includes('beta-'));
  assert(!output.includes('beta.private'));
  process.stdout.write(output);
} finally {
  executor?.close();
  rmSync(directory, { recursive: true, force: true });
}
