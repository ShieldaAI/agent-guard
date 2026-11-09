// Writes a small ledger with a released executor build, for format-compatibility tests.
// Usage: node scripts/generate-ledger-fixture.mjs <executor dist/index.js> <output directory> <label>
// The key and tokens are test-only fixture values.
import { chmodSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [entry, output, label] = process.argv.slice(2);
if (!entry || !output || !label) throw new Error('usage: generate-ledger-fixture.mjs <dist/index.js> <out> <label>');
const { DurableExecutor } = await import(pathToFileURL(entry).href);
export const FIXTURE_KEY = Buffer.alloc(32, 0x5a);

async function write(directory, witnessed) {
  // The witness lives outside the database directory: a separate restore domain.
  for (const part of ['', 'data', 'witness']) {
    mkdirSync(join(directory, part), { recursive: true, mode: 0o700 });
    chmodSync(join(directory, part), 0o700);
  }
  const root = realpathSync(directory);
  const executor = new DurableExecutor({
    database: join(root, 'data', 'ledger.sqlite'),
    encryptionKey: Buffer.from(FIXTURE_KEY),
    clock: () => 1_000_000,
    ...(witnessed ? { rollbackWitness: { path: join(root, 'witness', 'witness.sqlite'), mode: 'create' } } : {}),
  });
  let fail = false;
  executor.approveTool(
    'write',
    executor.registerTool({
      name: 'write',
      description: 'fixture write',
      maxCost: 5,
      resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
      execute: () => {
        if (fail) throw new Error('backend lost');
        return { value: 'ok', actualCost: 2 };
      },
    }),
  );
  executor.approveTool(
    'review',
    executor.registerTool({
      name: 'review',
      description: 'needs approval',
      maxCost: 1,
      requiresApproval: true,
      resolve: args => ({ resourceId: args.id, tenantId: 'acme' }),
      execute: () => ({ value: 'reviewed' }),
    }),
  );
  const budget = { maxCalls: 20, maxConcurrent: 2, maxCost: 100, deadline: 9_000_000 };
  const root_ = executor.createTask({
    id: 'root',
    principalId: 'operator',
    tenantId: 'acme',
    grants: [
      { tool: 'write', resources: ['doc-1', 'doc-2', 'doc-3'] },
      { tool: 'review', resources: ['doc-1'] },
    ],
    budget,
  });
  const child = executor.delegateTask('root', {
    id: 'child',
    grants: [{ tool: 'write', resources: ['doc-2'] }],
    budget: { maxCalls: 5, maxConcurrent: 1, maxCost: 20, deadline: 8_000_000 },
  });
  const other = executor.createTask({
    id: 'other-tenant',
    principalId: 'someone',
    tenantId: 'globex',
    grants: [{ tool: 'write', resources: ['doc-9'] }],
    budget,
  });
  const ok = await executor.prepare('root', { tool: 'write', args: { id: 'doc-1' } });
  await executor.execute('root', ok.id);
  const delegated = await executor.prepare('child', { tool: 'write', args: { id: 'doc-2' } });
  await executor.execute('child', delegated.id);
  fail = true;
  const uncertain = await executor.prepare('root', { tool: 'write', args: { id: 'doc-3' } });
  await executor.execute('root', uncertain.id).catch(() => {});
  const reconciled = await executor.prepare('root', { tool: 'write', args: { id: 'doc-1' } });
  await executor.execute('root', reconciled.id).catch(() => {});
  executor.reconcile(reconciled.id, { outcome: 'FAILED', actualCost: 1, reference: 'fixture-receipt' });
  fail = false;
  const pending = await executor.prepare('root', { tool: 'review', args: { id: 'doc-1' } });
  const approvalId = executor.approve(pending.id, { approverId: 'reviewer', expiresAt: 8_500_000 });
  executor.close();
  const manifest = {
    label,
    witnessed,
    tokens: { root: root_.token, child: child.token, other: other.token },
    actions: {
      succeeded: ok.id,
      delegated: delegated.id,
      uncertain: uncertain.id,
      reconciled: reconciled.id,
      pending: pending.id,
    },
    approvalId,
    expected: { root: { calls: 4, spent: 5, reserved: 5 }, child: { calls: 1, spent: 2, reserved: 0 } },
  };
  writeFileSync(join(root, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
}
await write(join(output, `${label}-plain`), false);
await write(join(output, `${label}-witnessed`), true);
console.log(`wrote ${label} fixtures`);
