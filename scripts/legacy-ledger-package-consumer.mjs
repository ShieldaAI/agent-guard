// Runs in the packed consumer with the actual published alpha.3 under an alias.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, realpathSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DurableExecutor as LegacyExecutor } from 'legacy-executor';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const directory = realpathSync(mkdtempSync(join(tmpdir(), 'guard-upgrade-consumer-')));
const data = join(directory, 'private'); mkdirSync(data, { mode: 0o700 });
const key = randomBytes(32), options = { database: join(data, 'authority.sqlite'), encryptionKey: key, clock: () => 1000 };
const task = { id: 'retired-published-task', tenantId: 'fixture', principalId: 'operator',
  grants: [{ tool: 'write', resources: ['record'] }], budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: 100_000 } };
const scope = { tenantId: task.tenantId, taskId: task.id };
let owner, effects = 0;
try {
  owner = new LegacyExecutor(options);
  const fingerprint = owner.registerTool({ name: 'write', description: 'Synthetic compatibility effect', maxCost: 1,
    resolve: () => ({ tenantId: 'fixture', resourceId: 'record' }), execute: () => { effects++; return { value: true, actualCost: 1 }; } });
  owner.approveTool('write', fingerprint); owner.createTask(task);
  const prepared = await owner.prepare(task.id, { tool: 'write', args: {} }); await owner.execute(task.id, prepared.id);
  owner.close(); owner = undefined;

  owner = new DurableExecutor(options);
  const before = owner.snapshot(task.id); assert.equal(before.calls, 1); assert.equal(before.spent, 1);
  const retirement = owner.previewTaskFamilyRetirement(scope);
  owner.retireTaskFamily({ ...scope, expectedDigest: retirement.reviewDigest });
  const archive = owner.previewTaskFamilyRetirement(scope);
  const receipt = owner.archiveTaskFamily({ ...scope, expectedDigest: archive.reviewDigest });
  owner.close(); owner = undefined;

  const protectedBytes = readFileSync(options.database);
  assert.throws(() => { const old = new LegacyExecutor(options); old.close(); }, { code: 'STORE_UNAVAILABLE' });
  assert.deepEqual(readFileSync(options.database), protectedBytes, 'rejected older reader must not alter current authority');
  owner = new DurableExecutor(options);
  assert.throws(() => owner.createTask(task), { code: 'DUPLICATE_TASK' });
  assert.equal(owner.findTaskFamilyArchive(scope).archiveId, receipt.archiveId);
  assert.equal(effects, 1);
  console.log('Published alpha.3 ledger upgrade preserves spent authority; older binary refuses retired schema and cannot repeat the effect.');
} finally { owner?.close(); key.fill(0); rmSync(directory, { recursive: true, force: true }); }
