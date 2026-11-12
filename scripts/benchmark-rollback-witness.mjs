// Local synthetic timing only: an entirely new ledger for each phase, no provider or existing state.
import { mkdtempSync, mkdirSync, realpathSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';

const p95 = values => [...values].sort((a, b) => a - b)[Math.ceil(0.95 * values.length) - 1];
const warmup = 10,
  measured = 50;
if (process.platform === 'win32') throw new Error('The witness profile requires a supported POSIX filesystem.');
const phases = [];
for (const witnessed of [false, true, true, false]) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'guard-witness-benchmark-')));
  let e;
  try {
    for (const dir of ['authority', 'control']) mkdirSync(join(root, dir), { mode: 0o700 });
    e = new DurableExecutor({
      database: join(root, 'authority', 'state'),
      encryptionKey: randomBytes(32),
      ...(witnessed ? { rollbackWitness: { mode: 'create', path: join(root, 'control', 'latest') } } : {}),
    });
    let effects = 0;
    e.approveTool(
      'update',
      e.registerTool({
        name: 'update',
        description: 'Count one synthetic effect',
        requiresApproval: true,
        resolve: () => ({ tenantId: 'fixture', resourceId: 'record' }),
        execute: () => ({ value: ++effects }),
      }),
    );
    const deadline = Date.now() + 120_000;
    const { taskId } = e.createTask({
      id: 'worker',
      principalId: 'fixture',
      tenantId: 'fixture',
      grants: [{ tool: 'update', resources: ['record'] }],
      budget: { maxCalls: warmup + measured, maxConcurrent: 1, maxCost: 0, deadline },
    });
    const samples = [];
    for (let i = 0; i < warmup + measured; i++) {
      const start = performance.now();
      const action = await e.prepare(taskId, { tool: 'update', args: {} });
      const approvalId = e.approve(action.id, { approverId: 'fixture', expiresAt: deadline });
      assert.equal(await e.execute(taskId, action.id, { approvalId }), i + 1);
      if (i >= warmup) samples.push(performance.now() - start);
    }
    assert.equal(e.snapshot(taskId).calls, effects);
    phases.push({ witnessed, effects, samplesMs: samples });
  } finally {
    try {
      e?.close();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
}
const summary = witnessed => ({
  measured: 2 * measured,
  p95Ms: p95(phases.filter(p => p.witnessed === witnessed).flatMap(p => p.samplesMs)),
});
console.log(
  JSON.stringify(
    {
      kind: 'synthetic-prepare-approve-execute',
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      warmupPerPhase: warmup,
      default: summary(false),
      witnessed: summary(true),
      phases,
    },
    null,
    2,
  ),
);
