import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('approval bookkeeping does not retain dropped invocation payloads', () => {
  // Exercise actual garbage collection in a separate process, keeping the guard alive throughout.
  const moduleUrl = new URL('../dist/index.js', import.meta.url).href;
  const source = `
    import assert from 'node:assert/strict';
    import { setImmediate } from 'node:timers/promises';
    import { AgentGuard } from ${JSON.stringify(moduleUrl)};
    const guard = new AgentGuard();
    const fp = guard.registerTool({ name: 'write', description: 'Write', requiresApproval: true,
      resolve: (_args, task) => ({ resourceId: 'record:1', tenantId: task.tenantId }),
      execute: () => ({ value: 'ok' }),
    });
    guard.approveTool('write', fp);
    const task = guard.createTask({ id: 'task', principalId: 'user', tenantId: 'tenant',
      grants: [{ tool: 'write', resources: ['record:1'] }],
      budget: { maxCalls: 10, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 60_000 },
    });
    for (const dispatched of [false, true]) {
      const weak = await (async () => {
        const prepared = await guard.prepare(task, { tool: 'write', args: { payload: 'sensitive invocation' } });
        const approvalId = guard.approve(prepared, { approverId: 'reviewer', expiresAt: Date.now() + 30_000 });
        if (dispatched) await guard.execute(prepared, { approvalId });
        return new WeakRef(prepared.action.args);
      })();
      for (let attempt = 0; attempt < 20; attempt++) {
        await setImmediate();
        global.gc();
        if (weak.deref() === undefined) break;
      }
      assert.equal(weak.deref(), undefined, dispatched ? 'consumed approval retains arguments' : 'unused approval retains dropped arguments');
    }
    assert.equal(guard.snapshot(task).calls, 1);
  `;
  const result = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '--eval', source], {
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr || result.stdout);
});
