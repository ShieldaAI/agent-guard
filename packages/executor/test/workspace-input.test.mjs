import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ArtifactBroker, DurableExecutor, runGovernedSandbox } from '../dist/index.js';
import { readWorkspaceInput } from '../dist/workspace-input.js';

function fixture(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'guard-input-test-')));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const root = join(dir, 'workspace'), nested = join(root, 'nested'), outside = join(dir, 'outside');
  for (const directory of [root, nested, outside]) fs.mkdirSync(directory);
  fs.writeFileSync(join(nested, 'item'), 'selected');
  fs.writeFileSync(join(outside, 'item'), 'foreign!');
  return { root, nested, outside };
}

if (process.platform === 'darwin' || process.platform === 'linux') {
  test('bounded input capture accepts the selected file and rejects a FIFO without blocking', t => {
    const { root, nested } = fixture(t);
    assert.equal(readWorkspaceInput(root, 'nested/item', 8).toString(), 'selected');
    assert.throws(() => readWorkspaceInput(root, 'nested/item', 7), /bounded/);
    fs.linkSync(join(nested, 'item'), join(nested, 'alias'));
    assert.throws(() => readWorkspaceInput(root, 'nested/item', 8), /hard links/);
    const pipe = spawnSync('mkfifo', [join(nested, 'pipe')]);
    assert.equal(pipe.status, 0);
    // Give the child a deadline so a regression fails the test instead of hanging the runner.
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import {readWorkspaceInput} from ${JSON.stringify(new URL('../dist/workspace-input.js', import.meta.url))};
       try { readWorkspaceInput(process.argv[1], 'nested/pipe', 8); process.exitCode=1; }
       catch (error) { if (!/regular files/.test(error.message)) throw error; }`, root], { timeout: 5000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr.toString());
  });

  test('a directory swap during capture cannot send an outside file to the guest',
    { skip: !process.env.AGENT_GUARD_SANDBOX_IMAGE }, async t => {
      const { root, nested, outside } = fixture(t);
      const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
      const broker = new ArtifactBroker({ key: randomBytes(32), keyId: 'fixture' });
      t.after(() => { broker.close(); executor.close(); });
      const { taskId } = executor.createTask({ id: 'fixture', principalId: 'operator', tenantId: 'local',
        grants: [], budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 } });
      let swapped = false;
      function replaceDirectory() {
        if (swapped) return;
        fs.renameSync(nested, nested + '-old');
        fs.symlinkSync(outside, nested, 'dir');
        swapped = true;
      }
      const originalStat = fs.lstatSync, originalOpen = fs.openSync;
      // On the vulnerable implementation the parent has passed its check when
      // lstat returns. On the corrected paths force replacement at the final open.
      fs.lstatSync = (path, ...rest) => {
        const info = originalStat(path, ...rest);
        if (path === nested) replaceDirectory();
        return info;
      };
      fs.openSync = (path, ...rest) => {
        if (typeof path === 'string' && (path === join(nested, 'item') ||
            /^\/proc\/self\/fd\/\d+\/item$/.test(path))) replaceDirectory();
        return originalOpen(path, ...rest);
      };
      syncBuiltinESMExports();
      try {
        const result = await runGovernedSandbox(executor, taskId, {
          broker, workspace: root, profile: { image: process.env.AGENT_GUARD_SANDBOX_IMAGE },
          inputFiles: ['nested/item'], command: ['/bin/cat', 'nested/item'], origin: 'synthetic-input-check',
        });
        assert.equal(result.result.exitCode, 0);
        assert.equal(result.result.stdout, 'selected');
      } catch (error) {
        assert.match(error.message, /could not be opened without symlinks/);
      } finally {
        fs.openSync = originalOpen;
        fs.lstatSync = originalStat;
        syncBuiltinESMExports();
      }
      assert.equal(swapped, true);
    });
}
