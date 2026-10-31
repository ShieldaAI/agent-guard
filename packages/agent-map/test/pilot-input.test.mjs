import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPilotConfig } from '../../../examples/cartography-pilot.mjs';

test(process.platform === 'win32'
  ? 'pilot configuration rejects unsupported native Windows before opening input'
  : 'pilot configuration rejects a FIFO replacement at open without blocking and closes it', async t => {
  if (process.platform === 'win32') {
    await assert.rejects(readPilotConfig('unused-pilot-input.json'), /PILOT_PLATFORM_UNSUPPORTED/);
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), 'agent-guard-pilot-input-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'config.json');
  await writeFile(path, '{}', { mode: 0o600 });
  // Replace a real regular file precisely at open, after any path metadata check.
  // A child deadline prevents a blocking regression from hanging the test worker.
  const script = `
    import assert from 'node:assert/strict';
    import fs from 'node:fs/promises';
    import { spawnSync } from 'node:child_process';
    import { syncBuiltinESMExports } from 'node:module';
    import { pathToFileURL } from 'node:url';
    const [path, entry] = process.argv.slice(1);
    const open = fs.open;
    let replaced = false, closed = false;
    fs.open = async (...args) => {
      if (args[0] !== path) return open(...args);
      await fs.unlink(path);
      const pipe = spawnSync('mkfifo', [path], { encoding: 'utf8' });
      assert.equal(pipe.status, 0, pipe.stderr);
      await fs.chmod(path, 0o600);
      replaced = true;
      const file = await open(...args);
      const close = file.close.bind(file);
      file.close = async () => { await close(); closed = true; };
      return file;
    };
    syncBuiltinESMExports();
    const { readPilotConfig } = await import(pathToFileURL(entry));
    await assert.rejects(readPilotConfig(path), /PILOT_CONFIG_INVALID/);
    assert.equal(replaced, true);
    assert.equal(closed, true);
  `;
  const entry = fileURLToPath(new URL('../../../examples/cartography-pilot.mjs', import.meta.url));
  const result = spawnSync(process.execPath, ['--no-warnings', '--input-type=module', '-e', script, path, entry], {
    encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL',
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});
