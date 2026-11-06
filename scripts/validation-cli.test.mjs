import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('validation CLIs invoked through a directory alias evaluate the inputs and replace stale results', t => {
  const directory = mkdtempSync(join(tmpdir(), 'guard-validation-alias-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const here = fileURLToPath(new URL('../', import.meta.url));
  const actual = join(directory, 'checkout'), alias = join(directory, 'alias');
  mkdirSync(join(actual, 'scripts'), { recursive: true });
  symlinkSync(actual, alias, 'junction');
  for (const dependency of ['examples', 'node_modules', 'packages']) {
    symlinkSync(join(here, dependency), join(actual, dependency), 'junction');
  }
  const evidence = join(actual, 'artifacts', 'platform-evidence.json');
  mkdirSync(join(actual, 'artifacts'));
  writeFileSync(evidence, '{"passed":true}');
  copyFileSync(join(here, 'scripts', 'benchmark-admission-diagnostics.mjs'),
    join(actual, 'scripts', 'benchmark-admission-diagnostics.mjs'));
  for (const [name, status] of [['verify-platform.mjs', 1], ['score-operator-study.mjs', 2], ['benchmark-admission.mjs', 1]]) {
    copyFileSync(join(here, 'scripts', name), join(actual, 'scripts', name));
    const result = spawnSync(process.execPath, [join(alias, 'scripts', name)], {
      env: { ...process.env, AGENT_GUARD_EXPECTED_HOST: 'invalid' }, encoding: 'utf8', timeout: 10_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, status, result.stderr);
    if (name === 'verify-platform.mjs') assert.equal(JSON.parse(readFileSync(evidence)).passed, false);
    else if (name === 'score-operator-study.mjs') assert.equal(JSON.parse(result.stderr).status, 'unverified');
    else assert.match(result.stderr, /ADMISSION_START_FAILED/);
  }
});
