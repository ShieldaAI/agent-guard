import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createPilotReviewFixture } from './fixtures/pilot-review.mjs';

const cli = fileURLToPath(new URL('../dist/pilot-review-cli.js', import.meta.url));
const args = ['--candidate', 'candidate', '--policy', 'policy', '--bundle', 'bundle'];
const readFailure = 'Could not read pilot inputs. Check file types, permissions, sizes and JSON.';
function launch(cwd, args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', timeout: 5_000 });
}
function files(t) {
  const dir = mkdtempSync(join(tmpdir(), 'guard-private-pilot-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const name of ['candidate', 'policy', 'bundle']) writeFileSync(join(dir, name), '{}', { mode: 0o600 });
  return dir;
}
function expectInputFailure(cwd) {
  const child = launch(cwd, args);
  assert.equal(child.status, 1, child.error?.message);
  assert.equal(child.stdout, '');
  assert.equal(child.stderr.trim(), readFailure);
}

test('pilot review launcher has explicit arguments and rejects repeats without disclosing paths', () => {
  const help = launch(tmpdir(), ['--help']);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /agent-guard-pilot-review --policy/);
  for (const input of [[], [...args, '--policy', 'SECRET_PATH'], [...args, '--unknown=SECRET_PATH'], [...args, 'SECRET_PATH']]) {
    const child = launch(tmpdir(), input);
    assert.equal(child.status, 1);
    assert.equal(child.stdout, '');
    assert.equal(child.stderr, help.stdout);
  }
});

test('pilot review launcher rejects invalid UTF-8 and duplicate decoded keys before verification', t => {
  const dir = files(t);
  for (const data of [Buffer.from([0xff]), '{"outer":[{"id":1,"\\u0069d":2}]}']) {
    writeFileSync(join(dir, 'bundle'), data);
    expectInputFailure(dir);
  }
  writeFileSync(join(dir, 'bundle'), '{"x":1}');
  const child = launch(dir, args);
  assert.equal(child.status, 1);
  assert.equal(child.stderr.trim(), 'Pilot review verification failed.');
});

test('pilot review launcher bounds regular files and rejects hard links', t => {
  const dir = files(t);
  for (const [name, limit] of [['candidate', 64 * 1024 * 1024], ['policy', 32 * 1024], ['bundle', 1024 * 1024]]) {
    truncateSync(join(dir, name), limit + 1);
    expectInputFailure(dir);
    writeFileSync(join(dir, name), '{}');
  }
  linkSync(join(dir, 'bundle'), join(dir, 'other'));
  expectInputFailure(dir);
});

test('pilot review launcher enforces POSIX permissions and refuses symlinks and FIFOs', { skip: process.platform === 'win32' }, t => {
  const dir = files(t);
  chmodSync(join(dir, 'policy'), 0o620);
  expectInputFailure(dir);
  chmodSync(join(dir, 'policy'), 0o600);
  chmodSync(join(dir, 'bundle'), 0o640);
  expectInputFailure(dir);
  chmodSync(join(dir, 'bundle'), 0o600);
  rmSync(join(dir, 'candidate'));
  symlinkSync(join(dir, 'bundle'), join(dir, 'candidate'));
  expectInputFailure(dir);
  rmSync(join(dir, 'candidate'));
  const fifo = spawnSync('mkfifo', [join(dir, 'candidate')]);
  assert.equal(fifo.status, 0);
  expectInputFailure(dir);
});

test('an unsafe policy directory cannot substitute another signed deployment', { skip: process.platform === 'win32' }, t => {
  const dir = files(t);
  const enrolled = join(dir, 'enrolled');
  mkdirSync(enrolled, { mode: 0o700 });
  const f = createPilotReviewFixture({ policy(p) { p.mode = 'company-pilot'; } });
  writeFileSync(join(enrolled, 'policy'), JSON.stringify(f.policy), { mode: 0o600 });
  writeFileSync(join(dir, 'candidate'), f.candidateBytes);
  writeFileSync(join(dir, 'bundle'), JSON.stringify(f.bundle), { mode: 0o600 });
  const run = policy => launch(dir, ['--candidate', 'candidate', '--policy', policy, '--bundle', 'bundle']);
  assert.equal(run('enrolled/policy').status, 0);
  const denied = path => {
    const child = run(path);
    assert.equal(child.status, 1);
    assert.equal(child.stdout, '');
    assert.equal(child.stderr.trim(), readFailure);
  };
  chmodSync(enrolled, 0o777);
  denied('enrolled/policy');
  chmodSync(enrolled, 0o700);
  symlinkSync('enrolled', join(dir, 'link'));
  denied('link/policy');
});
