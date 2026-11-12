import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPilotReviewFixture } from './fixtures/pilot-review.mjs';

const cli = fileURLToPath(new URL('../dist/pilot-review-cli.js', import.meta.url));
const args = ['--candidate', 'candidate', '--policy', 'policy', '--bundle', 'bundle'];
const usage = 'agent-guard-pilot-review --policy PATH --candidate PATH --bundle PATH [--rehearsal]';
function launch(cwd, args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', timeout: 5_000 });
}
function files(t) {
  const dir = mkdtempSync(join(tmpdir(), 'guard-private-pilot-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const name of ['candidate', 'policy', 'bundle']) writeFileSync(join(dir, name), '{}', { mode: 0o600 });
  return dir;
}
/** Code alone on the first stderr line, one plain sentence naming the input on the second, no path. */
function assertFailure(child, code, hint, cwd) {
  assert.equal(child.status, 1, child.error?.message);
  assert.equal(child.stdout, '');
  const lines = child.stderr.split('\n');
  assert.equal(lines.length, 3, child.stderr);
  assert.equal(lines[0], code);
  assert.match(lines[1], hint);
  assert.equal(lines[2], '');
  if (cwd) assert.equal(child.stderr.includes(cwd), false);
}
function expectInputFailure(cwd, code, hint) {
  assertFailure(launch(cwd, args), code, hint, cwd);
}

test('pilot review launcher has explicit arguments and rejects repeats without disclosing paths', () => {
  const help = launch(tmpdir(), ['--help']);
  assert.equal(help.status, 0);
  assert.equal(help.stdout.split('\n')[0], usage);
  assert.match(help.stdout, /exits 1 and prints an error code/);
  for (const input of [
    [],
    [...args, '--policy', 'SECRET_PATH'],
    [...args, '--unknown=SECRET_PATH'],
    [...args, 'SECRET_PATH'],
  ]) {
    const child = launch(tmpdir(), input);
    assert.equal(child.status, 1);
    assert.equal(child.stdout, '');
    assert.equal(child.stderr, `PILOT_ARGUMENT_INVALID\nUsage: ${usage}\n`);
  }
});

test('pilot review launcher rejects invalid UTF-8 and duplicate decoded keys before verification', t => {
  const dir = files(t);
  for (const data of [Buffer.from([0xff]), '{"outer":[{"id":1,"\\u0069d":2}]}']) {
    writeFileSync(join(dir, 'bundle'), data);
    expectInputFailure(dir, 'PILOT_INPUT_INVALID', /^Bundle: .*JSON/);
  }
  writeFileSync(join(dir, 'bundle'), '{"x":1}');
  assertFailure(launch(dir, args), 'PILOT_REVIEW_INVALID', /^Failed check POLICY: /, dir);
});

test('pilot review launcher bounds regular files and rejects hard links', t => {
  const dir = files(t);
  for (const [name, limit] of [
    ['candidate', 64 * 1024 * 1024],
    ['policy', 32 * 1024],
    ['bundle', 1024 * 1024],
  ]) {
    truncateSync(join(dir, name), limit + 1);
    expectInputFailure(dir, 'PILOT_INPUT_TOO_LARGE', new RegExp(`^${name[0].toUpperCase()}${name.slice(1)}: `));
    writeFileSync(join(dir, name), '{}');
  }
  linkSync(join(dir, 'bundle'), join(dir, 'other'));
  expectInputFailure(dir, 'PILOT_INPUT_UNSAFE', /^Bundle: .*one link/);
});

test(
  'pilot review launcher enforces POSIX permissions and refuses symlinks and FIFOs',
  { skip: process.platform === 'win32' },
  t => {
    const dir = files(t);
    chmodSync(join(dir, 'policy'), 0o620);
    expectInputFailure(dir, 'PILOT_INPUT_UNSAFE', /^Policy: /);
    chmodSync(join(dir, 'policy'), 0o600);
    chmodSync(join(dir, 'bundle'), 0o640);
    expectInputFailure(dir, 'PILOT_INPUT_UNSAFE', /^Bundle: /);
    chmodSync(join(dir, 'bundle'), 0o600);
    rmSync(join(dir, 'candidate'));
    expectInputFailure(dir, 'PILOT_INPUT_UNAVAILABLE', /^Candidate: the file does not exist\.$/);
    symlinkSync(join(dir, 'bundle'), join(dir, 'candidate'));
    expectInputFailure(dir, 'PILOT_INPUT_UNAVAILABLE', /^Candidate: .*link is refused/);
    rmSync(join(dir, 'candidate'));
    const fifo = spawnSync('mkfifo', [join(dir, 'candidate')]);
    assert.equal(fifo.status, 0);
    expectInputFailure(dir, 'PILOT_INPUT_UNSAFE', /^Candidate: /);
  },
);

test(
  'an unsafe policy directory cannot substitute another signed deployment',
  { skip: process.platform === 'win32' },
  t => {
    const dir = files(t);
    const enrolled = join(dir, 'enrolled');
    mkdirSync(enrolled, { mode: 0o700 });
    const f = createPilotReviewFixture({
      policy(p) {
        p.mode = 'company-pilot';
      },
    });
    writeFileSync(join(enrolled, 'policy'), JSON.stringify(f.policy), { mode: 0o600 });
    writeFileSync(join(dir, 'candidate'), f.candidateBytes);
    writeFileSync(join(dir, 'bundle'), JSON.stringify(f.bundle), { mode: 0o600 });
    const run = policy => launch(dir, ['--candidate', 'candidate', '--policy', policy, '--bundle', 'bundle']);
    assert.equal(run('enrolled/policy').status, 0);
    const denied = path => assertFailure(run(path), 'PILOT_INPUT_UNSAFE', /^Policy: a directory above it/, dir);
    chmodSync(enrolled, 0o777);
    denied('enrolled/policy');
    chmodSync(enrolled, 0o700);
    symlinkSync('enrolled', join(dir, 'link'));
    denied('link/policy');
  },
);

test('pilot review input replacement after opening fails before evidence verification', t => {
  const dir = files(t);
  const f = createPilotReviewFixture({
    policy(p) {
      p.mode = 'company-pilot';
    },
  });
  const contents = { policy: JSON.stringify(f.policy), candidate: f.candidateBytes, bundle: JSON.stringify(f.bundle) };
  for (const [name, bytes] of Object.entries(contents)) writeFileSync(join(dir, name), bytes, { mode: 0o600 });
  assert.equal(launch(dir, args).status, 0);
  for (const selected of Object.keys(contents)) {
    const hook = join(dir, 'replace-after-open.mjs');
    writeFileSync(
      hook,
      `import fs from 'node:fs';
      import { resolve } from 'node:path'; import { syncBuiltinESMExports } from 'node:module';
      const original = fs.openSync; let replaced = false;
      fs.openSync = function(path, ...rest) {
        const fd = original(path, ...rest);
        if (!replaced && resolve(String(path)) === resolve(${JSON.stringify(selected)})) {
          replaced = true;
          fs.renameSync(path, String(path) + '.original');
          fs.writeFileSync(path, '{}', { mode: 0o600, flag: 'wx' });
        }
        return fd;
      }; syncBuiltinESMExports();`,
    );
    const child = spawnSync(process.execPath, ['--import', pathToFileURL(hook).href, cli, ...args], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 5_000,
    });
    assertFailure(child, 'PILOT_INPUT_UNSAFE', new RegExp(`^${selected[0].toUpperCase()}${selected.slice(1)}: `), dir);
    writeFileSync(join(dir, selected), contents[selected], { mode: 0o600 });
  }
});
