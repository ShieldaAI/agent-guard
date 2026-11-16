import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TOOL_VERSION } from '@shieldaai/agent-guard-check';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const version = JSON.parse(read('../package.json')).version;

// Every place that pins the package version must move with it on a release.
test('version references match package.json', () => {
  assert.equal(TOOL_VERSION, version);
  const places = {
    'action/action.yml': read('../action/action.yml'),
    'skill/agent-guard-check/SKILL.md': read('../skill/agent-guard-check/SKILL.md'),
    'README.md': read('../README.md'),
    '.pre-commit-hooks.yaml': read('../../../.pre-commit-hooks.yaml'),
  };
  for (const [path, text] of Object.entries(places)) {
    const pinned = [
      ...text.matchAll(
        /agent-guard-check@(\d+\.\d+\.\d+[\w.-]*)|default: (\d+\.\d+\.\d+)|agent-guard-check (\d+\.\d+\.\d+)/g,
      ),
    ].map(match => match[1] ?? match[2] ?? match[3]);
    assert.ok(pinned.length > 0, `${path} pins no version`);
    for (const value of pinned) assert.equal(value, version, `${path} pins ${value}`);
  }
});

test('the action pins third-party actions by commit', () => {
  const action = read('../action/action.yml');
  for (const match of action.matchAll(/uses:\s*([^\s#]+)/g)) assert.match(match[1], /@[0-9a-f]{40}$/, match[1]);
});

test(
  'the action script runs the scanner, writes its outputs and refuses a non-exact version',
  { skip: process.platform === 'win32' },
  async t => {
    const {
      mkdtempSync,
      mkdirSync,
      writeFileSync,
      chmodSync,
      rmSync,
      readFileSync: readFile,
    } = await import('node:fs');
    const { spawnSync } = await import('node:child_process');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const { parse } = await import('yaml');
    const action = parse(read('../action/action.yml'));
    const script = action.runs.steps.find(step => step.id === 'check').run;
    const dir = mkdtempSync(join(tmpdir(), 'agc-action-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    // Stand in for npx: run the local build instead of downloading the published package.
    const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
    writeFileSync(join(bin, 'npx'), `#!/bin/sh\nshift\nshift\nexec "${process.execPath}" "${cli}" "$@"\n`);
    chmodSync(join(bin, 'npx'), 0o755);
    const repo = join(dir, 'repo');
    mkdirSync(join(repo, '.claude'), { recursive: true });
    writeFileSync(join(repo, '.claude/settings.json'), '{"permissions":{"defaultMode":"bypassPermissions"}}');
    const env = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_TEMP: join(dir, 'tmp'),
      GITHUB_STEP_SUMMARY: join(dir, 'summary.md'),
      GITHUB_OUTPUT: join(dir, 'output.txt'),
      AGC_PATH: '.',
      AGC_FAIL_ON: '',
      AGC_BASE: '',
      AGC_BASELINE: '',
      AGC_FILES: '',
      AGC_VERSION: version,
    };
    const run = spawnSync('bash', ['-c', script], { cwd: repo, env, encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    const outputs = readFile(env.GITHUB_OUTPUT, 'utf8');
    assert.match(outputs, /^exit-code=1$/m);
    assert.match(outputs, /^sarif-file=.*results\.sarif$/m);
    assert.match(readFile(env.GITHUB_STEP_SUMMARY, 'utf8'), /### Agent Guard Check/);
    assert.equal(JSON.parse(readFile(join(dir, 'tmp/agent-guard-check/results.sarif'), 'utf8')).version, '2.1.0');
    const bad = spawnSync('bash', ['-c', script], {
      cwd: repo,
      env: { ...env, AGC_VERSION: 'latest; echo pwned' },
      encoding: 'utf8',
    });
    assert.equal(bad.status, 2);
    assert.ok(!bad.stdout.includes('pwned'));
  },
);
