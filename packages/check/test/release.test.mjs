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

test('the action finds the base commit and target branch in a merge queue', async () => {
  const { parse } = await import('yaml');
  const env = parse(read('../action/action.yml')).runs.steps.find(step => step.id === 'check').env;
  assert.equal(
    env.AGC_BASE,
    '${{ inputs.base || github.event.pull_request.base.sha || github.event.merge_group.base_sha }}',
  );
  assert.equal(
    env.AGC_BRANCH,
    '${{ github.base_ref || github.event.merge_group.base_ref || github.event.repository.default_branch }}',
  );
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
      AGC_GITHUB_RULES: 'false',
      AGC_REPO: 'acme/app',
      AGC_BRANCH: 'main',
      AGC_TOKEN: 'workflow-token',
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

test(
  'the action asks GitHub for branch rules only when github-rules is on and the version knows the flag',
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
    const { parse } = await import('yaml');
    const script = parse(read('../action/action.yml')).runs.steps.find(step => step.id === 'check').run;
    const dir = mkdtempSync(join(tmpdir(), 'agc-action-gh-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    // Stand in for npx: record the arguments and the token the scanner would get.
    const log = join(dir, 'calls.txt');
    writeFileSync(
      join(bin, 'npx'),
      `#!/bin/sh\nprintf '%s token=%s agc=%s\\n' "$*" "$GITHUB_TOKEN" "\${AGC_TOKEN-}" >> "${log}"\nexit 0\n`,
    );
    chmodSync(join(bin, 'npx'), 0o755);
    const repo = join(dir, 'repo');
    mkdirSync(repo);
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
      AGC_REPO: 'acme/app',
      AGC_BRANCH: 'release/2',
      AGC_TOKEN: 'workflow-token',
    };
    const calls = overrides => {
      writeFileSync(log, '');
      const run = spawnSync('bash', ['-c', script], { cwd: repo, env: { ...env, ...overrides }, encoding: 'utf8' });
      assert.equal(run.status, 0, run.stderr);
      return readFile(log, 'utf8').trim().split('\n');
    };
    const on = calls({ AGC_VERSION: '1.6.0', AGC_GITHUB_RULES: 'true' });
    assert.equal(on.length, 3);
    for (const line of on) {
      assert.match(line, /--github-repo acme\/app --github-branch release\/2/);
      assert.match(line, /token=workflow-token agc=$/, 'the token reaches the scanner as GITHUB_TOKEN only');
    }
    // A merge queue gives the target branch as a full ref.
    for (const line of calls({ AGC_VERSION: '1.6.0', AGC_GITHUB_RULES: 'true', AGC_BRANCH: 'refs/heads/release/2' }))
      assert.match(line, /--github-branch release\/2 /);
    for (const overrides of [
      { AGC_VERSION: '1.6.0', AGC_GITHUB_RULES: 'false' },
      { AGC_VERSION: '1.5.0', AGC_GITHUB_RULES: 'true' },
    ])
      for (const line of calls(overrides)) {
        assert.doesNotMatch(line, /--github-repo/, JSON.stringify(overrides));
        assert.match(line, /token= agc=$/, 'no token without the check');
      }
  },
);

test(
  'the comment step warns instead of failing when the token cannot comment (a fork)',
  { skip: process.platform === 'win32' },
  async t => {
    const { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } = await import('node:fs');
    const { spawnSync } = await import('node:child_process');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { parse } = await import('yaml');
    const action = parse(read('../action/action.yml'));
    const step = action.runs.steps.find(entry => entry.env?.REPORT);
    const dir = mkdtempSync(join(tmpdir(), 'agc-comment-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    const report = join(dir, 'report.md');
    writeFileSync(report, '### Agent Guard Check\n');
    const env = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      GITHUB_REPOSITORY: 'acme/app',
      PR: '7',
      REPORT: report,
    };
    // gh refusing every call, as it does with a fork's read-only token.
    writeFileSync(join(bin, 'gh'), '#!/bin/sh\necho "HTTP 403: Resource not accessible by integration" >&2\nexit 1\n');
    chmodSync(join(bin, 'gh'), 0o755);
    const refused = spawnSync('bash', ['-c', step.run], { env, encoding: 'utf8' });
    assert.equal(refused.status, 0, refused.stderr);
    assert.match(refused.stdout, /::warning::agent-guard-check could not comment/);
    // gh that lists no comment and accepts the new one: the comment is posted, no warning.
    const log = join(dir, 'calls.txt');
    writeFileSync(join(bin, 'gh'), `#!/bin/sh\necho "$@" >> "${log}"\nexit 0\n`);
    const posted = spawnSync('bash', ['-c', step.run], { env, encoding: 'utf8' });
    assert.equal(posted.status, 0, posted.stderr);
    assert.doesNotMatch(posted.stdout, /::warning::/);
    assert.match(readFileSync(log, 'utf8'), /--method POST repos\/acme\/app\/issues\/7\/comments/);
  },
);
