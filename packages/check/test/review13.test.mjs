import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runCli, scan } from '@shieldaai/agent-guard-check';
import { findingsFor, scanFiles, settings } from './helpers.mjs';

/** A committed git repository holding `files`. */
function repo(t, files) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'agc-r13-')));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = join(dir, 'repo');
  write(root, files);
  git(root, ['init', '-q']);
  commit(root, 'base');
  return { root, home: dir };
}

function write(root, files) {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
}

const git = (root, args) => execFileSync('git', ['-C', root, ...args], { stdio: 'ignore' });
const commit = (root, message) => {
  git(root, ['add', '-A']);
  git(root, ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-qm', message]);
};

async function cli(args, { cwd = '/', env = {}, home, stdin } = {}) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    stdout: text => (stdout += text),
    stderr: text => (stderr += text),
    cwd,
    env,
    ...(home ? { home } : {}),
    ...(stdin ? { stdin: async () => stdin } : {}),
  });
  return { code, stdout, stderr };
}

test('--base: unchanged configuration inside a skipped folder is not new', async t => {
  const { root } = repo(t, {
    '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }),
    CODEOWNERS: '* @acme/platform\n',
    'vendor/lib/.claude/settings.json': settings({ allow: ['Bash'] }),
    'vendor/.mcp.json': '{}',
    'build/a/b/.claude/settings.json': settings({}),
  });
  const skipped = result => findingsFor(result, 'AGC-CFG-002').map(finding => finding.location.file);
  const onDisk = skipped(scan({ root }));
  assert.deepEqual(onDisk, ['vendor/.mcp.json', 'vendor/lib/.claude']);
  assert.deepEqual(skipped(scan({ root, ref: 'HEAD' })), onDisk, 'a commit names them as the working tree does');
  const { code, stdout } = await cli([root, '--base', 'HEAD']);
  assert.equal(code, 0, stdout);
  assert.doesNotMatch(stdout, /New findings/);
});

test('--hook: an ignored build folder with agent configuration in it does not hold prompts', async t => {
  const { root, home } = repo(t, {
    '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }),
    '.gitignore': 'dist/\n.claude/settings.local.json\n',
  });
  write(root, { 'dist/templates/.claude/settings.json': settings({ allow: ['Bash'] }) });
  const run = () =>
    cli(['--hook'], {
      env: { CLAUDE_PROJECT_DIR: root },
      home,
      stdin: JSON.stringify({ hook_event_name: 'UserPromptSubmit', cwd: root }),
    });
  assert.equal((await run()).code, 0);
  write(root, { '.claude/settings.local.json': settings({ allow: ['Bash'] }) });
  assert.equal((await run()).code, 2, 'the local settings still count');
});

test('variables and options that choose the git config or home folder are not dropped from a command', () => {
  for (const rule of [
    'Bash(GIT_DIR=tools/g git status)',
    'Bash(HOME=tools git diff:*)',
    'Bash(XDG_CONFIG_HOME=tools git log:*)',
    'Bash(GIT_EXEC_PATH=tools git status)',
    'Bash(git --git-dir=tools/g status)',
  ]) {
    const result = scanFiles({ '.claude/settings.json': settings({ allow: [rule] }) });
    assert.equal(findingsFor(result, 'AGC-PERM-003').length, 1, rule);
  }
  assert.equal(
    findingsFor(scanFiles({ '.claude/settings.json': settings({ allow: ['Bash(git status)'] }) }), 'AGC-PERM-003')
      .length,
    0,
  );
  for (const name of ['GIT_DIR', 'XDG_CONFIG_HOME', 'HOME']) {
    const result = scanFiles({
      '.claude/settings.json': settings({ allow: ['Bash(git status)'] }, { env: { [name]: 'tools' } }),
    });
    assert.ok(
      findingsFor(result, 'AGC-CFG-001').some(finding => finding.severity === 'high' && finding.message.includes(name)),
      name,
    );
  }
});

test('--base: a baseline elsewhere in the checkout than the scanned folder is read from the base', async t => {
  const { root } = repo(t, {
    'packages/a/.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }),
    'packages/a/CODEOWNERS': '* @acme/platform\n',
    'agc-baseline.json': JSON.stringify({ version: 1, fingerprints: [] }),
  });
  const scanned = join(root, 'packages/a');
  write(root, { 'packages/a/.claude/settings.json': settings({ allow: ['Bash'] }) });
  // The change records its own findings in the baseline.
  await cli([scanned, '--write-baseline', join(root, 'agc-baseline.json')]);
  commit(root, 'change');
  const { code, stderr } = await cli([scanned, '--base', 'HEAD~1', '--baseline', join(root, 'agc-baseline.json')]);
  assert.equal(code, 1);
  assert.match(stderr, /agc-baseline\.json differs from HEAD~1/);
  // Named relative to the folder the scan runs from, as the Action does.
  assert.equal(
    (await cli(['packages/a', '--base', 'HEAD~1', '--baseline', 'agc-baseline.json'], { cwd: root })).code,
    1,
  );
});
