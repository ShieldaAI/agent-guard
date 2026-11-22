import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { MemorySource, runCli, scan } from '@shieldaai/agent-guard-check';
import { findingsFor, settings } from './helpers.mjs';

const POSTGRES = {
  command: 'npx',
  args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2', 'postgresql://localhost/app'],
};
const SHARED = {
  '.mcp.json': JSON.stringify({ mcpServers: { postgres: POSTGRES } }),
  '.claude/settings.json': settings({ allow: ['Bash(npm test:*)', 'mcp__postgres__query'] }),
  '.gitignore': '.claude/settings.local.json\n',
};

/** A git repository holding `files`, committed, plus an empty home folder. */
function repo(t, files = SHARED, { git = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'agc-hook-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = join(dir, 'repo');
  const home = join(dir, 'home');
  mkdirSync(home);
  write(root, files);
  if (git) {
    const run = args => execFileSync('git', ['-C', root, ...args], { stdio: 'ignore' });
    run(['init', '-q']);
    run(['add', '-A']);
    run(['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-qm', 'base']);
  }
  return { root, home };
}

function write(root, files) {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
}

async function hook({ root, home }, { event = 'SessionStart', args = [], env = {}, stdin } = {}) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(['--hook', ...args], {
    stdout: text => (stdout += text),
    stderr: text => (stderr += text),
    cwd: '/',
    env: { CLAUDE_PROJECT_DIR: root, ...env },
    home,
    stdin: async () => stdin ?? JSON.stringify({ hook_event_name: event, cwd: root }),
  });
  return { code, stdout, stderr };
}

const WEBFETCH = settings({ allow: ['WebFetch'] });

test('--hook stays silent when the session runs only what git tracks', async t => {
  const result = await hook(repo(t));
  assert.deepEqual(result, { code: 0, stdout: '', stderr: '' });
});

test('--hook reports what the gitignored settings.local.json adds, and exits 2', async t => {
  const r = repo(t);
  write(r.root, { '.claude/settings.local.json': WEBFETCH });
  const start = await hook(r);
  assert.equal(start.code, 2);
  assert.equal(start.stdout, '', 'nothing goes into Claude’s context');
  assert.match(start.stderr, /settings no pull request shows/);
  assert.match(start.stderr, /CRITICAL AGC-TRI-001 \.claude\/settings\.local\.json:\d+:/);
  assert.doesNotMatch(start.stderr, /Prompts are held/);
  const prompt = await hook(r, { event: 'UserPromptSubmit' });
  assert.equal(prompt.code, 2);
  assert.match(prompt.stderr, /Prompts are held until this is fixed/);
});

test('--hook reads the developer’s own Claude Code settings, but not Codex or Gemini', async t => {
  const r = repo(t);
  write(r.home, { '.claude/settings.json': WEBFETCH });
  const user = await hook(r);
  assert.equal(user.code, 2);
  assert.match(user.stderr, /AGC-TRI-001 ~\/\.claude\/settings\.json:\d+:/);
  const other = repo(t);
  write(other.home, { '.codex/config.toml': 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n' });
  assert.equal((await hook(other)).code, 0, 'a Codex setting is not this Claude Code session');
});

test('--hook reports only what the local layers add, not what the repository already had', async t => {
  const committed = repo(t, {
    ...SHARED,
    '.claude/settings.json': settings({ allow: ['mcp__postgres__query', 'WebFetch'] }),
  });
  write(committed.root, { '.claude/settings.local.json': WEBFETCH });
  assert.equal((await hook(committed)).code, 0, 'the trifecta is in the reviewed file: CI’s to report');
  const record =
    "reviews:\n  - agent: .claude/settings.json\n    owner: '@acme'\n    review_by: 2020-01-01\n    capabilities: [exec]\n";
  const lapsed = repo(t, { ...SHARED, '.agc-reviews.yaml': record });
  assert.equal((await hook(lapsed)).code, 0, 'a passed review date is not a local change');
});

test('--hook uses the tracked .agc.yaml: an untracked one cannot quiet it', async t => {
  const r = repo(t, { ...SHARED, '.gitignore': '.claude/settings.local.json\n.agc.yaml\n' });
  write(r.root, { '.claude/settings.local.json': WEBFETCH, '.agc.yaml': 'fail_on: none\n' });
  assert.equal((await hook(r)).code, 2);
  const lowered = repo(t, { ...SHARED, '.agc.yaml': 'fail_on: critical\n' });
  write(lowered.root, { '.claude/settings.local.json': settings({ allow: ['Read(~/**)'] }) });
  assert.equal((await hook(lowered)).code, 0, 'a high finding under a tracked fail_on: critical');
  assert.equal((await hook(lowered, { args: ['--fail-on', 'high'] })).code, 2, '--fail-on overrides it');
});

test('--hook outside git: everything but the per-developer files counts as shared', async t => {
  const r = repo(t, SHARED, { git: false });
  assert.equal((await hook(r)).code, 0);
  write(r.root, { '.claude/settings.local.json': WEBFETCH });
  const result = await hook(r);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /settings only this machine has/);
});

test('--hook in CI reads no personal settings', async t => {
  const r = repo(t);
  write(r.home, { '.claude/settings.json': WEBFETCH });
  assert.equal((await hook(r, { env: { CI: 'true' } })).code, 0);
});

test('--hook finds the project from CLAUDE_PROJECT_DIR, the hook input, or a path', async t => {
  const r = repo(t);
  write(r.root, { '.claude/settings.local.json': WEBFETCH });
  const fromInput = await runCli(['--hook'], {
    stdout: () => {},
    stderr: () => {},
    cwd: '/',
    env: {},
    home: r.home,
    stdin: async () => JSON.stringify({ hook_event_name: 'SessionStart', cwd: r.root }),
  });
  assert.equal(fromInput, 2);
  const fromPath = await runCli(['--hook', r.root], {
    stdout: () => {},
    stderr: () => {},
    cwd: '/',
    env: {},
    home: r.home,
    stdin: async () => 'not json',
  });
  assert.equal(fromPath, 2, 'unreadable input falls back to SessionStart');
});

test('--hook never blocks a prompt because of its own mistake: those exit 1', async t => {
  const r = repo(t);
  for (const args of [['--github-repo', 'a/b'], ['--format', 'json'], ['--fail-on', 'bogus'], ['--nope'], ['a', 'b']]) {
    const result = await hook(r, { event: 'UserPromptSubmit', args });
    assert.equal(result.code, 1, args.join(' '));
  }
  const missing = await hook({ root: join(r.root, 'missing'), home: r.home }, { event: 'UserPromptSubmit' });
  assert.equal(missing.code, 1);
  assert.match(missing.stderr, /--hook:/);
});

test('the recommended hook command is not reported as a hook that reaches the network', () => {
  const hookSettings = command =>
    JSON.stringify({
      hooks: {
        SessionStart: [{ matcher: 'startup|resume', hooks: [{ type: 'command', command }] }],
        UserPromptSubmit: [{ hooks: [{ type: 'command', command }] }],
      },
    });
  const scanned = command =>
    findingsFor(
      scan({ root: '/r', source: new MemorySource({ '.claude/settings.json': hookSettings(command) }) }),
      'AGC-PERM-003',
    );
  assert.equal(scanned('npx --no-install agent-guard-check --hook').length, 0);
  assert.equal(scanned('npx --no-install @shieldaai/agent-guard-check --hook --fail-on medium').length, 0);
  // Forms that download or reach out stay findings.
  assert.equal(scanned('npx -y @shieldaai/agent-guard-check@1.6.0 --hook').length, 2);
  assert.equal(scanned('npx --no-install agent-guard-check --hook --github-repo a/b').length, 2);
  assert.equal(scanned('npx --no-install agent-guard-check --hook; curl https://example.com').length, 2);
  // A bare name could be any program on PATH, --offline any cached package, and npm_config_* changes what runs.
  assert.equal(scanned('agent-guard-check --hook').length, 2);
  assert.equal(scanned('npx --offline agent-guard-check --hook').length, 2);
  assert.equal(scanned('npm_config_node_options=--require=x npx --no-install agent-guard-check --hook').length, 2);
});

const gitIn = (root, ...args) => execFileSync('git', ['-C', root, ...args], { stdio: 'ignore' });
const commitAll = root => {
  gitIn(root, 'add', '-A');
  gitIn(root, '-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-qm', 'more');
};

test('--hook: notes about tracked files (too large, a skipped folder) are in both scans, not local', async t => {
  const r = repo(t, {
    ...SHARED,
    'vendor/x/.claude/settings.json': settings({}),
    '.claude/agents/big.md': `---\nname: big\ndescription: d\n---\n${'x'.repeat(1024 * 1024 + 10)}`,
  });
  assert.equal((await hook(r, { event: 'UserPromptSubmit' })).code, 0);
});

test('--hook: an unstaged or hidden edit to a tracked file is not reviewed yet, and is reported', async t => {
  const r = repo(t);
  write(r.root, { '.claude/settings.json': settings({ allow: ['mcp__postgres__query', 'WebFetch'] }) });
  const unstaged = await hook(r);
  assert.equal(unstaged.code, 2);
  assert.match(unstaged.stderr, /AGC-TRI-001 \.claude\/settings\.json:/);
  gitIn(r.root, 'update-index', '--skip-worktree', '.claude/settings.json');
  assert.equal((await hook(r)).code, 2, 'hidden from git status, still not in any pull request');
  gitIn(r.root, 'update-index', '--no-skip-worktree', '.claude/settings.json');
  gitIn(r.root, 'add', '.claude/settings.json');
  assert.equal((await hook(r)).code, 0, 'staged: the pull request will show it, and CI judges it');
});

test('--hook: an unstaged edit to .agc.yaml cannot quiet it', async t => {
  const r = repo(t, { ...SHARED, '.agc.yaml': 'fail_on: high\n' });
  write(r.root, { '.agc.yaml': 'fail_on: none\n', '.claude/settings.local.json': WEBFETCH });
  assert.equal((await hook(r)).code, 2);
});

test('--hook: submodules and checkouts inside the folder are not local settings', async t => {
  const sub = repo(t, { '.claude/settings.json': settings({ allow: ['Bash(curl:*)', 'mcp__x'] }) });
  const r = repo(t);
  execFileSync(
    'git',
    ['-C', r.root, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', sub.root, 'libs/sub'],
    {
      stdio: 'ignore',
    },
  );
  commitAll(r.root);
  assert.equal((await hook(r)).code, 0, 'a submodule’s tracked settings');
  const nested = repo(t);
  write(nested.root, { '.gitignore': '.claude/settings.local.json\n.claude/worktrees/\n' });
  commitAll(nested.root);
  gitIn(nested.root, 'worktree', 'add', '-q', '.claude/worktrees/feat');
  write(nested.root, { '.claude/worktrees/feat/.claude/settings.json': settings({ allow: ['Bash(curl:*)'] }) });
  assert.equal((await hook(nested)).code, 0, 'a worktree inside the folder');
});

test('--hook: a folder its parent repository does not track is judged as outside git', async t => {
  const parent = repo(t, { 'README.md': '# home\n', '.gitignore': 'project/\n' });
  const project = { root: join(parent.root, 'project'), home: parent.home };
  write(project.root, SHARED);
  assert.equal((await hook(project)).code, 0, 'nothing local yet');
  write(project.root, { '.claude/settings.local.json': WEBFETCH });
  const result = await hook(project);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /settings only this machine has/);
});

test('--hook reads CLAUDE_CONFIG_DIR in place of ~/.claude', async t => {
  const r = repo(t);
  const configDir = join(r.home, 'elsewhere');
  write(configDir, { 'settings.json': WEBFETCH });
  assert.equal((await hook(r)).code, 0, 'not in ~/.claude');
  assert.equal((await hook(r, { env: { CLAUDE_CONFIG_DIR: configDir } })).code, 2);
});

test('--hook edge cases: --hook=, help in hook mode, a prompt too long to read whole', async t => {
  const r = repo(t);
  for (const argv of [['--hook=1'], ['--hook', '--help'], ['--hook', '--version'], ['--hook', '--list-rules']]) {
    let stdout = '';
    const code = await runCli(argv, {
      stdout: text => (stdout += text),
      stderr: () => {},
      cwd: r.root,
      env: {},
      home: r.home,
    });
    assert.equal(code, 1, argv.join(' '));
    assert.equal(stdout, '', 'nothing for Claude’s context');
  }
  write(r.root, { '.claude/settings.local.json': WEBFETCH });
  const cut = JSON.stringify({
    session_id: 's',
    cwd: r.root,
    hook_event_name: 'UserPromptSubmit',
    prompt: 'x'.repeat(100),
  }).slice(0, -20);
  const result = await hook(r, { stdin: cut });
  assert.equal(result.code, 2);
  assert.match(result.stderr, /Prompts are held/, 'the event survives a cut-off prompt');
});

test('--hook: a stray .git in .claude hides nothing; a linked or filtered tracked file is not local', async t => {
  const r = repo(t);
  write(r.root, { '.claude/settings.local.json': WEBFETCH, '.claude/.git': '' });
  assert.equal((await hook(r)).code, 2, 'Claude Code still reads .claude/settings.local.json');

  const linked = repo(t, {
    ...SHARED,
    'shared/settings.json': settings({ allow: ['Bash(npm test:*)', 'mcp__postgres__query'] }),
    '.claude/settings.json': '',
  });
  rmSync(join(linked.root, '.claude/settings.json'));
  execFileSync('ln', ['-s', '../shared/settings.json', join(linked.root, '.claude/settings.json')]);
  commitAll(linked.root);
  assert.equal((await hook(linked, { event: 'UserPromptSubmit' })).code, 0, 'a committed symlink, unchanged');

  const filtered = repo(t, { ...SHARED, '.gitattributes': '.claude/settings.json filter=b64\n' });
  gitIn(filtered.root, 'config', 'filter.b64.clean', 'base64');
  gitIn(filtered.root, 'config', 'filter.b64.smudge', 'base64 -d');
  write(filtered.root, { '.claude/settings.json': settings({ allow: ['Bash(npm test:*)', 'mcp__postgres__query'] }) });
  gitIn(filtered.root, 'add', '-A');
  commitAll(filtered.root);
  assert.equal((await hook(filtered, { event: 'UserPromptSubmit' })).code, 0, 'staged in its clean form');
});

test('--hook: a quoted argument cannot pose as the hook form', () => {
  const scanned = command =>
    findingsFor(
      scan({
        root: '/r',
        source: new MemorySource({
          '.claude/settings.json': JSON.stringify({
            hooks: { SessionStart: [{ hooks: [{ type: 'command', command }] }] },
          }),
        }),
      }),
      'AGC-PERM-003',
    ).length;
  assert.equal(scanned('npx --no-install agent-guard-check "--hook --fail-on none"'), 1);
});

test('--hook names a personal settings file it could not read, even when nothing is added', async t => {
  const r = repo(t);
  mkdirSync(join(r.home, '.claude', 'settings.json'), { recursive: true }); // a folder, not a file
  const result = await hook(r);
  assert.equal(result.code, 0);
  assert.match(result.stderr, /Not read .*~\/\.claude\/settings\.json/);
});
