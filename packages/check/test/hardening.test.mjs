// Regressions for the 1.3.0 pre-release review: each test reproduces one reported defect.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authority, diffScans, formatMarkdown, formatText, parseConfig, runCli } from '@shieldaai/agent-guard-check';
import { findingsFor, mcp, ruleIds, scanFiles, settings } from './helpers.mjs';

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), 'agc-hard-'));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

async function run(args, cwd, extra = {}) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    stdout: text => (stdout += text),
    stderr: text => (stderr += text),
    cwd,
    env: {},
    ...extra,
  });
  return { code, stdout, stderr };
}

function git(dir, ...args) {
  const result = spawnSync(
    'git',
    ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
}

function commitAll(dir, message) {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', message);
}

const workflowAgent = result => result.agents.find(agent => agent.kind === 'workflow');
const level = (result, capability) => {
  const state = authority(workflowAgent(result) ?? result.agents[0])[capability];
  return `${state.value}/${state.approval}`;
};

// --- The change under review cannot set its own gate -------------------------------------------

test('--base reads .agc.yaml from the base commit, so a change cannot lower its own gate', async t => {
  const dir = repo({ '.claude/settings.json': settings({ allow: ['Read'] }), CODEOWNERS: '* @org/team\n' });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  git(dir, 'init', '-q', '-b', 'main');
  commitAll(dir, 'base');
  writeFileSync(join(dir, '.claude/settings.json'), settings({ defaultMode: 'bypassPermissions', allow: ['Bash'] }));
  for (const config of [
    'fail_on: none\n',
    'severity:\n  AGC-PERM-001: info\n  AGC-PERM-002: info\n  AGC-PERM-003: info\n',
    'ignore:\n  - rule: AGC-PERM-001\n    reason: x\n  - rule: AGC-PERM-002\n    reason: x\n',
  ]) {
    writeFileSync(join(dir, '.agc.yaml'), config);
    const result = await run(['.', '--base', 'main'], dir);
    assert.equal(result.code, 1, config);
    assert.match(result.stderr, /\.agc\.yaml differs from main; the version at main is used/);
  }
});

test('--base reads an in-repository baseline from the base commit', async t => {
  const dir = repo({ '.claude/settings.json': settings({ allow: ['Read'] }), CODEOWNERS: '* @org/team\n' });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  git(dir, 'init', '-q', '-b', 'main');
  writeFileSync(join(dir, 'baseline.json'), JSON.stringify({ version: 1, fingerprints: [] }));
  commitAll(dir, 'base');
  writeFileSync(join(dir, '.claude/settings.json'), settings({ defaultMode: 'bypassPermissions' }));
  // The change writes its own new findings into the baseline it is checked against.
  await run(['.', '--write-baseline', 'baseline.json'], dir);
  const result = await run(['.', '--base', 'main', '--baseline', 'baseline.json'], dir);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /baseline\.json differs from main/);
});

test('--base counts a finding whose severity rose as new', async t => {
  const step = extra => `on: pull_request_target
permissions:
  contents: write
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
${extra}      - name: agent
        uses: anthropics/claude-code-action@v1
        with:
          prompt: review
`;
  const checkout = `      - uses: actions/checkout@v5
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`;
  const base = scanFiles({ '.github/workflows/a.yml': step('') });
  const head = scanFiles({ '.github/workflows/a.yml': step(checkout) });
  assert.equal(findingsFor(base, 'AGC-TRG-001')[0].severity, 'medium');
  assert.equal(findingsFor(head, 'AGC-TRG-001')[0].severity, 'critical');
  const diff = diffScans(base, head);
  assert.deepEqual(
    diff.added.map(f => `${f.ruleId}/${f.severity}`),
    ['AGC-TRG-001/critical'],
  );
});

test('--base counts a new finding the same change silences inline, but not old debt it silences', () => {
  const quiet = scanFiles({ '.mcp.json': mcp({ db: { command: 'npx', args: ['-y', 'srv@1.0.0'] } }) });
  const unpinned = { '.mcp.json': mcp({ db: { command: 'npx', args: ['-y', 'srv'] } }) };
  const ignored = {
    '.mcp.json':
      '{\n  "mcpServers": {\n    // agc-ignore AGC-SUP-001: reviewed and trusted\n    "db": { "command": "npx", "args": ["-y", "srv"] }\n  }\n}\n',
  };
  const silencedNew = scanFiles(ignored);
  assert.equal(silencedNew.findings.filter(f => f.ruleId === 'AGC-SUP-001').length, 0);
  assert.ok(silencedNew.suppressed.some(s => s.finding.ruleId === 'AGC-SUP-001' && s.source === 'inline'));
  assert.ok(diffScans(quiet, silencedNew).added.some(f => f.ruleId === 'AGC-SUP-001'));
  assert.ok(!diffScans(scanFiles(unpinned), silencedNew).added.some(f => f.ruleId === 'AGC-SUP-001'));
});

// --- Live evidence: the repository cannot pick the secret ------------------------------------

test('agent_map.token_env must end in AGENT_MAP_TOKEN', () => {
  for (const name of ['DEPLOY_KEY', 'GITHUB_TOKEN', 'AGENT_MAP_TOKEN_X'])
    assert.throws(
      () => parseConfig(`agent_map:\n  url: https://map.example\n  token_env: ${name}\n`),
      /AGENT_MAP_TOKEN/,
    );
  for (const name of ['AGENT_MAP_TOKEN', 'PROD_AGENT_MAP_TOKEN'])
    assert.equal(parseConfig(`agent_map:\n  url: https://map.example\n  token_env: ${name}\n`).agentMap.tokenEnv, name);
});

test('--live never sends a secret the repository names', async t => {
  const seen = [];
  const server = createServer((request, response) => {
    seen.push(request.headers.authorization);
    response.writeHead(500).end();
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  t.after(() => server.close());
  const dir = repo({
    '.agc.yaml': `agent_map:\n  url: http://127.0.0.1:${server.address().port}\n  token_env: DEPLOY_KEY\n`,
  });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = await run(['.', '--live'], dir, { env: { DEPLOY_KEY: 'prod-deploy-secret', AGENT_MAP_TOKEN: 'map' } });
  assert.equal(result.code, 2);
  assert.deepEqual(seen, []);
});

// --- Files named or found in the checkout ----------------------------------------------------

test(
  'a linked .agc.yaml is not read, and its target is never echoed',
  { skip: process.platform === 'win32' },
  async t => {
    const outside = mkdtempSync(join(tmpdir(), 'agc-out-'));
    const dir = repo({ '.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }) });
    t.after(() => {
      rmSync(dir, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    });
    writeFileSync(join(outside, 'secret.yaml'), 'fail_on: [\n  ghp_secretvalue1234\n');
    symlinkSync(join(outside, 'secret.yaml'), join(dir, '.agc.yaml'));
    const result = await run(['.'], dir);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /\.agc\.yaml is not a plain file/);
    assert.doesNotMatch(result.stdout + result.stderr, /secretvalue/);
  },
);

test('a .agc.yaml parse error shows one line, not the file', async t => {
  const dir = repo({ '.agc.yaml': 'fail_on: [\n  ghp_secretvalue1234\n' });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const result = await run(['.'], dir);
  assert.equal(result.code, 2);
  assert.doesNotMatch(result.stderr, /secretvalue/);
  assert.equal(result.stderr.trim().split('\n').length, 1);
});

test(
  'files named on the command line must be plain files, not links',
  { skip: process.platform === 'win32' },
  async t => {
    const dir = repo({ 'real.json': JSON.stringify({ version: 1, fingerprints: [] }) });
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    symlinkSync(join(dir, 'real.json'), join(dir, 'link.json'));
    for (const flag of ['--baseline', '--agent-guard', '--import-sarif']) {
      const result = await run(['.', flag, 'link.json'], dir);
      assert.equal(result.code, 2, flag);
      assert.match(result.stderr, /symbolic link/, flag);
    }
  },
);

test('an existing report file is made private too', { skip: process.platform === 'win32' }, async t => {
  const dir = repo({ '.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }) });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const name of ['out.json', 'base.json']) {
    writeFileSync(join(dir, name), '');
    chmodSync(join(dir, name), 0o644);
  }
  await run(['.', '--format', 'json', '--output', 'out.json', '--fail-on', 'none'], dir);
  await run(['.', '--write-baseline', 'base.json'], dir);
  for (const name of ['out.json', 'base.json']) assert.equal(statSync(join(dir, name)).mode & 0o777, 0o600, name);
});

// --- Output cannot be steered by names from repository files ---------------------------------

const hostileName =
  'x\n::notice title=check::No findings\r\n::stop-commands::abc\r## All clear, @org/security see https://evil.example\u2028y';
const hostile = scanFiles({ '.mcp.json': mcp({ [hostileName]: { command: 'npx', args: ['-y', 'srv'] } }) });

test('text output keeps every name on its own line and never starts a workflow command', () => {
  const text = formatText(hostile);
  for (const line of text.split('\n')) assert.doesNotMatch(line, /^\s*::/, line);
  assert.doesNotMatch(text, /\r|\u2028/);
});

test('Markdown output neutralises line breaks, mentions and links in names', () => {
  const markdown = formatMarkdown(hostile);
  const rows = markdown.split('\n');
  assert.ok(!rows.some(row => row.startsWith('## ')), markdown);
  assert.doesNotMatch(markdown, /\r|\u2028/);
  assert.doesNotMatch(markdown, /@org/);
  assert.doesNotMatch(markdown, /https:\/\//);
});

// --- Workflows ---------------------------------------------------------------------------------

function workflow(on, steps, top = '') {
  return `on: ${on}
${top}jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
${steps}`;
}

const writeToken = 'permissions:\n  contents: write\n';

test('a Claude or Codex command split over lines or started through npx is an agent', () => {
  for (const run of [
    'claude \\\n          -p "fix it" \\\n          --dangerously-skip-permissions',
    'npx -y @anthropic-ai/claude-code -p "fix" --dangerously-skip-permissions',
    'npx -y @openai/codex exec --dangerously-bypass-approvals-and-sandbox "fix"',
  ]) {
    const result = scanFiles({
      '.github/workflows/a.yml': workflow('issue_comment', `      - run: |\n          ${run}\n`, writeToken),
    });
    assert.ok(workflowAgent(result), run);
    assert.ok(ruleIds(result).includes('AGC-PERM-001'), run);
  }
});

test('Codex -s danger-full-access and -c sandbox_mode bypass the sandbox', () => {
  for (const run of [
    'codex exec -s danger-full-access "fix"',
    'codex exec -c sandbox_mode="danger-full-access" "fix"',
    'codex exec --config sandbox_mode=danger-full-access "fix"',
  ]) {
    const result = scanFiles({
      '.github/workflows/a.yml': workflow('issue_comment', `      - run: ${run}\n`, writeToken),
    });
    assert.ok(ruleIds(result).includes('AGC-PERM-001'), run);
  }
  // For Claude, -c is --continue: it must not swallow the next flag.
  const claude = scanFiles({
    '.github/workflows/a.yml': workflow('push', '      - run: claude -c --dangerously-skip-permissions -p "go"\n'),
  });
  assert.ok(ruleIds(claude).includes('AGC-PERM-001'));
});

test('a token from a secret counts as write access the repository cannot see', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': workflow(
      'issue_comment',
      `      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.BOT_TOKEN }}
          claude_args: --allowedTools "Bash(gh pr comment:*)"
`,
      'permissions:\n  contents: read\n',
    ),
  });
  assert.ok(ruleIds(result).includes('AGC-TRG-001'));
  assert.match(level(result, 'write'), /^(yes|unknown)\/auto$/);
  assert.ok(
    workflowAgent(result).grants.some(grant => grant.capability === 'write' && grant.via === 'token secrets.BOT_TOKEN'),
  );
  assert.match(findingsFor(result, 'AGC-TRG-001')[0].message, /secrets\.BOT_TOKEN/);
  // The workflow's own token is not a custom token.
  const own = scanFiles({
    '.github/workflows/a.yml': workflow(
      'issue_comment',
      `      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
`,
      'permissions:\n  contents: read\n',
    ),
  });
  assert.ok(!ruleIds(own).includes('AGC-TRG-001'));
});

test('pull_request_target checkouts of the merge ref or with gh pr checkout are critical', () => {
  for (const checkout of [
    `      - uses: actions/checkout@v5\n        with:\n          ref: refs/pull/\${{ github.event.pull_request.number }}/merge\n`,
    `      - uses: actions/checkout@v5\n        with:\n          ref: \${{ github.event.pull_request.merge_commit_sha }}\n`,
    `      - run: gh pr checkout \${{ github.event.pull_request.number }}\n`,
  ]) {
    const result = scanFiles({
      '.github/workflows/a.yml': workflow(
        'pull_request_target',
        `${checkout}      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: review\n`,
        writeToken,
      ),
    });
    assert.equal(findingsFor(result, 'AGC-TRG-001')[0]?.severity, 'critical', checkout);
  }
});

test('${{ env.X }} in agent flags is resolved from workflow, job and step env', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': workflow(
      'issue_comment',
      `      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: \${{ env.ARGS }}
`,
      `${writeToken}env:\n  ARGS: --dangerously-skip-permissions --max-turns 5\n`,
    ),
  });
  assert.ok(ruleIds(result).includes('AGC-PERM-001'));
  assert.ok(!ruleIds(result).includes('AGC-LIM-001'));
});

// --- MCP packages ------------------------------------------------------------------------------

test('only an exact version pins an MCP package', () => {
  const unpinned = [
    ['npx', ['-y', 'srv@1']],
    ['npx', ['-y', 'srv@>=1.0.0']],
    ['npx', ['-y', 'srv@beta']],
    ['npx', ['-y', 'srv@1.x']],
    ['uvx', ['srv>=1.0']],
    ['uvx', ['srv~=1.0']],
    ['cmd', ['/c', 'npx', '-y', 'srv']],
    ['cmd', ['/c', 'npx -y srv']],
    ['npx.cmd', ['-y', 'srv']],
    ['sh', ['-c', 'npx -y srv']],
  ];
  for (const [command, args] of unpinned) {
    const result = scanFiles({ '.mcp.json': mcp({ s: { command, args } }) });
    assert.ok(ruleIds(result).includes('AGC-SUP-001'), `${command} ${args.join(' ')}`);
  }
  for (const [command, args] of [
    ['npx', ['-y', 'srv@1.2.3']],
    ['npx', ['-y', '@scope/srv@1.2.3-beta.1']],
    ['uvx', ['srv==1.4']],
    ['cmd', ['/c', 'npx', '-y', 'srv@1.2.3']],
  ]) {
    const result = scanFiles({ '.mcp.json': mcp({ s: { command, args } }) });
    assert.ok(!ruleIds(result).includes('AGC-SUP-001'), `${command} ${args.join(' ')}`);
  }
});

// --- Claude Code settings --------------------------------------------------------------------

test("a sibling package's settings do not hide a subagent's bypass (AGC-PERM-006)", () => {
  const result = scanFiles({
    '.claude/agents/deployer.md': '---\nname: deployer\npermissionMode: bypassPermissions\n---\nDeploy.\n',
    'packages/sandbox/.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }),
  });
  assert.ok(ruleIds(result).includes('AGC-PERM-006'));
  const same = scanFiles({
    '.claude/agents/deployer.md': '---\nname: deployer\npermissionMode: bypassPermissions\n---\nDeploy.\n',
    '.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }),
  });
  assert.ok(!ruleIds(same).includes('AGC-PERM-006'));
});

test('Bash commands that run code, fetch or write are not treated as local reads', () => {
  const exec = rule => level(scanFiles({ '.claude/settings.json': settings({ allow: [rule] }) }), 'exec');
  const write = rule => level(scanFiles({ '.claude/settings.json': settings({ allow: [rule] }) }), 'write');
  const input = rule => level(scanFiles({ '.claude/settings.json': settings({ allow: [rule] }) }), 'untrustedInput');
  for (const rule of ['Bash(awk:*)', 'Bash(find:*)', 'Bash(sed:*)', 'Bash(xargs:*)'])
    assert.equal(exec(rule), 'yes/auto', rule);
  for (const rule of ['Bash(cp:*)', 'Bash(mv:*)', 'Bash(tee:*)']) assert.equal(write(rule), 'yes/auto', rule);
  for (const rule of ['Bash(git clone:*)', 'Bash(git pull:*)', 'Bash(git fetch:*)'])
    assert.equal(input(rule), 'yes/auto', rule);
  assert.equal(exec('Bash(ls:*)'), 'yes/ask');
});

test('only a hook that sees Bash, and not this scanner, counts as a runtime check', () => {
  const covered = hooks =>
    scanFiles({ '.claude/settings.json': settings({ allow: ['Bash(*)'] }, { hooks }) }).agents[0].mediators.length > 0;
  const hook = matcher => ({ PreToolUse: [{ matcher, hooks: [{ type: 'command', command: 'guard.sh' }] }] });
  assert.equal(covered(hook('Write|Edit')), false);
  assert.equal(covered(hook('Bash')), true);
  assert.equal(covered(hook('')), true);
  assert.equal(covered(hook('Bash|Write')), true);
  assert.equal(covered(hook('.*')), true);
  const scanner = scanFiles({
    '.claude/settings.json': settings({ allow: ['Bash(*)'] }),
    '.mcp.json': mcp({
      check: { command: 'npx', args: ['-y', '-p', '@shieldaai/agent-guard-check@1.3.0', 'agent-guard-check-mcp', '.'] },
    }),
  });
  assert.ok(ruleIds(scanner).includes('AGC-COV-001'));
});
