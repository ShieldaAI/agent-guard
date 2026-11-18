// Variants from the seventh review round. Synthetic configs; temporary folders only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authority, DirectorySource, scan } from '@shieldaai/agent-guard-check';
import { findingsFor, ruleIds, scanFiles, settings } from './helpers.mjs';

const temp = (t, name) => {
  const dir = mkdtempSync(join(tmpdir(), name));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

test('a diamond of folder links cannot use up the walk before .claude is read', t => {
  const dir = temp(t, 'agc-diamond-');
  // Levels !0 .. !24, each holding two links to the next level: 2^24 paths if walked naively.
  for (let i = 0; i <= 24; i++) mkdirSync(join(dir, `!${i}`));
  for (let i = 0; i < 24; i++) {
    for (let k = 0; k < 2; k++) symlinkSync(join(dir, `!${i + 1}`), join(dir, `!${i}`, `l${k}`), 'dir');
    for (let k = 0; k < 50; k++) writeFileSync(join(dir, `!${i}`, `f${k}`), '');
  }
  mkdirSync(join(dir, '.claude'));
  writeFileSync(join(dir, '.claude', 'settings.json'), settings({ defaultMode: 'bypassPermissions' }));
  const started = Date.now();
  const result = scan({ root: dir, source: new DirectorySource(dir) });
  assert.ok(Date.now() - started < 20_000);
  assert.ok(ruleIds(result).includes('AGC-PERM-001'));
  const truncated = findingsFor(result, 'AGC-CFG-002').filter(f => f.message.includes('stopped before'));
  assert.equal(truncated.length, 1);
  assert.equal(truncated[0].severity, 'high');
});

test('config folders are walked before filler that sorts first', t => {
  const dir = temp(t, 'agc-order-');
  mkdirSync(join(dir, '!filler'));
  for (let k = 0; k < 10; k++) writeFileSync(join(dir, '!filler', `f${k}`), '');
  mkdirSync(join(dir, '.claude'));
  writeFileSync(join(dir, '.claude', 'settings.json'), '{}');
  const listed = new DirectorySource(dir).list();
  assert.deepEqual(listed, ['.claude/settings.json']);
});

const job = (steps, { on = 'issues', permissions = 'contents: write', env = '' } = {}) =>
  `on: ${on}\npermissions:\n  ${permissions}\njobs:\n  a:\n    runs-on: ubuntu-latest\n${env}    steps:\n${steps}`;
const run = script =>
  `      - run: |\n${script
    .split('\n')
    .map(line => `          ${line}`)
    .join('\n')}\n`;

for (const [name, script] of [
  ['quoted name', '"claude" -p hi --dangerously-skip-permissions'],
  ['split name', 'cl""aude -p hi --dangerously-skip-permissions'],
  ['short-flag cluster', 'claude -cp hi --dangerously-skip-permissions'],
  [
    'env prefix and wrappers',
    'FOO=1 time env A=1 npx -y @anthropic-ai/claude-code@latest -p x --dangerously-skip-permissions',
  ],
  ['indented in an if', 'if true; then\n  claude -p "$P" --dangerously-skip-permissions\nfi'],
  ['flags in a shell variable', 'FLAGS="--dangerously-skip-permissions"\nclaude -p hi $FLAGS'],
  ['bash -c', 'bash -lc "claude -p hi --dangerously-skip-permissions"'],
  ['command substitution', 'OUT="$(claude -p hi --dangerously-skip-permissions)"'],
])
  test(`a Claude CLI call is found and judged: ${name}`, () => {
    const result = scanFiles({ '.github/workflows/a.yml': job(run(script)) });
    assert.ok(ruleIds(result).includes('AGC-PERM-001'), JSON.stringify(ruleIds(result)));
  });

for (const [name, script] of [
  ['version check', 'claude --version && echo ok'],
  ['install', 'npm i -g @anthropic-ai/claude-code'],
  ['echo', 'echo "use codex e and claude -p"'],
  ['mcp management', 'claude mcp add foo -- npx bar'],
  ['heredoc text', 'cat <<EOF > notes.txt\nclaude -p not-run\nEOF'],
])
  test(`no agent is found in a script that does not run one: ${name}`, () => {
    const result = scanFiles({ '.github/workflows/a.yml': job(run(script)) });
    assert.equal(result.agents.filter(agent => agent.kind === 'workflow').length, 0);
  });

test('flags the scan cannot read ($FLAGS, an expression in claude_args) are unknown reach', () => {
  const unknownVar = scanFiles({ '.github/workflows/a.yml': job(run('claude -p hi $FLAGS')) });
  assert.ok(ruleIds(unknownVar).includes('AGC-CFG-001'));
  const expr = scanFiles({
    '.github/workflows/a.yml': job(
      '      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: ${{ inputs.args }}\n',
    ),
  });
  assert.ok(ruleIds(expr).includes('AGC-CFG-001'));
  const model = scanFiles({
    '.github/workflows/a.yml': job(
      '      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: --model ${{ vars.MODEL }}\n',
    ),
  });
  assert.ok(!ruleIds(model).includes('AGC-CFG-001'));
});

test('a fork of claude-code-action and a composite action wrapping the CLI are agents', () => {
  const fork = scanFiles({
    '.github/workflows/a.yml': job(
      '      - uses: someone/claude-code-action@v1\n        with:\n          claude_args: --dangerously-skip-permissions\n',
    ),
  });
  assert.ok(ruleIds(fork).includes('AGC-PERM-001'));
  const composite = scanFiles({
    '.github/workflows/a.yml': job('      - uses: ./\n'),
    'action.yml': 'runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n',
    '.github/actions/inner/action.yml':
      'runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: "\\"claude\\" -p go"\n',
  });
  assert.equal(composite.agents.filter(agent => agent.kind === 'workflow').length, 1);
});

test('variadic --allowedTools keeps every tool', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': job(
      '      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: --allowedTools Read Bash\n',
    ),
  });
  const agent = result.agents.find(item => item.kind === 'workflow');
  assert.equal(authority(agent).exec.value, 'yes');
});

test('secrets in other expression forms and through $GITHUB_ENV reach the agent', () => {
  for (const env of [
    '    env:\n      ALL: ${{ toJSON(secrets) }}\n',
    "    env:\n      DB: ${{ secrets['PROD_DB'] }}\n",
    "    env:\n      DB: ${{ format('{0}', secrets.PROD_DB) }}\n",
  ]) {
    const result = scanFiles({ '.github/workflows/a.yml': job(run('claude -p hi'), { env }) });
    const agent = result.agents.find(item => item.kind === 'workflow');
    assert.equal(authority(agent).privateData.value, 'yes', env);
  }
  const exported = scanFiles({
    '.github/workflows/a.yml': job(`${run('echo "DB=${{ secrets.PROD_DB }}" >> "$GITHUB_ENV"')}${run('claude -p hi')}`),
  });
  const agent = exported.agents.find(item => item.kind === 'workflow');
  assert.equal(authority(agent).privateData.value, 'yes');
  const prompt = scanFiles({
    '.github/workflows/a.yml': job(
      '      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: "use ${{ secrets.PROD_DB }}"\n',
    ),
  });
  assert.equal(authority(prompt.agents.find(item => item.kind === 'workflow')).privateData.value, 'yes');
});

test('a model-key variable holding a non-model secret is the agent’s data', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': job(run('claude -p hi'), {
      env: '    env:\n      ANTHROPIC_API_KEY: ${{ secrets.PROD_DB_API_KEY }}\n',
    }),
  });
  assert.equal(authority(result.agents.find(item => item.kind === 'workflow')).privateData.value, 'yes');
});

test('a reusable workflow takes its callers’ triggers, or unknown ones with no caller here', () => {
  const callee = job(run('claude -p hi --dangerously-skip-permissions'), { on: 'workflow_call' });
  const called = scanFiles({
    '.github/workflows/callee.yml': callee,
    '.github/workflows/caller.yml':
      'on: issue_comment\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n    secrets: inherit\n',
  });
  const agent = called.agents.find(item => item.kind === 'workflow');
  assert.equal(authority(agent).untrustedInput.value, 'yes');
  const alone = scanFiles({ '.github/workflows/callee.yml': callee });
  const lone = alone.agents.find(item => item.kind === 'workflow');
  assert.notEqual(authority(lone).untrustedInput.value, 'no');
});

test('two steps with one name are two agents, and settings paths follow working-directory', () => {
  const twice = scanFiles({
    '.github/workflows/a.yml': job(
      `      - name: agent\n        run: claude -p hi\n      - name: agent\n        run: claude -p hi --dangerously-skip-permissions\n`,
    ),
  });
  assert.equal(twice.agents.filter(agent => agent.kind === 'workflow').length, 2);
  const nested = scanFiles({
    '.github/workflows/a.yml': job('      - working-directory: tools\n        run: claude -p hi --settings ./s.json\n'),
    'tools/s.json': JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }),
  });
  assert.ok(ruleIds(nested).includes('AGC-PERM-001'));
});
