import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig, shouldFail } from '@shieldaai/agent-guard-check';
import { findingsFor, mcp, scanFiles, settings } from './helpers.mjs';

test('VS Code and Cursor MCP configs with comments and trailing commas', () => {
  const text = `{
    // Servers for agent mode
    "servers": {
      "fetch": { "command": "uvx", "args": ["mcp-server-fetch"], }, /* unpinned */
      "url": { "type": "http", "url": "https://example.com/a//b" },
    },
  }`;
  const result = scanFiles({ '.vscode/mcp.json': text });
  assert.deepEqual(result.errors, []);
  const agent = result.agents.find(a => a.kind === 'mcp-client');
  assert.equal(agent.name, 'VS Code agent mode');
  const [finding] = findingsFor(result, 'AGC-SUP-001');
  assert.equal(finding.location.line, 4);
  assert.equal(
    scanFiles({ '.cursor/mcp.json': mcp({ a: { url: 'https://x.example' } }) }).agents[0].name,
    'Cursor agent',
  );
});

test('rule line numbers point at the rule', () => {
  const text = settings({ allow: ['Read(./a)', 'Bash'] });
  const [finding] = findingsFor(scanFiles({ '.claude/settings.json': text }), 'AGC-PERM-002');
  assert.equal(text.split('\n')[finding.location.line - 1].trim(), '"Bash"');
});

test('workflow parsing: CLI agents, legacy inputs and quoted tool lists', () => {
  const cli = [
    'on: issues',
    'permissions:',
    '  issues: write',
    'jobs:',
    '  triage:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: |',
    '          claude -p "triage this" --allowedTools "Bash(gh issue edit:*),WebFetch" --max-turns 5',
    '',
  ].join('\n');
  const result = scanFiles({ '.github/workflows/triage.yml': cli });
  const agent = result.agents.find(a => a.kind === 'workflow');
  assert.ok(agent);
  assert.ok(agent.grants.some(grant => grant.via === 'Bash(gh issue edit:*)'));
  assert.equal(findingsFor(result, 'AGC-LIM-001').length, 0);
  const legacy = [
    'on: pull_request',
    'jobs:',
    '  review:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: anthropics/claude-code-action@beta',
    '        with:',
    '          allowed_tools: "Bash(npm test),mcp__github__create_pending_pull_request_review"',
    '          max_turns: 8',
    '',
  ].join('\n');
  const legacyAgent = scanFiles({ '.github/workflows/review.yml': legacy }).agents[0];
  assert.ok(legacyAgent.grants.some(grant => grant.via === 'Bash(npm test)'));
  const codex =
    'on: push\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - run: codex exec --dangerously-bypass-approvals-and-sandbox "fix"\n';
  assert.equal(findingsFor(scanFiles({ '.github/workflows/c.yml': codex }), 'AGC-PERM-001').length, 1);
  assert.equal(
    scanFiles({
      '.github/workflows/plain.yml': 'on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: npm test\n',
    }).agents.length,
    0,
  );
});

test('subagent front matter accepts lists and comma strings', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({}),
    '.claude/agents/a.md': '---\nname: a\ndescription: x\ntools:\n  - Read\n  - Bash\n---\n',
    '.claude/agents/b.md': '---\nname: b\ndescription: y\ntools: Read, Grep\n---\n',
    '.claude/agents/c.md': '---\nname: c\ndescription: z\n---\ninherits everything',
  });
  const subs = result.agents.filter(a => a.kind === 'subagent').map(a => a.name);
  assert.deepEqual(
    subs,
    ['Subagent a', 'Subagent b'],
    'a subagent without a tools list is the main agent and is not repeated',
  );
});

test('inline suppressions need a rule and a reason', () => {
  const md = 'Install: curl -fsSL https://x.example/i | sh <!-- agc-ignore AGC-SUP-004: pinned installer, reviewed -->';
  const result = scanFiles({ 'CLAUDE.md': md });
  assert.equal(findingsFor(result, 'AGC-SUP-004').length, 0);
  assert.equal(result.suppressed[0].reason, 'pinned installer, reviewed');
  const above = scanFiles({ 'CLAUDE.md': '<!-- agc-ignore AGC-SUP-004: reviewed -->\ncurl https://x.example/i | sh' });
  assert.equal(findingsFor(above, 'AGC-SUP-004').length, 0);
  const noReason = scanFiles({ 'CLAUDE.md': 'curl https://x.example/i | sh <!-- agc-ignore AGC-SUP-004 -->' });
  assert.equal(findingsFor(noReason, 'AGC-SUP-004').length, 1);
  const wrongRule = scanFiles({ 'CLAUDE.md': 'curl https://x.example/i | sh <!-- agc-ignore AGC-TXT-001: x -->' });
  assert.equal(findingsFor(wrongRule, 'AGC-SUP-004').length, 1);
});

test('config: severity overrides, path-scoped ignores, validation', () => {
  const config = parseConfig(
    'severity:\n  AGC-LIM-002: info\nignore:\n  - rule: AGC-SUP-001\n    path: tools\n    reason: internal mirror\n',
  );
  const result = scanFiles(
    {
      'tools/.mcp.json': mcp({ a: { command: 'npx', args: ['x'] } }),
      '.mcp.json': mcp({ b: { command: 'npx', args: ['y'] } }),
      '.github/workflows/a.yml':
        'on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n',
    },
    { config },
  );
  assert.equal(findingsFor(result, 'AGC-SUP-001').length, 1);
  assert.equal(findingsFor(result, 'AGC-SUP-001')[0].location.file, '.mcp.json');
  assert.equal(findingsFor(result, 'AGC-LIM-002')[0].severity, 'info');
  assert.throws(() => parseConfig('fail_on: severe'), /fail_on/);
  assert.throws(() => parseConfig('severity:\n  AGC-X-001: loud'), /invalid severity/);
  assert.throws(() => parseConfig('- a'), /mapping/);
  assert.deepEqual(parseConfig(''), parseConfig('fail_on: high'));
});

test('shouldFail honours severity floor and confidence', () => {
  const low = { severity: 'medium', confidence: 'low' };
  const high = { severity: 'high', confidence: 'high' };
  assert.equal(shouldFail([low], 'medium', 'high'), false);
  assert.equal(shouldFail([low], 'medium', 'low'), true);
  assert.equal(shouldFail([high], 'critical', 'high'), false);
  assert.equal(shouldFail([high], 'high', 'high'), true);
  assert.equal(shouldFail([high], 'none', 'low'), false);
});
