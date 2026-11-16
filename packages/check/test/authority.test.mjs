import test from 'node:test';
import assert from 'node:assert/strict';
import { authority } from '@shieldaai/agent-guard-check';
import { findingsFor, mcp, scanFiles, settings } from './helpers.mjs';

const postgres = {
  command: 'npx',
  args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2', 'postgresql://localhost/db'],
};
const github = {
  command: 'npx',
  args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'],
  env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${GITHUB_TOKEN}' },
};
const main = result => result.agents.find(agent => agent.kind === 'claude-code');

test('defaults: shell, edits, fetches and MCP tools all need approval', () => {
  const result = scanFiles({ '.mcp.json': mcp({ postgres }) });
  const a = authority(main(result));
  assert.equal(a.exec.value, 'yes');
  assert.equal(a.exec.approval, 'ask');
  assert.equal(a.egress.approval, 'ask');
  assert.equal(a.privateData.approval, 'ask');
  assert.equal(a.untrustedInput.approval, 'ask');
  // Every leg is behind a prompt: not a trifecta finding.
  assert.deepEqual(findingsFor(result, 'AGC-TRI-001'), []);
  assert.deepEqual(findingsFor(result, 'AGC-TRI-002'), []);
});

test('trifecta with an unguarded way out is critical', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ postgres }),
    '.claude/settings.json': settings({ allow: ['mcp__postgres', 'WebFetch'] }),
  });
  const [finding] = findingsFor(result, 'AGC-TRI-001');
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
  assert.match(finding.message, /mcp__postgres/);
  assert.match(finding.message, /WebFetch/);
  assert.equal(finding.location.file, '.claude/settings.json');
});

test('trifecta whose way out still needs approval is medium when untrusted input arrives unasked', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ postgres }),
    '.claude/settings.json': settings({ allow: ['mcp__postgres', 'WebSearch'] }),
  });
  assert.deepEqual(findingsFor(result, 'AGC-TRI-001'), []);
  const [finding] = findingsFor(result, 'AGC-TRI-002');
  assert.ok(finding);
  assert.equal(finding.severity, 'medium');
});

test('no trifecta finding when a person approves both untrusted input and sending out', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ postgres }),
    '.claude/settings.json': settings({ allow: ['mcp__postgres'] }),
  });
  assert.deepEqual([...findingsFor(result, 'AGC-TRI-001'), ...findingsFor(result, 'AGC-TRI-002')], []);
});

test('a domain-limited WebFetch is not a way out', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ postgres }),
    '.claude/settings.json': settings({
      allow: ['mcp__postgres', 'WebFetch(domain:docs.example.com)'],
      deny: ['Bash', 'WebFetch'],
    }),
  });
  const a = authority(main(result));
  assert.equal(a.untrustedInput.value, 'yes');
  assert.equal(a.egress.value, 'no');
});

test('denying a whole tool removes what it gave', () => {
  const result = scanFiles({ '.claude/settings.json': settings({ deny: ['Bash', 'WebFetch'] }) });
  const a = authority(main(result));
  assert.equal(a.exec.value, 'no');
  assert.equal(a.egress.value, 'no');
});

test('bypass mode makes everything run without approval', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ github }),
    '.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }),
  });
  const a = authority(main(result));
  for (const capability of ['exec', 'egress', 'privateData', 'untrustedInput'])
    assert.equal(a[capability].approval, 'auto', capability);
  assert.equal(findingsFor(result, 'AGC-PERM-001').length, 1);
  assert.equal(findingsFor(result, 'AGC-TRI-001').length, 1);
});

test('an unlisted MCP server is unknown, never assumed safe', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ inhouse: { command: 'node', args: ['server.js'] } }),
    '.claude/settings.json': settings({ allow: ['mcp__inhouse', 'WebFetch'] }),
  });
  const a = authority(main(result));
  assert.equal(a.privateData.value, 'unknown');
  const [finding] = findingsFor(result, 'AGC-TRI-002');
  assert.ok(finding, 'two legs plus an unknown one is reported');
  assert.match(finding.message, /unknown/);
});

test('read-only MCP tool rules do not carry the server’s write or egress', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ github }),
    '.claude/settings.json': settings({ allow: ['mcp__github__get_issue'], deny: ['Bash', 'WebFetch', 'WebSearch'] }),
  });
  const a = authority(main(result));
  assert.equal(a.untrustedInput.approval, 'auto');
  // Egress still exists through the server, but only behind approval.
  assert.equal(a.egress.approval, 'ask');
});

test('subagents with a tools list only keep those tools', () => {
  const result = scanFiles({
    '.mcp.json': mcp({ postgres }),
    '.claude/settings.json': settings({ allow: ['mcp__postgres', 'WebFetch'] }),
    '.claude/agents/reader.md':
      '---\nname: reader\ndescription: Reads the database\ntools: Read, Grep, mcp__postgres\n---\nRead only.',
  });
  const sub = result.agents.find(agent => agent.kind === 'subagent');
  assert.ok(sub);
  const a = authority(sub);
  assert.equal(a.privateData.value, 'yes');
  assert.equal(a.egress.value, 'no');
  assert.equal(a.untrustedInput.value, 'no');
});

test('headless agents cannot use prompt-only paths', () => {
  const workflow = `on: push\npermissions:\n  contents: read\njobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: summarize\n`;
  const result = scanFiles({ '.github/workflows/a.yml': workflow });
  const agent = result.agents.find(item => item.kind === 'workflow');
  const a = authority(agent);
  assert.equal(a.exec.value, 'no');
  assert.equal(a.egress.value, 'no');
});

test('agents in separate directories are separate', () => {
  const result = scanFiles({
    'apps/web/.claude/settings.json': settings({ allow: ['Bash'] }),
    '.claude/settings.json': settings({}),
  });
  const ids = result.agents.map(agent => agent.id).sort();
  assert.deepEqual(ids, ['claude-code:.', 'claude-code:apps/web']);
});
