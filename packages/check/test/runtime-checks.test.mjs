// A runtime check counts only for the calls it sees (AGC-COV-001). Synthetic configs only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { formatText, mediates } from '@shieldaai/agent-guard-check';
import { findingsFor, mcp, scanFiles, settings } from './helpers.mjs';

const hook = matcher => ({ PreToolUse: [{ matcher, hooks: [{ type: 'command', command: './guard.sh' }] }] });
const cov = files => findingsFor(scanFiles(files), 'AGC-COV-001');

test('a hook that sees only Bash does not cover WebFetch', () => {
  const found = cov({ '.claude/settings.json': settings({ allow: ['Bash', 'WebFetch'] }, { hooks: hook('Bash') }) });
  assert.equal(found.length, 1);
  assert.match(found[0].message, /send data out .*\(WebFetch\)/);
  assert.match(found[0].message, /its runtime checks do not see those calls/);
  assert.doesNotMatch(found[0].message, /run code/, 'Bash is covered by the hook');
});

test('a hook whose matcher names every risky tool covers them', () => {
  for (const matcher of ['Bash|WebFetch', 'WebFetch|Bash', '(Bash|WebFetch)', '', '*', '.*'])
    assert.equal(
      cov({ '.claude/settings.json': settings({ allow: ['Bash', 'WebFetch'] }, { hooks: hook(matcher) }) }).length,
      0,
      matcher,
    );
});

test('matchers are case-sensitive and match the whole tool name', () => {
  for (const matcher of ['bash', 'Bas', 'Bash2', 'WebFetch'])
    assert.equal(
      cov({ '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks: hook(matcher) }) }).length,
      1,
      matcher,
    );
});

test('an invalid matcher covers nothing', () => {
  assert.equal(cov({ '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks: hook('Bash(') }) }).length, 1);
});

test('a hook on an MCP server must see every tool of that server', () => {
  const files = matcher => ({
    '.claude/settings.json': settings({ allow: ['mcp__fetch'] }, { hooks: hook(matcher) }),
    '.mcp.json': mcp({ fetch: { command: 'uvx', args: ['mcp-server-fetch==2025.4.7'] } }),
  });
  assert.equal(cov(files('mcp__fetch__.*')).length, 0);
  assert.equal(cov(files('mcp__.*')).length, 0);
  assert.equal(cov(files('mcp__fetch__fetch')).length, 1, 'one tool of the server is not the server');
  assert.equal(cov(files('mcp__fetch')).length, 1, 'tool names are mcp__<server>__<tool>');
  assert.equal(cov(files('Bash')).length, 1);
});

test('an allow-all rule is covered only by a hook that sees every tool', () => {
  const files = matcher => ({ '.claude/settings.json': settings({ allow: ['*'] }, { hooks: hook(matcher) }) });
  assert.equal(cov(files('Bash')).length, 1);
  assert.equal(cov(files('Bash|WebFetch|Edit|Write')).length, 1);
  assert.equal(cov(files('')).length, 0);
  assert.equal(cov(files('.*')).length, 0);
});

test('a gateway or Agent Guard server covers only the calls made through it', () => {
  const gateway = { command: 'docker', args: ['mcp', 'gateway', 'run'] };
  const fetch = { command: 'uvx', args: ['mcp-server-fetch==2025.4.7'] };
  // The fetch server is configured beside the gateway, so its calls never pass through it.
  const bypassed = cov({
    '.claude/settings.json': settings({ allow: ['mcp__fetch'] }),
    '.mcp.json': mcp({ gateway, fetch }),
  });
  assert.equal(bypassed.length, 1);
  assert.match(bypassed[0].message, /mcp__fetch/);
  const guard = { command: 'node', args: ['./agent-guard-proxy.js'] };
  assert.equal(
    cov({ '.claude/settings.json': settings({ allow: ['mcp__fetch', 'Bash'] }), '.mcp.json': mcp({ guard, fetch }) })
      .length,
    1,
    'an Agent Guard server does not see Bash or another server',
  );
});

test('mediates() decides per tool', () => {
  const at = { file: '.claude/settings.json', line: 1 };
  const bashHook = { kind: 'pre-tool-hook', location: at, matcher: 'Bash' };
  assert.equal(mediates(bashHook, 'Bash'), true);
  assert.equal(mediates(bashHook, 'WebFetch'), false);
  assert.equal(mediates(bashHook, undefined), false, 'a grant with no tool is never seen');
  const gateway = { kind: 'mcp-gateway', location: at, server: 'gw' };
  assert.equal(mediates(gateway, 'mcp__gw'), true);
  assert.equal(mediates(gateway, 'mcp__other'), false);
  assert.equal(mediates(gateway, 'Bash'), false);
  assert.equal(mediates({ kind: 'agent-guard', location: at }, 'mcp__x'), false, 'no server, no coverage');
});

test('the text report says what each runtime check sees', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks: { ...hook('Bash'), ...{} } }),
  });
  assert.match(formatText(result), /runtime check: pre-tool-hook \(Bash\)/);
  const every = scanFiles({ '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks: hook('') }) });
  assert.match(formatText(every), /runtime check: pre-tool-hook \(every tool\)/);
});

test('a hostile matcher stays on one line in the text report', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['Bash'] }, { hooks: hook('Bash\n::error::x') }),
  });
  const line = formatText(result)
    .split('\n')
    .find(item => item.includes('runtime check:'));
  assert.ok(line && !line.includes('\n'));
  assert.doesNotMatch(formatText(result), /^::error::/m);
});
