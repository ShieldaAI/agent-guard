import test from 'node:test';
import assert from 'node:assert/strict';
import { MemorySource, scan } from '@shieldaai/agent-guard-check';

// Large inputs must stay fast: an inventory near the executor's own size limits, and a
// repository with many agent files.
test('a 5,000-task, 1,000-tool inventory scans in a few seconds', () => {
  const tools = Array.from({ length: 1000 }, (_, i) => ({
    name: `tool.${i}`,
    fingerprint: 'a'.repeat(64),
    registered: true,
    approved: true,
    requiresApproval: false,
    readsUntrusted: i % 3 === 0,
    sendsExternal: i % 5 === 0,
    untrustedContext: null,
  }));
  const tasks = Array.from({ length: 5000 }, (_, i) => ({
    id: `task-${i}`,
    principalId: `agent-${i % 50}`,
    parentTaskId: i % 10 === 0 || i === 0 ? null : `task-${i - (i % 10)}`,
    grants: Array.from({ length: 8 }, (_, g) => ({
      tool: `tool.${(i + g * 37) % 1000}`,
      resources: [`opaque:${i}-${g}`],
    })),
    budget: { maxCalls: 10, maxConcurrent: 1, maxCost: 0, deadline: Date.parse('2030-01-01T00:00:00Z') },
    allowedRecipients: ['opaque:r'],
    revoked: false,
    sensitive: i % 7 === 0,
    untrusted: false,
  }));
  const text = JSON.stringify({
    schemaVersion: 2,
    profile: 'core',
    snapshotId: 'x',
    generatedAt: '2026-11-16T00:00:00.000Z',
    untrustedContextDefault: 'allow',
    tools,
    tasks,
  });
  const started = performance.now();
  const result = scan({
    root: '/r',
    source: new MemorySource({}),
    agentGuardFiles: [{ path: 'inventory.json', text }],
  });
  const elapsed = performance.now() - started;
  assert.deepEqual(result.errors, []);
  assert.ok(result.findings.length > 0);
  assert.ok(elapsed < 10_000, `took ${Math.round(elapsed)} ms`);
});

test('a repository with 400 subagents and 200 workflows scans in a few seconds', () => {
  const files = {};
  for (let i = 0; i < 400; i += 1)
    files[`.claude/agents/a${i}.md`] =
      `---\nname: a${i}\ndescription: agent ${i}\ntools: Read, Bash\nmodel: opus\n---\nWork.\n`;
  for (let i = 0; i < 200; i += 1)
    files[`.github/workflows/w${i}.yml`] =
      'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      issues: write\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: hi\n';
  files['.claude/settings.json'] = JSON.stringify({ permissions: { allow: ['Bash(npm test:*)'] } });
  const started = performance.now();
  const result = scan({ root: '/r', source: new MemorySource(files) });
  const elapsed = performance.now() - started;
  assert.ok(result.agents.length >= 600);
  assert.ok(elapsed < 10_000, `took ${Math.round(elapsed)} ms`);
});
