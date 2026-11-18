// Variants from the tenth review round. Synthetic configs only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { authority } from '@shieldaai/agent-guard-check';
import { findingsFor, ruleIds, scanFiles, settings } from './helpers.mjs';

const source = '---\non: issues\nengine: claude\ntools:\n  github:\n    read-only: true\n---\nGo\n';
const lock = run =>
  `# gh-aw-metadata: {"schema_version":"v4"}\non: issues\njobs:\n  agent:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${JSON.stringify(run)}\n`;

for (const run of [
  'claude --print --allowed-tools "Read Bash" "$PROMPT"',
  'claude --print --allowed-tools Read Bash -- "$PROMPT"',
  'codex exec --dangerously-bypass-approvals-and-sandbox "$PROMPT"',
  'gemini --yolo -p "$PROMPT"',
])
  test(`a hand-edited lock is caught: ${run}`, () => {
    const result = scanFiles({ '.github/workflows/t.md': source, '.github/workflows/t.lock.yml': lock(run) });
    assert.ok(
      findingsFor(result, 'AGC-CFG-001').some(item => item.message.includes('edited by hand')),
      run,
    );
  });

test('a lock with the tools its source gives is not', () => {
  const result = scanFiles({
    '.github/workflows/t.md': source,
    '.github/workflows/t.lock.yml': lock('claude --print --allowed-tools "Read,Grep" "$PROMPT"'),
  });
  assert.ok(!findingsFor(result, 'AGC-CFG-001').some(item => item.message.includes('edited by hand')));
});

test('a Bash rule for a script that runs its arguments allows any command', () => {
  const claude = result => result.agents.find(agent => agent.kind === 'claude-code');
  for (const body of [
    '#!/bin/sh\nexec "$@"\n',
    'eval "$*"\n',
    'import subprocess, sys\nsubprocess.run(sys.argv[1:])\n',
  ]) {
    const file = body.includes('import') ? 'tools/ci.py' : 'tools/ci.sh';
    const rule = body.includes('import') ? 'Bash(python3 tools/ci.py:*)' : 'Bash(./tools/ci.sh:*)';
    const result = scanFiles({ '.claude/settings.json': settings({ allow: [rule] }), [file]: body });
    assert.ok(ruleIds(result).includes('AGC-PERM-003'), body);
    assert.equal(authority(claude(result)).egress.approval, 'auto', body);
  }
  const plain = scanFiles({
    '.claude/settings.json': settings({ allow: ['Bash(./tools/ci.sh:*)'] }),
    'tools/ci.sh': '#!/bin/sh\nnpm test -- "$@"\n',
  });
  assert.ok(!ruleIds(plain).includes('AGC-PERM-003'));
  for (const rule of ['Bash(make:*)', 'Bash(go test:*)', 'Bash(cargo:*)', 'Bash(just:*)'])
    assert.ok(
      ruleIds(scanFiles({ '.claude/settings.json': settings({ allow: [rule] }) })).includes('AGC-PERM-003'),
      rule,
    );
  assert.ok(
    !ruleIds(scanFiles({ '.claude/settings.json': settings({ allow: ['Bash(make test)'] }) })).includes('AGC-PERM-003'),
  );
});

test('CLAUDE_CONFIG_DIR and HOME redirects are read, or unknown outside the repository', () => {
  const wf = env =>
    `on: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: claude -p hi --max-turns 3\n        env:\n          ${env}\n`;
  const bypass = JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } });
  assert.ok(
    ruleIds(
      scanFiles({
        '.github/workflows/a.yml': wf('CLAUDE_CONFIG_DIR: ${{ github.workspace }}/ci/claude'),
        'ci/claude/settings.json': bypass,
      }),
    ).includes('AGC-PERM-001'),
  );
  assert.ok(
    ruleIds(
      scanFiles({
        '.github/workflows/a.yml': wf('HOME: ${{ github.workspace }}/ci'),
        'ci/.claude/settings.json': bypass,
      }),
    ).includes('AGC-PERM-001'),
  );
  assert.ok(
    findingsFor(scanFiles({ '.github/workflows/a.yml': wf('CLAUDE_CONFIG_DIR: /tmp/c') }), 'AGC-CFG-001').some(
      item => item.severity === 'high',
    ),
  );
});
