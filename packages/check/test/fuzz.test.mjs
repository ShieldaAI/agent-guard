import test from 'node:test';
import assert from 'node:assert/strict';
import { mcp, scanFiles, settings } from './helpers.mjs';

// Deterministic pseudo-random generator so failures reproduce.
function prng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

const seeds = {
  '.claude/settings.json': settings(
    {
      allow: ['Bash(npm test:*)', 'mcp__db', 'WebFetch', 'Edit(CLAUDE.md)'],
      deny: ['Read(./.env)'],
      defaultMode: 'default',
    },
    {
      hooks: { SessionStart: [{ matcher: '', hooks: [{ type: 'command', command: 'cat notes.md' }] }] },
      env: { API_KEY: '${KEY}' },
    },
  ),
  '.mcp.json': mcp({
    db: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2'], env: { TOKEN: '${T}' } },
    r: { url: 'https://x.example' },
  }),
  '.github/workflows/a.yml':
    'on:\n  issue_comment:\n    types: [created]\npermissions:\n  issues: write\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: --allowedTools "Bash,WebFetch" --max-turns 3\n',
  '.claude/agents/a.md': '---\nname: a\ndescription: d\ntools: Read, Bash\n---\nbody',
  'CLAUDE.md': '# Notes\n\nRun tests.\n',
  '.codex/config.toml':
    'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\nweb_search = "live"\n[sandbox_workspace_write]\nnetwork_access = true\n[mcp_servers.db]\ncommand = "npx"\nargs = ["-y", "x@1.0.0"]\n[profiles.ci]\napproval_policy = "never"\n',
  '.gemini/settings.json': JSON.stringify({
    general: { defaultApprovalMode: 'auto_edit' },
    tools: { allowed: ['run_shell_command(git status)'], exclude: ['web_fetch'] },
    mcpServers: { gh: { command: 'npx', args: ['-y', 'x@1'], trust: true } },
  }),
  '.claude-plugin/marketplace.json': JSON.stringify({
    name: 'm',
    plugins: [
      { name: 'a', source: './a' },
      { name: 'b', source: { source: 'github', repo: 'o/b', ref: 'v1' } },
      { name: 'c', source: { source: 'npm', package: '@o/c@1.0.0' } },
    ],
  }),
  'agent-guard-inventory.json': JSON.stringify({
    schemaVersion: 2,
    profile: 'core',
    snapshotId: 's',
    generatedAt: '2026-11-16T00:00:00.000Z',
    untrustedContextDefault: 'allow',
    tools: [{ name: 't', approved: true, registered: true, readsUntrusted: true, sendsExternal: true }],
    tasks: [
      {
        id: 'k',
        principalId: 'p',
        parentTaskId: null,
        grants: [{ tool: 't', resources: ['*'] }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: 1 },
        allowedRecipients: [],
        revoked: false,
        sensitive: null,
        untrusted: true,
      },
    ],
  }),
};

const PIECES = [
  '{',
  '}',
  '[',
  ']',
  '"',
  ',',
  ':',
  '\n',
  '  ',
  '-',
  '*',
  'null',
  '0',
  'true',
  '\u200b',
  '&a',
  '*a',
  '\\',
  'mcp__',
  '(',
  ')',
];

function mutate(text, random) {
  let out = text;
  const edits = 1 + Math.floor(random() * 6);
  for (let i = 0; i < edits; i += 1) {
    const at = Math.floor(random() * (out.length + 1));
    const roll = random();
    if (roll < 0.4) out = out.slice(0, at) + out.slice(at + 1 + Math.floor(random() * 8));
    else if (roll < 0.8) out = out.slice(0, at) + PIECES[Math.floor(random() * PIECES.length)] + out.slice(at);
    else out = out.slice(0, at) + out.slice(at).split('').reverse().join('').slice(0, 20) + out.slice(at + 20);
  }
  return out;
}

test('mutated configuration never crashes the scan', () => {
  const random = prng(20261116);
  for (let round = 0; round < 400; round += 1) {
    const files = Object.fromEntries(
      Object.entries(seeds).map(([path, text]) => [path, random() < 0.6 ? mutate(text, random) : text]),
    );
    let result;
    assert.doesNotThrow(() => {
      result = scanFiles(files);
    }, `round ${round}`);
    for (const finding of result.findings) {
      assert.ok(finding.location.line >= 1, `round ${round}: line`);
      assert.equal(typeof finding.message, 'string');
    }
    assert.ok(
      result.errors.every(error => !error.message.includes('could not run')),
      `round ${round}: ${JSON.stringify(result.errors)}`,
    );
  }
});

test('valid JSON of the wrong shape is tolerated', () => {
  for (const value of [
    'null',
    '[]',
    '1',
    '"x"',
    '{"permissions": []}',
    '{"permissions": {"allow": "Bash"}}',
    '{"hooks": {"Stop": [1, null, {"hooks": "x"}]}}',
    '{"mcpServers": {"a": null, "b": {"args": "x"}}}',
  ])
    assert.doesNotThrow(() => scanFiles({ '.claude/settings.json': value, '.mcp.json': value }), value);
  for (const value of [
    'on: push\njobs: []',
    'on: push\njobs:\n  a: 1',
    'on: push\njobs:\n  a:\n    steps: {}',
    'jobs:\n  a:\n    steps:\n      - null\n      - uses: 3',
  ])
    assert.doesNotThrow(() => scanFiles({ '.github/workflows/a.yml': value }), value);
  for (const value of [
    'null',
    '[]',
    '{"tools": 1, "tasks": [], "profile": "core"}',
    '{"kind": "agent-guard-description"}',
  ])
    assert.doesNotThrow(
      () =>
        scanFiles({
          'agent-guard-x.json': value,
          '.gemini/settings.json': value,
          '.claude-plugin/marketplace.json': value,
        }),
      value,
    );
  for (const value of ['', 'mcp_servers = 3', '[mcp_servers]\nx = 1', 'profiles = "x"', '[[a]]\nb = 1'])
    assert.doesNotThrow(() => scanFiles({ '.codex/config.toml': value }), value);
});

test('mutated SARIF either imports or fails with a plain error', async () => {
  const { importSarif } = await import('@shieldaai/agent-guard-check');
  const seed = JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 't', rules: [{ id: 'R' }] } },
        results: [
          {
            ruleId: 'R',
            ruleIndex: 0,
            level: 'error',
            message: { text: 'm' },
            locations: [{ physicalLocation: { artifactLocation: { uri: 'a%ZZ.txt' }, region: { startLine: 2 } } }],
          },
        ],
      },
    ],
  });
  const random = prng(7);
  for (let round = 0; round < 300; round += 1) {
    const text = mutate(seed, random);
    try {
      const findings = importSarif(text, 'x.sarif');
      for (const finding of findings) assert.ok(finding.location.line >= 1 && typeof finding.ruleId === 'string');
    } catch (error) {
      assert.ok(!(error instanceof TypeError), `round ${round}: ${error.message}`);
    }
  }
});
