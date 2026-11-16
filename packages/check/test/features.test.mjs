import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  formatInventory,
  formatSarif,
  importSarif,
  MemorySource,
  parseConfig,
  planFixes,
  formatDiff,
  runCli,
  scan,
} from '@shieldaai/agent-guard-check';
import { findingsFor, json, mcp, ruleIds, scanFiles, settings } from './helpers.mjs';

function repo(t, files) {
  const dir = mkdtempSync(join(tmpdir(), 'agc-feat-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
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

const agentWorkflow = (extraWith = '', stepExtra = '') =>
  [
    'on:',
    '  schedule:',
    "    - cron: '0 3 * * *'",
    'permissions:',
    '  contents: read',
    'jobs:',
    '  agent:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: anthropics/claude-code-action@v1',
    ...(stepExtra ? [stepExtra] : []),
    '        with:',
    '          prompt: tidy the docs',
    ...(extraWith ? [extraWith] : []),
    '',
  ].join('\n');

// ---- policy as code ----

test('POL-001: servers off the allowlist are flagged by name, catalog ID, package or image', () => {
  const files = {
    '.mcp.json': mcp({
      gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.0.0'] },
      pg: { command: 'docker', args: ['run', '-i', 'mcp/postgres:1.2'] },
      notes: { command: 'npx', args: ['-y', 'notes-mcp@2.0.0'] },
    }),
  };
  const config = parseConfig('policy:\n  allowed_mcp_servers: [github, mcp/postgres]\n');
  const findings = findingsFor(scanFiles(files, { config }), 'AGC-POL-001');
  assert.deepEqual(
    findings.map(finding => finding.message.split('"')[1]),
    ['notes'],
  );
  assert.deepEqual(findingsFor(scanFiles(files), 'AGC-POL-001'), [], 'no policy, no finding');
});

test('POL-002: remote hosts must be on the allowlist; a bare domain covers subdomains', () => {
  const files = {
    '.mcp.json': mcp({
      a: { type: 'http', url: 'https://mcp.example.com/mcp' },
      b: { type: 'http', url: 'https://tools.evil.test/mcp' },
    }),
  };
  const config = parseConfig('policy:\n  allowed_mcp_hosts: [example.com]\n');
  const findings = findingsFor(scanFiles(files, { config }), 'AGC-POL-002');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /tools\.evil\.test/);
});

test('POL-003: a forbidden combination uses the configured severity and only certain grants', () => {
  const files = { '.claude/settings.json': settings({ allow: ['WebFetch', 'Bash(git push:*)'] }) };
  const config = parseConfig(
    [
      'policy:',
      '  forbid:',
      '    - name: untrusted input with unasked writes',
      '      severity: critical',
      '      when: { untrustedInput: auto, egress: auto }',
      '    - name: never matches',
      '      when: { spend: any }',
    ].join('\n'),
  );
  const findings = findingsFor(scanFiles(files, { config }), 'AGC-POL-003');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.match(findings[0].message, /"untrusted input with unasked writes"/);
});

test('policy config errors are precise', () => {
  assert.throws(
    () => parseConfig('policy:\n  forbid:\n    - name: x\n      when: { telepathy: auto }\n'),
    /unknown capability "telepathy"/,
  );
  assert.throws(() => parseConfig('policy:\n  allowed_mcp_server: [x]\n'), /unknown key "policy\.allowed_mcp_server"/);
  assert.throws(() => parseConfig('agent_map:\n  url: http://map.example\n'), /https/);
  assert.throws(
    () => parseConfig('agent_map:\n  url: https://map.example\n  token: abc\n'),
    /never put an Agent Map token/,
  );
  assert.throws(() => parseConfig('agent_guard:\n  max_calls: -1\n'), /positive number/);
  assert.equal(parseConfig('agent_map:\n  url: http://localhost:4000/\n').agentMap.url, 'http://localhost:4000');
});

// ---- fixes ----

test('fixes move risky allow rules to ask and drop bypass mode, verified by a rescan', () => {
  const files = {
    '.claude/settings.json': settings({
      defaultMode: 'bypassPermissions',
      allow: ['Bash(curl:*)', 'Bash(npm test:*)', 'Edit(.claude/settings.json)'],
    }),
  };
  const source = new MemorySource(files);
  const result = scan({ root: '/repo', source });
  const plan = planFixes(result, source, overlay => scan({ root: '/repo', source: overlay }));
  assert.equal(plan.edits.length, 1);
  const after = JSON.parse(plan.edits[0].after);
  assert.equal(after.permissions.defaultMode, 'default');
  assert.deepEqual(after.permissions.allow, ['Bash(npm test:*)']);
  assert.deepEqual(after.permissions.ask, ['Bash(curl:*)', 'Edit(.claude/settings.json)']);
  const rescanned = scan({ root: '/repo', source: new MemorySource({ '.claude/settings.json': plan.edits[0].after }) });
  for (const id of ['AGC-PERM-001', 'AGC-PERM-003', 'AGC-PER-002']) assert.ok(!ruleIds(rescanned).includes(id), id);
  const diff = formatDiff(plan.edits[0]);
  assert.match(diff, /^--- a\/\.claude\/settings\.json\n\+\+\+ b\/\.claude\/settings\.json\n@@ /);
  assert.match(diff, /\n-\s+"defaultMode": "bypassPermissions"/);
});

test('fixes skip JSON with comments instead of dropping them', () => {
  const text = '{\n  // team rule\n  "permissions": { "defaultMode": "bypassPermissions" }\n}\n';
  const source = new MemorySource({ '.claude/settings.json': text });
  const plan = planFixes(scan({ root: '/repo', source }), source, overlay => scan({ root: '/repo', source: overlay }));
  assert.deepEqual(plan.edits, []);
  assert.match(plan.skipped[0].reason, /comments/);
});

test('workflow fixes add a step timeout and a turn limit, and the YAML stays valid', () => {
  const files = { '.github/workflows/agent.yml': agentWorkflow() };
  const source = new MemorySource(files);
  const result = scan({ root: '/repo', source });
  assert.ok(ruleIds(result).includes('AGC-LIM-001') && ruleIds(result).includes('AGC-LIM-002'));
  const plan = planFixes(result, source, overlay => scan({ root: '/repo', source: overlay }));
  const after = plan.edits[0].after;
  const step = parseYaml(after).jobs.agent.steps[0];
  assert.equal(step['timeout-minutes'], 30);
  assert.equal(step.with['claude_args'], '--max-turns 30');
  assert.deepEqual(plan.edits[0].fixed.map(item => item.ruleId).sort(), ['AGC-LIM-001', 'AGC-LIM-002']);
});

test('the turn-limit fix appends to an existing single-line claude_args', () => {
  const files = { '.github/workflows/agent.yml': agentWorkflow('          claude_args: "--model sonnet"') };
  const source = new MemorySource(files);
  const plan = planFixes(scan({ root: '/repo', source }), source, overlay => scan({ root: '/repo', source: overlay }));
  const step = parseYaml(plan.edits[0].after).jobs.agent.steps[0];
  assert.equal(step.with['claude_args'], '--model sonnet --max-turns 30');
});

test('--fix-dry-run prints a diff and writes nothing; --fix writes and rescans', async t => {
  const original = settings({ defaultMode: 'bypassPermissions' });
  const dir = repo(t, { '.claude/settings.json': original, CODEOWNERS: '* @org/team\n' });
  const dry = await run(['.', '--fix-dry-run'], dir);
  assert.equal(dry.code, 0);
  assert.match(dry.stdout, /\+\s+"defaultMode": "default"/);
  assert.equal(readFileSync(join(dir, '.claude/settings.json'), 'utf8'), original);
  const fixed = await run(['.', '--fix'], dir);
  assert.match(fixed.stderr, /fixed: AGC-PERM-001 \.claude\/settings\.json/);
  assert.equal(fixed.code, 0);
  assert.equal(JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8')).permissions.defaultMode, 'default');
  assert.equal((await run(['.', '--fix', '--base', 'HEAD'], dir)).code, 2);
});

// ---- inventory and SARIF import ----

test('the inventory lists agents, capabilities and counts without finding text', () => {
  const result = scanFiles({ '.claude/settings.json': settings({ allow: ['WebFetch', 'Bash(git push:*)'] }) });
  const inventory = JSON.parse(formatInventory(result));
  assert.equal(inventory.kind, 'agent-guard-check-inventory');
  assert.equal(inventory.agents.length, 1);
  const [agent] = inventory.agents;
  assert.equal(agent.capabilities.untrustedInput.level, 'yes, no approval');
  assert.ok(agent.capabilities.egress.via.includes('WebFetch'));
  assert.ok(!JSON.stringify(inventory).includes('"message"'));
  assert.equal(JSON.stringify(inventory), JSON.stringify(JSON.parse(formatInventory(result))), 'deterministic');
});

const otherSarif = json({
  version: '2.1.0',
  runs: [
    {
      tool: { driver: { name: 'mcp-scan', rules: [{ id: 'TP-1', shortDescription: { text: 'Tool poisoning' } }] } },
      results: [
        {
          ruleId: 'TP-1',
          ruleIndex: 0,
          level: 'error',
          message: { text: 'Tool description hides an instruction‮' },
          locations: [{ physicalLocation: { artifactLocation: { uri: '.mcp.json' }, region: { startLine: 3 } } }],
        },
        { ruleId: 'TP-1', level: 'warning', message: { text: 'suppressed' }, suppressions: [{ kind: 'inSource' }] },
        { ruleId: 'X', message: { text: 'scored' }, properties: { 'security-severity': '9.1' } },
      ],
    },
  ],
});

test('imported SARIF findings keep their tool, are cleaned and get stable fingerprints', () => {
  const findings = importSarif(otherSarif, 'other.sarif');
  assert.equal(findings.length, 2);
  assert.equal(findings[0].ruleId, 'mcp-scan/TP-1');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].message, 'Tool description hides an instruction');
  assert.deepEqual(findings[0].location, { file: '.mcp.json', line: 3 });
  assert.equal(findings[1].severity, 'critical');
  assert.equal(findings[0].fingerprint, importSarif(otherSarif, 'again').at(0).fingerprint);
  assert.throws(() => importSarif('{"version":"2.0.0","runs":[]}', 'old.sarif'), /not a SARIF 2\.1\.0 log/);
});

test('imported findings get their own SARIF run with valid rule indexes', () => {
  const result = scan({ root: '/repo', source: new MemorySource({}), imported: importSarif(otherSarif, 'x') });
  const sarif = JSON.parse(formatSarif(result));
  assert.equal(sarif.runs.length, 2);
  assert.equal(sarif.runs[1].tool.driver.name, 'mcp-scan');
  for (const run of sarif.runs)
    for (const item of run.results) assert.equal(run.tool.driver.rules[item.ruleIndex].id, item.ruleId);
});

test('CLI: --import-sarif gates the run and baselines cover imported findings', async t => {
  const dir = repo(t, { 'other.sarif': otherSarif, CODEOWNERS: '* @org/team\n' });
  assert.equal((await run(['.', '--import-sarif', 'other.sarif'], dir)).code, 1);
  assert.equal((await run(['.', '--import-sarif', 'other.sarif', '--write-baseline', 'b.json'], dir)).code, 0);
  assert.equal((await run(['.', '--import-sarif', 'other.sarif', '--baseline', 'b.json'], dir)).code, 0);
  const bad = await run(['.', '--import-sarif', 'missing.sarif'], dir);
  assert.equal(bad.code, 2);
});

// ---- CLI evidence flags ----

test('CLI: --agent-guard reads a record from outside the repository', async t => {
  const outside = repo(t, {
    'guard.json': json({
      kind: 'agent-guard-description',
      schemaVersion: 1,
      untrustedContextDefault: 'allow',
      tools: [
        {
          name: 'shell.run',
          fingerprint: 'sha256:x',
          revision: 1,
          approved: false,
          requiresApproval: false,
          controlPlane: false,
          maxCost: 0,
          readsUntrusted: null,
          untrustedContext: null,
          sendsExternal: null,
        },
      ],
    }),
  });
  const dir = repo(t, { CODEOWNERS: '* @org/team\n' });
  const result = await run(
    ['.', '--agent-guard', join(outside, 'guard.json'), '--format', 'json', '--fail-on', 'none'],
    dir,
  );
  assert.equal(result.code, 0, result.stderr);
  const body = JSON.parse(result.stdout);
  assert.equal(body.modes.agentGuard[0].kind, 'description');
  assert.ok(body.findings.some(finding => finding.ruleId === 'AGC-AGX-005'));
});

test('CLI: live evidence needs a token, https, and never leaks the token', async t => {
  const dir = repo(t, { CODEOWNERS: '* @org/team\n' });
  assert.match((await run(['.', '--live'], dir)).stderr, /agent_map\.url/);
  assert.match((await run(['.', '--agent-map-url', 'https://map.example'], dir)).stderr, /AGENT_MAP_TOKEN/);
  assert.match(
    (await run(['.', '--agent-map-url', 'http://map.example'], dir, { env: { AGENT_MAP_TOKEN: 't' } })).stderr,
    /https/,
  );
  assert.match(
    (await run(['.', '--agent-map-url', 'https://u:p@map.example'], dir, { env: { AGENT_MAP_TOKEN: 't' } })).stderr,
    /never in the URL/,
  );
  const secret = 'agm_secret_value_123';
  const denied = await run(['.', '--agent-map-url', 'https://map.example'], dir, {
    env: { AGENT_MAP_TOKEN: secret },
    fetch: async () => new Response(JSON.stringify({ error: `MAP_UNAUTHENTICATED ${secret}` }), { status: 401 }),
  });
  assert.equal(denied.code, 2);
  assert.ok(!denied.stderr.includes(secret));
  const answers = {
    get_inventory_health: {
      sources: [
        {
          id: 's',
          sourceId: 'prod',
          stale: false,
          undeclaredActivity: { status: 'complete', tasks: 2, principals: 1 },
        },
      ],
    },
    list_unclaimed_identities: { status: 'complete', total: 0, identities: [] },
    list_agents: { agents: [] },
  };
  const live = await run(['.', '--agent-map-url', 'https://map.example', '--format', 'json'], dir, {
    env: { AGENT_MAP_TOKEN: 't' },
    fetch: async (_url, init) => new Response(JSON.stringify({ data: answers[JSON.parse(init.body).operation] })),
  });
  assert.equal(live.code, 1);
  const body = JSON.parse(live.stdout);
  assert.equal(body.modes.live.url, 'https://map.example');
  assert.deepEqual(
    body.findings.map(finding => finding.ruleId),
    ['AGC-DRF-001'],
  );
});

test('CLI: --list-rules prints every rule', async () => {
  const listed = await run(['--list-rules'], process.cwd());
  assert.equal(listed.code, 0);
  for (const id of ['AGC-PERM-001', 'AGC-AGX-003', 'AGC-DRF-001', 'AGC-POL-003'])
    assert.match(listed.stdout, new RegExp(id));
});
