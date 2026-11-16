import test from 'node:test';
import assert from 'node:assert/strict';
import { authority } from '@shieldaai/agent-guard-check';
import { findingsFor, json, ruleIds, scanFiles, settings } from './helpers.mjs';

const agentOf = (result, kind) => result.agents.find(agent => agent.kind === kind);

// ---- Codex ----

test('Codex: the default sandbox writes the workspace without network; no findings by itself', () => {
  const result = scanFiles({ '.codex/config.toml': 'model = "gpt-5-codex"\n' });
  const codex = agentOf(result, 'codex');
  assert.equal(codex.name, 'Codex (project)');
  const a = authority(codex);
  assert.equal(a.write.approval, 'auto');
  assert.equal(a.egress.approval, 'ask', 'escalation outside the sandbox needs approval');
  assert.ok(!ruleIds(result).some(id => id.startsWith('AGC-PERM') || id.startsWith('AGC-TRI')));
});

test('Codex: never + danger-full-access is a bypass, also in a profile', () => {
  const toml = [
    'approval_policy = "never"',
    'sandbox_mode = "danger-full-access"',
    '',
    '[profiles.safe]',
    'approval_policy = "on-request"',
    'sandbox_mode = "read-only"',
    '',
    '[profiles.ci]',
    'approval_policy = "never"',
    '',
  ].join('\n');
  const findings = findingsFor(scanFiles({ '.codex/config.toml': toml }), 'AGC-PERM-001');
  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map(finding => finding.location.line).sort(), [2, 8]);
  assert.match(findings.find(finding => finding.location.line === 8).message, /profile "ci"/);
});

test('Codex: network access plus web search plus a private-data server is a trifecta', () => {
  const toml = [
    'approval_policy = "on-request"',
    'web_search = "live"',
    '[sandbox_workspace_write]',
    'network_access = true',
    '',
    '[mcp_servers.db]',
    'command = "npx"',
    'args = ["-y", "@modelcontextprotocol/server-postgres@0.6.2", "postgresql://localhost/app"]',
    '',
  ].join('\n');
  const result = scanFiles({ '.codex/config.toml': toml });
  const [trifecta] = findingsFor(result, 'AGC-TRI-001');
  assert.ok(trifecta, ruleIds(result).join(','));
  const server = result.agents.length && findingsFor(result, 'AGC-SUP-001');
  assert.deepEqual(server, [], 'pinned package');
});

test('Codex: invalid TOML is an error, not a crash', () => {
  const result = scanFiles({ '.codex/config.toml': 'approval_policy = \n' });
  assert.equal(result.errors[0].file, '.codex/config.toml');
});

// ---- Gemini CLI ----

test('Gemini: yolo is a bypass unless disabled', () => {
  const yolo = json({ general: { defaultApprovalMode: 'yolo' } });
  assert.equal(findingsFor(scanFiles({ '.gemini/settings.json': yolo }), 'AGC-PERM-001').length, 1);
  const disabled = json({ general: { defaultApprovalMode: 'yolo' }, security: { disableYoloMode: true } });
  assert.deepEqual(findingsFor(scanFiles({ '.gemini/settings.json': disabled }), 'AGC-PERM-001'), []);
});

test('Gemini: allowed shell commands are judged like Claude allow rules', () => {
  const result = scanFiles({
    '.gemini/settings.json': json({ tools: { allowed: ['run_shell_command(curl)', 'run_shell_command(git status)'] } }),
  });
  const findings = findingsFor(result, 'AGC-PERM-003');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /Bash\(curl\)/);
  assert.equal(findings[0].location.file, '.gemini/settings.json');
  assert.ok(findings[0].location.line > 1);
});

test('Gemini: tools.exclude and tools.core remove built-in tools', () => {
  const excluded = scanFiles({
    '.gemini/settings.json': json({ tools: { exclude: ['run_shell_command', 'web_fetch'] } }),
  });
  const a = authority(agentOf(excluded, 'gemini'));
  assert.equal(a.exec.value, 'no');
  const core = scanFiles({ '.gemini/settings.json': json({ tools: { core: ['read_file', 'google_web_search'] } }) });
  const b = authority(agentOf(core, 'gemini'));
  assert.equal(b.exec.value, 'no');
  assert.equal(b.untrustedInput.value, 'yes');
});

test('Gemini: a trusted MCP server is an unasked allow; mcp.allowed filters servers', () => {
  const files = {
    '.gemini/settings.json': json({
      mcp: { allowed: ['gh'] },
      mcpServers: {
        gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.0.0'], trust: true },
        other: { command: 'npx', args: ['-y', 'other-mcp'] },
      },
    }),
  };
  const result = scanFiles(files);
  assert.equal(findingsFor(result, 'AGC-PERM-002').length, 1);
  assert.deepEqual(findingsFor(result, 'AGC-SUP-001'), [], 'the filtered-out server does not count');
  assert.equal(authority(agentOf(result, 'gemini')).egress.approval, 'auto');
});

// ---- Claude Code subagents and plugins ----

const subagent = frontmatter => `---\n${frontmatter}\n---\nDo the work.\n`;

test('PERM-006: a subagent with bypassPermissions runs its tools unasked', () => {
  const files = {
    '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }),
    '.claude/agents/fixer.md': subagent('name: fixer\ndescription: fixes things\npermissionMode: bypassPermissions'),
  };
  const result = scanFiles(files);
  const [finding] = findingsFor(result, 'AGC-PERM-006');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.location.line, 4);
  const sub = result.agents.find(agent => agent.kind === 'subagent');
  assert.equal(authority(sub).exec.approval, 'auto');
  assert.equal(authority(sub).egress.approval, 'auto');
});

test('PERM-006: acceptEdits is low; disallowedTools removes tools', () => {
  const files = {
    '.claude/settings.json': settings({}),
    '.claude/agents/writer.md': subagent(
      'name: writer\ndescription: writes\npermissionMode: acceptEdits\ndisallowedTools: Bash, WebFetch',
    ),
  };
  const result = scanFiles(files);
  assert.equal(findingsFor(result, 'AGC-PERM-006')[0].severity, 'low');
  const sub = result.agents.find(agent => agent.kind === 'subagent');
  assert.equal(authority(sub).write.approval, 'auto');
  assert.equal(authority(sub).exec.value, 'no');
});

test('subagent inline MCP servers are checked like any other server', () => {
  const files = {
    '.claude/agents/browser.md': subagent(
      'name: browser\ndescription: tests in a browser\nmcpServers:\n  - playwright:\n      command: npx\n      args: ["-y", "@playwright/mcp"]',
    ),
  };
  const result = scanFiles(files);
  const [unpinned] = findingsFor(result, 'AGC-SUP-001');
  assert.ok(unpinned, ruleIds(result).join(','));
  assert.equal(unpinned.location.file, '.claude/agents/browser.md');
});

test('SUP-005: marketplaces and plugins without pins', () => {
  const files = {
    '.claude/settings.json': json({
      extraKnownMarketplaces: {
        floating: { source: { source: 'github', repo: 'org/tools' }, autoUpdate: true },
        tagged: { source: { source: 'github', repo: 'org/pinned', ref: 'v1.2.0' } },
        local: { source: { source: 'directory', path: './plugins' } },
      },
      enabledPlugins: { 'fmt@floating': true },
    }),
    '.claude-plugin/marketplace.json': json({
      name: 'ours',
      plugins: [
        { name: 'inside', source: './plugins/inside' },
        { name: 'branch', source: { source: 'github', repo: 'org/branch' } },
        { name: 'pinned', source: { source: 'github', repo: 'org/pinned', ref: 'v2', sha: 'a'.repeat(40) } },
        { name: 'npmrange', source: { source: 'npm', package: '@org/plugin', version: '^1.0.0' } },
        { name: 'npmexact', source: { source: 'npm', package: '@org/plugin', version: '1.0.0' } },
      ],
    }),
  };
  const findings = findingsFor(scanFiles(files), 'AGC-SUP-005');
  const by = Object.fromEntries(findings.map(finding => [finding.message.split('"')[1], finding.severity]));
  assert.deepEqual(by, { floating: 'high', branch: 'medium', npmrange: 'medium' });
});

// ---- workflows ----

const workflow = ({ on, permissions = 'contents: write', jobExtra = '', withLines = 'prompt: hi' }) =>
  [
    `on: ${on}`,
    'jobs:',
    '  agent:',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 10',
    ...(jobExtra ? [`    ${jobExtra}`] : []),
    '    permissions:',
    `      ${permissions}`,
    '    steps:',
    '      - uses: anthropics/claude-code-action@v1',
    '        with:',
    ...withLines.split('\n').map(line => `          ${line}`),
    '',
  ].join('\n');

test('TRG-002: a scheduled agent with contents: write and no environment', () => {
  const scheduled = scanFiles({ '.github/workflows/a.yml': workflow({ on: 'schedule' }) });
  assert.equal(findingsFor(scheduled, 'AGC-TRG-002').length, 1);
  const reviewed = scanFiles({
    '.github/workflows/a.yml': workflow({ on: 'schedule', jobExtra: 'environment: production' }),
  });
  assert.deepEqual(findingsFor(reviewed, 'AGC-TRG-002'), []);
  const readOnly = scanFiles({ '.github/workflows/a.yml': workflow({ on: 'push', permissions: 'contents: read' }) });
  assert.deepEqual(findingsFor(readOnly, 'AGC-TRG-002'), []);
  const manual = scanFiles({ '.github/workflows/a.yml': workflow({ on: 'workflow_dispatch' }) });
  assert.deepEqual(findingsFor(manual, 'AGC-TRG-002'), []);
});

test('IDN-002: static cloud keys in workflows and MCP servers', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': workflow({
      on: 'workflow_dispatch',
      permissions: 'contents: read',
      withLines: 'prompt: hi\nclaude_args: --max-turns 5\nmcp_config: x',
    }).replace(
      '      - uses: anthropics/claude-code-action@v1',
      '      - uses: anthropics/claude-code-action@v1\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
    ),
    '.mcp.json': json({
      mcpServers: {
        aws: {
          command: 'uvx',
          args: ['awslabs.aws-api-mcp-server==1.0.0'],
          env: { AWS_SECRET_ACCESS_KEY: '${AWS_SECRET_ACCESS_KEY}' },
        },
      },
    }),
  });
  const findings = findingsFor(result, 'AGC-IDN-002');
  assert.equal(findings.length, 2, findings.map(f => f.message).join('\n'));
});

test('GOV-003: model aliases are info; full IDs pass', () => {
  const result = scanFiles({
    '.github/workflows/a.yml': workflow({
      on: 'workflow_dispatch',
      permissions: 'contents: read',
      withLines: 'prompt: hi\nclaude_args: --model sonnet --max-turns 3',
    }),
    '.claude/agents/x.md': subagent('name: x\ndescription: x\ntools: Read\nmodel: claude-sonnet-4-5-20250929'),
    '.gemini/settings.json': json({ model: { name: 'gemini-flash-latest' } }),
  });
  const findings = findingsFor(result, 'AGC-GOV-003');
  assert.deepEqual(
    findings.map(finding => finding.severity),
    ['info', 'info'],
  );
  assert.ok(findings.every(finding => !finding.message.includes('20250929')));
});
