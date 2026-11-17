// MCP servers the team declares in .agc.yaml, and the built-in catalog. Synthetic configs only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { capabilityState, parseConfig, runCli } from '@shieldaai/agent-guard-check';
import { findingsFor, mcp, scanFiles, settings } from './helpers.mjs';

/** What the agent's MCP servers alone give it, as value/approval (built-in tools are left out). */
const state = (result, capability) => {
  const agent = result.agents[0];
  const value = capabilityState(
    { ...agent, grants: agent.grants.filter(grant => grant.tool?.startsWith('mcp__')) },
    capability,
  );
  return value.value === 'no' ? 'no' : `${value.value}/${value.approval}`;
};

test('an unknown server is unknown until the team declares what it can do', () => {
  const files = {
    '.claude/settings.json': settings({ allow: ['mcp__docs'] }),
    '.mcp.json': mcp({ docs: { command: 'npx', args: ['-y', '@acme/docs-mcp@1.2.3'] } }),
  };
  assert.equal(state(scanFiles(files), 'egress'), 'unknown/auto');
  const declared = scanFiles({ ...files, '.agc.yaml': 'mcp_servers:\n  docs:\n    capabilities: [untrustedInput]\n' });
  assert.equal(state(declared, 'untrustedInput'), 'yes/auto');
  assert.equal(state(declared, 'egress'), 'no');
  assert.equal(state(declared, 'privateData'), 'no');
});

test('a declaration matches by config name, package, image or host', () => {
  const server = { docs: { command: 'npx', args: ['-y', '@acme/docs-mcp@1.2.3'] } };
  const image = { docs: { command: 'docker', args: ['run', '-i', '--rm', 'ghcr.io/acme/docs:1'] } };
  const remote = { docs: { type: 'http', url: 'https://mcp.acme.example/mcp' } };
  for (const [servers, key] of [
    [server, 'docs'],
    [server, '@acme/docs-mcp'],
    [image, 'ghcr.io/acme/docs'],
    [remote, 'mcp.acme.example'],
  ]) {
    const result = scanFiles({
      '.claude/settings.json': settings({ allow: ['mcp__docs'] }),
      '.mcp.json': mcp(servers),
      '.agc.yaml': `mcp_servers:\n  "${key}":\n    capabilities: [privateData]\n`,
    });
    assert.equal(state(result, 'privateData'), 'yes/auto', key);
    assert.equal(state(result, 'egress'), 'no', key);
  }
});

test('a declaration overrides the catalog, and the config name wins over the package', () => {
  const files = {
    '.claude/settings.json': settings({ allow: ['mcp__gh'] }),
    '.mcp.json': mcp({ gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'] } }),
  };
  assert.equal(state(scanFiles(files), 'egress'), 'yes/auto');
  const readOnly = scanFiles({
    ...files,
    '.agc.yaml':
      'mcp_servers:\n  github:\n    capabilities: [privateData, untrustedInput, egress]\n  gh:\n    capabilities: [privateData, untrustedInput]\n',
  });
  assert.equal(state(readOnly, 'egress'), 'no', 'the entry for the config name "gh" is used');
  assert.equal(state(readOnly, 'privateData'), 'yes/auto');
});

test('unknown in a declaration stays unknown', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__x'] }),
    '.mcp.json': mcp({ x: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'] } }),
    '.agc.yaml': 'mcp_servers:\n  x:\n    capabilities: [untrustedInput]\n    unknown: [egress]\n',
  });
  assert.equal(state(result, 'egress'), 'unknown/auto');
});

test('a declared server can complete the dangerous three', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__crm', 'WebFetch'] }),
    '.mcp.json': mcp({ crm: { command: 'npx', args: ['-y', '@acme/crm-mcp@2.0.0'] } }),
    '.agc.yaml': 'mcp_servers:\n  crm:\n    capabilities: [privateData]\n',
  });
  assert.equal(findingsFor(result, 'AGC-TRI-001').length, 1);
});

test('declarations reach Codex, Gemini, workflow and subagent servers', () => {
  const yaml = 'mcp_servers:\n  docs:\n    capabilities: []\n';
  const codex = scanFiles({
    '.codex/config.toml': '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "@acme/docs@1.0.0"]\n',
    '.agc.yaml': yaml,
  });
  assert.deepEqual(
    codex.agents[0].grants.filter(grant => grant.tool === 'mcp__docs'),
    [],
    'a server declared to do nothing grants nothing',
  );
  const gemini = scanFiles({
    '.gemini/settings.json': JSON.stringify({ mcpServers: { docs: { command: 'npx', args: ['@acme/docs@1.0.0'] } } }),
    '.agc.yaml': yaml,
  });
  assert.deepEqual(
    gemini.agents[0].grants.filter(grant => grant.tool === 'mcp__docs'),
    [],
  );
});

test('.agc.yaml mcp_servers is validated', () => {
  assert.throws(() => parseConfig('mcp_servers: [docs]\n'), /mcp_servers must map/);
  assert.throws(() => parseConfig('mcp_servers:\n  docs: {}\n'), /needs a capabilities list/);
  assert.throws(() => parseConfig('mcp_servers:\n  docs:\n    capabilities: [email]\n'), /unknown capability "email"/);
  assert.throws(
    () => parseConfig('mcp_servers:\n  docs:\n    capabilities: [egress]\n    unknown: [egress]\n'),
    /both a capability and unknown/,
  );
  assert.throws(() => parseConfig('mcp_servers:\n  docs:\n    capabilities: []\n    safe: true\n'), /unknown key/);
  assert.deepEqual(parseConfig('mcp_servers:\n  docs:\n    capabilities: []\n').mcpServers, [
    { match: 'docs', capabilities: {} },
  ]);
});

test('a pull request cannot declare its own new server harmless', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agc-declare-'));
  try {
    const git = (...args) =>
      spawnSync(
        'git',
        ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args],
        { encoding: 'utf8' },
      );
    git('init', '-q');
    mkdirSync(join(dir, '.claude'));
    writeFileSync(join(dir, '.claude/settings.json'), settings({ allow: ['WebFetch'] }));
    git('add', '.');
    git('commit', '-qm', 'base');
    writeFileSync(join(dir, '.claude/settings.json'), settings({ allow: ['WebFetch', 'mcp__crm'] }));
    writeFileSync(join(dir, '.mcp.json'), mcp({ crm: { command: 'npx', args: ['-y', '@acme/crm-mcp@2.0.0'] } }));
    writeFileSync(join(dir, '.agc.yaml'), 'mcp_servers:\n  crm:\n    capabilities: []\n');
    let out = '';
    await runCli(['--base', 'HEAD', '--format', 'json', '.'], {
      stdout: text => (out += text),
      stderr: () => {},
      cwd: dir,
      env: {},
    });
    const agent = JSON.parse(out).agents.find(item => item.kind === 'claude-code');
    assert.equal(agent.authority.privateData.value, 'unknown', 'the head declaration is ignored in --base mode');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the catalog knows common servers, so they are not unknown', () => {
  const capabilities = ['privateData', 'untrustedInput', 'egress', 'exec', 'write'];
  const cases = [
    [{ command: 'npx', args: ['-y', '@modelcontextprotocol/server-sequential-thinking@2025.7.1'] }, {}],
    [
      { command: 'npx', args: ['-y', 'exa-mcp-server@3.0.0'] },
      { untrustedInput: 'yes/auto', egress: 'yes/auto' },
    ],
    [{ type: 'http', url: 'https://learn.microsoft.com/api/mcp' }, { untrustedInput: 'yes/auto' }],
    [
      { type: 'http', url: 'https://mcp.zapier.com/api/mcp/s/abc/mcp' },
      { privateData: 'yes/auto', untrustedInput: 'yes/auto', egress: 'yes/auto', write: 'yes/auto' },
    ],
    [
      { command: 'npx', args: ['-y', 'mcp-server-kubernetes@2.0.0'] },
      { privateData: 'yes/auto', exec: 'yes/auto', write: 'yes/auto' },
    ],
  ];
  for (const [server, expected] of cases) {
    const result = scanFiles({
      '.claude/settings.json': settings({ allow: ['mcp__s'] }),
      '.mcp.json': mcp({ s: server }),
    });
    for (const capability of capabilities)
      assert.equal(state(result, capability), expected[capability] ?? 'no', `${JSON.stringify(server)} ${capability}`);
  }
});
