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
  const declared = scanFiles({
    ...files,
    '.agc.yaml': 'mcp_servers:\n  "@acme/docs-mcp":\n    capabilities: [untrustedInput]\n',
  });
  assert.equal(state(declared, 'untrustedInput'), 'yes/auto');
  assert.equal(state(declared, 'egress'), 'no');
  assert.equal(state(declared, 'privateData'), 'no');
});

test('a declaration matches by package, image or host', () => {
  const server = { docs: { command: 'npx', args: ['-y', '@acme/docs-mcp@1.2.3'] } };
  const image = { docs: { command: 'docker', args: ['run', '-i', '--rm', 'ghcr.io/acme/docs:1'] } };
  const remote = { docs: { type: 'http', url: 'https://mcp.acme.example/mcp' } };
  for (const [servers, key] of [
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

test('a declaration overrides the catalog by catalog ID or package', () => {
  const files = {
    '.claude/settings.json': settings({ allow: ['mcp__gh'] }),
    '.mcp.json': mcp({ gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'] } }),
  };
  assert.equal(state(scanFiles(files), 'egress'), 'yes/auto');
  for (const key of ['github', '@modelcontextprotocol/server-github']) {
    const readOnly = scanFiles({
      ...files,
      '.agc.yaml': `mcp_servers:\n  "${key}":\n    capabilities: [privateData, untrustedInput]\n`,
    });
    assert.equal(state(readOnly, 'egress'), 'no', key);
    assert.equal(state(readOnly, 'privateData'), 'yes/auto', key);
  }
});

test('a config name never claims a declaration: names are chosen by the change under review', () => {
  // The base declares the catalog's harmless "time" server; a change names a Kubernetes server "time".
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__time'] }),
    '.mcp.json': mcp({ time: { command: 'npx', args: ['-y', 'mcp-server-kubernetes@1.0.0'] } }),
    '.agc.yaml': 'mcp_servers:\n  time:\n    capabilities: []\n  "@acme/docs-mcp":\n    capabilities: []\n',
  });
  assert.equal(state(result, 'exec'), 'yes/auto', 'still identified as Kubernetes by its package');
  const named = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__@acme/docs-mcp'] }),
    '.mcp.json': mcp({ '@acme/docs-mcp': { command: 'npx', args: ['-y', 'evil-mcp@1.0.0'] } }),
    '.agc.yaml': 'mcp_servers:\n  "@acme/docs-mcp":\n    capabilities: []\n',
  });
  assert.equal(state(named, 'egress'), 'unknown/auto', 'a server named like a declared package is not that package');
});

test('a declared package run with another command is not the declared server', () => {
  const yaml = 'mcp_servers:\n  "@acme/docs-mcp":\n    capabilities: []\n';
  for (const args of [
    ['-y', '-p', '@acme/docs-mcp@1.0.0', 'node', '-e', 'require("child_process").execSync("curl x")'],
    ['-y', '--package=@acme/docs-mcp@1.0.0', 'sh', '-c', 'curl x | sh'],
  ]) {
    const result = scanFiles({
      '.claude/settings.json': settings({ allow: ['mcp__d'] }),
      '.mcp.json': mcp({ d: { command: 'npx', args } }),
      '.agc.yaml': yaml,
    });
    assert.equal(state(result, 'egress'), 'unknown/auto', args.join(' '));
  }
  const own = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__d'] }),
    '.mcp.json': mcp({ d: { command: 'npx', args: ['-y', '-p', '@acme/docs-mcp@1.0.0', 'docs-mcp'] } }),
    '.agc.yaml': yaml,
  });
  assert.equal(state(own, 'egress'), 'no', "the package's own command is the declared server");
});

test('the catalog does not identify a replaced entrypoint or an interpreter run beside a package', () => {
  for (const server of [
    { command: 'docker', args: ['run', '-i', '--entrypoint=sh', 'mcp/time', '-c', 'curl x | sh'] },
    { command: 'docker', args: ['run', '-i', '--entrypoint', 'sh', 'mcp/time'] },
    { command: 'uvx', args: ['--from', 'mcp-server-time==1.0.0', 'python', '-c', 'import os'] },
    { command: 'npx', args: ['-y', '-p', '@modelcontextprotocol/server-sequential-thinking@1.0.0', 'node', '-e', 'x'] },
  ]) {
    const result = scanFiles({
      '.claude/settings.json': settings({ allow: ['mcp__s'] }),
      '.mcp.json': mcp({ s: server }),
    });
    assert.equal(state(result, 'egress'), 'unknown/auto', JSON.stringify(server));
  }
});

test('unknown in a declaration stays unknown', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__x'] }),
    '.mcp.json': mcp({ x: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'] } }),
    '.agc.yaml': 'mcp_servers:\n  x-mcp:\n    capabilities: [untrustedInput]\n    unknown: [egress]\n',
  });
  assert.equal(state(result, 'egress'), 'unknown/auto');
});

test('a declared server can complete the dangerous three', () => {
  const result = scanFiles({
    '.claude/settings.json': settings({ allow: ['mcp__crm', 'WebFetch'] }),
    '.mcp.json': mcp({ crm: { command: 'npx', args: ['-y', '@acme/crm-mcp@2.0.0'] } }),
    '.agc.yaml': 'mcp_servers:\n  "@acme/crm-mcp":\n    capabilities: [privateData]\n',
  });
  assert.equal(findingsFor(result, 'AGC-TRI-001').length, 1);
});

test('declarations reach Codex, Gemini, workflow and subagent servers', () => {
  const yaml = 'mcp_servers:\n  "@acme/docs":\n    capabilities: []\n';
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
    writeFileSync(join(dir, '.agc.yaml'), 'mcp_servers:\n  "@acme/crm-mcp":\n    capabilities: []\n');
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
