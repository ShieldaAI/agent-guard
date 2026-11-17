// --include-user: settings outside the repository. A temporary fake home only; never the real one.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authority, managedSettingsPath, readUserConfig, runCli } from '@shieldaai/agent-guard-check';
import { findingsFor, json, mcp, scanFiles, settings } from './helpers.mjs';

const level = (agent, capability) => {
  const state = authority(agent)[capability];
  return state.value === 'no' ? 'no' : `${state.value}/${state.approval}`;
};
const claude = result => result.agents.find(agent => agent.id === 'claude-code:.');

function fakeHome(files) {
  const home = mkdtempSync(join(tmpdir(), 'agc-home-'));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(home, path, '..'), { recursive: true });
    writeFileSync(join(home, path), text);
  }
  return home;
}

test('user allow rules and user-scope servers apply to the project', () => {
  const result = scanFiles(
    { '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }) },
    {
      userFiles: [
        { path: '~/.claude/settings.json', text: settings({ allow: ['WebFetch'] }) },
        {
          path: '~/.claude.json',
          text: mcp({ pg: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2'] } }),
        },
      ],
    },
  );
  const agent = claude(result);
  assert.equal(level(agent, 'egress'), 'yes/auto', 'WebFetch allowed in user settings');
  assert.equal(level(agent, 'privateData'), 'yes/ask', 'the user-scope postgres server');
  assert.equal(result.agents.filter(item => item.kind === 'claude-code').length, 1, 'no agent for ~ itself');
});

test('with only user settings, Claude Code at the root gets them', () => {
  const result = scanFiles(
    {},
    { userFiles: [{ path: '~/.claude/settings.json', text: settings({ allow: ['Bash'] }) }] },
  );
  assert.equal(level(claude(result), 'exec'), 'yes/auto');
  assert.ok(findingsFor(result, 'AGC-PERM-002').some(finding => finding.location.file === '~/.claude/settings.json'));
});

test('the project mode wins over the user mode; managed settings win over both', () => {
  const user = { path: '~/.claude/settings.json', text: settings({ defaultMode: 'bypassPermissions' }) };
  const project = { '.claude/settings.json': settings({ defaultMode: 'default' }) };
  assert.equal(level(claude(scanFiles(project, { userFiles: [user] })), 'exec'), 'yes/ask');
  assert.equal(level(claude(scanFiles({}, { userFiles: [user] })), 'exec'), 'yes/auto');
  const managed = {
    path: '<managed>/managed-settings.json',
    text: settings({ disableBypassPermissionsMode: 'disable', deny: ['WebFetch'] }),
  };
  const locked = claude(scanFiles({}, { userFiles: [user, managed] }));
  assert.equal(level(locked, 'exec'), 'yes/ask', 'managed settings disable bypass mode');
  assert.ok(!locked.grants.some(grant => grant.tool === 'WebFetch'), 'a managed deny applies');
});

test('local-scope servers in ~/.claude.json apply only to the scanned folder', () => {
  const text = json({
    projects: {
      '/repo': { mcpServers: { db: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2'] } } },
      '/elsewhere': { mcpServers: { s: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-slack@1.0.0'] } } },
    },
  });
  const result = scanFiles({}, { userFiles: [{ path: '~/.claude.json', text }] });
  const agent = claude(result);
  assert.ok(agent.grants.some(grant => grant.tool === 'mcp__db'));
  assert.ok(!agent.grants.some(grant => grant.tool === 'mcp__s'));
});

test('user Codex and Gemini settings are their own agents', () => {
  const result = scanFiles(
    {},
    {
      userFiles: [
        { path: '~/.codex/config.toml', text: 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n' },
        { path: '~/.gemini/settings.json', text: json({ general: { defaultApprovalMode: 'yolo' } }) },
      ],
    },
  );
  assert.deepEqual(result.agents.map(agent => agent.name).sort(), ['Codex (~)', 'Gemini CLI (~)']);
  assert.equal(findingsFor(result, 'AGC-PERM-001').length, 2);
});

test('readUserConfig reads only the known files, at most 1 MiB, and reports ~ paths', t => {
  const home = fakeHome({
    '.claude/settings.json': settings({ allow: ['Bash'] }),
    '.codex/config.toml': `model = "x"\n${'#'.repeat(1_100_000)}\n`,
    '.ssh/id_rsa': 'not read',
  });
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const files = readUserConfig(home, 'linux');
  assert.deepEqual(
    files.map(file => file.path),
    ['~/.claude/settings.json'],
    'oversized files and unrelated files are left out',
  );
  assert.equal(managedSettingsPath('darwin'), '/Library/Application Support/ClaudeCode/managed-settings.json');
  assert.equal(managedSettingsPath('linux'), '/etc/claude-code/managed-settings.json');
});

test('--include-user reads the home folder; it is refused in CI and with --fix', async t => {
  const home = fakeHome({ '.claude/settings.json': settings({ allow: ['Bash'] }) });
  const repo = mkdtempSync(join(tmpdir(), 'agc-repo-'));
  t.after(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  });
  const run = async (args, env = {}) => {
    let stdout = '';
    let stderr = '';
    const code = await runCli(args, {
      stdout: text => (stdout += text),
      stderr: text => (stderr += text),
      cwd: repo,
      env,
      home,
    });
    return { code, stdout, stderr };
  };
  const plain = await run(['--format', 'json']);
  assert.equal(JSON.parse(plain.stdout).agents.length, 0, 'without the flag, home is never read');
  const withUser = await run(['--format', 'json', '--include-user']);
  assert.equal(JSON.parse(withUser.stdout).agents[0].id, 'claude-code:.');
  const ci = await run(['--include-user'], { CI: 'true' });
  assert.equal(ci.code, 2);
  assert.match(ci.stderr, /local runs, not CI/);
  const fix = await run(['--include-user', '--fix']);
  assert.equal(fix.code, 2);
});

test('--include-user refuses --write-baseline and warns about a file it cannot read', async t => {
  const home = fakeHome({ '.claude.json': `{"x":"${'a'.repeat(1_100_000)}"}` });
  const repo = mkdtempSync(join(tmpdir(), 'agc-repo-'));
  t.after(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  });
  let stderr = '';
  const io = { stdout: () => {}, stderr: text => (stderr += text), cwd: repo, env: {}, home };
  assert.equal(await runCli(['--include-user', '--write-baseline', 'b.json'], io), 2);
  stderr = '';
  await runCli(['--include-user'], io);
  assert.match(stderr, /~\/\.claude\.json was not read/);
});

test('user-scope servers are judged by the server rules, and managed servers apply', () => {
  const result = scanFiles(
    {},
    {
      userFiles: [
        { path: '~/.claude.json', text: mcp({ k: { command: 'npx', args: ['-y', 'mcp-server-kubernetes'] } }) },
        {
          path: '<managed>/managed-mcp.json',
          text: mcp({ f: { command: 'uvx', args: ['mcp-server-fetch==2025.4.7'] } }),
        },
      ],
    },
  );
  assert.ok(findingsFor(result, 'AGC-SUP-001').some(finding => finding.location.file === '~/.claude.json'));
  assert.ok(claude(result).grants.some(grant => grant.tool === 'mcp__f'));
});

test('a bypass mode from user settings points at the user file', () => {
  const result = scanFiles(
    { '.claude/settings.json': settings({}) },
    { userFiles: [{ path: '~/.claude/settings.json', text: settings({ defaultMode: 'bypassPermissions' }) }] },
  );
  const found = findingsFor(result, 'AGC-COV-001');
  assert.equal(found[0].location.file, '~/.claude/settings.json');
});
