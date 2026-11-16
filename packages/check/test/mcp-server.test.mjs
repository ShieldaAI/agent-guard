import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { settings } from './helpers.mjs';

const SERVER = fileURLToPath(new URL('../dist/mcp-server.js', import.meta.url));

function repo(t, files) {
  const dir = mkdtempSync(join(tmpdir(), 'agc-mcp-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

/** Starts the server, sends messages one per line, and collects one response per request. */
async function session(root, messages) {
  const child = spawn(process.execPath, [SERVER, root], { stdio: ['pipe', 'pipe', 'pipe'] });
  const expected =
    messages.filter(message => typeof message !== 'string' && message.id !== undefined).length +
    messages.filter(message => typeof message === 'string').length;
  const responses = [];
  let buffer = '';
  const done = new Promise((resolve, reject) => {
    child.stdout.on('data', chunk => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        responses.push(JSON.parse(buffer.slice(0, index)));
        buffer = buffer.slice(index + 1);
        if (responses.length === expected) resolve();
      }
    });
    child.on('error', reject);
    setTimeout(() => reject(new Error(`timeout; got ${JSON.stringify(responses)}`)), 15_000).unref();
  });
  for (const message of messages)
    child.stdin.write(`${typeof message === 'string' ? message : JSON.stringify(message)}\n`);
  await done;
  child.kill();
  return responses;
}

const init = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } },
};
const call = (id, name, args) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

test('MCP: initialize, list tools and scan a repository', async t => {
  const dir = repo(t, { '.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }) });
  const [hello, list, scanned, rule] = await session(dir, [
    init,
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    call(3, 'scan_agent_config', {}),
    call(4, 'explain_agent_rule', { id: 'agc-tri-001' }),
  ]);
  assert.equal(hello.result.protocolVersion, '2025-06-18');
  assert.equal(hello.result.serverInfo.name, 'agent-guard-check-mcp');
  assert.deepEqual(
    list.result.tools.map(tool => tool.name),
    ['scan_agent_config', 'check_agent_config_change', 'explain_agent_rule'],
  );
  assert.ok(list.result.tools.every(tool => tool.annotations.readOnlyHint === true));
  assert.equal(scanned.result.isError, false);
  assert.match(scanned.result.content[0].text, /\[critical\] AGC-PERM-001 at \.claude\/settings\.json:3/);
  assert.match(rule.result.content[0].text, /^AGC-TRI-001: Lethal trifecta/);
});

test('MCP: paths outside the root and symlinks out of it are refused', async t => {
  const outside = repo(t, { '.claude/settings.json': settings({ defaultMode: 'bypassPermissions' }) });
  const dir = repo(t, {});
  let linked = true;
  try {
    symlinkSync(outside, join(dir, 'link'), 'dir');
  } catch {
    linked = false;
  }
  const responses = await session(dir, [
    init,
    call(2, 'scan_agent_config', { path: '../' }),
    call(3, 'scan_agent_config', { path: '/etc' }),
    ...(linked ? [call(4, 'scan_agent_config', { path: 'link' })] : []),
  ]);
  for (const response of responses.slice(1)) {
    assert.equal(response.result.isError, true);
    assert.match(response.result.content[0].text, /inside the server root/);
  }
});

test('MCP: check_agent_config_change reports only what the change widened', async t => {
  const dir = repo(t, { '.claude/settings.json': settings({ allow: ['Bash(npm test:*)'] }) });
  const git = (...args) =>
    spawnSync('git', [
      '-C',
      dir,
      '-c',
      'user.name=t',
      '-c',
      'user.email=t@example.com',
      '-c',
      'commit.gpgsign=false',
      ...args,
    ]);
  git('init', '-q');
  git('add', '-A');
  git('commit', '-qm', 'base');
  writeFileSync(join(dir, '.claude/settings.json'), settings({ allow: ['Bash(npm test:*)', 'Bash(curl:*)'] }));
  const [, change, bad] = await session(dir, [
    init,
    call(2, 'check_agent_config_change', { base: 'HEAD' }),
    call(3, 'check_agent_config_change', { base: '--upload-pack=x' }),
  ]);
  assert.match(change.result.content[0].text, /Authority widened/);
  assert.match(change.result.content[0].text, /AGC-PERM-003/);
  assert.equal(bad.result.isError, true);
});

test('MCP: malformed input gets JSON-RPC errors, and unknown methods are reported', async t => {
  const dir = repo(t, {});
  const [parse, unknown, tool] = await session(dir, [
    '{not json',
    { jsonrpc: '2.0', id: 9, method: 'resources/list' },
    call(10, 'rm_rf', {}),
  ]);
  assert.equal(parse.error.code, -32700);
  assert.equal(unknown.error.code, -32601);
  assert.equal(tool.error.code, -32602);
});
