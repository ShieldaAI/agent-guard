import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DirectorySource, GitSource, isCandidate, scan } from '@shieldaai/agent-guard-check';
import { scanFiles, settings } from './helpers.mjs';

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), 'agc-safe-'));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}

test('scanning never runs hooks, scripts or MCP servers', t => {
  const markerDir = mkdtempSync(join(tmpdir(), 'agc-marker-'));
  t.after(() => rmSync(markerDir, { recursive: true, force: true }));
  const marker = join(markerDir, 'ran');
  const dir = repo({
    '.claude/settings.json': settings(
      {},
      { hooks: { SessionStart: [{ hooks: [{ type: 'command', command: `touch ${marker}` }] }] } },
    ),
    '.mcp.json': JSON.stringify({ mcpServers: { s: { command: 'sh', args: ['-c', `touch ${marker}`] } } }),
    '.claude/skills/x/run.sh': `#!/bin/sh\ntouch ${marker}\n`,
  });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  scan({ root: dir });
  assert.equal(existsSync(marker), false);
});

test('only agent configuration paths are read', () => {
  for (const path of [
    '.claude/settings.json',
    'apps/x/.mcp.json',
    '.vscode/mcp.json',
    '.claude/agents/a.md',
    '.claude/skills/s/SKILL.md',
    'AGENTS.md',
    '.github/workflows/ci.yml',
    '.github/CODEOWNERS',
  ])
    assert.ok(isCandidate(path), path);
  for (const path of [
    'src/index.ts',
    '.env',
    '.claude/notes.txt',
    'docs/workflows/a.yml',
    '.github/workflows/sub/a.yml',
    'mcp.json',
    'sub/package.json',
  ])
    assert.ok(!isCandidate(path), path);
});

test('node_modules, symbolic links and oversized files are skipped', t => {
  const dir = repo({
    'node_modules/pkg/.mcp.json': '{"mcpServers":{"x":{"command":"npx","args":["y"]}}}',
    'outside/.mcp.json': '{}',
    'CLAUDE.md': `${'a'.repeat(1_100_000)}`,
  });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  try {
    symlinkSync(join(dir, 'outside'), join(dir, 'linked'), 'dir');
  } catch (error) {
    if (error.code !== 'EPERM') throw error; // Windows without symlink privilege: the rest still applies.
  }
  const source = new DirectorySource(dir);
  assert.deepEqual(source.list(), ['outside/.mcp.json']);
  assert.equal(source.skipped, 1);
});

test('malformed files are reported, not thrown', () => {
  const result = scanFiles({
    '.claude/settings.json': '{ "permissions": ',
    '.mcp.json': '[1, 2',
    '.github/workflows/a.yml': 'on: [push\njobs: {',
    'CLAUDE.md': 'fine',
  });
  assert.equal(result.errors.length, 3);
  assert.ok(result.errors.every(error => typeof error.message === 'string'));
});

test('YAML alias bombs are bounded', () => {
  const bomb = ['a: &a ["x","x","x","x","x","x","x","x","x"]'];
  for (let i = 0; i < 12; i += 1)
    bomb.push(
      `${'b'.repeat(i + 1)}: &${'b'.repeat(i + 1)} [${Array(9)
        .fill(`*${i === 0 ? 'a' : 'b'.repeat(i)}`)
        .join(',')}]`,
    );
  bomb.push('on: push', 'jobs: {}');
  const started = Date.now();
  const result = scanFiles({ '.github/workflows/bomb.yml': bomb.join('\n') });
  assert.ok(Date.now() - started < 2000);
  assert.equal(result.errors.length, 1);
});

test('long hostile lines do not slow the text rules down', () => {
  const started = Date.now();
  scanFiles({
    'CLAUDE.md': `curl ${'a'.repeat(200_000)}\n${'ignore '.repeat(50_000)}\n${'A'.repeat(300_000)}`,
    '.claude/settings.json': settings({ allow: [`Bash(${'x'.repeat(100_000)})`] }),
  });
  assert.ok(Date.now() - started < 3000, `took ${Date.now() - started} ms`);
});

test('git refs that look like options are refused', () => {
  for (const ref of ['--output=x', '-n', 'a..b', 'HEAD;rm', ''])
    assert.throws(() => new GitSource(tmpdir(), ref), /Refusing git ref/, ref);
  assert.doesNotThrow(() => new GitSource(tmpdir(), 'origin/main'));
});

test('Markdown next to workflows is read as instructions, not as a workflow', () => {
  const result = scanFiles({
    '.github/workflows/CLAUDE.md': 'The `format.yml` workflow: runs formatters.\nIt also: regenerates maps',
  });
  assert.deepEqual(result.errors, []);
});

test('named files are read only inside the root, never through a link', async t => {
  const { DirectorySource } = await import('@shieldaai/agent-guard-check');
  const { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const root = mkdtempSync(join(tmpdir(), 'agc-named-'));
  const outside = mkdtempSync(join(tmpdir(), 'agc-named-out-'));
  t.after(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });
  mkdirSync(join(root, 'build'));
  writeFileSync(join(root, 'build/guard.json'), '{"ok":true}');
  writeFileSync(join(outside, 'secret.json'), 'secret');
  const source = new DirectorySource(root);
  assert.equal(source.readNamed('build/guard.json'), '{"ok":true}');
  assert.equal(source.readNamed('./build/guard.json'), '{"ok":true}');
  for (const path of ['../secret.json', '/etc/passwd', 'build', 'build/../build/guard.json', ''])
    assert.equal(source.readNamed(path), undefined, path);
  try {
    symlinkSync(join(outside, 'secret.json'), join(root, 'build/link.json'));
    symlinkSync(outside, join(root, 'out'), 'dir');
  } catch (error) {
    if (error.code === 'EPERM') return; // Windows without symlink rights
    throw error;
  }
  assert.equal(source.readNamed('build/link.json'), undefined);
  assert.equal(source.readNamed('out/secret.json'), undefined);
});
