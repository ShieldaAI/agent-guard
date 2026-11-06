import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs, { closeSync, mkdtempSync, mkdirSync, openSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { resolveInstallationNpmCli, trustedNpmCli } from './trusted-npm.mjs';

function installation(t) {
  const root = mkdtempSync(join(tmpdir(), 'agent-guard-trusted-npm-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const node = join(root, 'node.exe');
  const npm = join(root, 'node_modules', 'npm');
  const cli = join(npm, 'bin', 'npm-cli.js');
  mkdirSync(dirname(cli), { recursive: true });
  writeFileSync(node, 'Node installation fixture; never executed.');
  writeFileSync(cli, 'Npm CLI fixture; never executed.');
  const manifest = data => writeFileSync(join(npm, 'package.json'), JSON.stringify(data));
  manifest({ name: 'npm', bin: { npm: 'bin/npm-cli.js' } });
  return { root, node, npm, cli, manifest };
}

test('trusted npm resolves the ordinary Windows Node installation without executing a .cmd shim', t => {
  const fixture = installation(t);
  writeFileSync(join(fixture.root, 'npm.cmd'), '@echo This shim must not be executed.');
  assert.equal(resolveInstallationNpmCli(fixture.node, 'win32'), realpathSync(fixture.cli));
});

test('trusted npm refuses an arbitrary POSIX sibling wrapper', t => {
  const fixture = installation(t);
  writeFileSync(join(fixture.root, 'npm'), '#!/bin/sh\nexit 0\n');
  assert.throws(() => resolveInstallationNpmCli(fixture.node, 'linux'), /TRUSTED_NPM_NOT_FOUND/);
});

test('trusted npm requires npm package identity and the standard CLI entry point', t => {
  const fixture = installation(t);
  fixture.manifest({ name: 'project-npm', bin: { npm: 'bin/npm-cli.js' } });
  assert.throws(() => resolveInstallationNpmCli(fixture.node, 'win32'), /TRUSTED_NPM_NOT_FOUND/);
  fixture.manifest({ name: 'npm', bin: { npm: '../custom.js' } });
  assert.throws(() => resolveInstallationNpmCli(fixture.node, 'win32'), /TRUSTED_NPM_NOT_FOUND/);
});

test('trusted npm rejects missing files, directory entry points, and oversized manifests', t => {
  const fixture = installation(t);
  writeFileSync(join(fixture.npm, 'package.json'), ' '.repeat(64 * 1024 + 1));
  assert.throws(() => resolveInstallationNpmCli(fixture.node, 'win32'), /TRUSTED_NPM_NOT_FOUND/);
  fixture.manifest({ name: 'npm', bin: { npm: 'bin/npm-cli.js' } });
  rmSync(fixture.cli);
  assert.throws(() => resolveInstallationNpmCli(fixture.node, 'win32'), /TRUSTED_NPM_NOT_FOUND/);
  mkdirSync(fixture.cli);
  assert.throws(() => resolveInstallationNpmCli(fixture.node, 'win32'), /TRUSTED_NPM_NOT_FOUND/);
});

test('trusted npm accepts a complete manifest at the byte limit', t => {
  const fixture = installation(t);
  const json = JSON.stringify({ name: 'npm', bin: { npm: 'bin/npm-cli.js' } });
  writeFileSync(join(fixture.npm, 'package.json'), json.padEnd(64 * 1024));
  assert.equal(resolveInstallationNpmCli(fixture.node, 'win32'), realpathSync(fixture.cli));
});

test('trusted npm bounds descriptor reads when a manifest grows after validation', t => {
  const fixture = installation(t);
  const writer = openSync(join(fixture.npm, 'package.json'), 'a');
  const originalStat = fs.fstatSync;
  const originalRead = fs.readSync;
  let changed = false;
  let bytesRead = 0;
  try {
    t.mock.method(fs, 'fstatSync', fd => {
      const snapshot = originalStat(fd);
      if (!changed) {
        changed = true;
        writeFileSync(writer, ' '.repeat(1024 * 1024));
      }
      return snapshot;
    });
    t.mock.method(fs, 'readSync', (fd, buffer, offset, length, position) => {
      const count = originalRead(fd, buffer, offset, length, position);
      bytesRead += count;
      return count;
    });
    syncBuiltinESMExports();
    assert.throws(() => resolveInstallationNpmCli(fixture.node, 'win32'), /TRUSTED_NPM_NOT_FOUND/);
    assert.equal(changed, true);
    assert.equal(bytesRead, 64 * 1024 + 1);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    closeSync(writer);
  }
});

test('trusted npm runs the current installation when npm_execpath points to unrelated JavaScript', t => {
  const fixture = installation(t);
  const unrelated = join(fixture.root, 'unrelated.mjs');
  writeFileSync(unrelated, 'throw new Error("Environment-selected npm must never run");\n');
  const previous = process.env.npm_execpath;
  try {
    process.env.npm_execpath = unrelated;
    const cli = trustedNpmCli();
    assert.notEqual(cli, unrelated);
    const result = spawnSync(process.execPath, [cli, '--version'], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/);
  } finally {
    if (previous === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = previous;
  }
});
