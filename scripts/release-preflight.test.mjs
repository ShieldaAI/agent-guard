import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateRelease } from './release-preflight.mjs';

function fixture(t, options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'agent-guard-release-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (path, value) => writeFileSync(join(root, path), JSON.stringify(value));
  mkdirSync(join(root, 'packages', 'core'), { recursive: true });
  mkdirSync(join(root, 'packages', 'adapter'), { recursive: true });
  write('package.json', { private: true, version: '0.1.0-alpha.1', workspaces: ['packages/core', 'packages/adapter'] });
  write('packages/core/package.json', { name: '@fixture/core', version: options.coreVersion ?? '0.1.0-alpha.1' });
  write('packages/adapter/package.json', {
    name: '@fixture/adapter', version: '0.1.0-alpha.1',
    [options.dependencyField ?? 'dependencies']: { '@fixture/core': options.dependencyVersion ?? '0.1.0-alpha.1' },
  });
  writeFileSync(join(root, '.gitignore'), 'artifacts/\n');
  const git = args => execFileSync('git', args, { cwd: root, stdio: 'pipe' });
  git(['init', '--quiet']);
  git(['add', '.']);
  git(['-c', 'user.name=Release Fixture', '-c', 'user.email=release@example.test', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Release fixture']);
  return { root, git };
}

test('release accepts a clean aligned checkout and ignored package artifacts', t => {
  const { root } = fixture(t);
  mkdirSync(join(root, 'artifacts'));
  writeFileSync(join(root, 'artifacts', 'fixture.tgz'), 'ignored fixture');
  assert.doesNotThrow(() => validateRelease(root));
});

test('release rejects tracked modifications and staged changes', t => {
  const { root, git } = fixture(t);
  const path = join(root, 'packages/core/package.json');
  writeFileSync(path, readFileSync(path, 'utf8') + '\n');
  assert.throws(() => validateRelease(root), /checkout must be clean/);
  git(['add', 'packages/core/package.json']);
  assert.throws(() => validateRelease(root), /checkout must be clean/);
});

test('release rejects untracked source files', t => {
  const { root } = fixture(t);
  writeFileSync(join(root, 'uncommitted.mjs'), '// fixture');
  assert.throws(() => validateRelease(root), /checkout must be clean/);
});

test('release rejects committed workspace version drift', t => {
  const { root } = fixture(t, { coreVersion: '0.1.0-alpha.0' });
  assert.throws(() => validateRelease(root), /Release version mismatch/);
});

for (const dependencyField of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies']) {
  test(`release rejects committed internal ${dependencyField} ranges`, t => {
    const { root } = fixture(t, { dependencyField, dependencyVersion: '^0.1.0-alpha.1' });
    assert.throws(() => validateRelease(root), /Release dependency mismatch/);
  });
}

test('release rejects an extracted package or nested directory', t => {
  const { root } = fixture(t);
  assert.throws(() => validateRelease(join(root, 'packages/core')), /repository root/);
  const extracted = mkdtempSync(join(tmpdir(), 'agent-guard-extracted-'));
  t.after(() => rmSync(extracted, { recursive: true, force: true }));
  assert.throws(() => validateRelease(extracted), /complete Git source checkout/);
});
