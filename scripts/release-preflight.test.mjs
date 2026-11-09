import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateRelease } from './release-preflight.mjs';

function fixture(t, options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'agent-guard-release-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (path, value) => writeFileSync(join(root, path), JSON.stringify(value));
  mkdirSync(join(root, 'packages', 'core'), { recursive: true });
  mkdirSync(join(root, 'packages', 'adapter'), { recursive: true });
  const version = options.version ?? '0.1.0-alpha.1';
  write('package.json', { private: true, version, workspaces: ['packages/core', 'packages/adapter'] });
  write('packages/core/package.json', { name: '@fixture/core', version: options.coreVersion ?? version });
  write('packages/adapter/package.json', {
    name: '@fixture/adapter',
    version,
    [options.dependencyField ?? 'dependencies']: { '@fixture/core': options.dependencyVersion ?? version },
  });
  if (options.releaseState !== undefined) write('release-state.json', options.releaseState);
  writeFileSync(join(root, '.gitignore'), 'artifacts/\n');
  const git = args => execFileSync('git', args, { cwd: root, stdio: 'pipe' });
  git(['init', '--quiet']);
  git(['add', '.']);
  git([
    '-c',
    'user.name=Release Fixture',
    '-c',
    'user.email=release@example.test',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '--quiet',
    '-m',
    'Release fixture',
  ]);
  return { root, git };
}

test('release accepts a clean aligned checkout and ignored package artifacts', t => {
  const { root } = fixture(t);
  mkdirSync(join(root, 'artifacts'));
  writeFileSync(join(root, 'artifacts', 'fixture.tgz'), 'ignored fixture');
  assert.doesNotThrow(() => validateRelease(root));
});

test('release root checks resolve directory aliases without accepting nested directories', t => {
  const { root } = fixture(t);
  const aliases = mkdtempSync(join(tmpdir(), 'agent-guard-release-alias-'));
  t.after(() => rmSync(aliases, { recursive: true, force: true }));
  const kind = process.platform === 'win32' ? 'junction' : 'dir';
  const rootAlias = join(aliases, 'root'),
    nestedAlias = join(aliases, 'nested');
  symlinkSync(root, rootAlias, kind);
  symlinkSync(join(root, 'packages/core'), nestedAlias, kind);
  assert.doesNotThrow(() => validateRelease(rootAlias));
  assert.throws(() => validateRelease(nestedAlias), /repository root/);
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

const approvedState = {
  schemaVersion: 1,
  version: '0.1.0',
  status: 'approved',
  blockers: [],
  evidence: ['docs/releases/0.1.0.md'],
};

test('stable release rejects a missing approval record', t => {
  const { root } = fixture(t, { version: '0.1.0' });
  assert.throws(() => validateRelease(root), /Stable release is blocked/);
});

for (const [name, releaseState] of [
  ['unresolved hold', { ...approvedState, status: 'blocked', blockers: ['Node security review pending'] }],
  ['different version', { ...approvedState, version: '0.1.1' }],
  ['approved with blockers', { ...approvedState, blockers: ['Acceptance pending'] }],
  ['invalid status', { ...approvedState, status: true }],
  ['invalid blockers type', { ...approvedState, blockers: '' }],
  ['missing evidence', { ...approvedState, evidence: [] }],
  ['invalid evidence type', { ...approvedState, evidence: 'docs/releases/0.1.0.md' }],
  ['empty evidence reference', { ...approvedState, evidence: [' '] }],
  ['unknown schema', { ...approvedState, schemaVersion: 2 }],
  ['null record', null],
]) {
  test(`stable release rejects ${name}`, t => {
    const { root } = fixture(t, { version: '0.1.0', releaseState });
    assert.throws(() => validateRelease(root), /Stable release is blocked/);
  });
}

test('stable release accepts a committed version-matched approval with evidence and no blockers', t => {
  const { root } = fixture(t, { version: '0.1.0', releaseState: approvedState });
  assert.doesNotThrow(() => validateRelease(root));
});
