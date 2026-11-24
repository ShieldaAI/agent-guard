import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { parseRange, satisfies } from '../dist/semver.js';

const VERSIONS = [];
for (const major of [0, 1, 2])
  for (const minor of [0, 1, 2, 3])
    for (const patch of [0, 1, 5])
      for (const pre of ['', '-0', '-beta.1', '-rc.2', '-alpha']) VERSIONS.push(`${major}.${minor}.${patch}${pre}`);
VERSIONS.push('1.2.3+build.5', 'v1.2.3', '1.2', 'x', '01.2.3');
const RANGES = [
  '*',
  '',
  'x',
  '1',
  '1.x',
  '1.2',
  '1.2.x',
  '1.2.3',
  '=1.2.3',
  'v1.2.3',
  '1.2.3+build',
  '^1.2.3',
  '^0.2.3',
  '^0.0.3',
  '^1.2',
  '^0.2',
  '^0',
  '^1.2.3-beta.1',
  '^0.0.3-beta',
  '^ 1.2.3',
  '~1.2.3',
  '~1.2',
  '~1',
  '~0.2.3-beta.1',
  '~>1.2',
  '~ 1.2.3',
  '>1.2.3',
  '>=1.2.3',
  '<1.2.3',
  '<=1.2.3',
  '>1.2',
  '<1.2',
  '>=1',
  '<=1.2',
  '> 1.2.3',
  '>=1.2.3-0',
  '<2.0.0-0',
  '^2.0.0-0',
  '>=1.2.3-beta.1 <1.2.4',
  '1.2.3 - 2.1.0',
  '1.2 - 2',
  '1.2.3 - 2.x',
  '1.2.3-beta.1 - 1.2.3',
  '>=1.0.0 <2.0.0',
  '>=0.1.0 <0.3.0 || ^2',
  '1.x || >=2.5.0 || 1.2.7 - 1.3.4',
  '>= 1.2.0 < 1.3.0',
  '^1.2.3 || ~0.1.5',
  '1.2.3-beta.1',
  'latest',
  'next',
  'not-a-range',
  '1.2.3.4',
  '>>1',
  '^^1',
  '1 2',
];

test('satisfies agrees with npm’s own node-semver', t => {
  const root = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout?.trim();
  const file = root && join(root, 'npm', 'node_modules', 'semver', 'index.js');
  if (!file || !existsSync(file)) return t.skip('npm’s semver not found');
  const semver = createRequire(import.meta.url)(file);
  const wrong = [];
  let checked = 0;
  for (const version of VERSIONS)
    for (const range of RANGES) {
      checked += 1;
      const want = semver.satisfies(version, range);
      if (satisfies(version, range) !== want) wrong.push(`${version} ${JSON.stringify(range)}: semver says ${want}`);
    }
  assert.deepEqual(wrong, []);
  assert.ok(checked > 10_000, `${checked} pairs`);
  // A tag is not a range; a range is one.
  for (const range of RANGES) assert.equal(parseRange(range) !== undefined, semver.validRange(range) !== null, range);
});

test('satisfies: cases written out', () => {
  assert.equal(satisfies('1.2.3', '^1.0.0'), true);
  assert.equal(satisfies('2.0.0', '^1.0.0'), false);
  assert.equal(satisfies('1.3.0-beta.1', '^1.2.0'), false, 'a prerelease needs a comparator of its own version');
  assert.equal(satisfies('1.2.3-beta.2', '^1.2.3-beta.1'), true);
  assert.equal(satisfies('0.2.5', '^0.2.3'), true);
  assert.equal(satisfies('0.3.0', '^0.2.3'), false);
  assert.equal(satisfies('1.2.9', '~1.2.3'), true);
  assert.equal(satisfies('1.3.0', '~1.2.3'), false);
  assert.equal(satisfies('1.5.0', '1.2.3 - 2.1.0'), true);
  assert.equal(satisfies('2.1.1', '1.2.3 - 2.1.0'), false);
  assert.equal(satisfies('1.2.3', 'latest'), false);
  assert.equal(satisfies('not-a-version', '*'), false);
});
