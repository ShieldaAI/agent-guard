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
  '1.0.0 - x',
  '1.0.0 - *',
  'x - 2',
  '* || ^1.0.0-beta',
  '^1.0.0-beta || *',
  '<x',
  '>x',
  '>=x',
  '<=*',
  '<*',
  '~x',
  '^x',
  '1.x.x',
  '1.2.*',
  '>=1.x <2',
  '=1',
  '=1.x',
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
      // A range the reader refuses is never satisfied (the caller then reports the package).
      const want = parseRange(range) === undefined ? false : semver.satisfies(version, range);
      if (satisfies(version, range) !== want) wrong.push(`${version} ${JSON.stringify(range)}: expected ${want}`);
    }
  assert.deepEqual(wrong, []);
  assert.ok(checked > 10_000, `${checked} pairs`);
  // Never a range node-semver refuses, and every range in this list that node-semver reads.
  for (const range of RANGES)
    if (parseRange(range) !== undefined) assert.notEqual(semver.validRange(range), null, range);
  const refused = RANGES.filter(range => parseRange(range) === undefined && semver.validRange(range) !== null);
  // Build metadata in a range is refused on purpose; the caller then reports the package.
  assert.deepEqual(refused, ['1.2.3+build'], 'ranges node-semver reads that this reader refuses');
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

test('satisfies agrees with node-semver on random ranges from the whole grammar', t => {
  const root = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout?.trim();
  const file = root && join(root, 'npm', 'node_modules', 'semver', 'index.js');
  if (!file || !existsSync(file)) return t.skip('npm’s semver not found');
  const semver = createRequire(import.meta.url)(file);
  let seed = 11;
  const random = n => ((seed = (seed * 1103515245 + 12345) % 2 ** 31), seed % n);
  const pick = list => list[random(list.length)];
  const part = () => pick(['0', '1', '2', '3', 'x', 'X', '*', '10']);
  const version = () => {
    const parts = 1 + random(3);
    const text = [part(), part(), part()].slice(0, parts).join('.');
    return pick(['', '', 'v']) + text + (parts === 3 ? pick(['', '', '-0', '-beta', '-beta.1', '-rc.2']) : '');
  };
  const comparator = () => pick(['', '', '^', '~', '>', '>=', '<', '<=', '=', '~>']) + pick(['', '', ' ']) + version();
  const set = () =>
    random(5) === 0 ? `${version()} - ${version()}` : Array.from({ length: 1 + random(3) }, comparator).join(' ');
  const range = () => Array.from({ length: 1 + random(3) }, set).join(pick([' || ', '||']));
  // A range the reader refuses (wildcards before numbers, a prerelease on a partial version) is
  // never satisfied, so the caller reports the package; every range it reads must agree exactly.
  const wrong = [];
  let read = 0;
  for (let i = 0; i < 1500; i += 1) {
    const text = range();
    const accepted = parseRange(text) !== undefined;
    if (accepted && semver.validRange(text) === null) wrong.push(`accepted, invalid: ${JSON.stringify(text)}`);
    if (accepted) read += 1;
    for (const v of VERSIONS.slice(0, 120)) {
      const want = accepted ? semver.satisfies(v, text) : false;
      if (satisfies(v, text) !== want) wrong.push(`${v} ${JSON.stringify(text)}`);
    }
  }
  assert.deepEqual(wrong.slice(0, 10), []);
  assert.ok(read > 500, `${read} of 1500 random ranges read`);
});

test('ranges the reader refuses rather than guess (node-semver reads them in ways it does not follow)', () => {
  // From the fuzz: a wildcard before a number, a prerelease on a partial version, build metadata.
  for (const range of [
    '0 - x.2',
    'x.2',
    '1.x.3',
    '1.*.0-rc.2 - 1',
    '=0.x.x-beta',
    '1.2-beta',
    '>=1.0.0+b1',
    '0.0.0+b1 - 0.0.0-beta.1',
  ]) {
    assert.equal(parseRange(range), undefined, range);
    assert.equal(satisfies('1.0.0', range), false, range);
  }
});
