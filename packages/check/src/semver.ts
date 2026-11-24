/**
 * The part of node-semver's `satisfies` that npx needs to tell whether an installed version meets a
 * range: `||`, hyphen ranges, comparators, `^`, `~`, x-ranges, and the rule that a prerelease
 * matches only a comparator with the same major.minor.patch and a prerelease of its own.
 * test/semver.test.mjs checks it against npm's own copy of node-semver.
 */

type Version = readonly [number, number, number, readonly string[]];
type Comparator = { readonly op: '<' | '<=' | '>' | '>=' | '='; readonly version: Version };

const NUM = '0|[1-9]\\d*';
const PART = '0|[1-9]\\d*|\\d*[a-zA-Z-][a-zA-Z0-9-]*';
const PRE = `(?:-(${PART}(?:\\.(?:${PART}))*))?`;
const BUILD = '(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?';
const EXACT = new RegExp(`^v?(${NUM})\\.(${NUM})\\.(${NUM})${PRE}${BUILD}$`);
const X = `${NUM}|x|X|\\*`;
const PARTIAL = new RegExp(`^v?(${X})(?:\\.(${X})(?:\\.(${X})${PRE}${BUILD})?)?$`);

/** A full version (`1.2.3`, `1.2.3-beta.1`), or undefined. */
export function parseVersion(text: string): Version | undefined {
  const match = EXACT.exec(text.trim());
  if (!match) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3]), match[4] ? match[4].split('.') : []];
}

function comparePre(a: readonly string[], b: readonly string[]): number {
  if (!a.length || !b.length) return a.length ? -1 : b.length ? 1 : 0;
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (nx !== ny) return nx ? -1 : 1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export function compareVersions(a: Version, b: Version): number {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return (a[i] as number) < (b[i] as number) ? -1 : 1;
  return comparePre(a[3], b[3]);
}

const isX = (part: string | undefined) => part === undefined || part === 'x' || part === 'X' || part === '*';

/** The comparators one space-separated part of a range stands for, or undefined when it is not one. */
function comparators(text: string): Comparator[] | undefined {
  const match = /^(<=|>=|<|>|=|\^|~>?|)\s*(.*)$/.exec(text);
  if (!match) return undefined;
  const op = match[1]!;
  const partial = PARTIAL.exec(match[2]!);
  if (!partial) return undefined;
  const [, a, b, c, pre] = partial;
  const pres = pre ? pre.split('.') : [];
  const M = Number(a);
  const m = Number(b);
  const p = Number(c);
  const v = (x: number, y: number, z: number, q: readonly string[] = []): Version => [x, y, z, q];
  const lt = (version: Version): Comparator => ({
    op: '<',
    version: v(...(version.slice(0, 3) as [number, number, number]), ['0']),
  });
  if (isX(a)) return op === '<' || op === '>' ? [{ op: '<', version: v(0, 0, 0, ['0']) }] : [];
  if (op === '^') {
    const low: Comparator = { op: '>=', version: v(M, isX(b) ? 0 : m, isX(c) ? 0 : p, pres) };
    if (M > 0 || isX(b)) return [low, lt(v(M + 1, 0, 0))];
    if (m > 0 || isX(c)) return [low, lt(v(0, m + 1, 0))];
    return [low, lt(v(0, 0, p + 1))];
  }
  if (op === '~' || op === '~>') {
    const low: Comparator = { op: '>=', version: v(M, isX(b) ? 0 : m, isX(c) ? 0 : p, pres) };
    return [low, lt(isX(b) ? v(M + 1, 0, 0) : v(M, m + 1, 0))];
  }
  if (isX(b) || isX(c)) {
    // A partial version is a range of every version it leaves open.
    const low = v(M, isX(b) ? 0 : m, 0);
    const high = isX(b) ? v(M + 1, 0, 0) : v(M, m + 1, 0);
    switch (op) {
      case '':
      case '=':
        return [{ op: '>=', version: low }, lt(high)];
      case '>':
        return [{ op: '>=', version: high }];
      case '>=':
        return [{ op: '>=', version: low }];
      case '<':
        return [lt(low)];
      case '<=':
        return [lt(high)];
    }
  }
  return [{ op: (op || '=') as Comparator['op'], version: v(M, m, p, pres) }];
}

/** The comparator sets a range stands for, or undefined when it is not a range (a tag such as `latest`). */
export function parseRange(range: string): Comparator[][] | undefined {
  const sets: Comparator[][] = [];
  for (const raw of range.trim().split('||')) {
    let text = raw.trim().replace(/(<=|>=|<|>|=|\^|~>?)\s+/g, '$1');
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    if (hyphen) {
      const low = comparators(`>=${hyphen[1]}`);
      const high = PARTIAL.exec(hyphen[2]!);
      if (!low || !high) return undefined;
      const [, a, b, c] = high;
      const upper = isX(b) ? `<${Number(a) + 1}.0.0-0` : isX(c) ? `<${a}.${Number(b) + 1}.0-0` : `<=${hyphen[2]}`;
      const top = comparators(upper);
      if (!top) return undefined;
      sets.push([...low, ...top]);
      continue;
    }
    if (text === '') text = '*';
    const set: Comparator[] = [];
    for (const part of text.split(/\s+/)) {
      const found = comparators(part);
      if (!found) return undefined;
      set.push(...found);
    }
    sets.push(set);
  }
  return sets;
}

function test(c: Comparator, version: Version): boolean {
  const order = compareVersions(version, c.version);
  switch (c.op) {
    case '<':
      return order < 0;
    case '<=':
      return order <= 0;
    case '>':
      return order > 0;
    case '>=':
      return order >= 0;
    case '=':
      return order === 0;
  }
}

/** node-semver's `satisfies(version, range)` without options. */
export function satisfies(versionText: string, range: string): boolean {
  const version = parseVersion(versionText);
  const sets = parseRange(range);
  if (!version || !sets) return false;
  return sets.some(set => {
    if (!set.every(c => test(c, version))) return false;
    if (!version[3].length) return true;
    // A prerelease matches only when a comparator names the same version with a prerelease.
    return set.some(
      c =>
        c.version[3].length > 0 &&
        !(c.version[3].length === 1 && c.version[3][0] === '0' && c.op === '<') &&
        c.version[0] === version[0] &&
        c.version[1] === version[1] &&
        c.version[2] === version[2],
    );
  });
}
