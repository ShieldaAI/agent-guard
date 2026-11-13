import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import * as root from '@shieldaai/agent-guard';
import * as internal from '@shieldaai/agent-guard/internal';
import { fileURLToPath } from 'node:url';

const STABLE = [
  'AgentGuard',
  'GuardError',
  'GuardErrorCatalog',
  'GuardErrorCode',
  'InvalidJsonError',
  'diffToolDefinitions',
  'isGuardError',
  'monotonicClock',
];
const INTERNAL = [
  'PolicyAdmission',
  'assertActionAuthority',
  'canonicalJson',
  'containsLiteralSecret',
  'digestJson',
  'immutableJson',
];

test('the root entry exports exactly the stable API; the internal SPI is not on it', () => {
  assert.deepEqual(Object.keys(root).sort(), [...STABLE].sort());
  for (const name of INTERNAL) assert.equal(name in root, false, `${name} is only on /internal`);
});

test('the internal entry exports exactly the internal SPI', () => {
  assert.deepEqual(Object.keys(internal).sort(), [...INTERNAL].sort());
});

test('InvalidJsonError is exported and thrown for over-limit JSON', () => {
  assert.throws(() => internal.immutableJson('x'.repeat(64), 8, 10, 16), root.InvalidJsonError);
});

test('first-party packages import the internal SPI from /internal, not the root', () => {
  const repo = fileURLToPath(new URL('../../../', import.meta.url));
  const sources = [];
  const walk = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const name = entry.name;
      if (name === 'node_modules' || name === 'dist' || name === 'test') continue;
      const path = join(directory, name);
      if (entry.isDirectory()) walk(path);
      else if (/\.(ts|mts|mjs)$/.test(name) && !name.endsWith('.d.ts')) sources.push(path);
    }
  };
  for (const directory of [
    'packages/executor/src',
    'packages/mcp/src',
    'packages/scenarios/src',
    'packages/agent-map/src',
    'apps',
  ])
    walk(join(repo, directory));
  const offenders = sources.filter(path => {
    for (const match of readFileSync(path, 'utf8').matchAll(
      /import(?:\s+type)?\s*\{([^}]*)\}\s*from\s*(['"])@shieldaai\/agent-guard\2/g,
    )) {
      if (
        match[1].split(',').some(item =>
          [...INTERNAL, 'AuthorityPhase', 'AuthorityState'].includes(
            item
              .replace(/^\s*type\s+/, '')
              .split(' as ')[0]
              .trim(),
          ),
        )
      )
        return true;
    }
    return false;
  });
  assert.deepEqual(offenders, []);
});
