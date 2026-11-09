import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import * as root from '@shieldaai/agent-guard';
import * as internal from '@shieldaai/agent-guard/internal';

const STABLE = ['AgentGuard', 'GuardError', 'GuardErrorCode', 'InvalidJsonError'];
const INTERNAL = ['PolicyAdmission', 'assertActionAuthority', 'canonicalJson', 'containsLiteralSecret', 'digestJson', 'immutableJson'];

test('the root entry exports the stable API plus deprecated internal aliases', () => {
  assert.deepEqual(Object.keys(root).sort(), [...STABLE, ...INTERNAL].sort());
  for (const name of INTERNAL) assert.equal(root[name], internal[name], `${name} alias is the same binding`);
});

test('the internal entry exports exactly the internal SPI', () => {
  assert.deepEqual(Object.keys(internal).sort(), [...INTERNAL].sort());
});

test('root aliases are marked @deprecated in the published declarations', () => {
  const declarations = readFileSync(new URL('../dist/deprecated.d.ts', import.meta.url), 'utf8');
  for (const name of [...INTERNAL, 'AuthorityPhase', 'AuthorityState']) {
    assert.match(declarations, new RegExp(`@deprecated[^\\n]*\\n\\s*export (?:declare )?(?:const|type|class) ${name}\\b`), name);
  }
});

test('InvalidJsonError is exported and thrown for over-limit JSON', () => {
  assert.throws(() => internal.immutableJson('x'.repeat(64), 8, 10, 16), root.InvalidJsonError);
});

test('first-party packages import the internal SPI from /internal, not the root', () => {
  const repo = new URL('../../../', import.meta.url).pathname;
  const sources = [];
  const walk = directory => {
    for (const name of readdirSync(directory)) {
      if (name === 'node_modules' || name === 'dist' || name === 'test') continue;
      const path = join(directory, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.(ts|mts|mjs)$/.test(name) && !name.endsWith('.d.ts')) sources.push(path);
    }
  };
  for (const directory of ['packages/executor/src', 'packages/mcp/src', 'packages/scenarios/src', 'packages/agent-map/src', 'apps']) walk(join(repo, directory));
  const offenders = sources.filter(path => {
    for (const match of readFileSync(path, 'utf8').matchAll(/import(?:\s+type)?\s*\{([^}]*)\}\s*from\s*'@shieldaai\/agent-guard'/g)) {
      if (match[1].split(',').some(item => [...INTERNAL, 'AuthorityPhase', 'AuthorityState'].includes(item.replace(/^\s*type\s+/, '').split(' as ')[0].trim()))) return true;
    }
    return false;
  });
  assert.deepEqual(offenders, []);
});
