import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RULES } from '@shieldaai/agent-guard-check';
import { rulesDoc } from '../scripts/rules-doc.mjs';

test('docs/rules.md is generated from the current rules', () => {
  const file = readFileSync(new URL('../docs/rules.md', import.meta.url), 'utf8');
  assert.equal(file, rulesDoc(), 'run: node packages/check/scripts/rules-doc.mjs --write');
});

test('the README lists every rule', () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  for (const rule of RULES) assert.ok(readme.includes(rule.id), `${rule.id} missing from README`);
});
