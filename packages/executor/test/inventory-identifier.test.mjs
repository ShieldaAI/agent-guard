import test from 'node:test';
import assert from 'node:assert/strict';
import { projectInventory, projectInventoryJson, validateInventorySource } from '../dist/inventory.js';
// Existing hash-pinned pre-finalizer fixture also preserves the original identifier
// validator. Its provenance/hash is checked by inventory-finalizer.test.mjs.
import {
  projectInventory as originalProject,
  validateInventorySource as originalSource,
} from './fixtures/inventory-before-finalizer.mjs';

const time = Date.UTC(2026, 10, 6);
const enrollment = { companyId: 'company', sourceId: 'source', enrollmentGeneration: 'generation' };
const ledger = (tenantId = 'tenant', principalId = 'principal') => ({
  schema: 1,
  revision: 1,
  epoch: 1,
  inventoryInstanceId: '00000000-0000-4000-8000-000000000001',
  tasks: {
    task: {
      options: {
        id: 'task',
        tenantId,
        principalId,
        grants: [{ tool: 'read', resources: ['record'] }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 0, deadline: time + 1000 },
      },
      parent: null,
      family: 'family',
      revoked: false,
      calls: 0,
      concurrent: 0,
      spent: 0,
      reserved: 0,
    },
  },
  families: { family: { sensitive: false } },
  tools: {},
});
const canonical = value => {
  const copy = JSON.parse(JSON.stringify(value));
  delete copy.snapshotId;
  return copy;
};
const valid = [
  ['short ASCII', 'agent'],
  ['ASCII boundary', 'a'.repeat(4096)],
  ['BMP boundary', '雪'.repeat(4096)],
  ['short astral UTF-16 boundary', '😀'.repeat(2048)],
  ['astral code-point boundary', '😀'.repeat(4096)],
  ['mixed code-point boundary', 'a' + '😀'.repeat(4095)],
  ['embedded non-NUL controls', 'a\n\t\u001c\u0085z'],
  ['escaping and combining marks', '"\\e\u0301雪😀'],
];
const invalid = [
  ['ASCII overflow', 'a'.repeat(4097)],
  ['BMP overflow', '雪'.repeat(4097)],
  ['astral overflow', '😀'.repeat(4097)],
  ['mixed overflow within 8192 UTF-16 units', 'aa' + '😀'.repeat(4095)],
  ['short high surrogate', 'a\ud800'],
  ['short low surrogate', '\udc00a'],
  ['long high surrogate', '😀'.repeat(2048) + '\ud800'],
  ['long low surrogate', '\udc00' + '😀'.repeat(2048)],
  ['reversed surrogate pair', '\udc00\ud800'],
  ['short NUL', 'a\0z'],
  ['long NUL', 'a'.repeat(4096) + '\0'],
  ['empty', ''],
  ['blank', ' \t\n\u001c\u0085'],
  ['long blank', ' '.repeat(4097)],
  ['number', 1],
  ['null', null],
  ['object', {}],
  ['boxed string', new String('agent')],
];

test('short and long Unicode identifiers preserve exact legacy projection and source validation', () => {
  for (const [name, value] of valid) {
    const state = ledger('tenant', value),
      source = { ...enrollment, companyId: value };
    const actual = projectInventory(state, new Map(), enrollment, { tenantId: 'tenant' }, time);
    const expected = originalProject(state, new Map(), enrollment, { tenantId: 'tenant' }, time);
    assert.deepEqual(canonical(actual), canonical(expected), name);
    const encoded = projectInventoryJson(state, new Map(), enrollment, { tenantId: 'tenant' }, time);
    assert.deepEqual(canonical(JSON.parse(encoded.json)), canonical(expected), name);
    assert.equal(encoded.bytes, Buffer.byteLength(encoded.json), name);
    assert.equal(actual.tasks[0].principalId, value, name);
    assert.deepEqual(validateInventorySource(source), originalSource(source), name);
    // Scope uses the same point limit but a distinct error category.
    const scoped = ledger(value);
    assert.deepEqual(
      canonical(projectInventory(scoped, new Map(), enrollment, { tenantId: value }, time)),
      canonical(originalProject(scoped, new Map(), enrollment, { tenantId: value }, time)),
      name,
    );
    assert.deepEqual(
      canonical(JSON.parse(projectInventoryJson(scoped, new Map(), enrollment, { tenantId: value }, time).json)),
      canonical(originalProject(scoped, new Map(), enrollment, { tenantId: value }, time)),
      name,
    );
  }
});

test('Unicode scalar, NUL, blank and exact point-count denials preserve each legacy error code', () => {
  for (const [name, value] of invalid) {
    for (const [code, current, original] of [
      [
        'INVENTORY_STATE_INVALID',
        () => projectInventory(ledger('tenant', value), new Map(), enrollment, { tenantId: 'tenant' }, time),
        () => originalProject(ledger('tenant', value), new Map(), enrollment, { tenantId: 'tenant' }, time),
      ],
      [
        'INVENTORY_STATE_INVALID',
        () => projectInventoryJson(ledger('tenant', value), new Map(), enrollment, { tenantId: 'tenant' }, time),
        () => originalProject(ledger('tenant', value), new Map(), enrollment, { tenantId: 'tenant' }, time),
      ],
      [
        'INVENTORY_SCOPE_INVALID',
        () => projectInventory(ledger(), new Map(), enrollment, { tenantId: value }, time),
        () => originalProject(ledger(), new Map(), enrollment, { tenantId: value }, time),
      ],
      [
        'INVENTORY_SCOPE_INVALID',
        () => projectInventoryJson(ledger(), new Map(), enrollment, { tenantId: value }, time),
        () => originalProject(ledger(), new Map(), enrollment, { tenantId: value }, time),
      ],
      [
        'INVENTORY_CONFIG_INVALID',
        () => validateInventorySource({ ...enrollment, companyId: value }),
        () => originalSource({ ...enrollment, companyId: value }),
      ],
    ]) {
      for (const operation of [current, original])
        assert.throws(operation, error => error.code === code && error.message === code, `${name}: ${code}`);
    }
  }
});
