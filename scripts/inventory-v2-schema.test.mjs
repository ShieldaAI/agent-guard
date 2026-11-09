import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderInventoryV2Schema, v2Path } from './inventory-v2-schema.mjs';

test('the v2 inventory schema is the generated $ref envelope over v1', () => {
  assert.equal(
    readFileSync(v2Path, 'utf8'),
    renderInventoryV2Schema(),
    'run: node scripts/inventory-v2-schema.mjs --write',
  );
  const schema = JSON.parse(renderInventoryV2Schema());
  assert.equal(schema.properties.schemaVersion.const, 2);
  assert.deepEqual(Object.keys(schema.$defs).sort(), ['task', 'tool'], 'only the changed records are restated');
  const refs = JSON.stringify(schema).match(/"\$ref":"[^"]+"/g) ?? [];
  assert.ok(
    refs.every(
      ref => ref.includes('agent-guard-inventory-v1.schema.json#/$defs/') || /#\/\$defs\/(task|tool)"$/.test(ref),
    ),
    'every other shape refers to v1',
  );
});
