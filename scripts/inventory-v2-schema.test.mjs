import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { manifestV3Path, renderInventoryV2Schema, renderManifestV3Schema, v2Path } from './inventory-v2-schema.mjs';

test('the v2 inventory schema is the generated $ref envelope over v1', () => {
  assert.equal(
    readFileSync(v2Path, 'utf8'),
    renderInventoryV2Schema(),
    'run: node scripts/inventory-v2-schema.mjs --write',
  );
  const schema = JSON.parse(renderInventoryV2Schema());
  assert.equal(schema.properties.schemaVersion.const, 2);
  assert.deepEqual(
    Object.keys(schema.$defs).sort(),
    ['manifest', 'task', 'tool'],
    'only the changed records are restated',
  );
  const refs = JSON.stringify(schema).match(/"\$ref":"[^"]+"/g) ?? [];
  assert.ok(
    refs.every(
      ref =>
        ref.includes('agent-guard-inventory-v1.schema.json#/$defs/') ||
        ref === '"$ref":"agent-guard-inventory-manifest-v3.schema.json"' ||
        /#\/\$defs\/(task|tool|manifest)"$/.test(ref),
    ),
    'every other shape refers to v1 or manifest v3',
  );
});

test('manifest v3 is the generated $ref envelope over manifest v2', () => {
  assert.equal(
    readFileSync(manifestV3Path, 'utf8'),
    renderManifestV3Schema(),
    'run: node scripts/inventory-v2-schema.mjs --write',
  );
  const schema = JSON.parse(renderManifestV3Schema());
  assert.equal(schema.properties.schemaVersion.const, 3);
  assert.ok(schema.required.includes('directAccess'), 'v3 always says what it declared, even []');
  assert.deepEqual(Object.keys(schema.$defs), ['directAccess']);
  const refs = JSON.stringify(schema).match(/"\$ref":"[^"]+"/g) ?? [];
  assert.ok(
    refs.every(
      ref =>
        ref.includes('agent-guard-inventory-manifest-v2.schema.json#/$defs/') || ref.endsWith('#/$defs/directAccess"'),
    ),
    'every other shape refers to manifest v2',
  );
});
