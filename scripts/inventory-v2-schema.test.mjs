import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  manifestV3Path,
  manifestV4Path,
  renderInventoryV2Schema,
  renderManifestV3Schema,
  renderManifestV4Schema,
  v2Path,
} from './inventory-v2-schema.mjs';

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
        ref === '"$ref":"agent-guard-inventory-manifest-v4.schema.json"' ||
        /#\/\$defs\/(task|tool|manifest)"$/.test(ref),
    ),
    'every other shape refers to v1, manifest v3 or manifest v4',
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

test('manifest v4 is the generated $ref envelope over manifest v3', () => {
  assert.equal(
    readFileSync(manifestV4Path, 'utf8'),
    renderManifestV4Schema(),
    'run: node scripts/inventory-v2-schema.mjs --write',
  );
  const schema = JSON.parse(renderManifestV4Schema());
  assert.equal(schema.properties.schemaVersion.const, 4);
  for (const field of ['directAccess', 'networkIsolation'])
    assert.ok(schema.required.includes(field), `v4 always says what it declared, even [] (${field})`);
  assert.deepEqual(Object.keys(schema.$defs), ['networkIsolation']);
  const entry = schema.$defs.networkIsolation;
  assert.deepEqual(entry.required, ['deploymentId', 'segmentId', 'egress', 'egressTargets', 'sandbox']);
  assert.deepEqual(entry.properties.egress.enum, ['none', 'allowlist', 'open']);
  assert.deepEqual(entry.properties.sandbox.enum, ['none', 'process', 'container', 'vm']);
  assert.equal(entry.properties.egressTargets.maxItems, 32);
  assert.deepEqual(entry.then, { properties: { egressTargets: { maxItems: 0 } } }, 'targets only for an allowlist');
  const refs = JSON.stringify(schema).match(/"\$ref":"[^"]+"/g) ?? [];
  assert.ok(
    refs.every(
      ref =>
        ref.includes('agent-guard-inventory-manifest-v2.schema.json#/$defs/') ||
        ref === '"$ref":"agent-guard-inventory-manifest-v3.schema.json#/$defs/directAccess"' ||
        ref.endsWith('#/$defs/networkIsolation"'),
    ),
    'every other shape refers to manifest v2 or v3',
  );
});
