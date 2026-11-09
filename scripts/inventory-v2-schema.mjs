// Generates schemas/agent-guard-inventory-v2.schema.json as a $ref envelope over v1.
// Only the task and tool records change (outside-content fields); everything else refers
// to the v1 definitions, so v1 stays the single source for the shared shapes.
// Usage: node scripts/inventory-v2-schema.mjs [--write]
import { readFileSync, writeFileSync } from 'node:fs';

const root = new URL('../schemas/', import.meta.url);
export const v2Path = new URL('agent-guard-inventory-v2.schema.json', root);
export const manifestV3Path = new URL('agent-guard-inventory-manifest-v3.schema.json', root);
const V1 = 'agent-guard-inventory-v1.schema.json';
const MANIFEST_V2 = 'agent-guard-inventory-manifest-v2.schema.json';
const MANIFEST_V3 = 'agent-guard-inventory-manifest-v3.schema.json';
const LOCAL = new Set(['task', 'tool', 'manifest']);

/** Points `#/$defs/x` at the base file, except the definitions this file restates. */
function rewrite(value, base = V1, local = LOCAL) {
  if (Array.isArray(value)) return value.map(item => rewrite(item, base, local));
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      if (key === '$ref' && typeof item === 'string' && item.startsWith('#/$defs/')) {
        const name = item.slice('#/$defs/'.length);
        return [key, local.has(name) ? item : `${base}${item}`];
      }
      return [key, rewrite(item, base, local)];
    }),
  );
}

/** Manifest v3: v2 plus a required host declaration of paths that bypass the guard. */
export function renderManifestV3Schema() {
  const v2 = JSON.parse(readFileSync(new URL(MANIFEST_V2, root), 'utf8'));
  const { $defs: _defs, $id: _id, title: _title, description: _description, ...envelope } = v2;
  const schema = {
    $schema: v2.$schema,
    $id: v2.$id.replace('manifest-v2', 'manifest-v3'),
    title: 'Agent Guard host inventory manifest v3',
    description:
      'Manifest v2 plus `directAccess`: host-declared paths that act without the guard. [] means the host declared none; it is not a check. Shared shapes are $refs into v2.',
    ...rewrite(envelope, MANIFEST_V2, new Set(['directAccess'])),
    $defs: {
      directAccess: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'deploymentId', 'kind', 'targetRef', 'description'],
        properties: {
          id: { $ref: `${MANIFEST_V2}#/$defs/opaque` },
          deploymentId: { $ref: `${MANIFEST_V2}#/$defs/identifier` },
          kind: { enum: ['shell', 'database', 'network', 'sdk', 'mcp', 'other'] },
          targetRef: { anyOf: [{ $ref: `${MANIFEST_V2}#/$defs/opaque` }, { type: 'null' }] },
          description: { $ref: `${MANIFEST_V2}#/$defs/purpose` },
        },
        description: 'At most 32 entries per deployment; deploymentId must name a declared deployment.',
      },
    },
  };
  schema.properties.schemaVersion = { const: 3 };
  schema.required = [...schema.required, 'directAccess'];
  schema.properties.directAccess = {
    type: 'array',
    maxItems: 1000,
    items: { $ref: '#/$defs/directAccess' },
  };
  return JSON.stringify(schema, null, 2) + '\n';
}

export function renderInventoryV2Schema() {
  const v1 = JSON.parse(readFileSync(new URL(V1, root), 'utf8'));
  const task = rewrite(structuredClone(v1.$defs.task));
  task.required = [...task.required, 'untrusted'];
  task.properties.untrusted = {
    type: 'boolean',
    description: 'The task family has read outside content (family-wide, never cleared).',
  };
  const tool = rewrite(structuredClone(v1.$defs.tool));
  tool.required = [...tool.required, 'readsUntrusted', 'untrustedContext', 'sendsExternal'];
  tool.properties.readsUntrusted = { type: ['boolean', 'null'] };
  tool.properties.untrustedContext = { enum: ['allow', 'require_approval', 'deny', null] };
  tool.properties.sendsExternal = { type: ['boolean', 'null'] };
  tool.allOf = [
    ...(tool.allOf ?? []),
    {
      if: { properties: { registered: { const: false } } },
      then: {
        properties: {
          readsUntrusted: { type: 'null' },
          untrustedContext: { type: 'null' },
          sendsExternal: { type: 'null' },
        },
      },
    },
  ];
  const { $defs: _defs, $id: _id, title: _title, description: _description, ...envelope } = v1;
  const schema = {
    $schema: v1.$schema,
    $id: v1.$id.replace('inventory-v1', 'inventory-v2'),
    title: 'Agent Guard inventory snapshot v2',
    description:
      'Same as v1 plus outside-content fields on tasks and tools, and manifest v3. Executors emit v2 only when a tool declares an outside-content label, a task family is untrusted, or the manifest is v3. Shared shapes are $refs into v1.',
    ...rewrite(envelope),
    $defs: {
      task,
      tool,
      // v2 snapshots also carry manifest v3 (directAccess); v1 and v2 manifests are unchanged.
      manifest: {
        oneOf: [{ $ref: `${V1}#/$defs/manifestV1` }, { $ref: `${V1}#/$defs/manifestV2` }, { $ref: MANIFEST_V3 }],
      },
    },
  };
  schema.properties.schemaVersion = { const: 2 };
  return JSON.stringify(schema, null, 2) + '\n';
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const text = renderInventoryV2Schema();
  if (process.argv.includes('--write')) {
    writeFileSync(v2Path, text);
    writeFileSync(manifestV3Path, renderManifestV3Schema());
  } else process.stdout.write(text);
}
