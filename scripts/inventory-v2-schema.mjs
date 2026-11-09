// Generates schemas/agent-guard-inventory-v2.schema.json as a $ref envelope over v1.
// Only the task and tool records change (outside-content fields); everything else refers
// to the v1 definitions, so v1 stays the single source for the shared shapes.
// Usage: node scripts/inventory-v2-schema.mjs [--write]
import { readFileSync, writeFileSync } from 'node:fs';

const root = new URL('../schemas/', import.meta.url);
export const v2Path = new URL('agent-guard-inventory-v2.schema.json', root);
const V1 = 'agent-guard-inventory-v1.schema.json';
const LOCAL = new Set(['task', 'tool']);

function rewrite(value) {
  if (Array.isArray(value)) return value.map(rewrite);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      if (key === '$ref' && typeof item === 'string' && item.startsWith('#/$defs/')) {
        const name = item.slice('#/$defs/'.length);
        return [key, LOCAL.has(name) ? item : `${V1}${item}`];
      }
      return [key, rewrite(item)];
    }),
  );
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
      'Same as v1 plus outside-content fields on tasks and tools. Executors emit v2 only when a tool declares an outside-content label or a task family is untrusted. Shared shapes are $refs into v1.',
    ...rewrite(envelope),
    $defs: { task, tool },
  };
  schema.properties.schemaVersion = { const: 2 };
  return JSON.stringify(schema, null, 2) + '\n';
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const text = renderInventoryV2Schema();
  if (process.argv.includes('--write')) writeFileSync(v2Path, text);
  else process.stdout.write(text);
}
