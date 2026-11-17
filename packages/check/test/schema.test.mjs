// The published inventory schema matches what --format inventory writes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CAPABILITIES, formatInventory } from '@shieldaai/agent-guard-check';
import { json, mcp, scanFiles, settings } from './helpers.mjs';

const schema = JSON.parse(
  readFileSync(new URL('../../../schemas/agent-guard-check-inventory-v1.schema.json', import.meta.url), 'utf8'),
);

/** A small validator for the JSON Schema keywords the schema uses. Returns error paths. */
function validate(value, node, path = '$', errors = []) {
  if (node.$ref) return validate(value, schema.$defs[node.$ref.replace('#/$defs/', '')], path, errors);
  if ('const' in node && value !== node.const) errors.push(`${path}: expected ${JSON.stringify(node.const)}`);
  if (node.enum && !node.enum.includes(value)) errors.push(`${path}: ${JSON.stringify(value)} not in enum`);
  if (node.oneOf) {
    const passing = node.oneOf.filter(option => validate(value, option, path, []).length === 0);
    if (passing.length !== 1) errors.push(`${path}: matches ${passing.length} of oneOf`);
  }
  const type =
    value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
  if (node.type && node.type !== type && !(node.type === 'number' && type === 'integer'))
    errors.push(`${path}: expected ${node.type}, got ${type}`);
  if (typeof node.minimum === 'number' && typeof value === 'number' && value < node.minimum)
    errors.push(`${path}: below minimum`);
  if (type === 'array' && node.items) value.forEach((item, i) => validate(item, node.items, `${path}[${i}]`, errors));
  if (type === 'object') {
    for (const key of node.required ?? []) if (!(key in value)) errors.push(`${path}: missing ${key}`);
    for (const [key, item] of Object.entries(value)) {
      if (node.propertyNames) validate(key, node.propertyNames, `${path} key ${key}`, errors);
      if (node.properties?.[key]) validate(item, node.properties[key], `${path}.${key}`, errors);
      else if (node.additionalProperties === false) errors.push(`${path}: unexpected ${key}`);
      else if (typeof node.additionalProperties === 'object')
        validate(item, node.additionalProperties, `${path}.${key}`, errors);
    }
  }
  return errors;
}

test('inventory output validates against the published schema', () => {
  const result = scanFiles({
    '.claude/settings.json': settings(
      { allow: ['Bash(curl:*)', 'mcp__db', 'WebFetch'] },
      { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: './g.sh' }] }] } },
    ),
    '.mcp.json': mcp({ db: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2'] } }),
    '.claude/agents/x.md': '---\nname: x\ndescription: x\ntools: Bash\n---\nGo.\n',
    '.codex/config.toml': 'sandbox_mode = "workspace-write"\n',
    'opencode.json': json({ permission: { bash: 'ask' } }),
    '.github/agents/a.agent.md': '---\ndescription: a\n---\nGo.\n',
    '.kiro/settings/mcp.json': mcp({ f: { command: 'uvx', args: ['mcp-server-fetch==2025.4.7'], autoApprove: ['*'] } }),
  });
  const inventory = JSON.parse(formatInventory(result));
  assert.ok(inventory.agents.length >= 6);
  assert.deepEqual(validate(inventory, schema), []);
});

test('the schema names every capability and every agent kind', () => {
  assert.deepEqual(schema.$defs.capability.enum, [...CAPABILITIES]);
  const kinds = new Set(schema.$defs.agent.properties.kind.examples);
  const source = readFileSync(new URL('../src/types.ts', import.meta.url), 'utf8');
  const declared = /export type AgentKind =([^;]+);/
    .exec(source)[1]
    .match(/'([a-z-]+)'/g)
    .map(item => item.slice(1, -1));
  assert.deepEqual([...kinds].sort(), declared.sort());
});

test('the validator rejects what the schema forbids', () => {
  const bad = {
    kind: 'agent-guard-check-inventory',
    schemaVersion: 2,
    tool: {},
    evidence: {},
    agents: [{}],
    summary: {},
    suppressed: -1,
  };
  assert.ok(validate(bad, schema).length > 5);
});
