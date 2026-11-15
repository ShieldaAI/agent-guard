import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentGuard } from '@shieldaai/agent-guard';
import {
  createDispatcher,
  jsonSchemaParser,
  registerApprovedTools,
  standardSchemaParser,
  taskBudget,
  validateJsonSchema,
} from '../dist/index.js';

const codeOf = (parse, value) => {
  try {
    parse(value);
    return 'OK';
  } catch (error) {
    return error.code;
  }
};

test('jsonSchemaParser enforces each supported keyword with its own detail code', () => {
  const parse = jsonSchemaParser({
    type: 'object',
    properties: {
      name: { type: 'string', minLength: 1, maxLength: 5 },
      code: { type: 'string', pattern: '^[A-Z]{3}$' },
      count: { type: 'integer', minimum: 1, maximum: 10, multipleOf: 2 },
      ratio: { type: 'number', exclusiveMinimum: 0, exclusiveMaximum: 1 },
      mode: { enum: ['a', 'b'] },
      fixed: { const: 'x' },
      tags: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 2, uniqueItems: true },
      meta: { type: 'object', additionalProperties: { type: 'number' }, maxProperties: 1 },
      note: { type: ['string', 'null'] },
      legacy: { type: 'string', nullable: true },
    },
    required: ['name'],
    additionalProperties: false,
  });
  assert.equal(codeOf(parse, { name: 'ok' }), 'OK');
  assert.equal(codeOf(parse, {}), 'SCHEMA_REQUIRED');
  assert.equal(codeOf(parse, { name: 7 }), 'SCHEMA_TYPE');
  assert.equal(codeOf(parse, { name: '' }), 'SCHEMA_LENGTH');
  assert.equal(codeOf(parse, { name: '😀😀😀😀😀' }), 'OK', 'length counts code points');
  assert.equal(codeOf(parse, { name: 'toolong' }), 'SCHEMA_LENGTH');
  assert.equal(codeOf(parse, { name: 'a', code: 'abc' }), 'SCHEMA_PATTERN');
  assert.equal(codeOf(parse, { name: 'a', count: 1.5 }), 'SCHEMA_TYPE');
  assert.equal(codeOf(parse, { name: 'a', count: 12 }), 'SCHEMA_RANGE');
  assert.equal(codeOf(parse, { name: 'a', count: 3 }), 'SCHEMA_MULTIPLE_OF');
  assert.equal(codeOf(parse, { name: 'a', ratio: 1 }), 'SCHEMA_RANGE');
  assert.equal(codeOf(parse, { name: 'a', mode: 'c' }), 'SCHEMA_ENUM');
  assert.equal(codeOf(parse, { name: 'a', fixed: 'y' }), 'SCHEMA_CONST');
  assert.equal(codeOf(parse, { name: 'a', tags: [] }), 'SCHEMA_ITEMS');
  assert.equal(codeOf(parse, { name: 'a', tags: ['x', 'x'] }), 'SCHEMA_ITEMS');
  assert.equal(codeOf(parse, { name: 'a', tags: [1] }), 'SCHEMA_TYPE');
  assert.equal(codeOf(parse, { name: 'a', meta: { a: 'x' } }), 'SCHEMA_TYPE');
  assert.equal(codeOf(parse, { name: 'a', meta: { a: 1, b: 2 } }), 'SCHEMA_PROPERTY_COUNT');
  assert.equal(codeOf(parse, { name: 'a', note: null, legacy: null }), 'OK');
  assert.equal(codeOf(parse, { name: 'a', extra: true }), 'SCHEMA_ADDITIONAL_PROPERTIES');
  assert.equal(codeOf(parse, ['name']), 'SCHEMA_TYPE');
});

test('combinators: anyOf, oneOf, allOf, not', () => {
  const parse = jsonSchemaParser({
    anyOf: [{ type: 'string' }, { type: 'number' }],
    not: { const: 'forbidden' },
  });
  assert.equal(codeOf(parse, 'x'), 'OK');
  assert.equal(codeOf(parse, 3), 'OK');
  assert.equal(codeOf(parse, true), 'SCHEMA_COMBINATION');
  assert.equal(codeOf(parse, 'forbidden'), 'SCHEMA_COMBINATION');
  const one = jsonSchemaParser({ oneOf: [{ type: 'integer' }, { type: 'number' }] });
  assert.equal(codeOf(one, 1.5), 'OK');
  assert.equal(codeOf(one, 2), 'SCHEMA_COMBINATION', 'an integer matches both branches');
  const all = jsonSchemaParser({ allOf: [{ type: 'string' }, { minLength: 2 }] });
  assert.equal(codeOf(all, 'a'), 'SCHEMA_COMBINATION');
});

test('unsupported keywords fail when the parser is built, never silently at call time', () => {
  for (const schema of [
    { $ref: '#/definitions/x' },
    { type: 'object', properties: { a: { if: { type: 'string' } } } },
    { patternProperties: {} },
    { type: 'strnig' },
    { pattern: '(' },
    { items: [{ type: 'string' }] },
    { minLength: -1 },
    'not a schema',
  ])
    assert.throws(() => jsonSchemaParser(schema), { code: 'UNSUPPORTED_SCHEMA' });
  // Annotations are fine.
  jsonSchemaParser({
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 't',
    description: 'd',
    format: 'email',
    examples: [],
    default: {},
  });
});

test('additionalProperties modes: schema (default), reject and strip', () => {
  const schema = { type: 'object', properties: { id: { type: 'string' } } };
  assert.deepEqual(jsonSchemaParser(schema)({ id: 'a', x: 1 }), { id: 'a', x: 1 });
  assert.equal(
    codeOf(jsonSchemaParser(schema, { additionalProperties: 'reject' }), { id: 'a', x: 1 }),
    'SCHEMA_ADDITIONAL_PROPERTIES',
  );
  assert.deepEqual(jsonSchemaParser(schema, { additionalProperties: 'strip' })({ id: 'a', x: 1 }), { id: 'a' });
  assert.throws(() => jsonSchemaParser(schema, { additionalProperties: 'maybe' }), { code: 'INVALID_OPTIONS' });
});

test('validateJsonSchema lists every issue with JSON Pointer paths', () => {
  const result = validateJsonSchema(
    {
      type: 'object',
      properties: { 'a/b': { type: 'string' }, list: { items: { type: 'number' } } },
      required: ['must'],
    },
    { 'a/b': 1, list: [1, 'x'] },
  );
  assert.equal(result.valid, false);
  assert.deepEqual(
    result.issues.map(issue => [issue.path, issue.keyword]),
    [
      ['/must', 'required'],
      ['/a~1b', 'type'],
      ['/list/1', 'type'],
    ],
  );
  assert.equal(validateJsonSchema(true, 'anything').valid, true);
  assert.equal(validateJsonSchema(false, 'anything').valid, false);
});

test('the parser plugs into the guard: invalid arguments never reach resolve or execute', async () => {
  const guard = new AgentGuard();
  let resolved = 0;
  registerApprovedTools(guard, [
    {
      name: 'transfer',
      description: 'Move money between two of the customer’s own accounts',
      inputSchema: {
        type: 'object',
        properties: { cents: { type: 'integer', minimum: 1, maximum: 10_000 } },
        required: ['cents'],
      },
      parse: jsonSchemaParser({
        type: 'object',
        properties: { cents: { type: 'integer', minimum: 1, maximum: 10_000 } },
        required: ['cents'],
      }),
      resolve: () => {
        resolved += 1;
        return { resourceId: 'acct', tenantId: 't' };
      },
      execute: args => ({ value: args.cents }),
    },
  ]);
  const task = guard.createTask({
    id: 'pay',
    principalId: 'p',
    tenantId: 't',
    grants: [{ tool: 'transfer', resources: ['acct'] }],
    budget: taskBudget({ maxCalls: 5, ttlMs: 10_000 }),
  });
  const dispatch = createDispatcher({ guard, task });
  assert.equal((await dispatch({ name: 'transfer', input: { cents: 1_000_000 } })).detail, 'SCHEMA_RANGE');
  assert.equal(resolved, 0);
  assert.equal((await dispatch({ name: 'transfer', input: { cents: 500 } })).result, 500);
});

test('standardSchemaParser works with any Standard Schema validator', async () => {
  const sync = {
    '~standard': {
      version: 1,
      vendor: 'test',
      validate: value =>
        typeof value?.id === 'string'
          ? { value: { id: value.id.trim() } }
          : { issues: [{ message: `bad ${JSON.stringify(value)}` }] },
    },
  };
  const parse = standardSchemaParser(sync);
  assert.deepEqual(parse({ id: ' 42 ' }), { id: '42' });
  assert.equal(codeOf(parse, { id: 1 }), 'SCHEMA_MISMATCH');
  const asyncSchema = { '~standard': { version: 1, vendor: 'test', validate: async () => ({ value: 1 }) } };
  assert.equal(codeOf(standardSchemaParser(asyncSchema), {}), 'SCHEMA_ASYNC');
  assert.throws(() => standardSchemaParser({}), { code: 'INVALID_OPTIONS' });
});

test('standardSchemaParser with Zod, when Zod is installed', async t => {
  let z;
  try {
    ({ z } = await import('zod'));
  } catch {
    t.skip('zod is not installed');
    return;
  }
  const parse = standardSchemaParser(z.object({ id: z.string().regex(/^\d+$/) }).strict());
  assert.deepEqual(parse({ id: '42' }), { id: '42' });
  assert.equal(codeOf(parse, { id: 'x' }), 'SCHEMA_MISMATCH');
  assert.equal(codeOf(parse, { id: '1', extra: true }), 'SCHEMA_MISMATCH');
});

test('random values never crash the validator and parse is consistent with validate', () => {
  const schema = {
    type: 'object',
    properties: { a: { type: 'string', maxLength: 3 }, b: { type: 'array', items: { type: 'integer' } } },
    required: ['a'],
  };
  const parse = jsonSchemaParser(schema);
  let seed = 7;
  const random = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
  const value = depth => {
    const pick = Math.floor(random() * 7);
    if (depth > 3 || pick === 0) return null;
    if (pick === 1) return random() > 0.5;
    if (pick === 2) return Math.floor(random() * 100) / (random() > 0.5 ? 1 : 3);
    if (pick === 3) return 'x'.repeat(Math.floor(random() * 5));
    if (pick === 4) return Array.from({ length: Math.floor(random() * 3) }, () => value(depth + 1));
    return Object.fromEntries(['a', 'b', 'c'].filter(() => random() > 0.4).map(key => [key, value(depth + 1)]));
  };
  for (let index = 0; index < 2_000; index += 1) {
    const input = value(0);
    const valid = validateJsonSchema(schema, input).valid;
    assert.equal(codeOf(parse, input) === 'OK', valid);
  }
});

test('oversized and repetitive arrays stay cheap', () => {
  const bounded = jsonSchemaParser({ type: 'array', maxItems: 10, uniqueItems: true, items: { type: 'number' } });
  let started = performance.now();
  assert.equal(
    codeOf(
      bounded,
      Array.from({ length: 20_000 }, (_, i) => i),
    ),
    'SCHEMA_ITEMS',
  );
  assert.ok(performance.now() - started < 200, 'past maxItems the items are not examined');
  const unbounded = jsonSchemaParser({ type: 'array', uniqueItems: true });
  started = performance.now();
  assert.equal(
    codeOf(
      unbounded,
      Array.from({ length: 5_000 }, (_, i) => ({ id: i, tags: ['a', 'b'] })),
    ),
    'OK',
  );
  assert.ok(performance.now() - started < 500, 'uniqueness is linear');
  assert.equal(
    codeOf(unbounded, [
      { a: 1, b: 2 },
      { b: 2, a: 1 },
    ]),
    'SCHEMA_ITEMS',
    'key order does not matter',
  );
  assert.equal(codeOf(unbounded, [1, '1', [1], { 1: 1 }]), 'OK');
});

test('nullable only widens the type', () => {
  const parse = jsonSchemaParser({ type: 'string', nullable: true, enum: ['a', 'b'] });
  assert.equal(codeOf(parse, 'a'), 'OK');
  assert.equal(codeOf(parse, null), 'SCHEMA_ENUM');
  assert.equal(codeOf(jsonSchemaParser({ nullable: true, allOf: [{ type: 'object' }] }), null), 'SCHEMA_COMBINATION');
  assert.equal(codeOf(jsonSchemaParser({ type: 'string', nullable: true }), null), 'OK');
});

test('multipleOf is exact', () => {
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 1 }), 3.0000000001), 'SCHEMA_MULTIPLE_OF');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 1000 }), 1000.0000005), 'SCHEMA_MULTIPLE_OF');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 1000 }), 3000), 'OK');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 0.01 }), 0.07), 'OK');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 0.01 }), 19.99), 'OK');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 0.01 }), 0.071), 'SCHEMA_MULTIPLE_OF');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 0.5 }), 2.5), 'OK');
});

test('strip keeps properties declared in allOf, anyOf and oneOf branches', () => {
  const schema = {
    type: 'object',
    properties: { mode: { type: 'string' } },
    allOf: [{ properties: { path: { type: 'string' } }, required: ['path'] }],
    anyOf: [{ properties: { depth: { type: 'integer' } } }, { properties: { all: { type: 'boolean' } } }],
  };
  const parse = jsonSchemaParser(schema, { additionalProperties: 'strip' });
  const parsed = parse({ mode: 'file', path: '/tmp/a', depth: 2, junk: 'x' });
  assert.deepEqual(parsed, { mode: 'file', path: '/tmp/a', depth: 2 });
  assert.equal(validateJsonSchema(schema, parsed).valid, true);
});

test('a "__proto__" key stays an ordinary own key', () => {
  const parse = jsonSchemaParser({ type: 'object' });
  const parsed = parse(JSON.parse('{"__proto__":{"admin":true},"id":"1"}'));
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(parsed.admin, undefined);
  assert.deepEqual(Object.keys(parsed), ['__proto__', 'id']);
});

test('nested quantifiers are refused unless allowed', () => {
  for (const pattern of ['^(a+)+$', '(\\w*\\.)*x', '(a{1,3})+'])
    assert.throws(() => jsonSchemaParser({ pattern }), { code: 'UNSUPPORTED_SCHEMA' });
  for (const pattern of ['^[0-9]+$', '(ab){2,}', '^(foo|bar)+$', '^\\(x+\\)+$']) jsonSchemaParser({ pattern });
  jsonSchemaParser({ pattern: '^([a-z]+\\.)*[a-z]+$' }, { allowNestedQuantifiers: true });
  assert.throws(() => jsonSchemaParser({}, { allowNestedQuantifiers: 'yes' }), { code: 'INVALID_OPTIONS' });
});

test('with pins, an unpinned tool is not approved', () => {
  const guard = new AgentGuard();
  const tool = name => ({
    name,
    description: name,
    resolve: () => ({ resourceId: 'r', tenantId: 't' }),
    execute: () => ({ value: 1 }),
  });
  const pins = registerApprovedTools(new AgentGuard(), [tool('a')]);
  assert.throws(() => registerApprovedTools(guard, [tool('a'), tool('b')], { pinned: pins }), {
    code: 'TOOL_PIN_MISMATCH',
    detail: 'b',
  });
  assert.equal(guard.toolChanges('a').approved, true);
  assert.equal(guard.toolChanges('b').approved, false);
});

test('the nested-quantifier check sees through groups, classes and fixed counts', () => {
  for (const pattern of ['((a+))+', '((ab)*)+', '(?:(a+))+', '([^)]+)*', '(a+){12}'])
    assert.throws(() => jsonSchemaParser({ pattern }), { code: 'UNSUPPORTED_SCHEMA' }, pattern);
  for (const pattern of ['(\\p{L})+', '(a{2})+', '([+])+', '(a+)?', '(a|b)+c*']) jsonSchemaParser({ pattern });
});

test('multipleOf refuses magnitudes it cannot check exactly', () => {
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 0.2 }), 2 ** 51 + 0.5), 'SCHEMA_MULTIPLE_OF');
  assert.equal(codeOf(jsonSchemaParser({ multipleOf: 2 }), 2 ** 53), 'OK', 'integer steps stay exact');
});

test('reject and strip modes respect names declared in branches and in required', () => {
  const branchy = { properties: { a: { type: 'string' } }, anyOf: [{ required: ['a'] }, { properties: { b: {} } }] };
  assert.equal(codeOf(jsonSchemaParser(branchy, { additionalProperties: 'reject' }), { a: 'x' }), 'OK');
  assert.equal(
    codeOf(jsonSchemaParser(branchy, { additionalProperties: 'reject' }), { a: 'x', z: 1 }),
    'SCHEMA_ADDITIONAL_PROPERTIES',
  );
  assert.deepEqual(
    jsonSchemaParser({ type: 'object', required: ['x'] }, { additionalProperties: 'strip' })({ x: 1, y: 2 }),
    { x: 1 },
  );
});
