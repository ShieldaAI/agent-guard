import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { InMemoryTransport } from '@modelcontextprotocol/client';
import { McpServer } from '@modelcontextprotocol/server';
import { AgentGuard } from '@shieldaai/agent-guard';
import { ManagedMcpConnection, compileBoundedSchema } from '../dist/index.js';

const directory = new URL('./fixtures/schemas/', import.meta.url);
const corpus = readdirSync(directory).filter(name => name.endsWith('.json'))
  .flatMap(file => Object.entries(JSON.parse(readFileSync(new URL(file, directory), 'utf8')).tools).map(([tool, schema]) => ({ file, tool, schema })));
const identity = { serverId: 'reference', transportIdentity: 'isolated-executor:reference-v1', tenantId: 'acme', principalId: 'operator' };

test('the reference-server schema corpus compiles under the bounded profile', () => {
  assert.ok(corpus.length >= 20, `corpus has ${corpus.length} schemas`);
  for (const { file, tool, schema } of corpus) {
    assert.doesNotThrow(() => compileBoundedSchema(schema), `${file}: ${tool}`);
  }
});

test('corpus schemas still validate the arguments they describe', () => {
  const find = name => compileBoundedSchema(corpus.find(entry => entry.tool === name).schema);
  const issue = find('create_issue');
  assert.equal(issue({ owner: 'acme', repo: 'guard', title: 'Bug', labels: ['bug', 'p1'] }), true);
  assert.equal(issue({ owner: 'acme', repo: 'guard', title: 'Bug', labels: ['bug', 'bug'] }), false, 'uniqueItems');
  assert.equal(issue({ owner: 'ac me', repo: 'guard', title: 'Bug' }), false, 'pattern');
  const fetch = find('fetch');
  assert.equal(fetch({ url: 'not a url but format is an annotation' }), true);
  assert.equal(fetch({ url: '' }), false, 'minLength still applies');
  const entities = find('create_entities');
  assert.equal(entities({ entities: [{ name: 'a', entityType: 'b', observations: [] }] }), true);
  assert.equal(entities({ entities: [{ name: 'a' }] }), false, 'local $defs reference');
  const time = find('convert_time');
  assert.equal(time({ source_timezone: 'UTC', time: '23:59', target_timezone: 'CET' }), true);
  assert.equal(time({ source_timezone: 'UTC', time: '24:00', target_timezone: 'CET' }), false);
});

test('uniqueItems compares canonical JSON, so key order does not hide a duplicate', () => {
  const validate = compileBoundedSchema({ type: 'array', uniqueItems: true });
  assert.equal(validate([{ a: 1, b: [1, 2] }, { b: [1, 2], a: 1 }]), false);
  assert.equal(validate([{ a: 1 }, { a: 2 }, 1, '1']), true);
  assert.equal(compileBoundedSchema({ type: 'array', uniqueItems: false })([1, 1]), true);
});

test('patterns with unbounded backtracking are refused; admitted ones stay fast', () => {
  for (const pattern of ['(a+)+$', '^(a|aa)+$', '(\\w)\\1', '^(?=x).*$', '(?<=x)y', 'a*b*', '^a*a*a*$', 'x'.repeat(513)]) {
    assert.throws(() => compileBoundedSchema({ type: 'string', pattern }), { code: 'SCHEMA_UNSUPPORTED' }, pattern);
  }
  const worst = compileBoundedSchema({ type: 'array', items: { type: 'string', pattern: '^\\d*\\d*x$' } });
  const started = performance.now();
  worst(Array.from({ length: 250 }, () => '1'.repeat(4_000)));
  assert.ok(performance.now() - started < 500, 'the per-validation pattern budget bounds total regex work');
  const single = compileBoundedSchema({ type: 'string', pattern: '^[a-z]+$' });
  assert.equal(single('a'.repeat(4_096)), true);
  assert.equal(single('a'.repeat(4_097)), false, 'longer strings never match a pattern');
});

test('dialects: draft-07, 2019-09 and 2020-12 are accepted; unknown dialects are not', () => {
  for (const $schema of ['http://json-schema.org/draft-07/schema#', 'https://json-schema.org/draft/2019-09/schema', 'https://json-schema.org/draft/2020-12/schema']) {
    assert.doesNotThrow(() => compileBoundedSchema({ $schema, type: 'object' }));
  }
  assert.throws(() => compileBoundedSchema({ $schema: 'https://example.com/custom', type: 'object' }), { code: 'SCHEMA_UNSUPPORTED' });
});

test('one unsupported tool schema is skipped and the rest of the registry loads', { timeout: 5_000 }, async t => {
  const server = new McpServer({ name: 'mixed', version: '1' });
  server.server.registerCapabilities({ tools: {} });
  server.server.setRequestHandler('tools/list', () => ({ tools: [
    { name: 'safe', inputSchema: { type: 'object', properties: { id: { type: 'string', pattern: '^[a-z]+$' } }, additionalProperties: false } },
    { name: 'catastrophic', inputSchema: { type: 'object', properties: { id: { type: 'string', pattern: '(a+)+$' } } } },
  ] }));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair(); await server.connect(serverTransport);
  t.after(() => server.close());
  const resolve = () => ({ resourceId: 'report', tenantId: 'acme' });
  const connection = await ManagedMcpConnection.connect({ guard: new AgentGuard(), identity, transport: clientTransport,
    tools: [{ name: 'safe', resolve }, { name: 'catastrophic', resolve }] });
  t.after(() => connection.close());
  assert.equal(connection.status, 'ready');
  assert.deepEqual(connection.registrations.map(entry => entry.remoteName), ['safe']);
  assert.deepEqual(connection.skipped.map(entry => ({ ...entry })), [{ kind: 'tool', remoteName: 'catastrophic', reason: 'SCHEMA_UNSUPPORTED' }]);
  assert.deepEqual(connection.inventory().operations.map(entry => entry.name), [connection.registrations[0].name]);
});
