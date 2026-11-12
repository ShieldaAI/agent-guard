import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';
import {
  createInventoryObserverToken,
  loadInventoryManifestFile,
  startInventoryServer,
  validateInventoryManifest,
  validateMcpConnectionInventory,
} from '../dist/entry-inventory.js';
import { createInventoryObservationSession } from '../dist/entry-internal.js';
import { validateInventorySource } from '../dist/inventory.js';
import { isInventoryIdentifier, MAX_IDENTIFIER_CODE_POINTS } from '../dist/identifiers.js';
import { removeAtExit } from './temp-directory.mjs';

const posix = typeof process.getuid === 'function';
const fixture = JSON.parse(readFileSync(new URL('fixtures/inventory-manifest.json', import.meta.url), 'utf8'));
const enrollment = { companyId: 'company', sourceId: 'source', enrollmentGeneration: 'generation' };
function executor(t) {
  const result = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32), inventory: enrollment });
  t.after(() => result.close());
  return result;
}
const observers = () => [{ token: createInventoryObserverToken(), tenantIds: ['tenant'] }];

test('a second inventory listener with a different reuse window is refused, not silently ignored', async t => {
  const owner = executor(t);
  const first = await createInventoryObservationSession(owner, 'default', { reuseUnchangedMs: 5000 });
  t.after(() => first.close());
  for (const options of [{ reuseUnchangedMs: 0 }, {}, { reuseUnchangedMs: 60_000 }])
    await assert.rejects(createInventoryObservationSession(owner, 'default', options), {
      name: 'ExecutorError',
      code: 'INVENTORY_CONFIG_INVALID',
      detail: 'REUSE_WINDOW_MISMATCH',
    });
  // The same window shares the first listener's worker.
  const same = await createInventoryObservationSession(owner, 'default', { reuseUnchangedMs: 5000 });
  await same.close();
  // The refused listeners did not disturb the first one.
  const request = {
    scope: { tenantId: 'tenant' },
    profile: 'core',
    signal: new AbortController().signal,
    deadline: performance.now() + 10_000,
  };
  const before = JSON.parse((await first.snapshot(request)).json);
  assert.equal(JSON.parse((await first.snapshot(request)).json).snapshotId, before.snapshotId, 'reuse still applies');
});

test('two inventory servers on one executor must agree on reuseUnchangedMs', async t => {
  const owner = executor(t);
  const first = await startInventoryServer({ executor: owner, observers: observers(), reuseUnchangedMs: 1000 });
  t.after(() => first.close());
  await assert.rejects(startInventoryServer({ executor: owner, observers: observers() }), {
    name: 'ExecutorError',
    code: 'INVENTORY_CONFIG_INVALID',
    detail: 'REUSE_WINDOW_MISMATCH',
  });
  const second = await startInventoryServer({ executor: owner, observers: observers(), reuseUnchangedMs: 1000 });
  await second.close();
  await first.close();
  // Once every listener is closed the next one chooses the window again.
  const third = await startInventoryServer({ executor: owner, observers: observers() });
  await third.close();
});

/** Count JSON values the way the manifest limits do: every object, array and scalar. */
function values(value) {
  if (value === null || typeof value !== 'object') return 1;
  let count = 1;
  for (const item of Array.isArray(value) ? value : Object.values(value)) count += values(item);
  return count;
}
/** A valid manifest whose size comes from many short IAM action names. */
function largeManifest(bindings) {
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const actions = [];
  for (const a of letters) actions.push(`s3:${a}`);
  for (const a of letters) for (const b of 'ab') if (actions.length < 128) actions.push(`s3:${a}${b}`);
  const manifest = structuredClone(fixture);
  const [binding] = manifest.resourceBindings;
  manifest.resourceBindings = Array.from({ length: bindings }, (_, index) => ({
    ...binding,
    id: `r${index}`,
    resourceRef: `i${index}`,
    actions,
  }));
  return manifest;
}
function privateFile(content) {
  const directory = mkdtempSync(join(tmpdir(), 'agent-guard-release-inventory-'));
  removeAtExit(directory);
  const path = join(directory, 'manifest.json');
  writeFileSync(path, content, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

test('the manifest file loader accepts every manifest size the validator accepts', { skip: !posix }, () => {
  const manifest = largeManifest(1000);
  const count = values(manifest);
  const json = JSON.stringify(manifest);
  assert.ok(count > 100_000 && count <= 200_000, `fixture has ${count} values`);
  assert.ok(Buffer.byteLength(json) <= 2 * 1024 * 1024);
  const validated = validateInventoryManifest(manifest);
  assert.deepEqual(loadInventoryManifestFile(privateFile(json)), validated);
});

test('past 200,000 values the loader and the validator refuse with the same code', { skip: !posix }, () => {
  const manifest = largeManifest(1500);
  const json = JSON.stringify(manifest);
  assert.ok(values(manifest) > 200_000);
  assert.ok(Buffer.byteLength(json) <= 2 * 1024 * 1024, 'only the value count is over a limit');
  const expected = { name: 'ExecutorError', code: 'INVENTORY_MANIFEST_LIMIT_EXCEEDED' };
  assert.throws(() => validateInventoryManifest(manifest), expected);
  assert.throws(() => loadInventoryManifestFile(privateFile(json)), expected);
});

const accepted = [
  'agent',
  'a'.repeat(MAX_IDENTIFIER_CODE_POINTS),
  '😀'.repeat(MAX_IDENTIFIER_CODE_POINTS),
  'a\n\t\u001c\u0085z',
];
const refused = [
  '',
  ' \t\n\u001c\u0085',
  'a\0b',
  'a\ud800',
  '\udc00a',
  'a'.repeat(MAX_IDENTIFIER_CODE_POINTS + 1),
  '😀'.repeat(MAX_IDENTIFIER_CODE_POINTS + 1),
  // 4,097 code points inside 8,192 UTF-16 units: only a code-point count refuses it.
  'aa' + '😀'.repeat(MAX_IDENTIFIER_CODE_POINTS - 1),
  7,
  null,
  undefined,
  ['agent'],
];
const mcpInventory = serverId => ({
  schemaVersion: 1,
  identity: { serverId, transportRef: `opaque:${'b'.repeat(64)}`, principalId: 'caller', tenantId: 'tenant' },
  sessionId: 'session',
  revision: 1,
  authorizationEpoch: 1,
  metadataRevision: 1,
  state: 'ready',
  metadataState: 'current',
  observedAt: '2026-10-29T00:00:00.000Z',
  operations: [],
});
/** Every public inventory entry point that validates an identifier, with its own refusal code. */
const entryPoints = {
  'ledger source': [value => validateInventorySource({ ...enrollment, sourceId: value }), 'INVENTORY_CONFIG_INVALID'],
  'host manifest': [
    value => validateInventoryManifest({ ...structuredClone(fixture), manifestId: value }),
    'INVENTORY_MANIFEST_INVALID',
  ],
  'MCP inventory': [value => validateMcpConnectionInventory(mcpInventory(value)), 'INVENTORY_MCP_INVALID'],
};

test('one identifier rule decides for the ledger, manifest, MCP and observer entry points', async t => {
  assert.equal(MAX_IDENTIFIER_CODE_POINTS, 4096);
  for (const value of accepted) assert.equal(isInventoryIdentifier(value), true);
  for (const value of refused) assert.equal(isInventoryIdentifier(value), false);
  for (const [name, [validate, code]] of Object.entries(entryPoints)) {
    for (const value of accepted) assert.doesNotThrow(() => validate(value), name);
    for (const value of refused) assert.throws(() => validate(value), { name: 'ExecutorError', code }, name);
  }
  const owner = executor(t);
  const start = tenantId =>
    startInventoryServer({
      executor: owner,
      observers: [{ token: createInventoryObserverToken(), tenantIds: [tenantId] }],
    });
  for (const value of accepted) await (await start(value)).close();
  for (const value of refused)
    await assert.rejects(start(value), { name: 'ExecutorError', code: 'INVENTORY_SERVER_CONFIG_INVALID' });
});
