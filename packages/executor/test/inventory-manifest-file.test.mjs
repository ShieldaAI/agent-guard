import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor } from '../dist/index.js';
import {
  createInventoryObserverToken,
  loadInventoryManifestFile,
  startInventoryServer,
  validateInventoryManifest,
} from '../dist/entry-inventory.js';
import { removeAtExit } from './temp-directory.mjs';

// The loader needs POSIX ownership and permissions; Windows is refused (tested below).
const posix = typeof process.getuid === 'function';
const fixture = readFileSync(new URL('fixtures/inventory-manifest.json', import.meta.url), 'utf8');
const example = readFileSync(new URL('../../../examples/agent-manifest.example.json', import.meta.url), 'utf8');
const directory = mkdtempSync(join(tmpdir(), 'agent-guard-manifest-'));
removeAtExit(directory);
let files = 0;
function file(content, mode = 0o600) {
  const path = join(directory, `manifest-${files++}.json`);
  writeFileSync(path, content, { mode });
  chmodSync(path, mode);
  return path;
}
const refused = (path, code = 'INVENTORY_MANIFEST_FILE_INVALID') =>
  assert.throws(() => loadInventoryManifestFile(path), { name: 'ExecutorError', code, message: code });

test('a private manifest file loads as the same frozen manifest the validator returns', { skip: !posix }, () => {
  const manifest = loadInventoryManifestFile(file(fixture));
  assert.deepEqual(manifest, validateInventoryManifest(JSON.parse(fixture)));
  assert.ok(Object.isFrozen(manifest) && Object.isFrozen(manifest.agents[0]));
});

test('the file is read once: a later edit does not change the loaded manifest', { skip: !posix }, () => {
  const path = file(fixture);
  const manifest = loadInventoryManifestFile(path);
  writeFileSync(path, fixture.replace('Report agent', 'Edited after load'));
  assert.equal(manifest.agents[0].name, 'Report agent');
  assert.equal(loadInventoryManifestFile(path).agents[0].name, 'Edited after load');
});

test('a file that others can read or write, a link, or a non-file is refused', { skip: !posix }, () => {
  for (const mode of [0o640, 0o604, 0o660, 0o606, 0o644, 0o666]) refused(file(fixture, mode));
  const target = file(fixture);
  const symbolic = join(directory, 'symbolic.json');
  symlinkSync(target, symbolic);
  refused(symbolic);
  const hard = join(directory, 'hard.json');
  linkSync(target, hard);
  // Two names for one file: neither is accepted.
  refused(hard);
  refused(target);
  const folder = join(directory, 'folder');
  mkdirSync(folder, { mode: 0o700 });
  refused(folder);
  refused(join(directory, 'missing.json'));
});

test('only an absolute path from host configuration is accepted', { skip: !posix }, () => {
  for (const path of ['manifest.json', './manifest.json', '', `${file(fixture)}\0`, undefined, null, 7, {}])
    refused(path);
});

test(
  'oversized, non-UTF-8, non-JSON and duplicate-member files are refused without echoing content',
  { skip: !posix },
  () => {
    const canary = 'private-file-canary';
    for (const content of [
      `{"padding":"${'x'.repeat(2 * 1024 * 1024)}"}`,
      Buffer.from([0x7b, 0xff, 0x7d]),
      `${canary} {`,
      `﻿${fixture}`,
      fixture.replace('"schemaVersion": 1,', `"schemaVersion": 1, "schemaVersion": 1, "${canary}": 1,`),
      '',
    ]) {
      try {
        loadInventoryManifestFile(file(content));
        assert.fail('an invalid manifest file was loaded');
      } catch (error) {
        assert.equal(error.code, 'INVENTORY_MANIFEST_FILE_INVALID');
        assert.equal(String(error.stack).includes(canary), false);
      }
    }
  },
);

test('well-formed JSON that is not a valid manifest keeps the validator codes', { skip: !posix }, () => {
  refused(file('{}'), 'INVENTORY_MANIFEST_INVALID');
  refused(file('[]'), 'INVENTORY_MANIFEST_INVALID');
  const unknownField = JSON.parse(fixture);
  unknownField.agents[0].secret = 'value';
  refused(file(JSON.stringify(unknownField)), 'INVENTORY_MANIFEST_INVALID');
  const danglingDeployment = JSON.parse(fixture);
  danglingDeployment.deployments[0].agentId = 'no-such-agent';
  refused(file(JSON.stringify(danglingDeployment)), 'INVENTORY_MANIFEST_REFERENCE_INVALID');
});

test('a platform without POSIX ownership is refused before the file is opened', () => {
  const original = process.getuid;
  process.getuid = undefined;
  try {
    refused(join(directory, 'missing.json'), 'INVENTORY_MANIFEST_FILE_UNSUPPORTED');
  } finally {
    process.getuid = original;
  }
});

test(
  'the example file declares an agent that has never run a task, and the observer serves it',
  { skip: !posix },
  async t => {
    const executor = new DurableExecutor({
      database: ':memory:',
      encryptionKey: randomBytes(32),
      inventory: { companyId: 'example-company', sourceId: 'company-host', enrollmentGeneration: 'catalog-1' },
    });
    t.after(() => executor.close());
    // The one field an operator must copy from their own executor: its exact source identity.
    const { source } = executor.inventorySnapshot({ tenantId: 'example-tenant' });
    const manifest = loadInventoryManifestFile(file(JSON.stringify({ ...JSON.parse(example), source })));
    const token = createInventoryObserverToken();
    const server = await startInventoryServer({
      executor,
      observers: [{ token, tenantIds: ['example-tenant'], profile: 'host' }],
      manifests: [manifest],
    });
    t.after(() => server.close());
    const response = await fetch(`${server.url}/v1/inventory/snapshot`, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ tenantId: 'example-tenant' }),
    });
    const snapshot = await response.json();
    assert.equal(response.status, 200, JSON.stringify(snapshot));
    assert.deepEqual(snapshot.tasks, []);
    assert.deepEqual(
      snapshot.manifest.agents.map(agent => [agent.id, agent.name, agent.teamId]),
      [['invoice-agent', 'Invoice assistant', 'finance']],
    );
    assert.deepEqual(snapshot.manifest.taskBindings, []);
  },
);
