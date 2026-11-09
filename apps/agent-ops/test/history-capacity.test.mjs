import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';
import { compactExportedTaskFamilies } from '../../../packages/executor/dist/lifecycle.js';
import { initializeRuntime, openRuntime, openMaintenance } from '../runtime.mjs';
import {
  companyHistory,
  HISTORY_SEGMENT_LIMIT,
  historySegmentUsage,
  assertHistorySegmentCapacity,
} from '../history-state.mjs';
import { encryptHistorySegment, historyFilename, historyHash } from '../history-files.mjs';
import {
  previewBusinessHistory,
  applyBusinessHistory,
  verifyHistoryStorage,
  businessHistoryBackupAdapter,
  lookupBusinessHistory,
} from '../retention.mjs';

function company(index) {
  return {
    namespace: randomUUID(),
    nextSequence: 1,
    highestExportedSequence: 0,
    archivedRequests: String(index),
    head: index ? { index, hash: 'a'.repeat(64), keyBase64: Buffer.alloc(32).toString('base64') } : null,
  };
}
function state(...indexes) {
  return {
    history: {
      version: 1,
      pending: null,
      companies: Object.fromEntries(indexes.map((index, i) => [`company-${i}`, company(index)])),
    },
  };
}
test('history capacity counts all companies and reserves a pending segment once', () => {
  const data = state(6000, 3999);
  assert.deepEqual(historySegmentUsage(data), {
    committed: 9999,
    reserved: 0,
    total: 9999,
    limit: HISTORY_SEGMENT_LIMIT,
  });
  assertHistorySegmentCapacity(data, 1);
  data.history.pending = { operationId: randomUUID() };
  assert.deepEqual(historySegmentUsage(data), {
    committed: 9999,
    reserved: 1,
    total: 10000,
    limit: HISTORY_SEGMENT_LIMIT,
  });
  assertHistorySegmentCapacity(data);
  assert.throws(() => assertHistorySegmentCapacity(data, 1), { code: 'HISTORY_SEGMENT_CAPACITY' });
  data.history.companies['company-1'].head.index++;
  assert.throws(() => assertHistorySegmentCapacity(data), { code: 'HISTORY_MIGRATION_REQUIRED' });
  assert.equal(historySegmentUsage(data).total, 10001, 'read-only monitoring retains the over-cap count');
});

test('history capacity rejects unsafe aggregate counters and invalid additional reservations', () => {
  assert.throws(() => historySegmentUsage(state(Number.MAX_SAFE_INTEGER, 1)), { code: 'HISTORY_COUNTER_CAPACITY' });
  for (const extra of [-1, 0.5, NaN, Infinity])
    assert.throws(() => assertHistorySegmentCapacity(state(), extra), { code: 'HISTORY_SCOPE_INVALID' });
  assert.deepEqual(historySegmentUsage({}), { committed: 0, reserved: 0, total: 0, limit: HISTORY_SEGMENT_LIMIT });
});

function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-history-cap-')));
  for (const name of ['data', 'witness', 'config', 'history', 'witness/history-mirror'])
    mkdirSync(join(root, name), { mode: 0o700 });
  const config = {
    ledgerDatabase: join(root, 'data/guard.sqlite'),
    backendDatabase: join(root, 'data/tickets.sqlite'),
    ledgerWitness: join(root, 'witness/guard.sqlite'),
    backendWitness: join(root, 'witness/tickets.sqlite'),
    keyringFile: join(root, 'config/keys.json'),
    historyDirectory: join(root, 'history'),
    historyMirrorDirectory: join(root, 'witness/history-mirror'),
  };
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'initial' });
  initializeRuntime(config, [
    { id: 'T-1', tenantId: 'acme', title: 'History capacity fixture', status: 'open' },
    { id: 'T-2', tenantId: 'other', title: 'Separate company fixture', status: 'open' },
  ]);
  let runtime, stores;
  const close = () => {
    runtime?.close();
    runtime = undefined;
    stores?.close();
    stores = undefined;
  };
  t.after(() => {
    close();
    rmSync(root, { recursive: true, force: true });
  });
  return {
    config,
    close,
    get stores() {
      return stores;
    },
    live() {
      close();
      return (runtime = openRuntime(config));
    },
    offline() {
      close();
      return (stores = openMaintenance(config, { allowHistoryPending: true }));
    },
  };
}
async function complete(runtime, tenantId, ticketId) {
  const actor = { id: 'owner', tenantId };
  const status = runtime.workflow.ticket(ticketId, tenantId).status === 'open' ? 'resolved' : 'open';
  const proposed = (await runtime.workflow.propose(actor, { ticketId, status })).request;
  return (await runtime.workflow.decide(actor, proposed.id, { digest: proposed.digest }, true)).request;
}

// Create an actual authenticated encrypted chain in linear time. Each segment
// contains a terminal request with no SDK task, as supported for failed creation.
// The normal verifier still reads/decrypts every segment; there is no fake cap or
// bypass of chain validation in the boundary and crash-resume checks below.
function appendRetainedFixture(stores, config, tenantId, count) {
  stores.backend.transaction(state => {
    companyHistory(state.ticketService, tenantId, true);
  });
  const backend = stores.backend.read(),
    guard = stores.guard.read(),
    retained = companyHistory(backend.ticketService, tenantId);
  const previousHash = retained.head?.hash ?? null;
  let head = retained.head;
  for (let offset = 0; offset < count; offset++) {
    const id = randomUUID(),
      operationId = randomUUID(),
      index = (head?.index ?? 0) + 1;
    const pending = {
      index,
      keyBase64: randomBytes(32).toString('base64'),
      ivBase64: randomBytes(12).toString('base64'),
    };
    const payload = {
      version: 1,
      backendInstanceId: backend.inventoryInstanceId,
      guardInstanceId: guard.inventoryInstanceId,
      tenantId,
      namespace: retained.namespace,
      operationId,
      index,
      createdAt: Date.now(),
      previous: head,
      requests: [{ id, taskId: `ticket:${id}`, operationId, tenantId, state: 'failed', noTask: true }],
      receipts: {},
      audit: [],
      archives: [],
    };
    const bytes = encryptHistorySegment(backend.inventoryInstanceId, tenantId, pending, payload);
    head = { index, hash: historyHash(bytes), keyBase64: pending.keyBase64 };
    const filename = historyFilename(backend.inventoryInstanceId, tenantId, head);
    for (const directory of [config.historyDirectory, config.historyMirrorDirectory])
      writeFileSync(join(directory, filename), bytes, { flag: 'wx', mode: 0o600 });
  }
  compactExportedTaskFamilies(stores.guard, {
    tenantId,
    namespace: retained.namespace,
    archiveIds: [],
    segmentHash: head.hash,
    previousHash,
  });
  stores.backend.transaction(state => {
    const company = companyHistory(state.ticketService, tenantId);
    company.head = head;
    company.archivedRequests = (BigInt(company.archivedRequests) + BigInt(count)).toString();
  });
}
function preserved(config) {
  return {
    authority: [
      config.ledgerDatabase,
      config.backendDatabase,
      config.ledgerWitness,
      config.backendWitness,
      config.keyringFile,
    ].map(path => readFileSync(path)),
    primaryFiles: readdirSync(config.historyDirectory).sort(),
    mirrorFiles: readdirSync(config.historyMirrorDirectory).sort(),
  };
}

test(
  'the real final history slot resumes after both intent and SDK crashes; excess compaction and legacy over-cap startup preserve authority',
  { skip: process.platform === 'win32' ? 'Witnessed single-owner history maintenance requires POSIX.' : false },
  async t => {
    const f = fixture(t),
      original = await complete(f.live(), 'acme', 'T-1');
    let stores = f.offline();
    appendRetainedFixture(stores, f.config, 'acme', 5000);
    appendRetainedFixture(stores, f.config, 'other', 4999);
    assert.equal(verifyHistoryStorage(stores, f.config, { includeFiles: true }).files.length, 9999);
    let preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    assert.throws(
      () =>
        applyBusinessHistory(stores, f.config, {
          tenantId: 'acme',
          digest: preview.digest,
          checkpoint(point) {
            if (point === 'intent-committed') throw Error('intent-crash');
          },
        }),
      /intent-crash/,
    );
    const priorIntent = stores.backend.read().ticketService.history.pending;
    assert.deepEqual(historySegmentUsage(stores.backend.read().ticketService), {
      committed: 9999,
      reserved: 1,
      total: 10000,
      limit: 10000,
    });

    stores = f.offline();
    preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    assert.equal(preview.status, 'recovery-required');
    assert.throws(
      () =>
        applyBusinessHistory(stores, f.config, {
          tenantId: 'acme',
          digest: preview.digest,
          checkpoint(point) {
            if (point === 'sdk-compacted') throw Error('sdk-crash');
          },
        }),
      /sdk-crash/,
    );
    assert.deepEqual(historySegmentUsage(stores.backend.read().ticketService), {
      committed: 9999,
      reserved: 1,
      total: 10000,
      limit: 10000,
    });
    const adapter = businessHistoryBackupAdapter(f.config);
    assert.equal(
      adapter.verify(
        new Map([
          ['authority', stores.guard],
          ['tickets', stores.backend],
        ]),
        f.config.historyMirrorDirectory,
      ).length,
      10000,
    );

    stores = f.offline();
    preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    assert.equal(applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: preview.digest }).requests, 1);
    assert.deepEqual(historySegmentUsage(stores.backend.read().ticketService), {
      committed: 10000,
      reserved: 0,
      total: 10000,
      limit: 10000,
    });
    assert.equal(verifyHistoryStorage(stores, f.config, { includeFiles: true }).files.length, 10000);
    assert.deepEqual(lookupBusinessHistory(stores, f.config, { tenantId: 'acme', requestId: original.id }).receipt, {
      ...original.receipt,
    });
    const live = f.live();
    assert.equal(live.workflow.ticket('T-1', 'acme').version, original.receipt.version);
    await complete(live, 'acme', 'T-1');
    await complete(live, 'other', 'T-2');
    stores = f.offline();
    const before = preserved(f.config);
    for (const tenantId of ['acme', 'other']) {
      assert.throws(() => previewBusinessHistory(stores, f.config, { tenantId }), { code: 'HISTORY_SEGMENT_CAPACITY' });
      assert.throws(() => applyBusinessHistory(stores, f.config, { tenantId, digest: '0'.repeat(64) }), {
        code: 'HISTORY_SEGMENT_CAPACITY',
      });
      assert.deepEqual(preserved(f.config), before);
    }
    assert.equal(stores.backend.read().ticketService.history.pending, null);

    // A durable intent left by an older writer must not turn the already full
    // manifest into a 10,001-file closure on resume.
    stores.backend.transaction(state => {
      const head = state.ticketService.history.companies.acme.head;
      state.ticketService.history.pending = {
        ...priorIntent,
        operationId: randomUUID(),
        previous: head,
        index: head.index + 1,
      };
    });
    const overReserved = preserved(f.config);
    assert.throws(() => applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: '0'.repeat(64) }), {
      code: 'HISTORY_MIGRATION_REQUIRED',
    });
    assert.deepEqual(preserved(f.config), overReserved);
    stores.backend.transaction(state => {
      state.ticketService.history.pending = null;
    });

    // Simulate an older writer that had no closure cap, while keeping the
    // actual encrypted chain and SDK/backend heads mutually consistent.
    appendRetainedFixture(stores, f.config, 'other', 1);
    const overCap = preserved(f.config);
    f.close();
    assert.throws(() => openRuntime(f.config), { code: 'HISTORY_MIGRATION_REQUIRED' });
    assert.throws(() => openRuntime(f.config, { checkOnly: true }), { code: 'HISTORY_MIGRATION_REQUIRED' });
    assert.deepEqual(preserved(f.config), overCap);
    t.diagnostic(
      'Validated 10,000 actual encrypted segments across two tenants, including mirrored pending closure; no limit override.',
    );
  },
);
