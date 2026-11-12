import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  readFileSync,
  readdirSync,
  copyFileSync,
  writeFileSync,
  symlinkSync,
  linkSync,
  chmodSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { createLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';
import { verifyTransferredTaskFamilyArchive } from '../../../packages/executor/dist/lifecycle.js';
import { initializeRuntime, openRuntime, openMaintenance } from '../runtime.mjs';
import { normalizeLimits } from '../limits.mjs';
import {
  previewBusinessHistory,
  applyBusinessHistory,
  verifyHistoryStorage,
  lookupBusinessHistory,
  enrollBusinessHistory,
  businessHistoryBackupAdapter,
} from '../retention.mjs';
import { decryptHistorySegment, encryptHistorySegment, readHistoryFile } from '../history-files.mjs';

const test = (name, fn) =>
  nodeTest(
    name,
    { skip: process.platform === 'win32' ? 'Witnessed single-owner history maintenance requires POSIX.' : false },
    fn,
  );
const owner = { id: 'owner', tenantId: 'acme' };
function fixture(t, { maxRequests = 2, afterCommit } = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-retention-')));
  for (const name of ['data', 'witness', 'config', 'history']) mkdirSync(join(directory, name), { mode: 0o700 });
  const config = {
    limits: normalizeLimits({ maxRequests }),
    ledgerDatabase: join(directory, 'data', 'guard.sqlite'),
    backendDatabase: join(directory, 'data', 'tickets.sqlite'),
    ledgerWitness: join(directory, 'witness', 'guard.sqlite'),
    backendWitness: join(directory, 'witness', 'tickets.sqlite'),
    keyringFile: join(directory, 'config', 'keys.json'),
    historyDirectory: join(directory, 'history'),
  };
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'initial' });
  initializeRuntime(config, [
    { id: 'T-1', tenantId: 'acme', title: 'PRIVATE RETAINED BUSINESS TITLE', status: 'open' },
    { id: 'T-2', tenantId: 'other', title: 'Other company', status: 'open' },
  ]);
  let runtime = openRuntime(config, { afterCommit }),
    stores;
  const close = () => {
    runtime?.close();
    runtime = undefined;
    stores?.close();
    stores = undefined;
  };
  t.after(() => {
    close();
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    config,
    directory,
    get runtime() {
      return runtime;
    },
    get stores() {
      return stores;
    },
    close,
    live(options) {
      close();
      return (runtime = openRuntime(config, options));
    },
    offline(options) {
      close();
      return (stores = openMaintenance(config, options));
    },
  };
}
async function complete(f, actor = owner, ticketId = 'T-1') {
  const status = f.runtime.workflow.ticket(ticketId, actor.tenantId).status === 'open' ? 'resolved' : 'open';
  const request = (await f.runtime.workflow.propose(actor, { ticketId, status })).request;
  return (await f.runtime.workflow.decide(actor, request.id, { digest: request.digest }, true)).request;
}
function compact(f, options = {}) {
  const stores = f.offline({ allowHistoryPending: true }),
    preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme', ...options });
  return applyBusinessHistory(stores, f.config, { tenantId: 'acme', ...options, digest: preview.digest });
}

test('reviewed company history permits repeated capacity reuse without identity or receipt loss', async t => {
  const f = fixture(t),
    saved = [],
    start = performance.now();
  for (let batch = 0; batch < 8; batch++) {
    saved.push(await complete(f), await complete(f));
    await assert.rejects(f.runtime.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' }), {
      code: 'RECORD_CAPACITY_REACHED',
    });
    const result = compact(f);
    assert.equal(result.requests, 2);
    assert.equal(result.segment, batch + 1);
    const guard = f.stores.guard.read(),
      data = f.stores.backend.read().ticketService;
    assert.equal(Object.keys(guard.tasks).length, 0);
    assert.equal(Object.keys(guard.lifecycle.archives).length, 0);
    assert.equal(Object.keys(guard.lifecycle.archivedTaskIds).length, 0);
    assert.equal(Object.keys(data.requests).length, 0);
    assert.equal(Object.keys(data.receipts).length, 0);
    assert.equal(data.audit.length, 0);
    assert.equal(data.history.companies.acme.archivedRequests, String((batch + 1) * 2));
    const verificationStarted = performance.now(),
      history = verifyHistoryStorage(f.stores, f.config);
    assert.equal(history.segments, batch + 1);
    if (batch === 7)
      t.diagnostic(
        `Full verification: ${history.segments} segments, ${history.bytes} encrypted bytes, ${Math.round(performance.now() - verificationStarted)} ms on this local fixture.`,
      );
    const found = lookupBusinessHistory(f.stores, f.config, { tenantId: 'acme', requestId: saved[0].id });
    assert.deepEqual(found.receipt, { ...saved[0].receipt });
    assert.throws(() => f.stores.guard.readArchive(found.request.archived), { code: 'STORE_ARCHIVE_UNAVAILABLE' });
    assert.equal(lookupBusinessHistory(f.stores, f.config, { tenantId: 'other', requestId: saved[0].id }), null);
    f.live();
    for (const tenantId of ['acme', 'other'])
      assert.throws(
        () =>
          f.runtime.executor.createTask({
            id: `ticket:${saved[0].id}`,
            tenantId,
            principalId: 'owner',
            grants: [],
            budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: Date.now() + 60_000 },
          }),
        { code: 'DUPLICATE_TASK' },
      );
  }
  assert.equal(new Set(saved.map(request => request.id)).size, 16);
  assert.equal(f.runtime.workflow.ticket('T-1', 'acme').version, 17);
  for (const file of readdirSync(f.config.historyDirectory))
    assert.equal(
      readFileSync(join(f.config.historyDirectory, file)).includes(Buffer.from('PRIVATE RETAINED BUSINESS TITLE')),
      false,
    );
  t.diagnostic(
    `8 retained segments /16 exact receipts; end-to-end local duration ${Math.round(performance.now() - start)} ms; no throughput SLA implied.`,
  );
});

test('legacy UUID requests retain permanent tombstones and exact archived root budgets', async t => {
  const f = fixture(t),
    id = randomUUID(),
    taskId = `ticket:${id}`,
    expiresAt = Date.now() + 300_000;
  const request = {
    id,
    taskId,
    operationId: randomUUID(),
    tenantId: 'acme',
    requesterId: 'owner',
    ticketId: 'T-1',
    title: 'Legacy ticket',
    beforeStatus: 'open',
    afterStatus: 'resolved',
    resourceVersion: '1',
    createdAt: Date.now(),
    expiresAt,
    state: 'preparing',
  };
  f.runtime.workflow.write(data => {
    data.requests[id] = request;
  });
  const budget = { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: expiresAt };
  const credential = f.runtime.executor.createTask({
    id: taskId,
    principalId: 'owner',
    tenantId: 'acme',
    grants: [{ tool: 'ticket.update', resources: ['T-1'] }],
    budget,
  });
  const prepared = await f.runtime.executor.prepare(taskId, { tool: 'ticket.update', args: { requestId: id } });
  const digest = createHash('sha256')
    .update(JSON.stringify([id, prepared.digest, 'T-1', 'open', 'resolved', '1', expiresAt]))
    .digest('hex');
  f.runtime.workflow.write(data => {
    Object.assign(data.requests[id], {
      actionId: prepared.id,
      actionDigest: prepared.digest,
      digest,
      state: 'pending',
    });
  });
  const completed = (await f.runtime.workflow.decide(owner, id, { digest }, true)).request;
  compact(f);
  assert.equal(Object.keys(f.stores.guard.read().lifecycle.archivedTaskIds).length, 1);
  const closure = verifyHistoryStorage(f.stores, f.config, { includeFiles: true }),
    backend = f.stores.backend.read(),
    company = backend.ticketService.history.companies.acme;
  const payload = decryptHistorySegment(
    readFileSync(closure.files[0].path),
    backend.inventoryInstanceId,
    'acme',
    company.head,
  );
  const decoded = verifyTransferredTaskFamilyArchive(f.stores.guard.read().inventoryInstanceId, payload.archives[0]);
  assert.deepEqual(decoded.tasks[taskId].options.budget, budget);
  assert.equal(decoded.tasks[taskId].calls, 1);
  assert.equal(decoded.tasks[taskId].spent, 1);
  assert.equal(decoded.tasks[taskId].revoked, true);
  assert.deepEqual(lookupBusinessHistory(f.stores, f.config, { tenantId: 'acme', requestId: id }).receipt, {
    ...completed.receipt,
  });
  f.live();
  assert.throws(() => f.runtime.executor.authenticate(credential.token), { code: 'UNAUTHENTICATED' });
  assert.throws(
    () => f.runtime.executor.createTask({ id: taskId, principalId: 'other', tenantId: 'other', grants: [], budget }),
    { code: 'DUPLICATE_TASK' },
  );
  const next = await complete(f);
  assert.match(next.id, /^[a-f0-9-]{36}-1$/);
});

test('a missing business head cannot hide an exported SDK commitment', async t => {
  const f = fixture(t);
  await complete(f);
  compact(f);
  f.stores.backend.transaction(state => {
    delete state.ticketService.history;
  });
  assert.throws(() => verifyHistoryStorage(f.stores, f.config), { code: 'HISTORY_COMMITMENT_MISMATCH' });
});

test('unconfirmed work is retained and cannot be crossed by a namespace retirement fence', async t => {
  const f = fixture(t, {
    afterCommit() {
      throw Error('lost response');
    },
  });
  const unknown = await complete(f);
  assert.equal(unknown.state, 'unconfirmed');
  const unknownReceipt = f.runtime.workflow.data().receipts[f.runtime.workflow.request(unknown.id).operationId];
  f.live();
  const second = await complete(f);
  let stores = f.offline(),
    preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.equal(preview.count, 1);
  assert.equal(preview.excludedUnresolved, 1);
  applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: preview.digest });
  const guard = stores.guard.read(),
    namespace = second.id.slice(0, 36);
  assert.equal(guard.lifecycle.namespaceFences[namespace].through, 0);
  assert.equal(Object.keys(guard.lifecycle.archivedTaskIds).length, 1);
  assert.equal(guard.tasks[`ticket:${unknown.id}`].reserved, 1);
  f.live();
  assert.throws(
    () =>
      f.runtime.executor.createTask({
        id: `ticket:${second.id}`,
        tenantId: 'acme',
        principalId: 'owner',
        grants: [],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: Date.now() + 60_000 },
      }),
    { code: 'DUPLICATE_TASK' },
  );
  assert.equal(f.runtime.workflow.reconcile(owner, unknown.id).request.state, 'completed');
  compact(f);
  stores = f.stores;
  assert.equal(stores.guard.read().lifecycle.namespaceFences[namespace].through, 2);
  assert.equal(Object.keys(stores.guard.read().lifecycle.archivedTaskIds).length, 0);
  assert.deepEqual(lookupBusinessHistory(stores, f.config, { tenantId: 'acme', requestId: unknown.id }).receipt, {
    ...unknownReceipt,
  });
});

for (const phase of [
  'intent-committed',
  'task-archived',
  'plaintext-bound',
  'export-planned',
  'export-durable',
  'sdk-compacted',
  'business-compacted',
]) {
  test(`history recovery is fail-closed and exact after ${phase}`, async t => {
    const f = fixture(t),
      original = await complete(f),
      stores = f.offline(),
      review = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    let interrupted = false;
    assert.throws(
      () =>
        applyBusinessHistory(stores, f.config, {
          tenantId: 'acme',
          digest: review.digest,
          checkpoint(point) {
            if (point === phase && !interrupted) {
              interrupted = true;
              throw Error('fixture crash');
            }
          },
        }),
      /fixture crash/,
    );
    assert.equal(interrupted, true);
    f.close();
    if (phase !== 'business-compacted') {
      assert.throws(() => openRuntime(f.config), { code: 'HISTORY_RECOVERY_REQUIRED' });
      const reopened = f.offline({ allowHistoryPending: true }),
        next = previewBusinessHistory(reopened, f.config, { tenantId: 'acme' });
      assert.equal(next.status, 'recovery-required');
      assert.equal(applyBusinessHistory(reopened, f.config, { tenantId: 'acme', digest: next.digest }).requests, 1);
    }
    const verified = f.offline();
    assert.equal(verifyHistoryStorage(verified, f.config).segments, 1);
    assert.deepEqual(lookupBusinessHistory(verified, f.config, { tenantId: 'acme', requestId: original.id }).receipt, {
      ...original.receipt,
    });
    f.live();
    assert.equal(f.runtime.workflow.ticket('T-1', 'acme').version, 2);
  });
}

test('a changed reviewed source cannot reuse the pending encryption key and nonce', async t => {
  const f = fixture(t),
    original = await complete(f),
    stores = f.offline(),
    review = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.throws(
    () =>
      applyBusinessHistory(stores, f.config, {
        tenantId: 'acme',
        digest: review.digest,
        checkpoint(point) {
          if (point === 'export-planned') throw Error('fixture pause');
        },
      }),
    /fixture pause/,
  );
  const pending = stores.backend.read().ticketService.history.pending;
  stores.backend.transaction(state => {
    state.ticketService.requests[original.id].title = 'changed after encryption binding';
  });
  const next = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  let encryptions = 0;
  assert.throws(
    () =>
      applyBusinessHistory(stores, f.config, {
        tenantId: 'acme',
        digest: next.digest,
        checkpoint(point) {
          if (point === 'encrypting') encryptions++;
        },
      }),
    { code: 'HISTORY_SOURCE_CHANGED' },
  );
  assert.equal(encryptions, 0);
  assert.deepEqual(readdirSync(f.config.historyDirectory), []);
  assert.equal(stores.backend.read().ticketService.history.pending.keyBase64, pending.keyBase64);
  assert.equal(Object.keys(stores.guard.read().lifecycle.archives).length, 1);
});

test('partial private staging recovers without overwriting a link or unrelated file', async t => {
  const f = fixture(t);
  await complete(f);
  const stores = f.offline(),
    preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.throws(
    () =>
      applyBusinessHistory(stores, f.config, {
        tenantId: 'acme',
        digest: preview.digest,
        checkpoint(point) {
          if (point === 'export-planned') throw Error('fixture pause');
        },
      }),
    /fixture pause/,
  );
  const pending = stores.backend.read().ticketService.history.pending,
    temp = join(f.config.historyDirectory, `.pending-${pending.operationId}`);
  const keyring = readFileSync(f.config.keyringFile);
  symlinkSync(f.config.keyringFile, temp);
  let next = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.throws(() => applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: next.digest }), {
    code: 'HISTORY_EVIDENCE_INVALID',
  });
  assert.deepEqual(readFileSync(f.config.keyringFile), keyring);
  rmSync(temp);
  writeFileSync(temp, 'partial ciphertext before a crash', { mode: 0o600 });
  next = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.equal(applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: next.digest }).requests, 1);
  assert.equal(
    readdirSync(f.config.historyDirectory).some(file => file.startsWith('.pending-')),
    false,
  );
});

test('missing or substituted retained evidence and backend rollback stop normal startup', async t => {
  const f = fixture(t);
  await complete(f);
  compact(f);
  const oldBackend = readFileSync(f.config.backendDatabase);
  f.live();
  await complete(f);
  compact(f);
  const files = verifyHistoryStorage(f.stores, f.config, { includeFiles: true }).files,
    historical = files.at(-1).path,
    bytes = readFileSync(historical);
  f.close();
  rmSync(historical);
  assert.throws(() => openRuntime(f.config), { code: 'HISTORY_EVIDENCE_UNAVAILABLE' });
  writeFileSync(historical, Buffer.alloc(bytes.length, 120), { mode: 0o600 });
  assert.throws(() => openRuntime(f.config), { code: 'HISTORY_EVIDENCE_INVALID' });
  writeFileSync(historical, bytes, { mode: 0o600 });
  const currentBackend = readFileSync(f.config.backendDatabase);
  writeFileSync(f.config.backendDatabase, oldBackend);
  assert.throws(() => openRuntime(f.config), { code: 'LEDGER_KEY_UNAVAILABLE' });
  writeFileSync(f.config.backendDatabase, currentBackend);
  f.live();
  assert.equal(f.runtime.workflow.ticket('T-1', 'acme').version, 3);
});

test('fresh-volume history relocation requires full verification and explicit re-enrollment', async t => {
  const f = fixture(t);
  const original = await complete(f);
  compact(f);
  const previousHead = f.stores.backend.read().ticketService.history.companies.acme.head;
  f.live();
  await complete(f);
  compact(f);
  const closure = verifyHistoryStorage(f.stores, f.config, { includeFiles: true }),
    newest = closure.files[0];
  assert.throws(
    () =>
      decryptHistorySegment(readFileSync(newest.path), f.stores.backend.read().inventoryInstanceId, 'acme', {
        ...f.stores.backend.read().ticketService.history.companies.acme.head,
        keyBase64: previousHead.keyBase64,
      }),
    { code: 'HISTORY_EVIDENCE_INVALID' },
  );
  const replacement = join(f.directory, 'restored-history');
  mkdirSync(replacement, { mode: 0o700 });
  for (const file of readdirSync(f.config.historyDirectory))
    copyFileSync(join(f.config.historyDirectory, file), join(replacement, file));
  f.close();
  f.config.historyDirectory = replacement;
  assert.throws(() => openRuntime(f.config), { code: 'HISTORY_DIRECTORY_NOT_ENROLLED' });
  const stores = f.offline({ ignoreHistoryEnrollment: true });
  assert.throws(
    () =>
      businessHistoryBackupAdapter(f.config).verify(
        new Map([
          ['authority', stores.guard],
          ['tickets', stores.backend],
        ]),
        replacement,
      ),
    { code: 'HISTORY_DIRECTORY_NOT_ENROLLED' },
  );
  const review = enrollBusinessHistory(stores, f.config);
  assert.equal(enrollBusinessHistory(stores, f.config, { apply: true, digest: review.digest }).status, 'enrolled');
  const adapter = businessHistoryBackupAdapter(f.config),
    files = adapter.verify(
      new Map([
        ['authority', stores.guard],
        ['tickets', stores.backend],
      ]),
      replacement,
    );
  assert.equal(files.length, 2);
  assert.ok(files.every(file => /^[a-f0-9]{64}$/.test(file.sha256)));
  assert.equal(
    lookupBusinessHistory(stores, f.config, { tenantId: 'acme', requestId: original.id }).receipt.version,
    2,
  );
  f.live();
  assert.equal(f.runtime.workflow.ticket('T-1', 'acme').version, 3);
});

test('a pending SDK commit can recover after verified history-volume relocation', async t => {
  const f = fixture(t),
    request = await complete(f),
    stores = f.offline(),
    review = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.throws(
    () =>
      applyBusinessHistory(stores, f.config, {
        tenantId: 'acme',
        digest: review.digest,
        checkpoint(point) {
          if (point === 'sdk-compacted') throw Error('fixture crash');
        },
      }),
    /fixture crash/,
  );
  const replacement = join(f.directory, 'replacement-history');
  mkdirSync(replacement, { mode: 0o700 });
  for (const file of readdirSync(f.config.historyDirectory))
    copyFileSync(join(f.config.historyDirectory, file), join(replacement, file));
  f.close();
  f.config.historyDirectory = replacement;
  const reopened = f.offline({ allowHistoryPending: true, ignoreHistoryEnrollment: true }),
    enrollment = enrollBusinessHistory(reopened, f.config);
  enrollBusinessHistory(reopened, f.config, { apply: true, digest: enrollment.digest });
  f.close();
  assert.throws(() => openRuntime(f.config), { code: 'HISTORY_RECOVERY_REQUIRED' });
  compact(f);
  assert.equal(
    lookupBusinessHistory(f.stores, f.config, { tenantId: 'acme', requestId: request.id }).receipt.version,
    2,
  );
  f.live();
  assert.equal(f.runtime.workflow.ticket('T-1', 'acme').version, 2);
});

test('compaction applies exactly the reviewed batch even when another review expires meanwhile', async t => {
  const f = fixture(t, { maxRequests: 4 });
  const done = await complete(f);
  // Still awaiting review now; it expires five minutes from now.
  const waiting = (await f.runtime.workflow.propose(owner, { ticketId: 'T-1', status: 'open' })).request;
  const stores = f.offline({ allowHistoryPending: true }),
    preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
  assert.equal(preview.count, 1, 'only the completed request was reviewed');
  // The clock passes the waiting review's expiry right after the batch is selected for the digest check.
  const now = Date.now;
  let calls = 0;
  t.after(() => {
    Date.now = now;
  });
  Date.now = () => (calls++ === 0 ? now() : now() + 10 * 60_000);
  const applied = applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: preview.digest });
  Date.now = now;
  assert.ok(calls > 1);
  assert.equal(applied.requests, 1, 'the request that expired after the review was not swept into the batch');
  const data = stores.backend.read().ticketService;
  assert.deepEqual(Object.keys(data.requests), [waiting.id]);
  assert.equal(data.requests[waiting.id].state, 'pending');
  assert.equal(lookupBusinessHistory(stores, f.config, { tenantId: 'acme', requestId: done.id }).request.id, done.id);
  assert.equal(lookupBusinessHistory(stores, f.config, { tenantId: 'acme', requestId: waiting.id }), null);
});

test('a history file with a wrong mode, an extra link or a symbolic link is a tamper finding, not an outage', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-history-file-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(join(directory, 'segment.agh'), 'ciphertext', { mode: 0o600 });
  assert.equal(readHistoryFile(directory, 'segment.agh').toString(), 'ciphertext');
  chmodSync(join(directory, 'segment.agh'), 0o644);
  assert.throws(() => readHistoryFile(directory, 'segment.agh'), { code: 'HISTORY_EVIDENCE_INVALID' });
  chmodSync(join(directory, 'segment.agh'), 0o600);
  linkSync(join(directory, 'segment.agh'), join(directory, 'second-name.agh'));
  assert.throws(() => readHistoryFile(directory, 'segment.agh'), { code: 'HISTORY_EVIDENCE_INVALID' });
  rmSync(join(directory, 'second-name.agh'));
  symlinkSync(join(directory, 'segment.agh'), join(directory, 'alias.agh'));
  assert.throws(() => readHistoryFile(directory, 'alias.agh'), { code: 'HISTORY_EVIDENCE_INVALID' });
  // Only a file that cannot be opened at all is reported as unavailable.
  assert.throws(() => readHistoryFile(directory, 'absent.agh'), { code: 'HISTORY_EVIDENCE_UNAVAILABLE' });
});

test('a history segment decrypts only with a full 16-byte tag and a 12-byte nonce', () => {
  const backendId = randomUUID(),
    pending = {
      index: 1,
      keyBase64: randomBytes(32).toString('base64'),
      ivBase64: randomBytes(12).toString('base64'),
    },
    payload = { version: 1, backendInstanceId: backendId, tenantId: 'acme', index: 1, previous: null },
    bytes = encryptHistorySegment(backendId, 'acme', pending, payload);
  // The head hash is recomputed for every variant, so only the cipher checks stand between it and acceptance.
  const open = candidate =>
    decryptHistorySegment(candidate, backendId, 'acme', {
      index: 1,
      hash: createHash('sha256').update(candidate).digest('hex'),
      keyBase64: pending.keyBase64,
    });
  assert.deepEqual(open(bytes), payload);
  const envelope = JSON.parse(bytes.toString('utf8')),
    tag = Buffer.from(envelope.tag, 'base64');
  assert.equal(tag.length, 16);
  for (const length of [0, 4, 8, 12, 15])
    assert.throws(
      () => open(Buffer.from(JSON.stringify({ ...envelope, tag: tag.subarray(0, length).toString('base64') }))),
      { code: 'HISTORY_EVIDENCE_INVALID' },
      `a ${length}-byte tag`,
    );
  for (const length of [8, 16])
    assert.throws(
      () => open(Buffer.from(JSON.stringify({ ...envelope, iv: randomBytes(length).toString('base64') }))),
      { code: 'HISTORY_EVIDENCE_INVALID' },
      `a ${length}-byte nonce`,
    );
});
