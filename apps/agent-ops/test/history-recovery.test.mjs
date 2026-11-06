import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, readFileSync, readdirSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';
import { initializeRuntime, openRuntime, openMaintenance } from '../runtime.mjs';
import { normalizeLimits } from '../limits.mjs';
import { previewBusinessHistory, applyBusinessHistory, verifyHistoryStorage, enrollBusinessHistoryMirror,
  businessHistoryBackupAdapter, enrollBusinessHistory, lookupBusinessHistory } from '../retention.mjs';
import { privateHistoryMirrorDirectory, historyFilename } from '../history-files.mjs';
import { manageBusinessRecovery } from '../custody.mjs';

const test = (name, fn) => nodeTest(name, { skip: process.platform === 'win32' ? 'Independent witnessed recovery requires POSIX.' : false }, fn);
const owner = { id: 'owner', tenantId: 'acme' };
function fixture(t, { mirror = true } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-history-recovery-')));
  for (const name of ['data', 'witness', 'config', 'history']) mkdirSync(join(root, name), { mode: 0o700 });
  const mirrorDirectory = join(root, 'witness', 'history-mirror'); mkdirSync(mirrorDirectory, { mode: 0o700 });
  const config = { limits: normalizeLimits(), ledgerDatabase: join(root, 'data', 'guard.sqlite'), backendDatabase: join(root, 'data', 'tickets.sqlite'),
    ledgerWitness: join(root, 'witness', 'guard.sqlite'), backendWitness: join(root, 'witness', 'tickets.sqlite'),
    keyringFile: join(root, 'config', 'keys.json'), historyDirectory: join(root, 'history'),
    ...(mirror ? { historyMirrorDirectory: mirrorDirectory } : {}) };
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'initial' });
  initializeRuntime(config, [{ id: 'T-1', tenantId: 'acme', title: 'PRIVATE RECOVERY RECEIPT', status: 'open' }]);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, config, mirrorDirectory };
}
async function complete(config) {
  const runtime = openRuntime(config);
  try {
    const status = runtime.workflow.ticket('T-1', 'acme').status === 'open' ? 'resolved' : 'open';
    const request = (await runtime.workflow.propose(owner, { ticketId: 'T-1', status })).request;
    return (await runtime.workflow.decide(owner, request.id, { digest: request.digest }, true)).request;
  } finally { runtime.close(); }
}
function compact(config, checkpoint) {
  const stores = openMaintenance(config, { allowHistoryPending: true });
  try {
    const plan = previewBusinessHistory(stores, config, { tenantId: 'acme' });
    return applyBusinessHistory(stores, config, { tenantId: 'acme', digest: plan.digest, checkpoint });
  } finally { stores.close(); }
}
const names = directory => readdirSync(directory).filter(name => name.endsWith('.agh'));

test('new mirrored history keeps identical encrypted evidence and rejects a disabled or missing mirror', async t => {
  const f = fixture(t), request = await complete(f.config); compact(f.config);
  const files = names(f.config.historyDirectory); assert.equal(files.length, 1);
  const original = readFileSync(join(f.config.historyDirectory, files[0]));
  assert.deepEqual(readFileSync(join(f.mirrorDirectory, files[0])), original);
  assert.equal(original.includes(Buffer.from('PRIVATE RECOVERY RECEIPT')), false);
  const stores = openMaintenance(f.config);
  try {
    for (const store of [stores.guard, stores.backend]) { assert.equal(store.read().schema, 3); assert.equal(store.read().recoveryMirror, 1); }
    assert.equal(lookupBusinessHistory(stores, f.config, { tenantId: 'acme', requestId: request.id }).receipt.status, 'resolved');
  } finally { stores.close(); }
  const { historyMirrorDirectory: _mirror, ...disabled } = f.config;
  assert.throws(() => openRuntime(disabled), { code: 'HISTORY_MIRROR_REQUIRED' });
  rmSync(join(f.mirrorDirectory, files[0]));
  assert.throws(() => openRuntime(f.config), { code: 'HISTORY_EVIDENCE_UNAVAILABLE' });
  writeFileSync(join(f.mirrorDirectory, files[0]), original, { mode: 0o600 });
  assert.equal(openRuntime(f.config, { checkOnly: true }).status, 'verified');
});

test('legacy mirror enrollment cannot publish a partial backfill and retries exact files', async t => {
  const f = fixture(t, { mirror: false });
  await complete(f.config); compact(f.config); await complete(f.config); compact(f.config);
  f.config.historyMirrorDirectory = f.mirrorDirectory;
  assert.throws(() => openRuntime(f.config), { code: 'RECOVERY_ENROLLMENT_REQUIRED' });
  const stores = openMaintenance(f.config, { allowRecoveryEnrollment: true });
  try {
    const preview = enrollBusinessHistoryMirror(stores, f.config);
    assert.equal(preview.segments, 2);
    assert.throws(() => enrollBusinessHistoryMirror(stores, f.config, { apply: true, digest: preview.digest,
      checkpoint(phase) { if (phase === 'mirror-backfill-file') throw Error('simulated-crash'); } }), /simulated-crash/);
    assert.equal(stores.backend.read().ticketService.history.mirrorEnrollment, undefined);
    assert.equal(names(f.mirrorDirectory).length, 1);
    const recovered = enrollBusinessHistoryMirror(stores, f.config, { apply: true, digest: enrollBusinessHistoryMirror(stores, f.config).digest });
    assert.equal(recovered.status, 'enrolled'); assert.equal(names(f.mirrorDirectory).length, 2);
    assert.equal(stores.guard.read().schema, 3); assert.equal(stores.backend.read().schema, 3);
    assert.equal(verifyHistoryStorage(stores, f.config).segments, 2);
    for (const name of names(f.mirrorDirectory)) assert.deepEqual(readFileSync(join(f.mirrorDirectory, name)), readFileSync(join(f.config.historyDirectory, name)));
  } finally { stores.close(); }
  assert.equal(openRuntime(f.config, { checkOnly: true }).status, 'verified');
});

test('mirror enrollment checks final metadata capacity before any native upgrade', t => {
  const f = fixture(t, { mirror: false }); f.config.historyMirrorDirectory = f.mirrorDirectory;
  const stores = openMaintenance(f.config, { allowRecoveryEnrollment: true });
  try {
    stores.backend.transaction(state => {
      state.retentionCapacityFixture = '';
      state.retentionCapacityFixture = 'x'.repeat(stores.backend.maxBytes - Buffer.byteLength(JSON.stringify(state)) - 64);
    });
    assert.throws(() => enrollBusinessHistoryMirror(stores, f.config), { code: 'STORE_CAPACITY_EXCEEDED' });
    assert.equal(stores.guard.read().recoveryMirror, undefined);
    assert.equal(stores.backend.read().recoveryMirror, undefined);
    assert.equal(stores.backend.read().ticketService.history.mirrorEnrollment, undefined);
    assert.equal(names(f.mirrorDirectory).length, 0);
  } finally { stores.close(); }
});

for (const phase of ['guard-mirror-enabled', 'backend-mirror-enabled']) {
  test(`legacy history enrollment resumes safely after ${phase}`, async t => {
    const f = fixture(t, { mirror: false }); await complete(f.config); compact(f.config);
    f.config.historyMirrorDirectory = f.mirrorDirectory;
    let stores = openMaintenance(f.config, { allowRecoveryEnrollment: true });
    try {
      const preview = enrollBusinessHistoryMirror(stores, f.config);
      assert.throws(() => enrollBusinessHistoryMirror(stores, f.config, { apply: true, digest: preview.digest,
        checkpoint(reached) { if (reached === phase) throw Error('simulated-crash'); } }), /simulated-crash/);
      assert.equal(stores.backend.read().ticketService.history.mirrorEnrollment, undefined);
      assert.equal(stores.guard.read().schema, 3);
    } finally { stores.close(); }
    assert.throws(() => openRuntime(f.config), error => ['RECOVERY_ENROLLMENT_REQUIRED', 'HISTORY_MIRROR_NOT_ENROLLED'].includes(error.code));
    stores = openMaintenance(f.config, { allowRecoveryEnrollment: true });
    try {
      const preview = enrollBusinessHistoryMirror(stores, f.config);
      enrollBusinessHistoryMirror(stores, f.config, { apply: true, digest: preview.digest });
    } finally { stores.close(); }
    assert.equal(openRuntime(f.config, { checkOnly: true }).status, 'verified');
  });
}

for (const phase of ['mirror-durable', 'export-durable', 'sdk-compacted']) {
  test(`mirrored history retains exact recovery evidence after ${phase}`, async t => {
    const f = fixture(t), request = await complete(f.config);
    assert.throws(() => compact(f.config, reached => { if (reached === phase) throw Error('simulated-crash'); }), /simulated-crash/);
    assert.equal(names(f.mirrorDirectory).length, 1);
    assert.throws(() => openRuntime(f.config), { code: 'HISTORY_RECOVERY_REQUIRED' });
    const stores = openMaintenance(f.config, { allowHistoryPending: true });
    try {
      const readers = new Map([['authority', stores.guard], ['tickets', stores.backend]]), adapter = businessHistoryBackupAdapter(f.config);
      const closure = adapter.verify(readers, f.mirrorDirectory);
      assert.equal(closure.length, phase === 'sdk-compacted' ? 1 : 0);
      assert.equal(stores.backend.read().ticketService.history.companies.acme.head, null);
    } finally { stores.close(); }
    const result = compact(f.config); assert.equal(result.segment, 1);
    const recovered = openMaintenance(f.config);
    try { assert.deepEqual(lookupBusinessHistory(recovered, f.config, { tenantId: 'acme', requestId: request.id }).receipt, { ...request.receipt }); }
    finally { recovered.close(); }
  });
}

test('a conflicting mirror segment stops SDK archive deletion and cannot be silently replaced', async t => {
  const f = fixture(t); await complete(f.config);
  assert.throws(() => compact(f.config, phase => { if (phase === 'export-planned') throw Error('simulated-crash'); }), /simulated-crash/);
  const stores = openMaintenance(f.config, { allowHistoryPending: true }); let path;
  try {
    const state = stores.backend.read(), pending = state.ticketService.history.pending;
    path = join(f.mirrorDirectory, historyFilename(state.inventoryInstanceId, pending.tenantId,
      { index: pending.index, hash: pending.targetHash, keyBase64: pending.keyBase64 }));
    writeFileSync(path, 'preserve conflicting evidence', { mode: 0o600 });
    const preview = previewBusinessHistory(stores, f.config, { tenantId: 'acme' });
    assert.throws(() => applyBusinessHistory(stores, f.config, { tenantId: 'acme', digest: preview.digest }), { code: 'HISTORY_EVIDENCE_INVALID' });
    assert.equal(Object.keys(stores.guard.read().lifecycle.archives).length, 1);
    assert.equal(Object.keys(stores.guard.read().lifecycle.externalHeads ?? {}).length, 0);
    assert.equal(stores.backend.read().ticketService.history.companies.acme.head, null);
    assert.equal(readFileSync(path, 'utf8'), 'preserve conflicting evidence');
  } finally { stores.close(); }
});

test('mirror recovery closure requires the SDK-committed pending segment before business publication', async t => {
  const f = fixture(t); await complete(f.config);
  assert.throws(() => compact(f.config, phase => { if (phase === 'sdk-compacted') throw Error('simulated-crash'); }), /simulated-crash/);
  const stores = openMaintenance(f.config, { allowHistoryPending: true });
  try {
    const readers = new Map([['authority', stores.guard], ['tickets', stores.backend]]), adapter = businessHistoryBackupAdapter(f.config);
    assert.equal(adapter.verify(readers, f.mirrorDirectory).length, 1);
    rmSync(join(f.mirrorDirectory, names(f.mirrorDirectory)[0]));
    assert.throws(() => adapter.verify(readers, f.mirrorDirectory), { code: 'HISTORY_EVIDENCE_UNAVAILABLE' });
  } finally { stores.close(); }
});

test('history mirror custody and restored primary enrollment remain explicit', async t => {
  const f = fixture(t); await complete(f.config); compact(f.config);
  assert.throws(() => privateHistoryMirrorDirectory({ ...f.config, historyMirrorDirectory: f.config.historyDirectory }), { code: 'HISTORY_MIRROR_CUSTODY_REQUIRED' });
  const previous = `${f.config.historyDirectory}-preserved`; renameSync(f.config.historyDirectory, previous);
  mkdirSync(f.config.historyDirectory, { mode: 0o700 });
  const oldConfig = { ...f.config, historyDirectory: previous };
  const stores = openMaintenance(oldConfig, { ignoreHistoryEnrollment: true });
  try {
    const readers = new Map([['authority', stores.guard], ['tickets', stores.backend]]), adapter = businessHistoryBackupAdapter(f.config);
    const closure = adapter.verify(readers, f.mirrorDirectory); assert.equal(closure.length, 1);
    for (const file of closure) writeFileSync(join(f.config.historyDirectory, file.name), readFileSync(join(f.mirrorDirectory, file.name)), { mode: 0o600 });
    assert.throws(() => verifyHistoryStorage(stores, f.config), { code: 'HISTORY_DIRECTORY_NOT_ENROLLED' });
    const preview = enrollBusinessHistory(stores, f.config);
    assert.equal(enrollBusinessHistory(stores, f.config, { apply: true, digest: preview.digest }).status, 'enrolled');
  } finally { stores.close(); }
  assert.equal(openRuntime(f.config, { checkOnly: true }).status, 'verified');
});

for (const pending of [false, true]) {
  test(`current independent mirrors repair both primary stores and history${pending ? ' with an SDK-committed pending segment' : ' after a newer write'}`, async t => {
    const f = fixture(t), first = await complete(f.config);
    let latest = first;
    if (pending) assert.throws(() => compact(f.config, phase => { if (phase === 'sdk-compacted') throw Error('simulated-crash'); }), /simulated-crash/);
    else {
      compact(f.config);
      // This earlier cold copy is already stale after the next authorized write.
      const stale = readFileSync(f.config.backendDatabase);
      latest = await complete(f.config);
      assert.notDeepEqual(readFileSync(f.config.backendDatabase), stale);
    }
    const witnesses = [f.config.ledgerWitness, f.config.backendWitness].map(path => readFileSync(path));
    rmSync(f.config.ledgerDatabase); rmSync(f.config.backendDatabase);
    rmSync(f.config.historyDirectory, { recursive: true }); mkdirSync(f.config.historyDirectory, { mode: 0o700 });
    const preview = manageBusinessRecovery(f.config, { operation: 'repair' });
    assert.equal(preview.historyFiles, 1); assert.equal(preview.applied, false);
    const result = manageBusinessRecovery(f.config, { operation: 'repair', apply: true, digest: preview.digest });
    assert.equal(result.applied, true); assert.equal(result.historyReenrollmentRequired, true);
    for (let i = 0; i < witnesses.length; i++) assert.deepEqual(readFileSync([f.config.ledgerWitness, f.config.backendWitness][i]), witnesses[i]);
    assert.throws(() => openRuntime(f.config), error => ['HISTORY_RECOVERY_REQUIRED', 'HISTORY_DIRECTORY_NOT_ENROLLED'].includes(error.code));
    const stores = openMaintenance(f.config, { allowHistoryPending: true, ignoreHistoryEnrollment: true });
    try {
      const enrollment = enrollBusinessHistory(stores, f.config);
      enrollBusinessHistory(stores, f.config, { apply: true, digest: enrollment.digest });
      if (!pending) assert.deepEqual({ ...stores.backend.read().ticketService.receipts[latest.receipt.operationId] }, { ...latest.receipt });
      else assert.match(stores.backend.read().ticketService.history.pending.targetHash, /^[a-f0-9]{64}$/);
    } finally { stores.close(); }
    if (pending) compact(f.config);
    const recovered = openMaintenance(f.config);
    try { assert.deepEqual(lookupBusinessHistory(recovered, f.config, { tenantId: 'acme', requestId: first.id }).receipt, { ...first.receipt }); }
    finally { recovered.close(); }
    const runtime = openRuntime(f.config);
    try { assert.equal(runtime.workflow.ticket('T-1', 'acme').version, pending ? 2 : 3); }
    finally { runtime.close(); }
  });
}
