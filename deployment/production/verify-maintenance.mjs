// Creates and removes only a new private temporary fixture. No deployment config
// or production path is accepted. Run against the built production image.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LEDGER_FORMAT_VERSION, createLedgerKeyring, loadLedgerKey, rotateLedgerKeyring } from '../../packages/executor/dist/entry-ops.js';
import { initializeRuntime, openRuntime } from '../../apps/agent-ops/runtime.mjs';
import { manageBusinessRecovery } from '../../apps/agent-ops/custody.mjs';

if (process.platform !== 'linux') throw Error('LINUX_DEPLOYMENT_REQUIRED');
const root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-ops-smoke-')));
let owner;
try {
  for (const name of ['data', 'witness', 'keys', 'history']) mkdirSync(join(root, name), { mode: 0o700 });
  mkdirSync(join(root, 'witness', 'history-mirror'), { mode: 0o700 });
  const config = { ledgerDatabase: join(root, 'data', 'authority.sqlite'), backendDatabase: join(root, 'data', 'tickets.sqlite'),
    ledgerWitness: join(root, 'witness', 'authority.sqlite'), backendWitness: join(root, 'witness', 'tickets.sqlite'), keyringFile: join(root, 'keys', 'keyring.json'),
    historyDirectory: join(root, 'history'), historyMirrorDirectory: join(root, 'witness', 'history-mirror') };
  createLedgerKeyring({ keyringFile: config.keyringFile, keyId: 'fixture-initial' });
  initializeRuntime(config, [{ id: 'T-1', tenantId: 'fixture', title: 'Disposable ticket', status: 'open' }]);
  owner = openRuntime(config, { afterCommit() { throw Error('fixture receipt interruption'); } });
  const actor = { id: 'fixture-requester', tenantId: 'fixture' }, reviewer = { id: 'fixture-reviewer', tenantId: 'fixture' };
  const proposed = await owner.workflow.propose(actor, { ticketId: 'T-1', status: 'resolved' });
  const interrupted = await owner.workflow.decide(reviewer, proposed.request.id, { digest: proposed.request.digest }, true);
  assert.equal(interrupted.request.state, 'unconfirmed');
  const taskId = owner.workflow.request(proposed.request.id).taskId;
  const counters = ({ calls, spent, reserved, concurrent }) => ({ calls, spent, reserved, concurrent });
  const reserved = counters(owner.executor.snapshot(taskId));
  assert.equal(reserved.calls, 1); assert.ok(reserved.reserved > 0);
  owner.close(); owner = undefined;
  const witnessPaths = [config.ledgerWitness, config.backendWitness], witnessBytes = witnessPaths.map(path => readFileSync(path));
  rmSync(join(root, 'data'), { recursive: true }); mkdirSync(join(root, 'data'), { mode: 0o700 });
  const repair = manageBusinessRecovery(config, { operation: 'repair' });
  manageBusinessRecovery(config, { operation: 'repair', apply: true, digest: repair.digest });
  witnessPaths.forEach((path, index) => assert.deepEqual(readFileSync(path), witnessBytes[index]));
  owner = openRuntime(config);
  assert.equal(owner.workflow.request(proposed.request.id).state, 'unconfirmed');
  assert.deepEqual(counters(owner.executor.snapshot(taskId)), reserved);
  assert.equal(owner.workflow.ticket('T-1', 'fixture').version, 2);
  owner.close(); owner = undefined;
  const options = { database: config.ledgerDatabase, witnessPath: config.ledgerWitness, keyringFile: config.keyringFile, nextKeyId: 'fixture-next' };
  rotateLedgerKeyring(options);
  const previous = loadLedgerKey({ ...options, database: config.backendDatabase, witnessPath: config.backendWitness });
  try { assert.equal(previous.keyId, 'fixture-initial'); } finally { previous.key.fill(0); }
  rotateLedgerKeyring({ ...options, database: config.backendDatabase, witnessPath: config.backendWitness });
  // `check` also reports the authority ledger layout: current format, mirror enrolled (schema 3).
  assert.deepEqual(openRuntime(config, { checkOnly: true }), { status: 'verified', guardKeyId: 'fixture-next', backendKeyId: 'fixture-next',
    ledgerFormat: { formatVersion: LEDGER_FORMAT_VERSION, schema: 3, features: ['recovery-mirror', 'retention'] } });
  owner = openRuntime(config);
  const reconciled = owner.workflow.reconcile(reviewer, proposed.request.id);
  assert.equal(reconciled.request.state, 'completed');
  assert.equal(owner.workflow.ticket('T-1', 'fixture').version, 2);
  const preview = owner.workflow.previewArchive(reviewer, { taskId: owner.workflow.request(proposed.request.id).taskId });
  assert.deepEqual(preview.preview.blockers, []);
  assert.equal(owner.workflow.archive(reviewer, { id: preview.preview.id, digest: preview.preview.digest }).archivedCount, 1);
  owner.close(); owner = undefined;
  const older = readFileSync(config.ledgerDatabase);
  owner = openRuntime(config); owner.close(); owner = undefined;
  const current = readFileSync(config.ledgerDatabase);
  try {
    writeFileSync(config.ledgerDatabase, older);
    assert.throws(() => openRuntime(config, { checkOnly: true }), { code: 'LEDGER_KEY_UNAVAILABLE' });
  } finally { writeFileSync(config.ledgerDatabase, current); }
  assert.equal(openRuntime(config, { checkOnly: true }).status, 'verified');
  process.stdout.write(JSON.stringify({ status: 'passed', platform: process.platform, node: process.versions.node,
    twoStoreRotation: true, interruptedReceiptReconciled: true, duplicateEffectPrevented: true, archivePersisted: true, rollbackRejected: true,
    unconfirmedReservationRecoveredAfterPrimaryLoss: true, repairLeavesWitnessesUnchanged: true }) + '\n');
} finally { owner?.close(); rmSync(root, { recursive: true, force: true }); }
