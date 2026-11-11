import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, cpSync, mkdtempSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableExecutor, LEDGER_FORMAT_VERSION } from '../dist/index.js';
import { LedgerStore } from '../dist/store.js';
import { migrateLedger } from '../dist/ledger-format.js';
import { removeAtExit } from './temp-directory.mjs';

const FIXTURES = new URL('./fixtures/ledgers/', import.meta.url);
const KEY = Buffer.alloc(32, 0x5a);
const fixtures = readdirSync(FIXTURES).sort();

/** A private, writable copy of a committed fixture (the store refuses group/world access). */
function copy(t, name) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'ledger-format-')));
  removeAtExit(directory);
  cpSync(new URL(name, FIXTURES), directory, { recursive: true });
  for (const part of ['', 'data', 'witness']) {
    try {
      chmodSync(join(directory, part), 0o700);
    } catch {
      /* plain fixtures have no witness directory */
    }
  }
  for (const file of ['data/ledger.sqlite', 'witness/witness.sqlite']) {
    try {
      chmodSync(join(directory, file), 0o600);
    } catch {
      /* absent for plain fixtures */
    }
  }
  const manifest = JSON.parse(readFileSync(join(directory, 'manifest.json'), 'utf8'));
  const open = () =>
    new DurableExecutor({
      database: join(directory, 'data', 'ledger.sqlite'),
      encryptionKey: Buffer.from(KEY),
      clock: () => 2_000_000,
      ...(manifest.witnessed
        ? { rollbackWitness: { path: join(directory, 'witness', 'witness.sqlite'), mode: 'resume' } }
        : {}),
    });
  return { directory, manifest, open };
}

test('fixtures cover alpha.3, 0.1.0 and the pre-format 0.2 build, plain and witnessed', () => {
  assert.deepEqual(fixtures, [
    '0.1.0-alpha.3-plain',
    '0.1.0-alpha.3-witnessed',
    '0.1.0-plain',
    '0.1.0-witnessed',
    '0.2.0-pre-format-plain',
    '0.2.0-pre-format-witnessed',
  ]);
});

// The rollback witness is POSIX-only, so witnessed fixtures cannot be opened on Windows.
const witnessedOnWindows = name => process.platform === 'win32' && name.endsWith('-witnessed');
for (const name of fixtures) {
  test(`${name}: opens, keeps authority and migrates to the current format`, { skip: witnessedOnWindows(name) }, t => {
    const f = copy(t, name);
    let executor = f.open();
    assert.deepEqual(
      { ...executor.ledgerFormat(), features: [...executor.ledgerFormat().features] },
      { formatVersion: LEDGER_FORMAT_VERSION, schema: executor.ledgerFormat().schema, features: ['retention'] },
      'startup records a recent event, which creates retention state',
    );
    for (const [taskId, expected] of Object.entries(f.manifest.expected)) {
      const snapshot = executor.snapshot(taskId);
      assert.deepEqual(
        { calls: snapshot.calls, spent: snapshot.spent, reserved: snapshot.reserved },
        expected,
        `${name} ${taskId}`,
      );
    }
    assert.equal(executor.authenticate(f.manifest.tokens.root), 'root');
    assert.equal(executor.authenticate(f.manifest.tokens.child), 'child');
    assert.equal(executor.authenticate(f.manifest.tokens.other), 'other-tenant');
    const status = id => executor.execution(id === f.manifest.actions.delegated ? 'child' : 'root', id);
    assert.equal(status(f.manifest.actions.succeeded).status, 'SUCCEEDED');
    assert.equal(status(f.manifest.actions.delegated).status, 'SUCCEEDED');
    assert.equal(
      status(f.manifest.actions.uncertain).status,
      'UNKNOWN',
      'an uncertain effect stays uncertain across versions',
    );
    const reconciled = status(f.manifest.actions.reconciled);
    assert.equal(reconciled.status, 'FAILED');
    assert.equal(reconciled.charged, 1);
    assert.match(reconciled.reconciliation.referenceHash, /^[a-f0-9]{64}$/);
    // The new build still reconciles an uncertain effect written by the old one.
    executor.reconcile(f.manifest.actions.uncertain, {
      outcome: 'SUCCEEDED',
      actualCost: 5,
      reference: 'late-receipt',
    });
    assert.equal(executor.snapshot('root').reserved, 0);
    executor.close();
    // Reopening a migrated ledger is a no-op for the format.
    executor = f.open();
    assert.equal(executor.ledgerFormat().formatVersion, LEDGER_FORMAT_VERSION);
    assert.equal(executor.snapshot('root').spent, f.manifest.expected.root.spent + 5);
    executor.close();
  });
}

test('a ledger from a newer format is refused without being changed', t => {
  const f = copy(t, '0.1.0-plain');
  const path = join(f.directory, 'data', 'ledger.sqlite');
  const store = new LedgerStore(path, Buffer.from(KEY));
  store.transaction(state => {
    state.formatVersion = LEDGER_FORMAT_VERSION + 1;
  });
  const before = store.read();
  store.close();
  assert.throws(() => f.open(), { code: 'STORE_FORMAT_UNSUPPORTED' });
  const after = new LedgerStore(path, Buffer.from(KEY));
  t.after(() => after.close());
  assert.deepEqual(after.read(), before, 'the refused open rolled back');
});

test('migration is stepwise, idempotent and rejects malformed versions', () => {
  const state = { schema: 1, tasks: {}, actions: {}, audit: [] };
  assert.equal(migrateLedger(state), 0);
  assert.equal(state.formatVersion, LEDGER_FORMAT_VERSION);
  assert.deepEqual(state.features, []);
  assert.equal(migrateLedger(state), LEDGER_FORMAT_VERSION, 'already current: no step runs');
  for (const formatVersion of [-1, 1.5, '1']) {
    assert.throws(() => migrateLedger({ ...state, formatVersion }), { code: 'STORE_FORMAT_INVALID' });
  }
});

test('features are recomputed at each commit once a ledger has a format version', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'ledger-features-')));
  removeAtExit(directory);
  const executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: Buffer.from(KEY) });
  t.after(() => executor.close());
  assert.deepEqual([...executor.ledgerFormat().features], ['retention']);
  executor.approveTool(
    'w',
    executor.registerTool({
      name: 'w',
      description: 'x',
      resolve: () => ({ resourceId: 'r', tenantId: 'a' }),
      execute: () => ({ value: 1 }),
    }),
  );
  executor.createTask({
    id: 't',
    principalId: 'p',
    tenantId: 'a',
    grants: [{ tool: 'w', resources: ['r'] }],
    budget: { maxCalls: 9, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 60_000 },
  });
  const scope = { tenantId: 'a', taskId: 't' };
  executor.retireTaskFamily({ ...scope, expectedDigest: executor.previewTaskFamilyRetirement(scope).reviewDigest });
  assert.deepEqual(
    [...executor.ledgerFormat().features],
    ['lifecycle', 'retention'],
    'retirement adds lifecycle state',
  );
});
