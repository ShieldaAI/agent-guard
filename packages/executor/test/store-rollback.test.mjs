import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LedgerStore } from '../dist/store.js';

test('a failing ROLLBACK keeps the original error and closes the store', t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'store-rollback-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const store = new LedgerStore(join(directory, 'ledger.sqlite'), Buffer.alloc(32, 41));
  store.transaction(state => {
    state.audit.push({ time: 1, event: 'committed' });
  });
  // Closing inside the transaction makes the later ROLLBACK itself fail.
  assert.throws(
    () =>
      store.transaction(() => {
        store.close();
        throw new Error('original failure');
      }),
    { message: 'original failure' },
  );
  assert.throws(() => store.read(), { code: 'STORE_CLOSED' }, 'an unknown transaction state is never served');
  const reopened = new LedgerStore(join(directory, 'ledger.sqlite'), Buffer.alloc(32, 41));
  t.after(() => reopened.close());
  assert.deepEqual(
    reopened.read().audit.map(entry => entry.event),
    ['committed'],
  );
});
