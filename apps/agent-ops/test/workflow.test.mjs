import nodeTest from 'node:test';
const test = (name, fn) =>
  nodeTest(
    name,
    {
      skip:
        process.platform === 'win32'
          ? 'The witnessed single-owner deployment requires POSIX; Linux is the supported runtime.'
          : false,
    },
    fn,
  );
import assert from 'node:assert/strict';
import { readFileSync, copyFileSync } from 'node:fs';
import { setup, owner } from './helpers.mjs';
import { openRuntime, initializeRuntime } from '../runtime.mjs';
import { rotateLedgerKeyring } from '../../../packages/executor/dist/ledger-maintenance.js';

test('persistent ticket CAS and receipt bind exact human review and survive restart', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  assert.equal(request.state, 'pending');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].status, 'open');
  await assert.rejects(fixture.workflow.decide(owner, request.id, { digest: 'changed' }, true), {
    code: 'REVIEW_STALE',
  });
  const completed = await fixture.workflow.decide(
    { ...owner, id: 'reviewer-alice' },
    request.id,
    { digest: request.digest },
    true,
  );
  assert.equal(completed.request.state, 'completed');
  assert.equal(completed.request.reviewerId, 'reviewer-alice');
  assert.equal(completed.request.receipt.version, 2);
  await assert.rejects(fixture.workflow.decide(owner, request.id, { digest: request.digest }, true), {
    code: 'REVIEW_STALE',
  });
  fixture.reopen();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.deepEqual(fixture.workflow.requests('acme').requests[0].receipt, completed.request.receipt);
  assert.equal(readFileSync(fixture.config.backendDatabase).includes(Buffer.from('Customer delivery')), false);
});
test('backend commit followed by lost response requires receipt-only reconciliation', async t => {
  const fixture = setup(t, {
    afterCommit: () => {
      throw Error('connection lost');
    },
  });
  const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  const unknown = await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true);
  assert.equal(unknown.request.state, 'unconfirmed');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.throws(() => fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }), {
    code: 'ARCHIVE_UNAVAILABLE',
  });
  fixture.reopen();
  assert.equal(fixture.workflow.reconcile(owner, request.id).request.state, 'completed');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.throws(() => fixture.workflow.reconcile(owner, request.id), { code: 'RECONCILIATION_UNAVAILABLE' });
});
test('absent receipt never permits reconciliation or redispatch', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  let authorized = true;
  const pending = fixture.workflow.decide(owner, request.id, { digest: request.digest }, true, () => {
    if (!authorized) throw Error('revoked');
  });
  authorized = false;
  const result = await pending;
  assert.equal(result.request.state, 'unconfirmed');
  assert.throws(() => fixture.workflow.reconcile(owner, request.id), { code: 'RECEIPT_NOT_FOUND' });
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
  await assert.rejects(fixture.workflow.decide(owner, request.id, { digest: request.digest }, true), {
    code: 'REVIEW_STALE',
  });
});
test('tenant and enrolled resource boundaries apply before task preparation', async t => {
  const fixture = setup(t);
  await assert.rejects(fixture.workflow.propose(owner, { ticketId: 'T-2', status: 'resolved' }), { code: 'NOT_FOUND' });
  await assert.rejects(
    fixture.workflow.propose({ ...owner, allowedTicketIds: ['T-2'] }, { ticketId: 'T-1', status: 'resolved' }),
    { code: 'FORBIDDEN' },
  );
  assert.deepEqual(fixture.workflow.requests('acme').requests, []);
});
test('restart requires a fresh review and competing requests use ticket CAS', async t => {
  const fixture = setup(t);
  const first = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  fixture.reopen();
  assert.equal(fixture.workflow.requests('acme').requests[0].state, 'review_required');
  await assert.rejects(fixture.workflow.decide(owner, first.id, { digest: first.digest }, true), {
    code: 'REVIEW_STALE',
  });
  const a = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  const b = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  await fixture.workflow.decide(owner, a.id, { digest: a.digest }, true);
  await assert.rejects(fixture.workflow.decide(owner, b.id, { digest: b.digest }, true), { code: 'TICKET_CHANGED' });
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
});
test('denial, expiry and concurrent approval cannot duplicate an effect', async t => {
  const fixture = setup(t);
  const denied = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  assert.equal(
    (await fixture.workflow.decide(owner, denied.id, { digest: denied.digest }, false)).request.state,
    'denied',
  );
  const expired = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  fixture.runtime.backend.transaction(state => {
    state.ticketService.requests[expired.id].expiresAt = 1;
  });
  await assert.rejects(fixture.workflow.decide(owner, expired.id, { digest: expired.digest }, true), {
    code: 'REVIEW_EXPIRED',
  });
  const fresh = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  const results = await Promise.allSettled([
    fixture.workflow.decide(owner, fresh.id, { digest: fresh.digest }, true),
    fixture.workflow.decide(owner, fresh.id, { digest: fresh.digest }, true),
  ]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
});
test('archive review frees live tasks, keeps business receipt, blocks stale preview and recovers lost business marker', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true);
  const { preview } = fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` });
  assert.deepEqual(preview.blockers, []);
  assert.throws(
    () => fixture.workflow.archive({ ...owner, id: 'someone-else' }, { id: preview.id, digest: preview.digest }),
    { code: 'ARCHIVE_PREVIEW_STALE' },
  );
  assert.equal(fixture.workflow.archive(owner, { id: preview.id, digest: preview.digest }).archivedCount, 1);
  assert.equal(fixture.runtime.executor.maintenanceStatistics({ tenantId: 'acme' }).tasks, 0);
  fixture.runtime.backend.transaction(state => {
    delete state.ticketService.requests[request.id].archived;
    state.ticketService.requests[request.id].archiveIntent = true;
  });
  fixture.reopen();
  assert.equal(fixture.workflow.requests('acme').requests[0].archived, true);
  assert.equal(fixture.workflow.requests('acme').requests[0].receipt.version, 2);
});
test('two independent witnesses reject backend rollback and initialization never resets authority', async t => {
  const fixture = setup(t);
  fixture.close();
  const saved = `${fixture.directory}/saved.sqlite`;
  copyFileSync(fixture.config.backendDatabase, saved);
  fixture.reopen();
  await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  fixture.close();
  copyFileSync(saved, fixture.config.backendDatabase);
  assert.throws(() => openRuntime(fixture.config));
  assert.throws(() => initializeRuntime(fixture.config, []), { code: 'INITIALIZATION_REQUIRES_NEW_FILES' });
});
test('partial two-store key rotation preserves receipts and archived evidence through restart', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true);
  const { preview } = fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` });
  fixture.workflow.archive(owner, { id: preview.id, digest: preview.digest });
  fixture.close();
  const config = fixture.config;
  rotateLedgerKeyring({
    database: config.ledgerDatabase,
    witnessPath: config.ledgerWitness,
    keyringFile: config.keyringFile,
    nextKeyId: 'rotation-1',
  });
  const checked = openRuntime(config, { checkOnly: true });
  assert.deepEqual(
    { ...checked, ledgerFormat: undefined },
    { status: 'verified', guardKeyId: 'rotation-1', backendKeyId: 'initial', ledgerFormat: undefined },
  );
  assert.equal(checked.ledgerFormat.formatVersion, 1, 'check reports the migrated authority layout');
  assert.ok(checked.ledgerFormat.features.includes('retention'));
  fixture.reopen();
  assert.equal(fixture.workflow.requests('acme').requests[0].receipt.version, 2);
  fixture.close();
  rotateLedgerKeyring({
    database: config.backendDatabase,
    witnessPath: config.backendWitness,
    keyringFile: config.keyringFile,
    nextKeyId: 'rotation-1',
  });
  fixture.reopen();
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.equal(
    fixture.runtime.executor.findTaskFamilyArchive({ tenantId: 'acme', taskId: `ticket:${request.id}` }).counts.tasks,
    1,
  );
});
test('archival retries safely after retirement committed but the archive write failed', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  await fixture.workflow.decide(owner, request.id, { digest: request.digest }, false);
  const executor = fixture.runtime.executor,
    original = executor.archiveTaskFamily.bind(executor);
  executor.archiveTaskFamily = () => {
    throw Error('storage unavailable');
  };
  const first = fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }).preview;
  assert.throws(() => fixture.workflow.archive(owner, { id: first.id, digest: first.digest }));
  executor.archiveTaskFamily = original;
  const fresh = fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }).preview;
  assert.equal(fixture.workflow.archive(owner, { id: fresh.id, digest: fresh.digest }).archivedCount, 1);
});
test('an error after successful execution remains unconfirmed until its exact receipt is reconciled', async t => {
  const fixture = setup(t),
    executor = fixture.runtime.executor;
  const execute = executor.execute.bind(executor);
  executor.execute = async (...args) => {
    await execute(...args);
    throw Error('post-success reporting failure');
  };
  const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  assert.equal(
    (await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true)).request.state,
    'unconfirmed',
  );
  assert.equal(fixture.workflow.reconcile(owner, request.id).request.state, 'completed');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
});
test('a pruned terminal receipt can finish its business marker only with exact receipt and settled one-call accounting', async t => {
  for (const unsettled of [false, true]) {
    const fixture = setup(
        t,
        unsettled
          ? {
              afterCommit: () => {
                throw Error('lost response');
              },
            }
          : {},
      ),
      executor = fixture.runtime.executor;
    if (!unsettled) {
      const execute = executor.execute.bind(executor);
      executor.execute = async (...args) => {
        await execute(...args);
        throw Error('post-success reporting failure');
      };
    }
    const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
    await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true);
    executor.execution = () => {
      throw Object.assign(Error('pruned'), { code: 'INVALID_PREPARED' });
    };
    if (unsettled)
      assert.throws(() => fixture.workflow.reconcile(owner, request.id), { code: 'RECONCILIATION_UNAVAILABLE' });
    else assert.equal(fixture.workflow.reconcile(owner, request.id).request.state, 'completed');
    assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  }
});
test('task creation failure leaves a readable failed request without a nonexistent archival candidate', async t => {
  const fixture = setup(t);
  fixture.runtime.executor.createTask = () => {
    throw Object.assign(Error('capacity'), { code: 'CAPACITY_EXCEEDED' });
  };
  await assert.rejects(fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' }), {
    code: 'CAPACITY_EXCEEDED',
  });
  assert.equal(fixture.workflow.requests('acme').requests[0].state, 'failed');
  assert.deepEqual(fixture.workflow.maintenance(owner).archiveCandidates, []);
});
