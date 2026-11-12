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
  assert.equal(unknown.request.cause, 'TOOL_FAILED', 'only a fixed code is kept, never the error message');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.throws(() => fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }), {
    code: 'ARCHIVE_UNAVAILABLE',
  });
  // A committed change can never be closed out as failed.
  assert.throws(() => fixture.workflow.previewCloseOut(owner, request.id), { code: 'RECEIPT_FOUND' });
  fixture.reopen();
  assert.throws(() => fixture.workflow.previewCloseOut(owner, request.id), { code: 'RECEIPT_FOUND' });
  assert.equal(fixture.workflow.reconcile(owner, request.id).request.state, 'completed');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.throws(() => fixture.workflow.reconcile(owner, request.id), { code: 'RECONCILIATION_UNAVAILABLE' });
});
const execution = (fixture, request) =>
  fixture.runtime.executor.execution(`ticket:${request.id}`, fixture.workflow.request(request.id).actionId);
const audited = (fixture, request, event) =>
  fixture.workflow.data().audit.find(item => item.requestId === request.id && item.event === event);
test('a backend refusal before any effect is definitive: authorization revoked during dispatch', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  let authorized = true;
  const pending = fixture.workflow.decide(owner, request.id, { digest: request.digest }, true, () => {
    if (!authorized) throw Error('revoked: private detail');
  });
  authorized = false;
  const result = await pending;
  assert.equal(result.request.state, 'failed');
  assert.equal(result.request.cause, 'AUTHORIZATION_REVOKED');
  assert.equal(JSON.stringify(fixture.workflow.data()).includes('private detail'), false);
  assert.deepEqual(
    { status: execution(fixture, request).status, charged: execution(fixture, request).charged },
    { status: 'FAILED', charged: 0 },
    'the reservation is settled at zero cost',
  );
  assert.equal(audited(fixture, request, 'DISPATCH_REFUSED').code, 'AUTHORIZATION_REVOKED');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
  assert.equal(fixture.workflow.maintenance(owner).unresolvedCount, 0);
  // Nothing is left to reconcile, and the used approval can never be dispatched again.
  assert.throws(() => fixture.workflow.reconcile(owner, request.id), { code: 'RECONCILIATION_UNAVAILABLE' });
  await assert.rejects(fixture.workflow.decide(owner, request.id, { digest: request.digest }, true), {
    code: 'REVIEW_STALE',
  });
  assert.deepEqual(fixture.workflow.previewArchive(owner, { taskId: `ticket:${request.id}` }).preview.blockers, []);
  fixture.reopen();
  assert.equal(fixture.workflow.requests('acme').requests[0].state, 'failed');
});
test('a ticket changed or a write refused inside the commit transaction is definitive, not unconfirmed', async t => {
  for (const [expected, cause, sabotage] of [
    [
      'changed',
      'TICKET_CHANGED',
      fixture =>
        fixture.runtime.backend.transaction(state => {
          state.ticketService.tickets['T-1'].version++;
        }),
    ],
    [
      'failed',
      'CLOCK_INVALID',
      fixture => {
        // Exactly one backend write (the commit) sees a clock that stepped backward.
        fixture.workflow.clock = () => {
          fixture.workflow.clock = Date.now;
          return 1;
        };
      },
    ],
  ]) {
    const fixture = setup(t),
      { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
    let checks = 0;
    // The third authorization check is the one made by the backend handler, just before its transaction.
    const result = await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true, () => {
      if (++checks === 3) sabotage(fixture);
    });
    assert.equal(checks, 3);
    assert.equal(result.request.state, expected, cause);
    assert.equal(result.request.cause, cause);
    assert.equal(execution(fixture, request).status, 'FAILED');
    assert.equal(execution(fixture, request).charged, 0);
    assert.equal(audited(fixture, request, 'DISPATCH_REFUSED').code, cause);
    assert.equal(fixture.workflow.tickets('acme').tickets[0].status, 'open');
    assert.equal(Object.keys(fixture.workflow.data().receipts).length, 0);
    assert.equal(fixture.workflow.maintenance(owner).unresolvedCount, 0);
  }
});
test('an unprovable dispatch failure stays unconfirmed until an operator closes it out against reviewed evidence', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  let checks = 0;
  const result = await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true, () => {
    if (++checks !== 3) return;
    // The store itself fails (not a refusal raised by the transaction body): nothing is provable in-process.
    const store = fixture.runtime.backend,
      transaction = store.transaction;
    store.transaction = () => {
      store.transaction = transaction;
      throw Error('disk unavailable');
    };
  });
  assert.equal(result.request.state, 'unconfirmed');
  assert.equal(result.request.cause, 'TOOL_FAILED');
  assert.equal(audited(fixture, request, 'OUTCOME_UNCONFIRMED').code, 'TOOL_FAILED');
  assert.equal(execution(fixture, request).status, 'UNKNOWN');
  fixture.reopen();
  // Reconciliation still needs a receipt and never treats absence as failure.
  assert.throws(() => fixture.workflow.reconcile(owner, request.id), { code: 'RECEIPT_NOT_FOUND' });
  const { closeOut } = fixture.workflow.previewCloseOut(owner, request.id);
  assert.deepEqual(
    { ...closeOut, digest: undefined },
    {
      requestId: request.id,
      operationId: `operation-${request.id}`,
      receipt: 'absent',
      ticketId: 'T-1',
      reviewedVersion: 1,
      reviewedStatus: 'open',
      ticketVersion: 1,
      ticketStatus: 'open',
      ticketChanged: false,
      execution: 'UNKNOWN',
      digest: undefined,
    },
  );
  assert.equal(fixture.workflow.requests('acme').requests[0].state, 'unconfirmed', 'a preview changes nothing');
  assert.throws(() => fixture.workflow.closeOut(owner, request.id, {}), { code: 'CLOSE_OUT_STALE' });
  assert.throws(() => fixture.workflow.closeOut(owner, request.id, { digest: 'f'.repeat(64) }), {
    code: 'CLOSE_OUT_STALE',
  });
  assert.throws(() => fixture.workflow.previewCloseOut({ ...owner, tenantId: 'other' }, request.id), {
    code: 'NOT_FOUND',
  });
  const closed = fixture.workflow.closeOut({ ...owner, id: 'operator-bo' }, request.id, { digest: closeOut.digest });
  assert.equal(closed.request.state, 'failed');
  assert.equal(closed.request.cause, 'CLOSED_WITHOUT_RECEIPT');
  assert.equal(audited(fixture, request, 'CLOSED_OUT').operatorId, 'operator-bo');
  assert.equal(execution(fixture, request).status, 'FAILED');
  assert.equal(execution(fixture, request).charged, 0);
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
  assert.equal(fixture.workflow.maintenance(owner).unresolvedCount, 0);
  assert.throws(() => fixture.workflow.closeOut(owner, request.id, { digest: closeOut.digest }), {
    code: 'RECONCILIATION_UNAVAILABLE',
  });
  await assert.rejects(fixture.workflow.decide(owner, request.id, { digest: request.digest }, true), {
    code: 'REVIEW_STALE',
  });
});
test('close-out covers a crash between approval and dispatch, and a ticket that moved on is shown beside the reviewed one', async t => {
  const fixture = setup(t);
  const stuck = async () => {
    const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
    // The durable state a crash leaves right after the approval was recorded: no dispatch ever started.
    fixture.runtime.backend.transaction(state => {
      Object.assign(state.ticketService.requests[request.id], { state: 'dispatching', reviewerId: 'owner' });
    });
    return request;
  };
  const first = await stuck(),
    pruned = await stuck(),
    second = await stuck();
  fixture.reopen();
  assert.equal(fixture.workflow.requests('acme').requests[0].state, 'unconfirmed');
  assert.throws(() => fixture.workflow.reconcile(owner, first.id), { code: 'RECEIPT_NOT_FOUND' });
  const { closeOut } = fixture.workflow.previewCloseOut(owner, first.id);
  assert.equal(closeOut.execution, 'PREPARED');
  assert.equal(fixture.workflow.closeOut(owner, first.id, { digest: closeOut.digest }).request.state, 'failed');
  await assert.rejects(
    fixture.runtime.executor.execute(`ticket:${first.id}`, fixture.workflow.request(first.id).actionId),
    { code: 'TASK_REVOKED' },
    'the prepared action can never run',
  );
  const other = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  // The executor dropped the stale prepared action; its task still proves that no call was ever admitted.
  const dropped = fixture.workflow.previewCloseOut(owner, pruned.id).closeOut;
  assert.equal(dropped.execution, 'NEVER_ADMITTED');
  assert.equal(fixture.workflow.closeOut(owner, pruned.id, { digest: dropped.digest }).request.state, 'failed');
  // Another request changes the ticket. The missing receipt still proves that the last request was
  // never applied, so it keeps an exit: the evidence shows the reviewed ticket beside the current one,
  // and the preview taken before the change is refused.
  const stale = fixture.workflow.previewCloseOut(owner, second.id).closeOut;
  assert.equal(stale.ticketChanged, false);
  await fixture.workflow.decide(owner, other.id, { digest: other.digest }, true);
  assert.throws(() => fixture.workflow.closeOut(owner, second.id, { digest: stale.digest }), {
    code: 'CLOSE_OUT_STALE',
  });
  assert.equal(fixture.workflow.requests('acme').requests.find(item => item.id === second.id).state, 'unconfirmed');
  assert.throws(() => fixture.workflow.reconcile(owner, second.id), { code: 'RECEIPT_NOT_FOUND' });
  const moved = fixture.workflow.previewCloseOut(owner, second.id).closeOut;
  assert.deepEqual(
    [moved.reviewedVersion, moved.reviewedStatus, moved.ticketVersion, moved.ticketStatus, moved.ticketChanged],
    [1, 'open', 2, 'resolved', true],
  );
  assert.notEqual(moved.digest, stale.digest, 'the digest binds the ticket state that was shown');
  fixture.reopen();
  assert.equal(fixture.workflow.previewCloseOut(owner, second.id).closeOut.digest, moved.digest);
  const closed = fixture.workflow.closeOut(owner, second.id, { digest: moved.digest }).request;
  assert.deepEqual([closed.state, closed.cause], ['failed', 'CLOSED_WITHOUT_RECEIPT']);
  assert.deepEqual(
    [fixture.workflow.tickets('acme').tickets[0].version, fixture.workflow.tickets('acme').tickets[0].status],
    [2, 'resolved'],
    'closing never touches the ticket',
  );
  assert.equal(fixture.workflow.maintenance(owner).unresolvedCount, 0);
  assert.deepEqual(fixture.workflow.previewArchive(owner, { taskId: `ticket:${second.id}` }).preview.blockers, []);
  // The request whose change was applied has a receipt and can never be closed as not applied.
  fixture.runtime.backend.transaction(state => {
    state.ticketService.requests[other.id].state = 'unconfirmed';
  });
  assert.throws(() => fixture.workflow.previewCloseOut(owner, other.id), { code: 'RECEIPT_FOUND' });
});
test('a ticket that changes between the close-out preview and the close refuses the reviewed digest', async t => {
  const fixture = setup(t),
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  fixture.runtime.backend.transaction(state => {
    Object.assign(state.ticketService.requests[request.id], { state: 'unconfirmed', reviewerId: 'owner' });
  });
  const shown = fixture.workflow.previewCloseOut(owner, request.id).closeOut;
  fixture.runtime.backend.transaction(state => {
    state.ticketService.tickets['T-1'].version++;
  });
  assert.throws(() => fixture.workflow.closeOut(owner, request.id, { digest: shown.digest }), {
    code: 'CLOSE_OUT_STALE',
  });
  // A receipt that appears is never closed over, whatever digest is presented.
  const again = fixture.workflow.previewCloseOut(owner, request.id).closeOut;
  fixture.runtime.backend.transaction(state => {
    state.ticketService.receipts[`operation-${request.id}`] = { operationId: `operation-${request.id}` };
  });
  assert.throws(() => fixture.workflow.closeOut(owner, request.id, { digest: again.digest }), {
    code: 'RECEIPT_FOUND',
  });
  assert.equal(fixture.workflow.request(request.id).state, 'unconfirmed');
});
test('tenant and enrolled resource boundaries apply before task preparation', async t => {
  const fixture = setup(t);
  await assert.rejects(fixture.workflow.propose(owner, { ticketId: 'T-2', status: 'resolved' }), { code: 'NOT_FOUND' });
  await assert.rejects(
    fixture.workflow.propose({ ...owner, allowedTicketIds: ['T-2'] }, { ticketId: 'T-1', status: 'resolved' }),
    { code: 'FORBIDDEN' },
  );
  // Outside its allowlist an agent gets one answer for an existing, a foreign and a nonexistent ticket.
  for (const ticketId of ['T-1', 'T-2', 'T-404'])
    await assert.rejects(
      fixture.workflow.propose({ ...owner, allowedTicketIds: ['T-9'] }, { ticketId, status: 'resolved' }),
      { code: 'FORBIDDEN', status: 403 },
      ticketId,
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
  // The review deadline passes (the deadline itself is part of the reviewed fingerprint).
  fixture.workflow.clock = () => Date.now() + 6 * 60_000;
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
  assert.equal(fixture.workflow.requests('acme').requests[0].cause, 'CAPACITY_EXCEEDED');
  assert.equal(fixture.workflow.data().audit.at(-1).event, 'PREPARATION_FAILED');
  assert.equal(fixture.workflow.data().audit.at(-1).code, 'CAPACITY_EXCEEDED');
  assert.deepEqual(fixture.workflow.maintenance(owner).archiveCandidates, []);
});

test('a settled receipt pruned without its outcome is never read as a failure', async t => {
  // The change was applied and settled; the executor then reports only that the action settled.
  const fixture = setup(t),
    executor = fixture.runtime.executor;
  const execute = executor.execute.bind(executor);
  executor.execute = async (...args) => {
    await execute(...args);
    throw Error('post-success reporting failure');
  };
  const { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  const real = executor.execution.bind(executor);
  executor.execution = (taskId, actionId) => ({ id: actionId, status: 'PRUNED' });
  const decided = await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true);
  assert.equal(decided.request.state, 'unconfirmed', 'an applied change is never marked failed');
  assert.equal(audited(fixture, request, 'OUTCOME_UNCONFIRMED').code, 'DISPATCH_FAILED');
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 2);
  assert.throws(() => fixture.workflow.previewCloseOut(owner, request.id), { code: 'RECEIPT_FOUND' });
  // The exact receipt plus settled one-unit accounting finish it, as for an action that is gone.
  assert.equal(fixture.workflow.reconcile(owner, request.id).request.state, 'completed');
  executor.execution = real;

  // A status this service does not know is unconfirmed too, never failed.
  const second = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'open' })).request;
  executor.execution = (taskId, actionId) => ({ id: actionId, status: 'SOMETHING_NEW' });
  assert.equal(
    (await fixture.workflow.decide(owner, second.id, { digest: second.digest }, true)).request.state,
    'unconfirmed',
  );
  assert.throws(() => fixture.workflow.reconcile(owner, second.id), { code: 'RECONCILIATION_UNAVAILABLE' });
  executor.execution = real;
  assert.equal(fixture.workflow.reconcile(owner, second.id).request.state, 'completed');
});
test('an action the executor left running or admitted is reconciled and closed like an unknown one', async t => {
  for (const status of ['RUNNING', 'ADMITTED']) {
    // With a receipt: the change was applied; reconcile settles the call as succeeded.
    const applied = setup(t, {
      afterCommit: () => {
        throw Error('lost response');
      },
    });
    const first = (await applied.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
    await applied.workflow.decide(owner, first.id, { digest: first.digest }, true);
    const real = applied.runtime.executor.execution.bind(applied.runtime.executor);
    applied.runtime.executor.execution = (...args) => ({ ...real(...args), status });
    assert.throws(() => applied.workflow.previewCloseOut(owner, first.id), { code: 'RECEIPT_FOUND' });
    assert.equal(applied.workflow.reconcile(owner, first.id).request.state, 'completed', status);
    assert.deepEqual([real(`ticket:${first.id}`, applied.workflow.request(first.id).actionId).status], ['SUCCEEDED']);

    // Without a receipt: close-out settles the call at zero cost.
    const lost = setup(t),
      second = (await lost.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
    let checks = 0;
    await lost.workflow.decide(owner, second.id, { digest: second.digest }, true, () => {
      if (++checks !== 3) return;
      const store = lost.runtime.backend,
        transaction = store.transaction;
      store.transaction = () => {
        store.transaction = transaction;
        throw Error('disk unavailable');
      };
    });
    const stored = lost.runtime.executor.execution.bind(lost.runtime.executor);
    lost.runtime.executor.execution = (...args) => ({ ...stored(...args), status });
    const { closeOut } = lost.workflow.previewCloseOut(owner, second.id);
    assert.equal(closeOut.execution, status);
    assert.equal(lost.workflow.closeOut(owner, second.id, { digest: closeOut.digest }).request.state, 'failed');
    const settled = stored(`ticket:${second.id}`, lost.workflow.request(second.id).actionId);
    assert.deepEqual([settled.status, settled.charged], ['FAILED', 0]);
  }
});
test('close-out reads the task accounting when the executor no longer holds the action', async t => {
  const fixture = setup(t),
    executor = fixture.runtime.executor,
    { request } = await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
  let checks = 0;
  await fixture.workflow.decide(owner, request.id, { digest: request.digest }, true, () => {
    if (++checks !== 3) return;
    const store = fixture.runtime.backend,
      transaction = store.transaction;
    store.transaction = () => {
      store.transaction = transaction;
      throw Error('disk unavailable');
    };
  });
  const real = executor.execution.bind(executor);
  for (const gone of [
    (taskId, actionId) => ({ id: actionId, status: 'PRUNED' }),
    () => {
      throw Object.assign(Error('pruned'), { code: 'INVALID_PREPARED' });
    },
  ]) {
    executor.execution = gone;
    // The call is still reserved: nothing proves how it ended.
    assert.throws(() => fixture.workflow.previewCloseOut(owner, request.id), { code: 'CLOSE_OUT_UNPROVEN' });
  }
  // Settled at zero cost, then pruned: one call, nothing spent, nothing reserved.
  executor.reconcile(fixture.workflow.request(request.id).actionId, {
    outcome: 'FAILED',
    actualCost: 0,
    reference: 'settled by an earlier close-out that could not finish',
  });
  executor.execution = (taskId, actionId) => ({ id: actionId, status: 'PRUNED' });
  const { closeOut } = fixture.workflow.previewCloseOut(owner, request.id);
  assert.equal(closeOut.execution, 'SETTLED_NO_CHARGE');
  assert.equal(fixture.workflow.closeOut(owner, request.id, { digest: closeOut.digest }).request.state, 'failed');
  executor.execution = real;
  assert.equal(fixture.workflow.tickets('acme').tickets[0].version, 1);
});
test('approval answers REVIEW_STALE when the stored action is gone or the row no longer matches its fingerprint', async t => {
  const fixture = setup(t),
    executor = fixture.runtime.executor;
  const gone = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  const prepared = executor.preparedAction.bind(executor);
  executor.preparedAction = () => {
    throw Object.assign(Error('pruned'), { code: 'INVALID_PREPARED' });
  };
  await assert.rejects(fixture.workflow.decide(owner, gone.id, { digest: gone.digest }, true), {
    code: 'REVIEW_STALE',
    status: 409,
  });
  executor.preparedAction = prepared;
  assert.equal(fixture.workflow.request(gone.id).state, 'pending', 'nothing was approved');

  // A row edited after review no longer matches the fingerprint the reviewer approved.
  const edited = (await fixture.workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  for (const change of [{ afterStatus: 'open' }, { beforeStatus: 'resolved' }, { expiresAt: edited.expiresAt + 1 }]) {
    fixture.runtime.backend.transaction(state => {
      Object.assign(state.ticketService.requests[edited.id], change);
    });
    for (const approve of [true, false])
      await assert.rejects(fixture.workflow.decide(owner, edited.id, { digest: edited.digest }, approve), {
        code: 'REVIEW_STALE',
      });
    fixture.runtime.backend.transaction(state => {
      Object.assign(state.ticketService.requests[edited.id], {
        afterStatus: 'resolved',
        beforeStatus: 'open',
        expiresAt: edited.expiresAt,
      });
    });
  }
  // The same check stands inside the commit: an edit during dispatch is refused before any effect.
  let checks = 0;
  const result = await fixture.workflow.decide(owner, edited.id, { digest: edited.digest }, true, () => {
    if (++checks === 3)
      fixture.runtime.backend.transaction(state => {
        state.ticketService.requests[edited.id].ticketId = 'T-9';
      });
  });
  assert.deepEqual([result.request.state, result.request.cause], ['failed', 'DISPATCH_AUTHORITY_MISSING']);
  assert.deepEqual(
    [fixture.workflow.tickets('acme').tickets[0].version, Object.keys(fixture.workflow.data().receipts).length],
    [1, 0],
  );
});
