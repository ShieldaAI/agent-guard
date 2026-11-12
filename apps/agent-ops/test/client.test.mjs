// The browser client's pure modules, and the contract between them and the real service.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFINITIVE_REFUSALS,
  ERROR_MESSAGES,
  GENERIC_ERROR_MESSAGE,
  HARMLESS_REFUSALS,
  REQUEST_STATES,
  TERMINAL_STATES,
  isSettled,
  receiptMatches,
} from '../public/contract.js';
import { failure } from '../public/api.js';
import {
  approval,
  emptyWorkspace,
  fragmentFor,
  mergePoll,
  parseFragment,
  pollDelay,
  requestableStatuses,
  selectionAfterReload,
  shownState,
  visibleRequests,
} from '../public/state.js';
import {
  STATE_LABELS,
  archiveCandidateLabel,
  blockerSentence,
  countdown,
  duration,
  effectSentence,
  requester,
} from '../public/text.js';
import * as check from '../public/validate.js';
import { errorBody, sessionBody } from '../responses.mjs';
import { setup, owner } from './helpers.mjs';

// These two start the real service, whose witnessed deployment requires POSIX (as in the
// workflow and server tests). The rest of this file runs everywhere.
const posixOnly = { skip: process.platform === 'win32' ? 'The witnessed deployment requires POSIX.' : false };

const copy = value => JSON.parse(JSON.stringify(value));
const row = (id, extra = {}) => ({
  id,
  ticketId: 'T-1',
  title: 'Customer delivery',
  tenantId: 'acme',
  beforeStatus: 'open',
  afterStatus: 'resolved',
  resourceVersion: '1',
  operationId: `operation-${id}`,
  digest: 'a'.repeat(64),
  expiresAt: 2000,
  createdAt: 1000,
  state: 'pending',
  requesterId: 'owner',
  requesterKind: 'person',
  archived: false,
  ...extra,
});
const session = (roles, forbidSelfApproval = false) => ({
  operator: { id: 'owner', tenantId: 'acme', roles },
  policy: { forbidSelfApproval },
});

test('the effect sentence states the change in the tense of its state, from validated fields only', () => {
  const request = row('r1');
  assert.equal(effectSentence(request), 'Ticket T-1 “Customer delivery” will change from open to resolved.');
  assert.equal(
    effectSentence(request, 'completed'),
    'Ticket T-1 “Customer delivery” was changed from open to resolved.',
  );
  assert.match(effectSentence(request, 'unconfirmed'), /may have changed from open to resolved\. The outcome is not/);
  for (const state of ['denied', 'withdrawn', 'expired', 'changed', 'failed', 'review_required'])
    assert.match(effectSentence(request, state), /would have changed from open to resolved\. Nothing was changed\.$/);
  assert.match(effectSentence({ ...request, afterStatus: 'deleted' }), /to unknown\.$/);
});

test('countdown, requester and archive labels read plainly', () => {
  assert.equal(duration(200_000), '3 min 20 s');
  assert.equal(duration(45_000), '45 s');
  assert.equal(duration(7_500_000), '2 h 5 min');
  assert.equal(countdown(201_000, 1000), 'expires in 3 min 20 s');
  assert.equal(countdown(1000, 1000), 'expired');
  assert.equal(requester(row('r', { requesterId: 'worker-1', requesterKind: 'agent' })), 'worker-1 (agent)');
  assert.equal(requester(row('r')), 'owner (person)');
  assert.equal(requester({ requesterId: 'legacy' }), 'legacy');
  const candidate = { ticketId: 'T-1', state: 'denied', requesterId: 'owner', createdAt: 0 };
  assert.notEqual(
    archiveCandidateLabel({ ...candidate, requestId: 'acme-1' }),
    archiveCandidateLabel({ ...candidate, requestId: 'acme-2' }),
  );
  assert.match(
    archiveCandidateLabel({ ...candidate, requestId: 'acme-1' }),
    /^Ticket T-1 · Denied · requested by owner · /,
  );
  assert.equal(blockerSentence('FAMILY_ACTIVE_WORK'), 'It is still being worked on. Wait until it finishes.');
  assert.equal(blockerSentence('SOMETHING_NEW'), 'It cannot be archived yet (SOMETHING_NEW).');
  // Every state the service can show has a label, and every terminal state is a shown state.
  assert.deepEqual(Object.keys(STATE_LABELS).sort(), [...REQUEST_STATES].sort());
  assert.ok(TERMINAL_STATES.every(state => REQUEST_STATES.includes(state)));
});

test('a background poll updates rows in place, holds new ones and never reorders or selects', () => {
  const current = [row('a'), row('b'), row('c')];
  const served = [row('new'), row('a', { state: 'denied', reviewerId: 'x' }), row('b')];
  const merged = mergePoll(current, [], served);
  assert.deepEqual(
    merged.requests.map(item => [item.id, item.state]),
    [
      ['a', 'denied'],
      ['b', 'pending'],
      ['c', 'pending'],
    ],
  );
  assert.equal(merged.requests[1], current[1], 'an unchanged row keeps its identity');
  assert.deepEqual(merged.changedIds, ['a']);
  assert.equal(merged.added, 1);
  assert.deepEqual(merged.goneIds, ['c']);
  assert.deepEqual(merged.newlyGone, ['c']);
  assert.equal(merged.incoming, served);
  const again = mergePoll(merged.requests, merged.goneIds, served);
  assert.deepEqual(again.newlyGone, []);
  assert.deepEqual(again.changedIds, []);
  assert.equal(mergePoll(current, [], current.map(copy)).incoming, null, 'nothing new: nothing held');
});

test('a reload keeps the selection only for the same request and never picks another', () => {
  const rows = [row('a'), row('b')];
  assert.deepEqual(selectionAfterReload('b', rows), { selectedRequestId: 'b', selectionGone: false });
  assert.deepEqual(selectionAfterReload('gone', rows), { selectedRequestId: '', selectionGone: true });
  assert.deepEqual(selectionAfterReload('', rows), { selectedRequestId: '', selectionGone: false });
  assert.equal(emptyWorkspace().selectedRequestId, '', 'a new workspace selects nothing');
  assert.equal(emptyWorkspace().targetStatus, '', 'no status is preselected');
});

test('decisions offered follow role, ownership, the self-approval policy and the deadline', () => {
  const mine = row('r'),
    theirs = row('r', { requesterId: 'someone' });
  assert.deepEqual(approval(session(['reviewer', 'requester']), mine, 1500), {
    decide: true,
    approve: true,
    selfApprovalForbidden: false,
    withdraw: true,
  });
  const forbidden = approval(session(['reviewer', 'requester'], true), mine, 1500);
  assert.equal(forbidden.approve, false);
  assert.equal(forbidden.decide, true, 'deny stays available');
  assert.equal(forbidden.selfApprovalForbidden, true);
  assert.equal(approval(session(['reviewer'], true), theirs, 1500).approve, true);
  assert.equal(approval(session(['requester']), theirs, 1500).withdraw, false);
  assert.equal(approval(session(['requester']), mine, 1500).decide, false);
  for (const request of [row('r', { state: 'completed' }), mine])
    assert.deepEqual(approval(session(['reviewer', 'requester']), request, request.state === 'pending' ? 2000 : 1500), {
      decide: false,
      approve: false,
    });
  assert.equal(shownState(mine, 2000), 'expired');
  assert.equal(shownState(mine, 1999), 'pending');
  assert.deepEqual(
    visibleRequests([mine, row('u', { state: 'unconfirmed' })], 'review', 2000).map(item => item.id),
    [],
  );
  assert.deepEqual(requestableStatuses(['open', 'resolved'], { status: 'open' }), ['resolved']);
  assert.deepEqual(requestableStatuses(['open', 'resolved'], undefined), []);
});

test('polling backs off after failures, stops while hidden and deep links round-trip', () => {
  assert.equal(pollDelay({ hidden: true, failures: 0 }), null);
  assert.equal(pollDelay({ hidden: false, failures: 0 }), 15_000);
  assert.equal(pollDelay({ hidden: false, failures: 2 }), 60_000);
  assert.equal(pollDelay({ hidden: false, failures: 50 }), 120_000);
  // Even the fastest polling stays far below the lowest configurable rate limit (60 a minute).
  assert.ok(60_000 / pollDelay({ hidden: false, failures: 0 }) <= 4);
  assert.deepEqual(parseFragment('#requests/acme-12'), { view: 'requests', requestId: 'acme-12' });
  assert.deepEqual(parseFragment('#setup'), { view: 'setup', requestId: '' });
  assert.deepEqual(parseFragment(fragmentFor('requests', 'acme-12')), { view: 'requests', requestId: 'acme-12' });
  assert.equal(fragmentFor('tickets', 'acme-12'), '#tickets');
  for (const junk of [
    '',
    '#main',
    '#requests/../x',
    '#requests/<script>',
    '#admin',
    null,
    '#requests/' + 'a'.repeat(81),
  ])
    assert.equal(parseFragment(junk), null, String(junk));
});

test('error wording has one source: the service sends it and the client only falls back to it', () => {
  for (const code of [...DEFINITIVE_REFUSALS, ...HARMLESS_REFUSALS])
    assert.equal(typeof ERROR_MESSAGES[code], 'string', code);
  assert.equal(failure(errorBody('REVIEW_EXPIRED')).message, ERROR_MESSAGES.REVIEW_EXPIRED);
  assert.equal(failure({ error: { code: 'REVIEW_EXPIRED', message: 'Served wording.' } }).message, 'Served wording.');
  assert.equal(failure({ error: { code: 'REVIEW_EXPIRED' } }).message, ERROR_MESSAGES.REVIEW_EXPIRED);
  assert.equal(failure(errorBody('SERVICE_UNAVAILABLE')).message, GENERIC_ERROR_MESSAGE);
  assert.equal(failure(errorBody('SERVICE_UNAVAILABLE')).code, 'SERVICE_UNAVAILABLE');
  assert.equal(failure({ error: { code: '<b>' } }).code, undefined);
  assert.equal(failure(null).message, GENERIC_ERROR_MESSAGE);
  for (const text of Object.values(ERROR_MESSAGES)) assert.doesNotMatch(text, /\b(backend|host|reconcil)/i);
});

test('the client accepts what the real service returns and rejects anything else', posixOnly, async t => {
  const fixture = setup(t, { mirror: true }),
    workflow = fixture.workflow,
    now = Date.now();
  const first = (await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
  const pending = copy(workflow.detail(first.id, 'acme'));
  assert.equal(check.detailValue(pending, 'acme', first.id).action.matchesRequest, true);
  const completed = copy(await workflow.decide({ ...owner, id: 'reviewer' }, first.id, { digest: first.digest }, true));
  assert.equal(check.requestResult(completed, 'acme', first.id).state, 'completed');
  const second = (await workflow.propose({ ...owner, kind: 'agent' }, { ticketId: 'T-1', status: 'open' })).request;
  const denied = copy(await workflow.decide(owner, second.id, { digest: second.digest, reason: 'Not needed' }, false));
  assert.equal(check.requestResult(denied, 'acme').denialReason, 'Not needed');
  const page = check.pageValue(copy(workflow.requests('acme')), 'requests', 0, 'acme');
  assert.deepEqual(page.rows.map(item => item.state).sort(), ['completed', 'denied']);
  assert.deepEqual(check.pageValue(copy(workflow.tickets('acme')), 'tickets', 0, 'acme').allowedStatuses, [
    'open',
    'resolved',
  ]);
  const maintenance = check.maintenanceValue(copy(workflow.maintenance(owner)));
  assert.equal(maintenance.archiveCandidates.length, 2);
  const preview = copy(workflow.previewArchive(owner, { taskId: maintenance.archiveCandidates[0].taskId }));
  assert.deepEqual(check.archivePreviewValue(preview, preview.preview.taskId).blockers, []);
  const signedIn = sessionBody({
    session: { csrfToken: 'token', operator: owner, expiresAt: now + 1000 },
    authorizationOrigins: ['https://idp.example'],
    issuer: 'https://idp.example',
    policy: workflow.requestPolicy,
  });
  assert.equal(check.sessionValue(copy(signedIn), now).policy.forbidSelfApproval, false);
  assert.equal(
    check.authorizationUrl({ authorizationUrl: 'https://idp.example/authorize?state=1' }, signedIn),
    'https://idp.example/authorize?state=1',
  );

  // Shapes the service never produces are refused, each for its own reason.
  const done = completed.request;
  const bad = (value, change) => {
    const next = copy(value);
    change(next);
    return next;
  };
  for (const [name, value] of [
    ['another tenant', bad(done, r => (r.tenantId = 'other'))],
    ['unknown state', bad(done, r => (r.state = 'approved'))],
    ['numeric version', bad(done, r => (r.resourceVersion = 1))],
    ['completed without its record', bad(done, r => delete r.receipt)],
    ['record for another request', bad(done, r => (r.receipt.requestId = 'x'))],
    ['record with another fingerprint', bad(done, r => (r.receipt.digest = 'b'.repeat(64)))],
    ['record with the wrong version', bad(done, r => (r.receipt.version = 9))],
    ['record on a pending request', bad(done, r => (r.state = 'pending'))],
    ['pending without a fingerprint', bad(pending.request, r => delete r.digest)],
    ['unknown requester kind', bad(done, r => (r.requesterKind = 'robot'))],
    ['lower-case cause', bad(done, r => (r.cause = 'oops'))],
  ])
    assert.throws(() => check.requestValue(value, 'acme'), Error, name);
  assert.equal(receiptMatches({ ...done, operationId: 'other' }, done.receipt), false);
  assert.equal(isSettled({ state: 'pending', expiresAt: 5 }, 5), true);
  assert.equal(isSettled({ state: 'preparing', expiresAt: 5 }, 9), false);
  const listed = copy(workflow.requests('acme'));
  for (const change of [
    p => (p.total = 1),
    p => (p.nextOffset = 2),
    p => (p.offset = 1),
    p => p.requests.push(p.requests[0]),
    p => (p.truncated = true),
  ])
    assert.throws(() => check.pageValue(bad(listed, change), 'requests', 0, 'acme'));
  assert.throws(() =>
    check.pageValue(
      bad(copy(workflow.tickets('acme')), p => delete p.allowedStatuses),
      'tickets',
      0,
    ),
  );
  assert.throws(() =>
    check.sessionValue(
      bad(signedIn, s => delete s.policy),
      now,
    ),
  );
  assert.throws(() => check.sessionValue(copy(signedIn), now + 1000), /expired/);
  assert.throws(() =>
    check.sessionValue(
      bad(signedIn, s => s.operator.roles.push('admin')),
      now,
    ),
  );
  assert.throws(() => check.authorizationUrl({ authorizationUrl: 'https://evil.example/authorize' }, signedIn));
  assert.throws(() => check.authorizationUrl({ authorizationUrl: 'https://idp.example/a?id_token=x' }, signedIn));
  assert.throws(() =>
    check.maintenanceValue(
      bad(maintenance, m => (m.archiveCandidates[0].label = 1) && delete m.archiveCandidates[0].requestId),
    ),
  );
  assert.throws(() =>
    check.maintenanceValue(bad(maintenance, m => (m.keyRotation = { state: 'offline_required', keyId: 'k' }))),
  );
  assert.throws(() =>
    check.archivePreviewValue(
      bad(preview, p => (p.preview.blockers = ['a sentence'])),
      preview.preview.taskId,
    ),
  );
  assert.throws(() =>
    check.detailValue(
      bad(pending, d => (d.action.matchesRequest = 'yes')),
      'acme',
      first.id,
    ),
  );
});

test(
  'close-out evidence shows the reviewed ticket beside the current one and must agree with the request',
  posixOnly,
  async t => {
    const fixture = setup(t),
      workflow = fixture.workflow;
    const stuck = async () => {
      const { request } = await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' });
      fixture.runtime.backend.transaction(state => {
        Object.assign(state.ticketService.requests[request.id], { state: 'unconfirmed', reviewerId: 'owner' });
      });
      return request;
    };
    const request = await stuck(),
      other = (await workflow.propose(owner, { ticketId: 'T-1', status: 'resolved' })).request;
    const untouched = check.closeOutValue(copy(workflow.previewCloseOut(owner, request.id)), request);
    assert.equal(untouched.ticketChanged, false);
    await workflow.decide(owner, other.id, { digest: other.digest }, true);
    const served = copy(workflow.previewCloseOut(owner, request.id));
    const moved = check.closeOutValue(served, request);
    assert.deepEqual(
      [moved.reviewedVersion, moved.reviewedStatus, moved.ticketVersion, moved.ticketStatus, moved.ticketChanged],
      [1, 'open', 2, 'resolved', true],
    );
    for (const change of [
      evidence => (evidence.ticketChanged = false),
      evidence => (evidence.reviewedVersion = 2),
      evidence => (evidence.reviewedStatus = 'resolved'),
      evidence => (evidence.ticketVersion = '2'),
      evidence => (evidence.ticketStatus = 'closed'),
      evidence => (evidence.receipt = 'present'),
      evidence => (evidence.requestId = other.id),
      evidence => delete evidence.digest,
    ]) {
      const altered = copy(served);
      change(altered.closeOut);
      assert.throws(() => check.closeOutValue(altered, request), /close-out evidence/);
    }
  },
);
