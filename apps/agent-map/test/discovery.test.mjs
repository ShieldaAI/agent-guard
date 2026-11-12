import test from 'node:test';
import assert from 'node:assert/strict';
import { OPERATIONS } from '../src/view-model.mjs';
import {
  accountReasonLabel,
  accountStale,
  discoveryHidden,
  taskLineageLabel,
  unclaimedSummary,
  undeclaredActivityLabel,
} from '../src/discovery-model.mjs';

test('the viewer may call the two discovery operations and nothing that writes', () => {
  for (const operation of ['list_undeclared_activity', 'list_unclaimed_identities'])
    assert.ok(OPERATIONS.includes(operation));
  assert.equal(OPERATIONS.includes('declare_agent'), false);
});

test('an undeclared count is shown only when the service counted it', () => {
  const counted = { status: 'complete', tasks: 2, tasksIsMinimum: false, principals: 1, principalsIsMinimum: false };
  assert.equal(undeclaredActivityLabel(counted).text, '2 tasks and 1 caller with no declared agent');
  assert.equal(
    undeclaredActivityLabel({ ...counted, status: 'partial', tasks: 10_000, tasksIsMinimum: true }).text,
    '10000+ tasks and 1 caller with no declared agent',
  );
  assert.equal(
    undeclaredActivityLabel({ ...counted, manifest: 'not_collected' }).text,
    '2 tasks and 1 caller with no declared agent (this source has no manifest)',
  );
  assert.deepEqual(undeclaredActivityLabel({ ...counted, tasks: 0, principals: 0 }), {
    tone: 'green',
    text: 'No task or caller without a declared agent',
  });
  // A capped zero cannot exist, and anything short of a count is never shown as none.
  for (const activity of [
    undefined,
    null,
    {},
    { status: 'unknown', reason: 'read_timeout' },
    { status: 'unknown', reason: '<script>' },
    { status: 'complete' },
    { status: 'complete', tasks: -1, principals: 0 },
    { status: 'complete', tasks: '0', principals: 0 },
    { status: 'surprise', tasks: 0, principals: 0 },
  ]) {
    const label = undeclaredActivityLabel(activity);
    assert.equal(label.tone, 'amber', JSON.stringify(activity));
    assert.match(label.text, /^Unknown: /);
    assert.equal(/[0-9<]/.test(label.text), false);
  }
});

test('a hidden discovery view shows no count', () => {
  const label = undeclaredActivityLabel({
    status: 'not_visible',
    reason: 'all_teams_required',
    tasks: 7,
    principals: 7,
  });
  assert.equal(label.text, 'Shown to all-teams readers only');
  assert.equal(discoveryHidden({ status: 'not_visible' }), true);
  assert.equal(discoveryHidden({ status: 'complete' }), false);
  assert.equal(discoveryHidden(undefined), false);
});

test('unclaimed identities are candidates, and unknown is never shown as none', () => {
  assert.equal(unclaimedSummary({ status: 'complete', total: 2 }).text, '2 candidates to review');
  assert.equal(unclaimedSummary({ status: 'complete', total: 1 }).text, '1 candidate to review');
  assert.deepEqual(unclaimedSummary({ status: 'complete', total: 0 }), {
    tone: 'green',
    text: 'Every collected IAM role and user is named by a declared agent',
  });
  assert.match(unclaimedSummary({ status: 'partial', total: 0 }).text, /the rest are unknown$/);
  for (const data of [
    undefined,
    {},
    { status: 'unknown', total: null, reason: null },
    { status: 'unknown', total: 0 },
    { status: 'complete', total: null },
    { status: 'complete' },
  ]) {
    const summary = unclaimedSummary(data);
    assert.equal(summary.tone, 'amber');
    assert.match(summary.text, /^Unknown: /, JSON.stringify(data));
  }
  assert.match(
    unclaimedSummary({ status: 'unknown', reason: 'cloud_not_collected' }).text,
    /no AWS account is collected/,
  );
});

test('a stale collection is marked on its account and never gets the all-clear headline', () => {
  const fresh = { status: 'complete', reason: null, observedAt: '2026-01-01T00:00:00.000Z', stale: false };
  const stale = { ...fresh, stale: true, ageSeconds: 10_800 };
  const unknown = { status: 'unknown', reason: 'stale', observedAt: '2025-12-01T00:00:00.000Z', stale: true };
  assert.equal(accountReasonLabel(fresh), 'Collected');
  assert.equal(accountReasonLabel(stale), 'Collected, but stale');
  // An account that is unknown says why; it is not also "collected".
  assert.equal(accountReasonLabel(unknown), 'The last AWS collection is older than the enrolled age limit.');
  assert.deepEqual([fresh, stale, unknown, {}, null, undefined].map(accountStale), [
    false,
    true,
    false,
    false,
    false,
    false,
  ]);
  // A service that reports no freshness is shown as before.
  assert.equal(accountReasonLabel({ status: 'complete', reason: null }), 'Collected');

  const clear = unclaimedSummary({ status: 'complete', total: 0, accounts: [fresh, fresh] });
  assert.deepEqual(clear, { tone: 'green', text: 'Every collected IAM role and user is named by a declared agent' });
  const aged = unclaimedSummary({ status: 'complete', total: 0, accounts: [fresh, stale] });
  assert.equal(aged.tone, 'amber');
  assert.equal(aged.text.includes('Every collected IAM role and user'), false);
  assert.match(aged.text, /^No unclaimed IAM role or user in the last collection; at least one collection is stale/);
  const candidates = unclaimedSummary({ status: 'complete', total: 2, accounts: [stale] });
  assert.equal(candidates.tone, 'amber');
  assert.match(candidates.text, /^2 candidates to review; at least one collection is stale/);
  const partial = unclaimedSummary({ status: 'partial', total: 1, accounts: [stale, unknown] });
  assert.match(partial.text, /the rest are unknown; at least one collection is stale/);
  // Only a complete account's own flag counts, and a malformed list changes nothing.
  for (const accounts of [[unknown], [], undefined, 'stale', [null]])
    assert.equal(unclaimedSummary({ status: 'complete', total: 0, accounts }).tone, 'green', JSON.stringify(accounts));
});

test('every unknown account says why, and task lineage separates sub-tasks from strangers', () => {
  assert.equal(accountReasonLabel({ status: 'complete', reason: null }), 'Collected');
  for (const reason of [
    'stale',
    'collection_invalid',
    'changed',
    'limit_exceeded',
    'claims_limit_exceeded',
    'new_reason',
    null,
  ])
    assert.ok(
      accountReasonLabel({ status: 'unknown', reason }).length > 20 &&
        accountReasonLabel({ status: 'unknown', reason }) !== 'Collected',
    );
  assert.equal(accountReasonLabel(undefined), 'The AWS collection could not be judged.');
  assert.match(taskLineageLabel({ parentDeclared: true, delegated: true }), /^Sub-task of a declared agent/);
  assert.equal(taskLineageLabel({ parentDeclared: false, derived: true }), 'Sub-task of an undeclared task');
  assert.equal(taskLineageLabel({ parentDeclared: false, delegated: false, derived: false }), 'No declared parent');
});
