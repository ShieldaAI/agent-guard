import test from 'node:test';
import assert from 'node:assert/strict';
import { OPERATIONS } from '../src/view-model.mjs';
import { queryDemo } from '../src/demo.mjs';
import {
  accountReasonLabel,
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

test('the synthetic demo answers both discovery operations with paged, labelled rows', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('Demo must stay local'));
  const [source] = (await queryDemo('get_inventory_health')).data.sources;
  assert.equal(undeclaredActivityLabel(source.undeclaredActivity).text, '2 tasks and 1 caller with no declared agent');
  const tasks = await queryDemo('list_undeclared_activity', { sourceId: source.id, limit: 1 });
  assert.deepEqual([tasks.data.items.length, tasks.data.total, tasks.data.truncated], [1, 2, true]);
  assert.equal(tasks.data.items[0].assessment, 'unknown');
  const callers = await queryDemo('list_undeclared_activity', { sourceId: source.id, kind: 'principals' });
  assert.equal(callers.data.items[0].principalId, 'batch-scheduler');
  await assert.rejects(queryDemo('list_undeclared_activity', { sourceId: 'other' }), /REFERENCE_NOT_FOUND/);
  const identities = await queryDemo('list_unclaimed_identities', {});
  assert.equal(
    identities.data.identities.every(identity => identity.candidate === true),
    true,
  );
  assert.equal(unclaimedSummary(identities.data).text, '2 candidates to review');
});
