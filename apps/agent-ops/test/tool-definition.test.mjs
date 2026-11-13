// The Maintenance page's tool-definition comparison: what the service reports and what the client accepts.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as check from '../public/validate.js';
import { toolHintLabel } from '../public/text.js';
import { toolReviewBody } from '../responses.mjs';
import { setup, owner } from './helpers.mjs';

const posixOnly = { skip: process.platform === 'win32' ? 'The witnessed deployment requires POSIX.' : false };
const copy = value => JSON.parse(JSON.stringify(value));
const LIMITS = { maxTickets: 10, maxRequests: 100, maxBackendBytes: 1024, maxLedgerBytes: 1024, maxRetainedKeys: 2 };
const fingerprint = letter => `sha256:${letter.repeat(64)}`;
const changed = (changes, extra = {}) =>
  toolReviewBody({
    name: 'ticket.update',
    status: 'changed',
    fingerprint: fingerprint('b'),
    approvedFingerprint: fingerprint('a'),
    approval: { approvedAt: 1_000 },
    changes,
    truncated: false,
    ...extra,
  });

test('the service reports its tool as a first approval, then as unchanged after a restart', posixOnly, t => {
  const fixture = setup(t);
  let tool = check.maintenanceValue(copy(fixture.workflow.maintenance(owner))).toolDefinition;
  assert.deepEqual(
    [tool.name, tool.status, tool.approvedFingerprint, tool.approvedAt, tool.changes.length, tool.truncated],
    ['ticket.update', 'first_approval', null, null, 0, false],
  );
  const first = tool.fingerprint;
  fixture.reopen();
  tool = check.maintenanceValue(copy(fixture.workflow.maintenance(owner))).toolDefinition;
  assert.deepEqual([tool.status, tool.fingerprint, tool.approvedFingerprint], ['unchanged', first, first]);
  assert.equal(Number.isSafeInteger(tool.approvedAt), true, 'the ledger recorded when the definition was approved');
  // The startup approval is in the ledger with the service as approver.
  assert.equal(fixture.runtime.executor.toolChanges('ticket.update').approval.approverId, 'system:startup');
});

test('definition text reaches the page as bounded text with invisible characters written out', () => {
  const markup = '<img src=x onerror=alert(1)>\u200b\u202e</pre><script>1</script>';
  const body = changed([
    { path: '/description', kind: 'changed', before: 'old', after: markup, hints: ['INSTRUCTION_TEXT'] },
    { path: '/inputSchema/properties/a\u200bb', kind: 'added', after: { note: 'x'.repeat(5000) }, hints: [] },
    { path: '/metadata/owner', kind: 'removed', before: null, hints: [] },
  ]);
  const [description, added, removed] = check.maintenanceValue({ ...baseline(), toolDefinition: copy(body) })
    .toolDefinition.changes;
  assert.equal(
    description.after.text,
    '"<img src=x onerror=alert(1)>\\u{200B}\\u{202E}</pre><script>1</script>"',
    'a JSON string: quoted, markup untouched for the client to show as text, invisible characters visible',
  );
  assert.equal(added.path, '/inputSchema/properties/a\\u{200B}b');
  assert.deepEqual([added.before, added.after.text.length, added.after.truncated], [null, 2000, true]);
  assert.deepEqual([removed.before, removed.after], [{ text: 'null', truncated: false }, null]);
  assert.equal(toolHintLabel('INSTRUCTION_TEXT'), 'New text reads like an instruction or names credentials');
  assert.equal(toolHintLabel('SOMETHING_NEW'), 'Check this change', 'an unknown hint still gets fixed wording');

  const many = changed(
    Array.from({ length: 80 }, (_, index) => ({ path: `/metadata/k${index}`, kind: 'added', after: 1, hints: [] })),
  );
  assert.deepEqual([many.changes.length, many.truncated], [50, true]);
});

test('the client refuses a comparison it cannot show safely', () => {
  const good = changed([{ path: '/description', kind: 'changed', before: 'a', after: 'b', hints: [] }]);
  const refuses = mutate => {
    const toolDefinition = copy(good);
    mutate(toolDefinition);
    assert.throws(() => check.maintenanceValue({ ...baseline(), toolDefinition }), /could not be verified/);
  };
  check.maintenanceValue({ ...baseline(), toolDefinition: copy(good) });
  assert.throws(() => check.maintenanceValue(baseline()), /could not be verified/, 'the comparison is required');
  refuses(tool => (tool.status = 'approved'));
  refuses(tool => (tool.fingerprint = 'b'.repeat(64)));
  refuses(tool => (tool.approvedFingerprint = '<b>'));
  refuses(tool => (tool.reason = 'too large'));
  refuses(tool => (tool.changes[0].after = '<b>raw string</b>'));
  refuses(tool => (tool.changes[0].after = { text: 'x'.repeat(2001), truncated: false }));
  refuses(tool => (tool.changes[0].after = { html: '<b>' }));
  refuses(tool => (tool.changes[0].kind = 'replaced'));
  refuses(tool => (tool.changes[0].before = null), 'a changed value has both sides');
  refuses(tool => (tool.changes[0].hints = ['<script>']));
  refuses(tool => (tool.changes[0].path = 7));
  refuses(tool => (tool.status = 'unchanged'), 'no changes are listed unless the status is changed');
  refuses(tool => (tool.changes = Array.from({ length: 51 }, () => tool.changes[0])));
});

/** A maintenance reply that passes every other check. */
function baseline() {
  return {
    archiveCandidates: [],
    archiveCandidatesTruncated: false,
    unresolvedCount: 0,
    records: 0,
    recordLimit: 100,
    capacityWarning: false,
    statistics: { ledgerBytes: 1 },
    history: {
      archivedRequests: '0',
      segments: 0,
      lastCommittedAt: null,
      commitment: null,
      pending: false,
      mode: 'reviewed-offline',
    },
    keyRotation: { state: 'offline', message: 'Offline only.' },
    limits: LIMITS,
    usage: { tickets: 0, requests: 0, receipts: 0, backendBytes: 0 },
    historyCapacity: { committed: 0, reserved: 0, total: 0, limit: 10_000 },
  };
}
