import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DurableExecutor } from '../../../packages/executor/dist/index.js';
import { LedgerStore } from '../../../packages/executor/dist/store.js';
import { normalizeLimits, DEFAULT_LIMITS, LIMIT_BOUNDS, assertCapacity } from '../limits.mjs';
import { TicketWorkflow, initializeTickets, validateTicketSeed } from '../workflow.mjs';

const seed = (id, tenantId = 'acme') => ({ id, tenantId, title: `Ticket ${id}`, status: 'open' });
const actor = tenantId => ({ id: `owner-${tenantId}`, tenantId });
function fixture(t, { tickets = [seed('T-1'), seed('T-2', 'other')], limits } = {}) {
  const store = new LedgerStore(':memory:', randomBytes(32), 64 * 1024 * 1024);
  const executor = new DurableExecutor({ database: ':memory:', encryptionKey: randomBytes(32) });
  t.after(() => {
    executor.close();
    store.close();
  });
  initializeTickets(store, { guardInstanceId: 'fixture-guard', tickets, limits });
  const options = { executor, store, guardInstanceId: 'fixture-guard', limits };
  return { store, executor, options, workflow: new TicketWorkflow(options) };
}

test('limits use backward-compatible defaults, strict integers and fixed ceilings', () => {
  assert.deepEqual(normalizeLimits(), DEFAULT_LIMITS);
  const configured = { maxRequests: 6000 },
    policy = normalizeLimits(configured);
  configured.maxRequests = 1;
  assert.equal(policy.maxRequests, 6000);
  assert.equal(Object.isFrozen(policy), true);
  for (const [name, { min, max }] of Object.entries(LIMIT_BOUNDS)) {
    assert.equal(Object.isFrozen(LIMIT_BOUNDS[name]), true);
    for (const value of [min, max]) assert.equal(normalizeLimits({ [name]: value })[name], value);
    for (const value of [min - 1, max + 1, 1.5, NaN, Infinity, '4', null, undefined, Number.MAX_SAFE_INTEGER + 1])
      assert.throws(() => normalizeLimits({ [name]: value }), { code: 'LIMITS_INVALID' });
  }
  for (const value of [null, [], false, { extra: 1 }, Object.create({ maxRequests: 1 }), { [Symbol('hidden')]: 1 }])
    assert.throws(() => normalizeLimits(value), { code: 'LIMITS_INVALID' });
  let invoked = false;
  assert.throws(
    () =>
      normalizeLimits({
        get maxRequests() {
          invoked = true;
          return 1;
        },
      }),
    { code: 'LIMITS_INVALID' },
  );
  assert.equal(invoked, false);
});

test('seed preflight supports empty onboarding and larger enrollments without retaining caller objects', () => {
  assert.deepEqual(validateTicketSeed([]), []);
  assert.throws(() => validateTicketSeed(Array(1)), { code: 'INVALID_INPUT' });
  const source = Array.from({ length: 501 }, (_, i) => seed(`T-${i}`));
  assert.throws(() => validateTicketSeed(source), { code: 'INVALID_SEED' });
  const accepted = validateTicketSeed(source, { maxTickets: 600 });
  source[0].title = 'changed after validation';
  assert.equal(accepted[0].title, 'Ticket T-0');
  assert.throws(() => validateTicketSeed([seed('duplicate'), seed('duplicate', 'other')]), { code: 'INVALID_SEED' });
  assert.throws(() => validateTicketSeed([{ ...seed('x'), version: 99 }]), { code: 'INVALID_INPUT' });
  assert.throws(() => validateTicketSeed([{ ...seed('x'), title: ' ' }]), { code: 'INVALID_SEED' });
});

test('capacity preflight counts all tenants and rejects shrinkage without deleting records', () => {
  const data = {
    tickets: { one: seed('one'), two: seed('two', 'other') },
    requests: { a: {}, b: {} },
    receipts: { a: {}, b: {} },
  };
  const before = structuredClone(data);
  assert.throws(() => assertCapacity(data, { maxTickets: 1 }), { code: 'LIMITS_BELOW_USAGE' });
  assert.throws(() => assertCapacity(data, { maxRequests: 1 }), { code: 'LIMITS_BELOW_USAGE' });
  assert.deepEqual(data, before);
  const usage = assertCapacity(data, { maxTickets: 2, maxRequests: 2 });
  assert.deepEqual({ ...usage, backendBytes: 0 }, { tickets: 2, requests: 2, receipts: 2, backendBytes: 0 });
  data.retainedEvidence = 'x'.repeat(1024 * 1024);
  assert.throws(() => assertCapacity(data, { maxBackendBytes: 1024 * 1024 }), { code: 'LIMITS_BELOW_USAGE' });
  assert.equal(data.retainedEvidence.length, 1024 * 1024);
});

test('startup binds persisted limits and never silently applies a changed policy', t => {
  const f = fixture(t, { tickets: [], limits: { maxRequests: 2 } });
  const before = f.store.read();
  assert.deepEqual({ ...before.ticketService.limits }, normalizeLimits({ maxRequests: 2 }));
  assert.throws(() => new TicketWorkflow({ ...f.options, limits: { maxRequests: 3 } }), {
    code: 'LIMITS_CHANGE_REQUIRES_OFFLINE',
  });
  assert.deepEqual(f.store.read(), before);
  // The trusted offline command first preflights both stores, then persists this policy.
  const next = normalizeLimits({ maxRequests: 3 });
  assertCapacity(before.ticketService, next);
  f.store.transaction(state => {
    state.ticketService.limits = next;
  });
  assert.equal(new TicketWorkflow({ ...f.options, limits: next }).maintenance(actor('acme')).recordLimit, 3);
});

test('legacy installations adopt only the same default policy', t => {
  const f = fixture(t);
  f.store.transaction(state => {
    delete state.ticketService.limits;
  });
  assert.throws(() => new TicketWorkflow({ ...f.options, limits: { maxRequests: 6000 } }), {
    code: 'LIMITS_CHANGE_REQUIRES_OFFLINE',
  });
  new TicketWorkflow(f.options);
  assert.deepEqual({ ...f.store.read().ticketService.limits }, DEFAULT_LIMITS);
});

test('global request capacity preserves pending authority, denied history and archived business records', async t => {
  const f = fixture(t, { limits: { maxRequests: 2 } });
  const first = (await f.workflow.propose(actor('acme'), { ticketId: 'T-1', status: 'resolved' })).request;
  const second = (await f.workflow.propose(actor('other'), { ticketId: 'T-2', status: 'resolved' })).request;
  const before = f.store.read();
  await assert.rejects(f.workflow.propose(actor('acme'), { ticketId: 'T-1', status: 'resolved' }), {
    code: 'RECORD_CAPACITY_REACHED',
  });
  assert.deepEqual(f.store.read(), before);
  await f.workflow.decide(actor('acme'), first.id, { digest: first.digest }, false);
  const preview = f.workflow.previewArchive(actor('acme'), { taskId: `ticket:${first.id}` }).preview;
  f.workflow.archive(actor('acme'), { id: preview.id, digest: preview.digest });
  await assert.rejects(f.workflow.propose(actor('acme'), { ticketId: 'T-1', status: 'resolved' }), {
    code: 'RECORD_CAPACITY_REACHED',
  });
  assert.equal(f.workflow.request(second.id, 'other').state, 'pending');
  const maintenance = f.workflow.maintenance(actor('acme'));
  assert.equal(maintenance.records, 1);
  assert.equal(maintenance.usage.requests, 2);
  assert.equal(maintenance.usage.tickets, 2);
  assert.equal(maintenance.capacityWarning, true);
  assert.equal(maintenance.usage.backendBytes, Buffer.byteLength(JSON.stringify(f.store.read())));
});

test('ticket and request pages expose all enrolled rows with tenant-local totals and bounded offsets', t => {
  const tickets = Array.from({ length: 601 }, (_, i) => seed(`T-${String(i).padStart(4, '0')}`));
  tickets.push(seed('PRIVATE', 'other'));
  const f = fixture(t, { tickets, limits: { maxTickets: 1000 } });
  f.store.transaction(state => {
    for (let i = 0; i < 601; i++) {
      const id = `R-${String(i).padStart(4, '0')}`;
      state.ticketService.requests[id] = {
        id,
        ticketId: tickets[i].id,
        tenantId: 'acme',
        title: 'Request',
        beforeStatus: 'open',
        afterStatus: 'resolved',
        resourceVersion: '1',
        state: i === 600 ? 'unconfirmed' : 'completed',
        createdAt: 1,
        expiresAt: 2,
        requesterId: 'owner',
      };
    }
    state.ticketService.requests.private = { id: 'private', tenantId: 'other', state: 'unconfirmed', createdAt: 1 };
  });
  const first = f.workflow.tickets('acme'),
    last = f.workflow.tickets('acme', { offset: first.nextOffset });
  assert.equal(first.total, 601);
  assert.equal(first.tickets.length, 500);
  assert.equal(first.nextOffset, 500);
  assert.equal(last.tickets.length, 101);
  assert.equal(last.nextOffset, null);
  assert.equal(last.truncated, false);
  assert.equal(new Set([...first.tickets, ...last.tickets].map(ticket => ticket.id)).size, 601);
  assert.deepEqual(
    f.workflow.tickets('other').tickets.map(ticket => ticket.id),
    ['PRIVATE'],
  );
  const requests = f.workflow.requests('acme'),
    rest = f.workflow.requests('acme', { offset: requests.nextOffset });
  assert.equal(requests.total, 601);
  assert.equal(requests.requests[0].state, 'unconfirmed');
  assert.equal(new Set([...requests.requests, ...rest.requests].map(request => request.id)).size, 601);
  assert.equal(f.workflow.requests('other').total, 1);
  assert.deepEqual(f.workflow.requests('other', { offset: 500 }).requests, []);
  for (const options of [
    { offset: -1 },
    { offset: 20_001 },
    { offset: '1' },
    { offset: 1.2 },
    { limit: 0 },
    { limit: 501 },
    { cursor: 'foreign' },
  ])
    assert.throws(
      () => f.workflow.requests('acme', options),
      error => ['PAGINATION_INVALID', 'INVALID_INPUT'].includes(error.code),
    );
});
