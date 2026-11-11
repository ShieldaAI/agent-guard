import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { MapService, MAP_OPERATIONS, validateQueryArguments } from '../dist/service.js';
import { Neo4jMapStore } from '../dist/store.js';
import { MapQueryError } from '../dist/types.js';

const NOW = Date.parse('2030-01-02T00:00:00Z');
const team = { subject: 'reader', companyId: 'company', tenantIds: ['alpha'], teamIds: ['team-one'], allTeams: false };
const all = { ...team, teamIds: [], allTeams: true };
const plain = value => JSON.parse(JSON.stringify(value));

// ---- Service ----

const projection = (extra = {}) => ({
  id: 'current',
  snapshotId: 'snapshot',
  generatedAt: new Date(NOW - 1000).toISOString(),
  status: 'published',
  nodes: [],
  edges: [],
  coverage: { tasks: { status: 'complete', observedAt: new Date(NOW - 2000).toISOString() } },
  ...extra,
});
const sourceOf = (current, extra = {}) => ({
  id: 'source',
  tenantId: 'alpha',
  sourceId: 'installation',
  profile: 'host',
  current,
  previous: null,
  ...extra,
});
const counts = (extra = {}) => ({ tasks: 3, tasksCapped: false, principals: 2, principalsCapped: false, ...extra });
const task = {
  id: 'entity:task',
  taskId: 'stray-task',
  principalId: 'stray-caller',
  delegated: false,
  derived: false,
  revoked: false,
  parentDeclared: false,
  tools: ['reports.read'],
  toolsTruncated: false,
};
/** A store that answers the plain read with one source and records every request. */
function serviceWith(discovery, profile = 'host') {
  const requests = [];
  const store = {
    async read(_scope, request = {}) {
      requests.push(plain(request));
      if (request.undeclared || request.unclaimedIdentities) return discovery(request);
      return { sources: [sourceOf(projection(), { profile })] };
    },
  };
  return { requests, service: new MapService(store, { clock: () => NOW }) };
}

test('the two discovery operations are registered with closed schemas', () => {
  assert.deepEqual(MAP_OPERATIONS.slice(-2), ['list_undeclared_activity', 'list_unclaimed_identities']);
  assert.equal(
    validateQueryArguments('list_undeclared_activity', { sourceId: 's', kind: 'principals' }).kind,
    'principals',
  );
  for (const [operation, args] of [
    ['list_undeclared_activity', {}],
    ['list_undeclared_activity', { sourceId: 's', kind: 'agents' }],
    ['list_undeclared_activity', { sourceId: 's', limit: 101 }],
    ['list_unclaimed_identities', { sourceId: 's' }],
    ['list_unclaimed_identities', { offset: -1 }],
  ])
    assert.throws(() => validateQueryArguments(operation, args), { code: 'MAP_REQUEST_INVALID' }, operation);
});

test('a team-scoped reader gets one fixed note and the store is never read', async () => {
  const { service, requests } = serviceWith(() => assert.fail('discovery read for a team-scoped reader'));
  const answers = [];
  for (const [operation, args] of [
    ['list_undeclared_activity', { sourceId: 'source' }],
    ['list_undeclared_activity', { sourceId: 'no-such-source', kind: 'principals', offset: 40 }],
    ['list_unclaimed_identities', {}],
  ]) {
    const { data } = await service.query(team, operation, args);
    answers.push(JSON.stringify(data));
    assert.deepEqual(Object.keys(data).sort(), ['note', 'status', 'visibility']);
    assert.equal(data.status, 'not_visible');
    assert.equal(data.visibility, 'all_teams_required');
    assert.equal(/[0-9]/.test(data.note), false, 'the note carries no count');
  }
  // The same words for a source that exists, one that does not, and for identities.
  assert.equal(new Set(answers).size, 1);
  assert.deepEqual(requests, []);
});

test('health gives a team-scoped reader no undeclared count and makes no second read', async () => {
  const { service, requests } = serviceWith(() => assert.fail('discovery read for a team-scoped reader'));
  const { data } = await service.query(team, 'get_inventory_health', {});
  assert.deepEqual(plain(data.sources[0].undeclaredActivity), { status: 'not_visible', reason: 'all_teams_required' });
  assert.equal(requests.length, 1);
});

test('health counts undeclared activity per source for an all-teams reader', async () => {
  const { service, requests } = serviceWith(() => ({ sources: [sourceOf(projection({ undeclared: counts() }))] }));
  const { data } = await service.query(all, 'get_inventory_health', { sourceId: 'source' });
  assert.deepEqual(plain(data.sources[0].undeclaredActivity), {
    status: 'complete',
    tasks: 3,
    tasksIsMinimum: false,
    principals: 2,
    principalsIsMinimum: false,
    manifest: 'collected',
  });
  assert.deepEqual(requests[1], { sourceId: 'source', undeclared: true });
});

test('a capped count is partial, and a source without a manifest says so', async () => {
  const { service } = serviceWith(
    () => ({
      sources: [
        sourceOf(projection({ undeclared: counts({ tasks: 10_000, tasksCapped: true }) }), { profile: 'core' }),
      ],
    }),
    'core',
  );
  const activity = (await service.query(all, 'get_inventory_health', {})).data.sources[0].undeclaredActivity;
  assert.equal(activity.status, 'partial');
  assert.equal(activity.tasksIsMinimum, true);
  assert.equal(activity.manifest, 'not_collected');
});

test('a failed, slow, oversized or outdated undeclared read leaves health answering with unknown', async () => {
  for (const [failure, reason] of [
    [new MapQueryError('MAP_UNAVAILABLE'), 'read_unavailable'],
    [new MapQueryError('MAP_LIMIT_EXCEEDED'), 'limit_exceeded'],
    [new MapQueryError('MAP_TIMEOUT'), 'read_timeout'],
    [new Error('driver exploded'), 'read_unavailable'],
    [() => ({ sources: [sourceOf(projection())] }), 'not_reported'],
    [() => ({ sources: [] }), 'not_reported'],
    [() => ({ sources: [sourceOf(projection({ id: 'newer', undeclared: counts() }))] }), 'publication_changed'],
  ]) {
    const { service } = serviceWith(() => {
      if (typeof failure === 'function') return failure();
      throw failure;
    });
    const { data } = await service.query(all, 'get_inventory_health', {});
    assert.equal(data.sources[0].stale, false, reason);
    assert.deepEqual(plain(data.sources[0].undeclaredActivity), { status: 'unknown', reason });
  }
});

test('list_undeclared_activity pages one source and labels every row as observed, not assessed', async () => {
  const { service, requests } = serviceWith(request => ({
    sources: [sourceOf(projection({ undeclared: counts({ page: { kind: request.page.kind, items: [task] } }) }))],
  }));
  const { data } = await service.query(all, 'list_undeclared_activity', { sourceId: 'source', limit: 1 });
  assert.deepEqual(requests, [{ sourceId: 'source', undeclared: true, page: { kind: 'tasks', offset: 0, limit: 1 } }]);
  assert.deepEqual(plain(data.items), [{ ...task, evidenceKind: 'observed', assessment: 'unknown' }]);
  assert.deepEqual(
    [data.kind, data.total, data.totalIsMinimum, data.offset, data.limit, data.truncated, data.visibility],
    ['tasks', 3, false, 0, 1, true, 'all_teams'],
  );
  assert.equal(data.counts.principals, 2);
  assert.equal(data.receipt.projectionId, 'current');
  assert.equal(data.assessment, 'unknown');
  assert.ok(data.limitations.some(text => text.includes('grants or blocks nothing')));
  await assert.rejects(service.query(all, 'list_undeclared_activity', { sourceId: 'other' }), {
    code: 'MAP_NOT_FOUND',
  });
});

test('a capped total is reported as a minimum and the listing as truncated', async () => {
  const { service } = serviceWith(() => ({
    sources: [
      sourceOf(
        projection({
          undeclared: counts({ principals: 10_000, principalsCapped: true, page: { kind: 'principals', items: [] } }),
        }),
      ),
    ],
  }));
  const { data } = await service.query(all, 'list_undeclared_activity', {
    sourceId: 'source',
    kind: 'principals',
    offset: 9990,
    limit: 100,
  });
  assert.deepEqual([data.total, data.totalIsMinimum, data.truncated], [10_000, true, true]);
});

test('a store answer without the requested page is unavailable, never an empty list', async () => {
  for (const undeclared of [undefined, counts(), counts({ page: { kind: 'principals', items: [] } })]) {
    const { service } = serviceWith(() => ({ sources: [sourceOf(projection(undeclared ? { undeclared } : {}))] }));
    await assert.rejects(service.query(all, 'list_undeclared_activity', { sourceId: 'source' }), {
      code: 'MAP_UNAVAILABLE',
    });
  }
});

const account = (extra = {}) => ({
  tenantId: 'alpha',
  partition: 'aws',
  accountId: '111122223333',
  status: 'complete',
  reason: null,
  observedAt: new Date(NOW - 60_000).toISOString(),
  observed: 5,
  unclaimed: 2,
  ...extra,
});
const identity = {
  arn: 'arn:aws:iam::111122223333:role/batch-runner',
  kind: 'role',
  name: 'batch-runner',
  path: '/',
  tenantId: 'alpha',
  partition: 'aws',
  accountId: '111122223333',
};
const unknownAccount = reason => account({ status: 'unknown', reason, observed: null, unclaimed: null });
const identities =
  (accounts, items = [], total = 0) =>
  () => ({
    sources: [sourceOf(projection())],
    unclaimedIdentities: { accounts, identities: items, total, bindingsWithoutIdentity: true },
  });

test('list_unclaimed_identities lists candidates, never findings', async () => {
  const { service, requests } = serviceWith(identities([account()], [identity], 2));
  const { data } = await service.query(all, 'list_unclaimed_identities', { limit: 1 });
  assert.deepEqual(requests, [{ unclaimedIdentities: true, page: { offset: 0, limit: 1 } }]);
  assert.deepEqual(plain(data.identities), [
    { ...identity, candidate: true, evidenceKind: 'provider_inventory', assessment: 'unknown' },
  ]);
  assert.deepEqual([data.status, data.reason, data.total, data.truncated], ['complete', null, 2, true]);
  assert.deepEqual([data.accounts[0].stale, data.accounts[0].ageSeconds], [false, 60]);
  assert.equal(data.bindingsWithoutIdentity, true);
  assert.deepEqual(plain(data.declaredFrom), [
    { sourceId: 'source', tenantId: 'alpha', snapshotId: 'snapshot', generatedAt: new Date(NOW - 1000).toISOString() },
  ]);
  assert.ok(data.limitations[0].startsWith('Candidates to review, not findings'));
  assert.equal(JSON.stringify(data).includes('finding":'), false);
});

test('missing, stale or invalid AWS data reads unknown with no total and no list', async () => {
  for (const [accounts, reason] of [
    [[], 'cloud_not_collected'],
    [[unknownAccount('stale')], null],
    [[unknownAccount('collection_invalid'), unknownAccount('changed')], null],
  ]) {
    const { service } = serviceWith(identities(accounts));
    const { data } = await service.query(all, 'list_unclaimed_identities', {});
    assert.deepEqual([data.status, data.reason, data.total, data.truncated], ['unknown', reason, null, false]);
    assert.deepEqual(plain(data.identities), []);
    assert.deepEqual(
      data.accounts.map(item => item.status),
      accounts.map(() => 'unknown'),
    );
  }
});

test('one unusable account makes the answer partial and keeps its reason', async () => {
  const { service } = serviceWith(identities([account(), unknownAccount('stale')], [identity], 2));
  const { data } = await service.query(all, 'list_unclaimed_identities', {});
  assert.deepEqual([data.status, data.total], ['partial', 2]);
  assert.deepEqual(
    data.accounts.map(item => [item.status, item.reason, item.unclaimed]),
    [
      ['complete', null, 2],
      ['unknown', 'stale', null],
    ],
  );
});

test('a store answer without identity evidence is unavailable', async () => {
  const { service } = serviceWith(() => ({ sources: [] }));
  await assert.rejects(service.query(all, 'list_unclaimed_identities', {}), { code: 'MAP_UNAVAILABLE' });
});

// ---- Store ----

const records = values => values.map(value => ({ get: name => value[name] }));
const coverage = JSON.stringify({
  tasks: { status: 'complete', observedAt: '2029-12-31T23:59:00Z' },
  tools: { status: 'complete', observedAt: '2029-12-31T23:59:00Z' },
});
const graphSource = {
  id: 'source',
  tenantId: 'alpha',
  nativeSourceId: 'installation',
  profile: 'host',
  currentId: 'projection',
  currentSnapshotId: 'receipt',
  currentGeneratedAt: '2029-12-31T23:59:30Z',
  currentCoverage: coverage,
  previousId: null,
  policyCoverage: null,
};
const kindOf = query =>
  query.startsWith('MATCH (s:GuardSource)')
    ? 'sources'
    : query.includes('$countLimit')
      ? 'undeclared_counts'
      : query.includes('AS parentDeclared')
        ? 'undeclared_tasks'
        : query.includes('AS principalId,tasks')
          ? 'undeclared_principals'
          : query.startsWith('MATCH (c:GuardAwsCollection)\n')
            ? 'collections'
            : query.includes('$claimLimit')
              ? 'claims'
              : query.includes('AS open')
                ? 'open_bindings'
                : query.includes('$memberLimit')
                  ? 'unclaimed_counts'
                  : query.includes('$collectionIds')
                    ? 'unclaimed_page'
                    : 'other';
/** A driver whose answers are chosen per query kind; every call is recorded. */
function backend(answers = {}) {
  const calls = [];
  const tx = {
    isOpen: () => true,
    rollback: async () => {},
    run: async function* (query, params) {
      const kind = kindOf(query);
      calls.push({ kind, query, params });
      const answer = answers[kind] ?? (kind === 'sources' ? [graphSource] : []);
      yield* records(
        typeof answer === 'function' ? answer(calls.filter(call => call.kind === kind).length, params) : answer,
      );
    },
  };
  const driver = {
    session: () => ({ beginTransaction: () => tx, close: async () => {} }),
    close: async () => {},
  };
  return { calls, store: new Neo4jMapStore(driver, { clock: () => NOW }) };
}
const kinds = calls => calls.map(call => call.kind);

test('discovery reads are refused for a team-scoped reader before any database access', async () => {
  const { calls, store } = backend();
  for (const request of [
    { undeclared: true },
    { unclaimedIdentities: true },
    { sourceId: 'source', undeclared: true, page: { kind: 'tasks', offset: 0, limit: 10 } },
  ])
    await assert.rejects(store.read(team, request), { code: 'MAP_REQUEST_INVALID' }, JSON.stringify(request));
  assert.deepEqual(calls, []);
});

test('discovery read modes are closed: no agent, no second mode, bounded pages', async () => {
  const { calls, store } = backend();
  const page = { kind: 'tasks', offset: 0, limit: 10 };
  for (const request of [
    { undeclared: true, unclaimedIdentities: true },
    { undeclared: true, summary: true },
    { undeclared: true, agentId: 'agent' },
    { undeclared: 'yes' },
    { undeclared: true, page },
    { sourceId: 'source', undeclared: true, page: { offset: 0, limit: 10 } },
    { sourceId: 'source', undeclared: true, page: { ...page, kind: 'agents' } },
    { sourceId: 'source', undeclared: true, page: { ...page, limit: 101 } },
    { sourceId: 'source', undeclared: true, page: { ...page, offset: -1 } },
    { sourceId: 'source', undeclared: true, page: { ...page, order: 'x' } },
    { sourceId: 'source', unclaimedIdentities: true },
    { unclaimedIdentities: true, page },
    { page: { offset: 0, limit: 10 } },
  ])
    await assert.rejects(store.read(all, request), { code: 'MAP_REQUEST_INVALID' }, JSON.stringify(request));
  assert.deepEqual(calls, []);
});

test('an undeclared read counts per source, loads no nodes and rechecks the publication', async () => {
  const { calls, store } = backend({ undeclared_counts: [{ tasks: 3, principals: 10_001 }] });
  const view = await store.read(all, { undeclared: true });
  assert.deepEqual(kinds(calls), ['sources', 'undeclared_counts', 'sources']);
  const [source] = view.sources;
  assert.deepEqual(plain(source.current.undeclared), {
    tasks: 3,
    tasksCapped: false,
    principals: 10_000,
    principalsCapped: true,
  });
  assert.deepEqual([source.current.nodes.length, source.current.id, source.profile], [0, 'projection', 'host']);
  assert.deepEqual(plain(source.current.coverage), {
    tasks: { status: 'complete', observedAt: '2029-12-31T23:59:00Z' },
  });
  const { params, query } = calls[1];
  assert.deepEqual([params.sourceId, params.projectionId, params.tenantId], ['source', 'projection', 'alpha']);
  assert.equal(params.countLimit.toNumber(), 10_001);
  // Every node the count passes through is scoped to this source, projection and tenant.
  for (const variable of ['t', 'c', 'pt', 'dd', 'da'])
    assert.ok(query.includes(`${variable}.source_id=$sourceId AND ${variable}.projection_id=$projectionId`), variable);
  assert.equal(view.unclaimedIdentities, undefined);
});

test('an undeclared page maps bounded rows and refuses malformed ones', async () => {
  const row = {
    id: 'entity:task',
    taskId: 'stray-task',
    principalId: 'stray-caller',
    delegated: true,
    derived: null,
    revoked: false,
    parentDeclared: true,
    tools: ['b.tool', 'a.tool', 'a.tool'],
  };
  const request = kind => ({ sourceId: 'source', undeclared: true, page: { kind, offset: 20, limit: 2 } });
  const tasks = backend({ undeclared_counts: [{ tasks: 30, principals: 1 }], undeclared_tasks: [row] });
  const view = await tasks.store.read(all, request('tasks'));
  assert.deepEqual(plain(view.sources[0].current.undeclared.page), {
    kind: 'tasks',
    items: [{ ...row, tools: ['a.tool', 'b.tool'], toolsTruncated: false }],
  });
  const paging = tasks.calls.find(call => call.kind === 'undeclared_tasks').params;
  assert.deepEqual([paging.pageOffset.toNumber(), paging.pageLimit.toNumber()], [20, 2]);

  const principals = backend({
    undeclared_counts: [{ tasks: 30, principals: 1 }],
    undeclared_principals: [{ id: 'entity:caller', principalId: 'stray-caller', tasks: 1001 }],
  });
  assert.deepEqual(
    plain((await principals.store.read(all, request('principals'))).sources[0].current.undeclared.page),
    {
      kind: 'principals',
      items: [{ id: 'entity:caller', principalId: 'stray-caller', tasks: 1000, tasksCapped: true }],
    },
  );

  for (const answers of [
    { undeclared_counts: [] },
    { undeclared_counts: [{ tasks: -1, principals: 0 }] },
    { undeclared_counts: [{ tasks: 1, principals: 0 }], undeclared_tasks: [{ ...row, parentDeclared: null }] },
    { undeclared_counts: [{ tasks: 1, principals: 0 }], undeclared_tasks: [{ ...row, taskId: '' }] },
    { undeclared_counts: [{ tasks: 1, principals: 0 }], undeclared_tasks: [{ ...row, revoked: 'no' }] },
    { undeclared_counts: [{ tasks: 1, principals: 0 }], undeclared_tasks: [row, row] },
    {
      undeclared_counts: [{ tasks: 1, principals: 0 }],
      undeclared_tasks: [row, { ...row, id: 'b' }, { ...row, id: 'c' }],
    },
  ])
    await assert.rejects(backend(answers).store.read(all, request('tasks')), { code: 'MAP_UNAVAILABLE' });
});

test('a publication that advances during a discovery read rejects the whole view', async () => {
  const { store } = backend({
    sources: count => [count > 1 ? { ...graphSource, currentId: 'newer' } : graphSource],
    undeclared_counts: [{ tasks: 0, principals: 0 }],
  });
  await assert.rejects(store.read(all, { undeclared: true }), { code: 'MAP_UNAVAILABLE' });
});

const collectionId = createHash('sha256')
  .update(JSON.stringify(['company', 'alpha', 'aws', '111122223333']))
  .digest('hex');
const collection = (extra = {}) => ({
  id: collectionId,
  tenantId: 'alpha',
  partition: 'aws',
  accountId: '111122223333',
  schemaVersion: 1,
  status: 'complete',
  capturedAt: NOW / 1000 - 60,
  contentHash: 'c'.repeat(64),
  ...extra,
});
const principal = (extra = {}) => ({
  collectionId,
  arn: 'arn:aws:iam::111122223333:role/service/batch-runner',
  role: true,
  user: false,
  name: 'batch-runner',
  path: '/service/',
  ...extra,
});
const identityRead = { unclaimedIdentities: true, page: { offset: 0, limit: 10 } };
const identityAnswers = (extra = {}) => ({
  collections: [collection()],
  claims: [{ arn: 'arn:aws:iam::111122223333:role/declared' }],
  open_bindings: [{ open: false }],
  unclaimed_counts: [{ observed: 4, unclaimed: 1, inconsistent: 0 }],
  unclaimed_page: [principal()],
  ...extra,
});

test('unclaimed identities are judged per account against the declared ARNs', async () => {
  const { calls, store } = backend(identityAnswers());
  const view = await store.read(all, identityRead);
  assert.deepEqual(kinds(calls), [
    'sources',
    'claims',
    'open_bindings',
    'collections',
    'unclaimed_counts',
    'unclaimed_page',
    'collections',
    'sources',
  ]);
  assert.deepEqual(plain(view.unclaimedIdentities), {
    accounts: [
      {
        tenantId: 'alpha',
        partition: 'aws',
        accountId: '111122223333',
        status: 'complete',
        reason: null,
        observedAt: new Date(NOW - 60_000).toISOString(),
        observed: 4,
        unclaimed: 1,
      },
    ],
    identities: [
      {
        arn: 'arn:aws:iam::111122223333:role/service/batch-runner',
        kind: 'role',
        name: 'batch-runner',
        path: '/service/',
        tenantId: 'alpha',
        partition: 'aws',
        accountId: '111122223333',
      },
    ],
    total: 1,
    bindingsWithoutIdentity: false,
  });
  const collections = calls.find(call => call.kind === 'collections');
  assert.deepEqual([collections.params.companyId, collections.params.tenantIds], ['company', ['alpha']]);
  for (const kind of ['unclaimed_counts', 'unclaimed_page']) {
    const { params, query } = calls.find(call => call.kind === kind);
    assert.deepEqual(params.claimed, ['arn:aws:iam::111122223333:role/declared'], kind);
    assert.ok(query.includes('c.company_id=$companyId'), kind);
  }
  assert.deepEqual(view.sources[0].current.nodes, []);
});

test('a missing answer about bindings without an identity is not read as none', async () => {
  const view = await backend(identityAnswers({ open_bindings: [] })).store.read(all, identityRead);
  assert.equal(view.unclaimedIdentities.bindingsWithoutIdentity, true);
});

test('no collection, or a stale, invalid or inconsistent one, is unknown and lists nothing', async () => {
  const none = await backend(identityAnswers({ collections: [] })).store.read(all, identityRead);
  assert.deepEqual(plain(none.unclaimedIdentities), {
    accounts: [],
    identities: [],
    total: 0,
    bindingsWithoutIdentity: false,
  });
  for (const [answers, reason, queried] of [
    [{ collections: [collection({ capturedAt: NOW / 1000 - 7201 })] }, 'stale', false],
    [{ collections: [collection({ capturedAt: NOW / 1000 + 1 })] }, 'collection_invalid', false],
    [{ collections: [collection({ status: 'collecting' })] }, 'collection_invalid', false],
    [{ collections: [collection({ schemaVersion: 2 })] }, 'collection_invalid', false],
    [{ collections: [collection({ contentHash: null })] }, 'collection_invalid', false],
    [{ collections: [collection({ id: 'f'.repeat(64) })] }, 'collection_invalid', false],
    [{ unclaimed_counts: [{ observed: 4, unclaimed: 1, inconsistent: 1 }] }, 'changed', true],
    [{ unclaimed_counts: [{ observed: 50_001, unclaimed: 50_001, inconsistent: 0 }] }, 'limit_exceeded', true],
  ]) {
    const { calls, store } = backend(identityAnswers(answers));
    const { accounts, identities, total } = (await store.read(all, identityRead)).unclaimedIdentities;
    assert.deepEqual(
      [accounts[0].status, accounts[0].reason, accounts[0].observed, accounts[0].unclaimed],
      ['unknown', reason, null, null],
    );
    assert.deepEqual([plain(identities), total], [[], 0], reason);
    assert.equal(kinds(calls).includes('unclaimed_counts'), queried, reason);
    assert.equal(kinds(calls).includes('unclaimed_page'), false, reason);
  }
});

test('the enrolled cloud age limit of the tenant bounds the collection, under the host ceiling', async () => {
  const enrolled = { ...graphSource, policyCoverage: JSON.stringify({ maxAgeSeconds: 30 }) };
  const strict = await backend(identityAnswers({ sources: [enrolled] })).store.read(all, identityRead);
  assert.equal(strict.unclaimedIdentities.accounts[0].reason, 'stale');
  const loose = { ...graphSource, policyCoverage: JSON.stringify({ maxAgeSeconds: 600_000 }) };
  const view = await backend(
    identityAnswers({ sources: [loose], collections: [collection({ capturedAt: NOW / 1000 - 7201 })] }),
  ).store.read(all, identityRead);
  assert.equal(view.unclaimedIdentities.accounts[0].reason, 'stale');
});

test('more declared identities than the claim limit leaves every account unknown', async () => {
  const claims = Array.from({ length: 10_001 }, (_, index) => ({ arn: `arn:aws:iam::111122223333:role/r${index}` }));
  const { calls, store } = backend(identityAnswers({ claims }));
  const { accounts, identities } = (await store.read(all, identityRead)).unclaimedIdentities;
  assert.deepEqual([accounts[0].status, accounts[0].reason], ['unknown', 'claims_limit_exceeded']);
  assert.deepEqual(plain(identities), []);
  assert.equal(kinds(calls).includes('unclaimed_counts'), false);
});

test('a malformed identity row or account, or a claimed ARN in the page, fails the read', async () => {
  for (const answers of [
    { unclaimed_page: [principal({ role: true, user: true })] },
    { unclaimed_page: [principal({ arn: 'arn:aws:iam::999999999999:role/service/batch-runner' })] },
    { unclaimed_page: [principal({ name: 'batch runner' })] },
    { unclaimed_page: [principal({ path: 'service/' })] },
    { unclaimed_page: [principal({ collectionId: 'f'.repeat(64) })] },
    { unclaimed_page: [principal({ arn: null })] },
    {
      claims: [{ arn: 'arn:aws:iam::111122223333:role/service/batch-runner' }],
      unclaimed_page: [principal()],
    },
    { collections: [collection({ accountId: '1234' })] },
    { collections: [collection({ tenantId: 'beta' })] },
    { collections: [collection({ partition: 'azure' })] },
    { claims: [{ arn: '' }] },
  ])
    await assert.rejects(backend(identityAnswers(answers)).store.read(all, identityRead), { code: 'MAP_UNAVAILABLE' });
});

test('a collection republished during the read rejects the whole view', async () => {
  const { store } = backend(
    identityAnswers({ collections: count => [collection(count > 1 ? { capturedAt: NOW / 1000 - 5 } : {})] }),
  );
  await assert.rejects(store.read(all, identityRead), { code: 'MAP_UNAVAILABLE' });
});

test('more enrolled collections than the limit is refused, not truncated', async () => {
  const many = Array.from({ length: 65 }, (_, index) => collection({ accountId: String(index).padStart(12, '0') }));
  await assert.rejects(backend(identityAnswers({ collections: many })).store.read(all, identityRead), {
    code: 'MAP_LIMIT_EXCEEDED',
  });
});
