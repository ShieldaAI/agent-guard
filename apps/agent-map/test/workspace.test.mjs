// The workspace hooks, run for real under react-dom with a stand-in document and a fake
// service: what a reader may still see after the page was away, without a browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import React, { useLayoutEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { useWorkspace } from '../src/hooks/use-workspace.mjs';
import { NO_FILTERS } from '../src/hooks/use-inventory.mjs';
import { useSourceChoice } from '../src/hooks/use-source-choice.mjs';

const tick = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));
async function until(check, label) {
  for (let i = 0; i < 400; i++) {
    if (check()) return;
    await tick(5);
  }
  assert.fail(`timed out waiting for ${label}`);
}
const csrf = letter => `agm_csrf_v1.${letter.repeat(43)}`;
const PEOPLE = {
  alice: {
    agents: [
      {
        id: 'a1',
        sourceId: 's-alice',
        name: 'alice payroll agent',
        ownerId: 'alice-owner',
        environments: ['alice-prod'],
      },
    ],
    sources: [{ id: 's-alice', tenantId: 'alice-tenant' }],
  },
  bob: {
    agents: [{ id: 'b1', sourceId: 's-bob', name: 'bob agent', ownerId: 'bob-owner', environments: ['bob-dev'] }],
    sources: [{ id: 's-bob', tenantId: 'bob-tenant' }],
  },
};

/** The least of an element that react-dom needs to render components that draw nothing. */
const container = page => ({
  nodeType: 1,
  nodeName: 'DIV',
  tagName: 'DIV',
  ownerDocument: page,
  addEventListener() {},
  removeEventListener() {},
});

/** A stand-in page and company gateway, and the real workspace hook mounted on them. */
async function open(t, { sessionDelay = 0 } = {}) {
  const listeners = () => {
    const held = new Map();
    return {
      addEventListener: (type, listener) => held.set(type, new Set(held.get(type)).add(listener)),
      removeEventListener: (type, listener) => held.get(type)?.delete(listener),
      fire: (type, event = {}) => [...(held.get(type) ?? [])].forEach(listener => listener(event)),
    };
  };
  const page = Object.assign(listeners(), { visibilityState: 'visible', activeElement: null, body: null });
  const frame = Object.assign(listeners(), {
    document: page,
    location: { pathname: '/', search: '', assign() {} },
    history: { replaceState() {} },
    HTMLIFrameElement: class {},
  });
  const server = {
    user: 'alice',
    csrf: csrf('A'),
    authenticated: true,
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sessionStatus: 200,
    offline: false,
    agentStatus: 200,
    requests: [],
  };
  const json = (status, body) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const saved = { document: globalThis.document, window: globalThis.window, fetch: globalThis.fetch };
  Object.assign(globalThis, {
    document: page,
    window: frame,
    fetch: async (path, init = {}) => {
      if (init.signal?.aborted) throw new DOMException('aborted', 'AbortError');
      if (path === '/auth/session') {
        server.requests.push('session');
        if (sessionDelay) await tick(sessionDelay);
        if (server.offline) throw new TypeError('offline');
        if (server.sessionStatus !== 200) return json(server.sessionStatus, { error: 'MAP_SESSION_REQUIRED' });
        return json(200, {
          mode: 'oidc',
          authenticated: server.authenticated,
          csrfToken: server.csrf,
          expiresAt: server.expiresAt,
        });
      }
      const { operation, args } = JSON.parse(init.body);
      if (!server.authenticated) return json(401, { error: 'MAP_SESSION_REQUIRED' });
      if (init.headers['X-CSRF-Token'] !== server.csrf) return json(403, { error: 'MAP_REQUEST_DENIED' });
      const mine = PEOPLE[server.user];
      server.requests.push(`${operation}:${server.user}`);
      if (operation === 'list_agents')
        return json(200, { operation, data: { agents: mine.agents, offset: 0, limit: 20, total: mine.agents.length } });
      if (operation === 'get_inventory_health') return json(200, { operation, data: { sources: mine.sources } });
      const agent = mine.agents.find(item => item.id === args.agentId && item.sourceId === args.sourceId);
      return agent && server.agentStatus === 200
        ? json(200, { operation, data: { agent, section: 'overview' } })
        : json(server.agentStatus === 200 ? 404 : server.agentStatus, { error: 'MAP_NOT_FOUND' });
    },
  });
  let view;
  const commits = [];
  // What a reader would see of each person's evidence in one committed render.
  const evidence = current =>
    JSON.stringify([
      current.selected.selection,
      current.selected.access,
      current.listing.agents,
      current.options,
      current.sources,
      current.filters,
      current.resourceSelection,
    ]);
  function Workspace() {
    const current = useWorkspace();
    view = current;
    useLayoutEffect(() => {
      commits.push({
        session: Boolean(current.session),
        covered: current.covered,
        checking: current.connection.checking,
        listingState: current.listing.state,
        agents: current.listing.agents.length,
        evidence: evidence(current),
      });
    });
    return null;
  }
  const root = createRoot(container(page));
  root.render(React.createElement(Workspace));
  t.after(async () => {
    root.unmount();
    await tick(10);
    Object.assign(globalThis, saved);
  });
  await until(() => view?.session, 'the company workspace');
  await until(() => view.sources.length, 'health');
  return {
    get view() {
      return view;
    },
    commits,
    server,
    away() {
      page.visibilityState = 'hidden';
      page.fire('visibilitychange');
    },
    back() {
      page.visibilityState = 'visible';
      page.fire('visibilitychange');
    },
  };
}
/** Alice opens her agent with a filter set and a resource open: a place worth keeping, and worth clearing. */
async function settle(page) {
  page.view.setFilter('environment', 'alice-prod');
  await until(() => page.server.requests.filter(request => request === 'list_agents:alice').length === 2, 'the filter');
  await until(() => page.view.listing.state === 'ready', 'the filtered list');
  await page.view.selectAgent(PEOPLE.alice.agents[0]);
  await until(() => page.view.selected.access, 'the open agent');
  page.view.showResource({ sourceId: 's-alice', id: 'alice-resource' });
  await until(() => page.view.tab === 'resources', 'the resource view');
}
const holdsAlice = commit => commit.evidence.includes('alice');

test('connecting shows the preloaded agents at once, never an empty inventory first', async t => {
  const page = await open(t);
  const first = page.commits.find(commit => commit.session);
  assert.deepEqual(
    { listingState: first.listingState, agents: first.agents },
    { listingState: 'ready', agents: 1 },
    'the first render with a session already lists the agents that connecting loaded',
  );
  assert.equal(
    page.commits.some(commit => commit.session && commit.listingState === 'ready' && commit.agents === 0),
    false,
  );
  // The preloaded page is used as it is: one listing request, not two.
  assert.equal(page.server.requests.filter(request => request === 'list_agents:alice').length, 1);
});

test('the evidence is covered from the moment the page goes away until the session check completes', async t => {
  const page = await open(t, { sessionDelay: 40 });
  await settle(page);
  assert.equal(page.view.covered, false);
  page.away();
  // Committed inside the browser's event, not in a later task: no frame can show the evidence on return.
  assert.equal(page.view.covered, true, 'covered before the visibilitychange handler returns');
  assert.equal(page.view.connection.checking, false, 'nothing is checked while the page is away');
  const from = page.commits.length - 1;
  await tick(20);
  assert.equal(page.server.requests.filter(request => request === 'session').length, 1, 'no check while hidden');
  page.back();
  await until(() => page.view.connection.checking, 'the session check');
  assert.equal(page.view.covered, true);
  await until(() => !page.view.connection.checking, 'the end of the session check');
  assert.equal(page.view.covered, false);
  const after = page.commits.slice(from);
  const uncovered = after.findIndex(commit => !commit.covered);
  assert.ok(uncovered > 0, 'covered commits come first');
  assert.equal(
    after.slice(0, uncovered).every(commit => commit.covered),
    true,
  );
  assert.equal(after[uncovered].checking, false, 'uncovered only once the check has completed');
  assert.equal(page.server.requests.filter(request => request === 'session').length, 2, 'one check on return');
});

test('the same session on return keeps its place and reads the list and health again', async t => {
  const page = await open(t);
  await settle(page);
  const before = page.server.requests.length;
  page.away();
  page.back();
  await until(() => page.server.requests.slice(before).includes('get_inventory_health:alice'), 'the refresh');
  await until(() => !page.view.covered && page.view.listing.state === 'ready', 'the uncovered workspace');
  const { view } = page;
  assert.equal(view.tab, 'resources');
  assert.deepEqual(view.filters, { ...NO_FILTERS, environment: 'alice-prod' });
  assert.deepEqual(view.resourceSelection, { sourceId: 's-alice', id: 'alice-resource' });
  assert.equal(view.selected.selection.name, 'alice payroll agent');
  assert.equal(view.selected.access.data.agent.name, 'alice payroll agent');
  assert.deepEqual(view.sources, PEOPLE.alice.sources);
  assert.equal(view.connection.error, '');
  assert.deepEqual(page.server.requests.slice(before).sort(), [
    'get_inventory_health:alice',
    'list_agents:alice',
    'session',
  ]);
});

for (const sessionDelay of [0, 30])
  test(`a different session on return leaves nothing of the previous one (session check takes ${sessionDelay} ms)`, async t => {
    const page = await open(t, { sessionDelay });
    await settle(page);
    page.away();
    const from = page.commits.length - 1;
    // Someone else signed in from another tab of this browser: same cookie jar, a new session.
    page.server.user = 'bob';
    page.server.csrf = csrf('B');
    page.back();
    await until(() => page.view.session?.csrfToken === csrf('B') && page.view.sources.length, "bob's workspace");
    await until(() => !page.view.covered, 'the uncovered workspace');
    const { view } = page;
    assert.equal(view.selected.selection, null);
    assert.equal(view.selected.access, null);
    assert.deepEqual(view.listing.agents, PEOPLE.bob.agents);
    assert.deepEqual(view.options, { owners: ['bob-owner'], environments: ['bob-dev'] });
    assert.deepEqual(view.sources, PEOPLE.bob.sources);
    assert.equal(view.tab, 'inventory');
    assert.deepEqual(view.filters, NO_FILTERS);
    assert.equal(view.offset, 0);
    assert.equal(view.resourceSelection, null);
    assert.equal(view.resourceOwner, null);
    assert.match(view.connection.error, /session changed/);
    // Not for one render either: whatever was drawn after the page went away either was covered
    // or held nothing of the previous session.
    const leaked = page.commits.slice(from).filter(commit => !commit.covered && holdsAlice(commit));
    assert.deepEqual(leaked, []);
    assert.equal(JSON.stringify(view.selected).includes('alice'), false);
    // The new workspace is a different one, so views keyed by it start over.
    assert.equal(typeof view.session.serial, 'number');
  });

for (const [name, change, message] of [
  ['a rejected session check', server => (server.sessionStatus = 401), /session ended or its access changed/],
  ['an unreachable service', server => (server.offline = true), /session ended or its access changed/],
  [
    'a session signed out elsewhere',
    server => (server.authenticated = false),
    /ended while this page was in the background/,
  ],
  [
    'an expired session',
    server => (server.expiresAt = new Date(Date.now() - 1000).toISOString()),
    /session ended or its access changed/,
  ],
])
  test(`${name} on return clears the evidence and never uncovers it`, async t => {
    const page = await open(t);
    await settle(page);
    page.away();
    const from = page.commits.length - 1;
    change(page.server);
    page.back();
    await until(() => !page.view.session, 'the sign-in page');
    await tick(20);
    const { view } = page;
    assert.equal(view.session, null);
    assert.match(view.connection.error, message);
    assert.equal(view.covered, false);
    assert.equal(view.connection.checking, false);
    assert.deepEqual(
      [view.selected.selection, view.selected.access, view.listing.agents, view.options.owners, view.sources],
      [null, null, [], [], []],
    );
    assert.deepEqual(view.filters, NO_FILTERS);
    assert.equal(view.tab, 'inventory');
    assert.deepEqual(
      page.commits.slice(from).filter(commit => !commit.covered && holdsAlice(commit)),
      [],
    );
  });

for (const [name, other] of [
  ['the same session', false],
  ['a different session', true],
])
  test(`going away again while the check runs keeps the evidence covered until a later return (${name})`, async t => {
    const page = await open(t, { sessionDelay: 30 });
    await settle(page);
    page.away();
    const from = page.commits.length - 1;
    if (other) Object.assign(page.server, { user: 'bob', csrf: csrf('B') });
    page.back();
    await until(() => page.view.connection.checking, 'the session check');
    page.away();
    // The check ends, and in the second case a new workspace opens, while nobody is looking.
    const owner = other ? 'bob' : 'alice';
    await until(
      () => !page.view.connection.checking && page.view.session?.csrfToken === page.server.csrf,
      'the end of the check',
    );
    await until(() => page.server.requests.includes(`get_inventory_health:${owner}`) || !other, 'the new workspace');
    await tick(30);
    assert.equal(page.view.covered, true, 'covered while the page is away');
    assert.deepEqual(
      page.commits.slice(from).filter(commit => commit.session && !commit.covered),
      [],
      'no render showed evidence between leaving and the later return',
    );
    page.back();
    await until(() => !page.view.covered, 'the uncovered workspace');
    assert.equal(page.view.connection.checking, false);
    assert.deepEqual(page.view.listing.agents, PEOPLE[owner].agents);
    assert.equal(
      JSON.stringify([page.view.selected.access, page.view.options, page.view.sources]).includes('alice'),
      !other,
    );
  });

test('a selection that fails or is cancelled drops its request for focus', async t => {
  const page = await open(t);
  const agent = PEOPLE.alice.agents[0];
  await page.view.selectAgent(agent);
  await until(() => page.view.selected.access, 'the open agent');
  assert.equal(page.view.selected.focusRequest.current, true, 'an opened agent may take focus');
  page.view.selected.focusRequest.current = false; // the detail view took it
  // Refreshing the open agent asks for no focus.
  await page.view.selectAgent(agent, false);
  assert.equal(page.view.selected.focusRequest.current, false);
  // A failed selection: the next agent that opens must not take focus unasked.
  page.server.agentStatus = 503;
  await page.view.selectAgent(agent);
  await until(() => page.view.selected.error, 'the failure');
  assert.equal(page.view.selected.focusRequest.current, false);
  assert.equal(page.view.selected.selection, null);
  // A selection cancelled by leaving the view.
  page.server.agentStatus = 200;
  const pending = page.view.selectAgent(agent);
  assert.equal(page.view.selected.focusRequest.current, true);
  page.view.openTab('owners');
  assert.equal(page.view.selected.focusRequest.current, false);
  await pending;
  assert.equal(page.view.selected.focusRequest.current, false);
});

test('a view picks the first source when sources arrive late, and never replaces the reader’s choice', async t => {
  const saved = { document: globalThis.document, window: globalThis.window };
  const page = { activeElement: null, body: null, addEventListener() {}, removeEventListener() {} };
  Object.assign(globalThis, { document: page, window: { document: page, HTMLIFrameElement: class {} } });
  let choice, choose;
  function View({ sources }) {
    [choice, choose] = useSourceChoice(sources);
    return null;
  }
  const root = createRoot(container(page));
  t.after(async () => {
    root.unmount();
    await tick(10);
    Object.assign(globalThis, saved);
  });
  const show = async sources => {
    root.render(React.createElement(View, { sources }));
    await tick(10);
  };
  // The view opened before health answered.
  await show([]);
  assert.equal(choice, '');
  await show([{ id: 'one' }, { id: 'two' }]);
  assert.equal(choice, 'one', 'the default arrives with the sources');
  // A refreshed list in another order keeps the source the view started on.
  await show([{ id: 'two' }, { id: 'one' }]);
  assert.equal(choice, 'one');
  // The source it started on is gone: the first listed one takes its place.
  await show([{ id: 'two' }, { id: 'three' }]);
  assert.equal(choice, 'two');
  choose('three');
  await tick(10);
  assert.equal(choice, 'three');
  await show([{ id: 'one' }, { id: 'two' }]);
  assert.equal(choice, 'three', 'a choice the reader made is kept');
  choose('');
  await tick(10);
  await show([{ id: 'one' }]);
  assert.equal(choice, '', 'so is choosing no source');
});
