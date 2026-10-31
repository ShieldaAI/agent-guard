import test from 'node:test';
import assert from 'node:assert/strict';
import cytoscape from 'cytoscape';
import { agentOptions, componentHealth, createQuerySession, displayTime, errorMessage, evidenceState, graphElements, initialExplanation, nodeName, queryReference } from '../src/view-model.mjs';
import { queryDemo } from '../src/demo.mjs';

const token = `agm_v1.${'x'.repeat(43)}`;
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', ...headers },
});

test('browser client sends only a fixed same-origin query with an in-memory bearer credential', async () => {
  const calls = [];
  const response = await queryReference(token, 'get_agent_access', { sourceId: 'source', agentId: 'agent' }, {
    fetchImpl: async (url, options) => {
      calls.push([url, options]);
      return json({ operation: 'get_agent_access', observedAt: '2026-10-30T00:00:00Z', data: { agent: { name: '<img src=x onerror=alert(1)>' } } });
    },
  });
  assert.equal(calls.length, 1);
  const [url, options] = calls[0];
  assert.equal(url, '/v1/query');
  assert.equal(options.headers.Authorization, `Bearer ${token}`);
  assert.deepEqual(JSON.parse(options.body), { operation: 'get_agent_access', args: { sourceId: 'source', agentId: 'agent' } });
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(response.data.agent.name, '<img src=x onerror=alert(1)>');
  assert.equal(JSON.stringify(response).includes(token), false);
});

test('invalid credentials and unknown operations cannot make a browser request', async () => {
  const options = { fetchImpl: () => assert.fail('Unexpected network access') };
  await assert.rejects(queryReference('executor-admin-token', 'list_agents', {}, options), { code: 'VIEWER_CREDENTIAL_INVALID' });
  await assert.rejects(queryReference(token, 'raw_cypher', { query: 'MATCH (n) RETURN n' }, options), { code: 'VIEWER_OPERATION_INVALID' });
});

test('remote error bodies and markup never become user-facing error messages', async () => {
  let captured;
  try {
    await queryReference(token, 'list_agents', {}, { fetchImpl: async () => json({ error: 'private-token <script>error</script>' }, 503) });
  } catch (error) { captured = error; }
  assert.equal(captured.code, 'REFERENCE_UNAVAILABLE');
  assert.equal(errorMessage(captured).includes('private-token'), false);
  assert.equal(errorMessage(captured).includes('<script>'), false);
  await assert.rejects(queryReference(token, 'list_agents', {}, {
    fetchImpl: async () => new Response('<html>private-token</html>', { headers: { 'content-type': 'text/html' } }),
  }), { code: 'VIEWER_RESPONSE_INVALID' });
  await assert.rejects(queryReference(token, 'list_agents', {}, {
    fetchImpl: async () => json({ operation: 'get_changes', data: {} }),
  }), { code: 'VIEWER_RESPONSE_INVALID' });
});

test('browser bounds both declared and streamed response sizes', async () => {
  await assert.rejects(queryReference(token, 'list_agents', {}, {
    fetchImpl: async () => json({ operation: 'list_agents', data: {} }, 200, { 'content-length': '4194305' }),
  }), { code: 'VIEWER_RESPONSE_LIMIT' });
  let cancelled = false;
  await assert.rejects(queryReference(token, 'list_agents', {}, {
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(4 * 1024 * 1024 + 1)); },
      cancel() { cancelled = true; },
    }), { headers: { 'content-type': 'application/json' } }),
  }), { code: 'VIEWER_RESPONSE_LIMIT' });
  assert.equal(cancelled, true);
});

test('browser deadline aborts an outstanding query', async () => {
  await assert.rejects(queryReference(token, 'get_inventory_health', {}, {
    timeoutMs: 10,
    fetchImpl: async (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }),
  }), { name: 'AbortError' });
});

test('disconnect aborts transport and old-session results or errors cannot enter a reconnected workspace', async () => {
  let resolveOld, rejectOld, oldSignal;
  const old = createQuerySession((_operation, args, { signal }) => {
    oldSignal = signal;
    return new Promise((resolve, reject) => { if (args.kind === 'result') resolveOld = resolve; else rejectOld = reject; });
  });
  const result = old.query('list_agents', { kind: 'result' });
  const error = old.query('get_changes', { kind: 'error' });
  old.close();
  assert.equal(oldSignal.aborted, true);
  resolveOld({ data: { agents: ['previous-tenant'] } });
  rejectOld(new Error('previous-tenant transport details'));
  await assert.rejects(result, { code: 'VIEWER_SESSION_ENDED' });
  await assert.rejects(error, { code: 'VIEWER_SESSION_ENDED' });
  await assert.rejects(old.query('list_agents'), { code: 'VIEWER_SESSION_ENDED' });
  const current = createQuerySession(async () => ({ data: { agents: ['current-tenant'] } }));
  assert.deepEqual(await current.query('list_agents'), { data: { agents: ['current-tenant'] } });
  current.close();
});

test('disconnect signal reaches the fetch transport without waiting for the query deadline', async () => {
  let transportSignal;
  const session = createQuerySession((operation, args, options) => queryReference(token, operation, args, {
    ...options,
    fetchImpl: async (_url, { signal }) => new Promise((_resolve, reject) => {
      transportSignal = signal;
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }),
  }));
  const result = session.query('get_inventory_health');
  session.close();
  assert.equal(transportSignal.aborted, true);
  await assert.rejects(result, { code: 'VIEWER_SESSION_ENDED' });
});

test('focused graph has exact endpoints and inert labels with no out-of-view edges', () => {
  const node = { id: 'quoted"] id', entityId: 'a', label: 'GuardAgent', properties: { name: '<script>alert(1)</script>' } };
  const graph = { nodes: [node, { id: 'resource', label: 'GuardExternalResource', properties: { arn: 'arn:aws:s3:::example/object', cloud_status: 'unresolved' } }],
    edges: [{ source: node.id, target: 'resource', kind: 'G_CLOUD_CONTAINER' }] };
  const elements = graphElements(graph);
  assert.equal(nodeName(node), '<script>alert(1)</script>');
  assert.equal(elements[0].data.label, '<script>alert(1)</script>');
  assert.match(elements[1].classes, /unavailable/);
  assert.equal(elements[2].classes, 'association unavailable');
  const cy = cytoscape({ headless: true, elements });
  try {
    assert.equal(cy.nodes().length, 2);
    assert.equal(cy.edges().length, 1);
    assert.equal(cy.getElementById(node.id).data('label'), '<script>alert(1)</script>');
    assert.equal(cy.edges()[0].source().id(), node.id);
  } finally { cy.destroy(); }
  assert.throws(() => graphElements({ ...graph, edges: [{ source: node.id, target: 'hidden', kind: 'G_MAPS_TO' }] }), /VIEWER_GRAPH_INVALID/);
});

test('conditional and unavailable relationships retain textual state and distinct line-style classes', () => {
  const graph = { nodes: [
    { id: 'task', label: 'GuardTask', properties: {} },
    { id: 'tool', label: 'GuardTool', properties: { requires_approval: true } },
    { id: 'connection', label: 'GuardMcpConnection', properties: { state: 'quarantined' } },
    { id: 'cloud', label: 'GuardExternalIdentity', properties: { cloud_status: 'stale' } },
  ], edges: [
    { source: 'task', target: 'tool', kind: 'G_FOR_TOOL' },
    { source: 'tool', target: 'connection', kind: 'G_VIA_CONNECTION' },
    { source: 'task', target: 'cloud', kind: 'G_USES_IDENTITY' },
  ] };
  const edges = graphElements(graph).slice(4);
  assert.match(edges[0].classes, /conditional/);
  assert.match(edges[0].data.label, /approval required/);
  assert.match(edges[1].classes, /unavailable/);
  assert.match(edges[1].data.label, /quarantined/);
  assert.match(edges[2].data.label, /Stale evidence/);
  assert.equal(evidenceState({ properties: { state: 'ready', assessment: 'unknown' } }).label, 'ready · access unknown');
  assert.equal(evidenceState({ properties: { revoked: true } }).kind, 'blocked');
});

test('graph rejects overflow, duplicates and unknown labels instead of displaying partial evidence', () => {
  const node = { id: 'agent', label: 'GuardAgent', properties: {} };
  for (const graph of [
    { nodes: [node, node], edges: [] },
    { nodes: [{ ...node, label: 'AWSSecret' }], edges: [] },
    { nodes: Array.from({ length: 2001 }, (_, i) => ({ ...node, id: String(i) })), edges: [] },
    { nodes: [node], edges: Array.from({ length: 5001 }, () => ({ source: 'agent', target: 'agent', kind: 'G_MAPS_TO' })) },
  ]) assert.throws(() => graphElements(graph), /VIEWER_GRAPH_INVALID/);
});

test('owner/environment choices derive only from visible agents and explanations use exported references', () => {
  assert.deepEqual(agentOptions([{ ownerId: 'owner', environments: ['production', 'production'] }, { ownerId: null, environments: ['staging'] }]),
    { owners: ['owner'], environments: ['production', 'staging'] });
  assert.deepEqual(initialExplanation({ tasks: [{ taskId: 'task' }], grants: [{ taskId: 'task', tool: 'read', resources: ['opaque:ref'] }] }),
    { taskId: 'task', tool: 'read', resourceId: 'opaque:ref' });
});

test('component freshness keeps independent capture times and never borrows a recent snapshot timestamp', () => {
  const observedAt = '2026-10-30T10:00:00Z';
  const source = { generatedAt: '2026-10-30T11:00:00Z', stale: false,
    coverage: { tasks: { status: 'complete', observedAt: '2026-10-30T10:59:00Z', stale: false, ageSeconds: 60 },
      mcp: { status: 'partial', observedAt, stale: true, ageSeconds: 3600 } } };
  const mcp = componentHealth(source.coverage.mcp);
  assert.equal(mcp.observedAt, observedAt);
  assert.equal(mcp.observedLabel, displayTime(observedAt));
  assert.equal(mcp.freshness, 'Stale capture');
  assert.equal(mcp.tone, 'amber');
  assert.equal(mcp.ageLabel, '1 hr old at query');
  assert.equal(componentHealth(source.coverage.tasks).freshness, 'Recent capture');
  assert.equal(componentHealth(source.coverage.tasks).ageLabel, '1 min old at query');
});

test('missing or invalid component capture times cannot be displayed as recent', () => {
  for (const coverage of ['complete', null, { status: 'complete', stale: false, ageSeconds: 0 },
    { status: 'complete', observedAt: 'invalid', stale: false, ageSeconds: 0 }]) {
    const state = componentHealth(coverage);
    assert.equal(state.freshness, 'Timestamp unknown');
    assert.equal(state.observedLabel, 'Capture time unknown');
    assert.equal(state.observedAt, null);
    assert.equal(state.tone, 'amber');
    assert.equal(state.ageLabel, null);
  }
  const unknown = componentHealth({ status: 'not_collected', observedAt: '2026-10-30T10:00:00Z' });
  assert.equal(unknown.freshness, 'Freshness unknown');
  assert.equal(unknown.status, 'not collected');
  assert.equal(unknown.tone, 'amber');
});

test('explicit synthetic demo exercises each view without network access', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('Demo must stay local'));
  const agents = (await queryDemo('list_agents')).data.agents;
  const access = await queryDemo('get_agent_access', { agentId: agents[0].id });
  const elements = graphElements(access.graph);
  assert.equal(elements.length, access.graph.nodes.length + access.graph.edges.length);
  const explanation = await queryDemo('explain_access', initialExplanation(access.data));
  assert.equal(explanation.data.assessment, 'unknown');
  const health = await queryDemo('get_inventory_health');
  assert.equal(health.data.sources.length, 1);
  const changes = await queryDemo('get_changes', { sourceId: agents[0].sourceId, since: 'previous' });
  assert.equal(changes.data.coverageGap, false);
  const candidates = await queryDemo('find_agents_with_access', { resourceRef: 'synthetic', action: 's3:GetObject' });
  assert.equal(candidates.data.candidates[0].assessment, 'unknown');
});
