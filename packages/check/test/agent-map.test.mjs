import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService, createMapToken, startMapServer } from '@shieldaai/agent-map';
import { AgentMapError, fetchLiveEvidence, MemorySource, scan } from '@shieldaai/agent-guard-check';
import { findingsFor, ruleIds } from './helpers.mjs';

const allTeams = { subject: 'scanner', companyId: 'company', tenantIds: ['tenant'], teamIds: [], allTeams: true };

/** A fetch that answers each operation with a fixed body, recording what was asked. */
function fakeFetch(answers, calls = []) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, init, body });
    const answer = answers[body.operation];
    const status = answer?.status ?? 200;
    return new Response(typeof answer?.raw === 'string' ? answer.raw : JSON.stringify(answer?.body ?? { data: {} }), {
      status,
    });
  };
}

const populated = {
  get_inventory_health: {
    body: {
      data: {
        sources: [
          {
            id: 'src-1',
            sourceId: 'prod-executor',
            stale: true,
            undeclaredActivity: { status: 'partial', tasks: 10000, tasksIsMinimum: true, principals: 3 },
          },
          {
            id: 'src-2',
            sourceId: 'quiet',
            stale: false,
            undeclaredActivity: { status: 'complete', tasks: 0, principals: 0 },
          },
        ],
      },
    },
  },
  list_unclaimed_identities: {
    body: {
      data: { status: 'complete', total: 2, identities: [{ name: 'ci-bot-role' }, { arn: 'arn:aws:iam::1:role/x' }] },
    },
  },
  list_agents: {
    body: {
      data: { agents: [{ id: 'e:1', agentId: 'invoice', name: 'Invoice agent', sourceId: 'src-1' }], truncated: false },
    },
  },
};

test('live evidence from a real Agent Map server: requests are accepted and an empty map finds nothing', async t => {
  const token = createMapToken();
  const service = new MapService({ read: async () => ({ sources: [] }) });
  const server = await startMapServer({ service, credentials: [{ token, scope: allTeams }] });
  t.after(() => server.close());
  const live = await fetchLiveEvidence({ url: server.url, token });
  assert.deepEqual(live.sources, []);
  assert.deepEqual(live.exposedAgents, []);
  const result = scan({ root: '/repo', source: new MemorySource({}), live });
  assert.ok(!ruleIds(result).some(id => id.startsWith('AGC-DRF')));
  assert.equal(result.modes.live.url, server.url);
});

test('a wrong token is an AgentMapError naming the code, never echoing the token', async t => {
  const service = new MapService({ read: async () => ({ sources: [] }) });
  const server = await startMapServer({ service, credentials: [{ token: createMapToken(), scope: allTeams }] });
  t.after(() => server.close());
  const wrong = createMapToken();
  await assert.rejects(fetchLiveEvidence({ url: server.url, token: wrong }), error => {
    assert.ok(error instanceof AgentMapError);
    assert.equal(error.status, 401);
    assert.match(error.message, /MAP_UNAUTHENTICATED/);
    assert.ok(!error.message.includes(wrong));
    return true;
  });
});

test('DRF rules turn live evidence into findings', async () => {
  const calls = [];
  const live = await fetchLiveEvidence({
    url: 'https://map.example',
    token: 't0k',
    fetch: fakeFetch(populated, calls),
  });
  assert.deepEqual(
    calls.map(call => call.body.operation),
    ['get_inventory_health', 'list_unclaimed_identities', 'list_agents'],
  );
  for (const call of calls) {
    assert.equal(call.url, 'https://map.example/v1/query');
    assert.equal(call.init.headers.authorization, 'Bearer t0k');
    assert.equal(call.init.redirect, 'error');
  }
  const result = scan({ root: '/repo', source: new MemorySource({}), live });
  const [undeclared] = findingsFor(result, 'AGC-DRF-001');
  assert.match(undeclared.message, /prod-executor saw 10000\+ task\(s\) and 3 caller/);
  assert.equal(findingsFor(result, 'AGC-DRF-001').length, 1);
  assert.match(findingsFor(result, 'AGC-DRF-002')[0].message, /2 unclaimed cloud identities, for example ci-bot-role/);
  assert.match(findingsFor(result, 'AGC-DRF-003')[0].message, /Invoice agent \(invoice, source src-1\)/);
  assert.equal(findingsFor(result, 'AGC-DRF-004').length, 1);
  assert.equal(findingsFor(result, 'AGC-DRF-003')[0].location.file, '.agc.yaml');
});

test('a team-scoped credential is noted, not treated as clean', async () => {
  const live = await fetchLiveEvidence({
    url: 'https://map.example',
    token: 't',
    fetch: fakeFetch({
      get_inventory_health: {
        body: { data: { sources: [{ id: 's', undeclaredActivity: { status: 'not_visible' } }] } },
      },
      list_unclaimed_identities: { body: { data: { visibility: 'not_visible', status: 'not_visible' } } },
      list_agents: { body: { data: { agents: [], truncated: false } } },
    }),
  });
  assert.equal(live.sources[0].undeclared, null);
  assert.equal(live.unclaimed, null);
  assert.equal(live.notes.length, 2);
  assert.ok(live.notes.every(note => /all-teams/.test(note)));
});

test('transport and format problems are AgentMapErrors', async () => {
  const cases = [
    [{ get_inventory_health: { status: 500, body: { error: 'MAP_UNAVAILABLE' } } }, /MAP_UNAVAILABLE/],
    [{ get_inventory_health: { raw: '<html>' } }, /non-JSON/],
    [{ get_inventory_health: { body: { nope: 1 } } }, /unexpected answer/],
  ];
  for (const [answers, pattern] of cases)
    await assert.rejects(
      fetchLiveEvidence({ url: 'https://map.example', token: 't', fetch: fakeFetch(answers) }),
      error => error instanceof AgentMapError && pattern.test(error.message),
    );
  const failing = async () => {
    throw new TypeError('fetch failed');
  };
  await assert.rejects(fetchLiveEvidence({ url: 'https://map.example', token: 't', fetch: failing }), /fetch failed/);
  const huge = async () => new Response('x'.repeat(9 * 1024 * 1024));
  await assert.rejects(fetchLiveEvidence({ url: 'https://map.example', token: 't', fetch: huge }), /larger than/);
});
