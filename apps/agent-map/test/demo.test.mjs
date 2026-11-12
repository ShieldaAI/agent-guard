import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import cytoscape from 'cytoscape';
import { MAP_OPERATIONS } from '@shieldaai/agent-map/service';
import { queryDemo } from '../src/demo.mjs';
import { DEMO_SOURCE_ID as sourceId } from '../src/demo-store.mjs';
import { demoBuildOptions, viewerBuildOptions } from '../build.mjs';
import { errorMessage, graphElements, initialExplanation, OPERATIONS, policyEvidenceRows } from '../src/view-model.mjs';
import { boundaryFlagRows, flagFilterArgs, outsideGuardRows } from '../src/boundary-model.mjs';
import { undeclaredActivityLabel, unclaimedSummary } from '../src/discovery-model.mjs';

const REPORT_ARN = 'arn:aws:s3:::company-reports/quarterly/summary.pdf';
const local = t => t.mock.method(globalThis, 'fetch', () => assert.fail('Demo must stay local'));
const edgesOf = elements => elements.filter(element => typeof element.data.target === 'string');
const access = agentId => queryDemo('get_agent_access', { sourceId, agentId });
/** The Explain form's defaults: the first task and its first grant, as the agent view loads them. */
async function explainDefaults(agentId) {
  const section = async name =>
    (await queryDemo('get_agent_inventory', { sourceId, agentId, section: name, limit: 20, offset: 0 })).data.items;
  const agent = (await queryDemo('get_agent_inventory', { sourceId, agentId })).data.agent;
  return {
    sourceId,
    ...initialExplanation({ agent, tasks: await section('tasks'), grants: await section('permissions') }),
  };
}

test('the demo answers every map operation through the real service, without the network', async t => {
  local(t);
  assert.deepEqual([...MAP_OPERATIONS].sort(), [...OPERATIONS].sort());
  const args = {
    list_agents: {},
    get_agent_access: { sourceId, agentId: 'agent-research' },
    explain_access: await explainDefaults('agent-research'),
    find_agents_with_access: { resourceRef: REPORT_ARN, action: 's3:GetObject' },
    get_changes: { sourceId, since: 'previous' },
    get_inventory_health: {},
    list_owners: {},
    list_resources: {},
    get_resource_access: { sourceId, resourceId: 'resource-binding' },
    get_agent_inventory: { sourceId, agentId: 'agent-research' },
    list_undeclared_activity: { sourceId },
    list_unclaimed_identities: {},
  };
  for (const operation of MAP_OPERATIONS) {
    const response = await queryDemo(operation, args[operation]);
    assert.equal(response.operation, operation);
    assert.ok(Number.isFinite(Date.parse(response.observedAt)), operation);
    assert.equal(typeof response.data, 'object', operation);
    // Plain JSON, as a gateway would deliver it: views may copy and extend it.
    assert.equal(Object.getPrototypeOf(response.data), Object.prototype, operation);
    assert.equal(Object.isFrozen(response.data), false, operation);
  }
  // The service's own argument rules apply: a missing required argument is refused, not guessed.
  await assert.rejects(queryDemo('get_agent_access', { agentId: 'agent-research' }), { code: 'MAP_REQUEST_INVALID' });
  await assert.rejects(queryDemo('unknown_operation'), { code: 'MAP_REQUEST_INVALID' });
});

test('an unknown agent, task or source is refused with the code the viewer explains', async () => {
  for (const [operation, args] of [
    ['get_agent_access', { sourceId, agentId: 'agent-unlisted' }],
    ['get_agent_inventory', { sourceId, agentId: 'agent-unlisted' }],
    ['get_agent_access', { sourceId: 'other-source', agentId: 'agent-research' }],
    ['list_undeclared_activity', { sourceId: 'other-source' }],
    ['explain_access', { ...(await explainDefaults('agent-research')), taskId: 'unlisted' }],
  ]) {
    const refused = await queryDemo(operation, args).then(
      () => assert.fail(`${operation} answered`),
      error => error,
    );
    assert.equal(refused.code, 'MAP_NOT_FOUND', operation);
    assert.match(errorMessage(refused), /unavailable in your authorized inventory/);
  }
});

test('the demo shows one exposed, one mitigated and one unknown agent, in the list and in each agent view', async t => {
  local(t);
  const plain = (await queryDemo('list_agents')).data.agents;
  assert.equal(
    plain.some(agent => 'boundaryFlags' in agent),
    false,
  );
  const listed = (await queryDemo('list_agents', flagFilterArgs(''))).data.agents;
  const expected = { 'Research assistant': 'exposed', 'Release assistant': 'mitigated', 'Finance reviewer': 'unknown' };
  assert.deepEqual(Object.fromEntries(listed.map(agent => [agent.name, agent.boundaryFlags.dangerousThree])), expected);
  assert.equal((await queryDemo('list_agents', flagFilterArgs('mitigated'))).data.agents.length, 1);
  assert.equal((await queryDemo('list_agents', flagFilterArgs('flagged'))).data.agents.length, 3);
  assert.equal((await queryDemo('list_agents', flagFilterArgs('absent'))).data.total, 0);

  const direct = {},
    scope = {};
  for (const agent of listed) {
    const response = await access(agent.id);
    const [flag] = response.data.boundaryFlags;
    // The detail flag is computed from the fixture's own grants and labels, and agrees with the list.
    assert.equal(flag.status, expected[agent.name], agent.name);
    assert.equal(flag.evidenceKind, 'declared');
    assert.deepEqual(flag.notes, []);
    assert.equal(boundaryFlagRows(response.data.boundaryFlags).legs.length, 3);
    assert.equal(response.data.graphStatus, 'included');
    const outside = outsideGuardRows(response.data.outsideGuard);
    direct[agent.name] = outside.directAccess.map(row => [row.status, row.entries.length]);
    scope[agent.name] = outside.identityScope.map(row => [row.status, row.reason, row.extraResources.length]);
    const elements = graphElements(response.graph, response.data.policyEvidence, {
      outsideGuard: response.data.outsideGuard,
      flagStatus: flag.status,
      tenantId: response.data.receipt.tenantId,
      boxes: true,
    });
    const cy = cytoscape({ headless: true, elements });
    try {
      assert.ok(cy.nodes(':parent').length >= 2);
      assert.equal(cy.getElementById(agent.id).hasClass(`flag-${flag.status}`), true);
    } finally {
      cy.destroy();
    }
  }
  assert.deepEqual(direct, {
    'Research assistant': [['found', 2]],
    'Release assistant': [['none_declared', 0]],
    'Finance reviewer': [['unknown', 0]],
  });
  assert.deepEqual(scope, {
    // The read tool's role reaches two buckets beyond its grants; the mail tool's identity is chosen at run time.
    'Research assistant': [
      ['unknown', 'identity_not_static', 0],
      ['broader_than_grants', null, 2],
    ],
    'Release assistant': [['matches_grants', null, 0]],
    'Finance reviewer': [['unknown', 'boundary_unresolved', 0]],
  });

  const research = await access('agent-research');
  const flag = research.data.boundaryFlags[0];
  assert.deepEqual(flag.legs, { privateData: 'present', outsideContent: 'present', externalSend: 'present' });
  assert.equal(flag.liveTasks, 2);
  assert.ok(flag.evidence.some(item => item.reason === 'binding_confidential'));
  assert.ok(flag.evidence.some(item => item.reason === 'tool_sends_external' && item.tool === 'mcp:mail:send'));
  const mitigation = (await access('agent-release')).data.boundaryFlags[0].evidence.filter(
    item => item.leg === 'mitigation',
  );
  assert.deepEqual(
    mitigation.map(item => item.reason),
    ['untrusted_context_require_approval'],
  );
  assert.equal((await access('agent-finance')).data.boundaryFlags[0].legs.externalSend, 'unknown');
  // The node the browser check selects, and the outside-guard drawing of the research agent.
  assert.ok(research.graph.nodes.some(node => node.id === 'resource' && node.label === 'GuardResource'));
  const elements = graphElements(research.graph, [], { outsideGuard: research.data.outsideGuard, boxes: true });
  assert.ok(edgesOf(elements).some(edge => edge.classes.startsWith('outside-guard')));
  assert.ok(edgesOf(elements).some(edge => edge.classes.startsWith('identity-reach')));
  assert.ok(
    research.data.outsideGuard.identityScope.some(record => record.extraResources.some(item => item.hasCondition)),
    'demo includes a conditional identity-scope candidate',
  );
  // The shell path names no target; the SDK path names a resource this reader can see.
  assert.deepEqual(
    research.data.outsideGuard.directAccess[0].entries.map(entry => [entry.kind, entry.targetStatus]),
    [
      ['sdk', 'visible'],
      ['shell', 'none'],
    ],
  );
});

test('the fixture policy evidence passes the service validation: conditional, absent and unresolved', async t => {
  local(t);
  const [research, release, finance] = await Promise.all(
    ['agent-research', 'agent-release', 'agent-finance'].map(access),
  );
  assert.equal(research.data.policyEvidence[0].candidates[0].hasCondition, true);
  assert.deepEqual(research.data.policyEvidence[0].candidates[0].conditionKeys, [
    'aws:PrincipalTag/team',
    'aws:SecureTransport',
  ]);
  assert.deepEqual(
    research.data.policyEvidence.map(record => [record.status, record.reason]),
    [
      ['complete', null],
      ['not_collected', 'unsupported_action'],
    ],
  );
  assert.equal(release.data.policyEvidence[0].reason, 'no_candidate');
  assert.equal(finance.data.policyEvidence[0].reason, 'boundary_unresolved');
  assert.deepEqual(
    [research, release, finance].map(response => response.data.policyCoverage.status),
    ['partial', 'complete', 'unavailable'],
  );
  // Every record also resolves against the focused graph the viewer draws it on.
  for (const response of [research, release, finance])
    assert.equal(
      policyEvidenceRows(response.data.policyEvidence, response.graph).length,
      response.data.policyEvidence.length,
    );
  const elements = graphElements(research.graph, research.data.policyEvidence);
  assert.ok(edgesOf(elements).some(edge => edge.classes === 'policy-candidate'));
  const changes = await queryDemo('get_changes', { sourceId });
  assert.equal(changes.data.policyHistory, 'not_collected');
});

test('explanations use the service codes: a matching grant stays unknown, a missing one is a blocker', async t => {
  // Capture times follow each read; hold the clock so two reads describe the same instant.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const form = await explainDefaults('agent-research');
  assert.deepEqual(form, {
    sourceId,
    taskId: 'research-assistant-task',
    tool: 'mcp:documents:read',
    resourceId: `opaque:${'d'.repeat(64)}`,
  });
  const explanation = (await queryDemo('explain_access', form)).data;
  assert.equal(explanation.assessment, 'unknown');
  assert.deepEqual(explanation.blockers, []);
  // Codes, as the service reports them; the viewer's label table turns them into words.
  assert.deepEqual(explanation.unknownChecks, [
    'live_authorization',
    'request_arguments_and_resolution',
    'custom_policy',
    'backend_authorization',
    'action_approval',
  ]);
  assert.equal(explanation.matchedGrants.length, 1);
  const research = await access('agent-research');
  assert.deepEqual(explanation.externalEvidence.policyEvidence, [research.data.policyEvidence[0]]);
  for (const override of [{ tool: 'mcp:documents:delete' }, { resourceId: 'out-of-scope' }]) {
    const { data } = await queryDemo('explain_access', { ...form, ...override });
    assert.equal(data.assessment, 'blocked');
    assert.ok(data.blockers.includes('declared_grant_missing'));
    assert.deepEqual(data.matchedGrants, []);
    assert.deepEqual(data.externalEvidence.policyEvidence, []);
  }
});

test('potential access matches the exact reference and action, and says when the list is cut', async () => {
  const selector = `opaque:${'d'.repeat(64)}`;
  for (const resourceRef of [REPORT_ARN, selector]) {
    const all = (await queryDemo('find_agents_with_access', { resourceRef, action: 's3:GetObject' })).data;
    assert.deepEqual(
      all.candidates.map(candidate => candidate.agent.name),
      ['Research assistant', 'Release assistant', 'Finance reviewer'],
    );
    assert.equal(all.truncated, false);
    assert.equal(all.candidates[0].assessment, 'unknown');
    assert.equal(all.candidates[0].evidence[0].policyEvidence[0].candidates[0].hasCondition, true);
    const cut = (await queryDemo('find_agents_with_access', { resourceRef, action: 's3:GetObject', limit: 2 })).data;
    assert.equal(cut.candidates.length, 2);
    assert.equal(cut.truncated, true);
  }
  for (const [resourceRef, action] of [
    [REPORT_ARN + '.old', 's3:GetObject'],
    [REPORT_ARN, 's3:DeleteObject'],
  ])
    assert.deepEqual((await queryDemo('find_agents_with_access', { resourceRef, action })).data.candidates, []);
});

test('the snapshot comparison shows a new task, an owner transfer, a quarantined connection and a new direct path', async () => {
  const changes = (await queryDemo('get_changes', { sourceId, since: 'previous' })).data;
  assert.equal(changes.coverageGap, false);
  assert.deepEqual(
    changes.details.map(item => [item.name, item.kind, item.categories[0]]),
    [
      ['Direct S3 SDK client in the worker', 'added', 'outside_guard'],
      ['Research assistant', 'changed', 'ownership'],
      ['mail-eu', 'changed', 'bindings'],
      ['research-followup', 'added', 'permissions'],
    ],
  );
  const owner = changes.details.find(item => item.label === 'GuardAgent');
  assert.deepEqual(owner.changedFields, ['owner_id']);
  assert.deepEqual([owner.before.properties.owner_id, owner.after.properties.owner_id], ['sam.rivera', 'alex.chen']);
  const connection = changes.details.find(item => item.label === 'GuardMcpConnection');
  assert.deepEqual([connection.before.properties.state, connection.after.properties.state], ['ready', 'quarantined']);
  assert.ok(changes.details.every(item => item.affectedAgents.some(agent => agent.name === 'Research assistant')));
  const outside = (await queryDemo('get_changes', { sourceId, changeKind: 'outside_guard' })).data.details;
  assert.equal(outside.length, 1);
  assert.equal(outside[0].evidenceKind, 'declared');
  // An agent's own changes tab: only what touches that agent.
  const release = (await queryDemo('get_changes', { sourceId, agentId: 'agent-release' })).data.details;
  assert.deepEqual(release, []);
});

test('the directory, sections and resource views page real service rows', async () => {
  const first = (await queryDemo('list_agents', { limit: 1 })).data;
  const second = (await queryDemo('list_agents', { limit: 1, offset: 1 })).data;
  assert.deepEqual([first.total, first.agents.length, first.truncated], [3, 1, true]);
  assert.notEqual(first.agents[0].id, second.agents[0].id);
  // Listed by name, as the service orders them.
  assert.deepEqual(
    (await queryDemo('list_agents')).data.agents.map(agent => agent.name),
    ['Finance reviewer', 'Release assistant', 'Research assistant'],
  );
  assert.equal((await queryDemo('list_agents', { search: 'release' })).data.total, 1);
  assert.equal(
    (await queryDemo('list_agents', { ownershipStatus: 'unknown' })).data.agents[0].name,
    'Finance reviewer',
  );
  const agentId = 'agent-research';
  const counts = (await queryDemo('get_agent_inventory', { sourceId, agentId })).data.counts;
  for (const section of [
    'overview',
    'deployments',
    'tasks',
    'permissions',
    'resources',
    'connections',
    'credentials',
    'relationships',
    'tools',
    'bindings',
    'identities',
    'policies',
  ]) {
    const result = (await queryDemo('get_agent_inventory', { sourceId, agentId, section, limit: 1 })).data;
    assert.equal(result.section, section);
    assert.equal(result.items.length, 1, section);
    if (section !== 'overview') assert.equal(result.total, counts[section], section);
    assert.equal(result.assessment, 'unknown');
    assert.equal(result.graphStatus, 'not_requested');
    assert.deepEqual(Object.values(result.collection), Array(4).fill('not_collected'));
    assert.equal(result.policyEvidence.length, section === 'policies' ? 1 : 0);
  }
  const overview = (await queryDemo('get_agent_inventory', { sourceId, agentId })).data;
  assert.equal(overview.agent.ownerName, 'Alex Chen');
  assert.equal(overview.agent.authorityId, 'company-catalog');
  assert.equal(overview.agent.manifestRevision, 7);
  // The service reports only allowlisted properties: nothing the collector does not record.
  const [connection] = (await queryDemo('get_agent_inventory', { sourceId, agentId, section: 'connections' })).data
    .items;
  assert.equal(connection.connection_id, 'documents-eu');
  assert.equal('metadata_revision' in connection, false);
  const relationship = (await queryDemo('get_agent_inventory', { sourceId, agentId, section: 'relationships' })).data
    .items[0];
  assert.ok(relationship.sourceName && relationship.targetName && relationship.sourceLabel && relationship.targetLabel);

  const owners = (await queryDemo('list_owners', { limit: 1 })).data;
  assert.equal(owners.total, 2);
  assert.deepEqual(
    [owners.owners[0].name, owners.owners[0].sourceId, owners.owners[0].agentCount, owners.owners[0].resourceCount],
    ['Alex Chen', sourceId, 1, 1],
  );
  assert.equal((await queryDemo('list_owners', { sourceId: 'other-source' })).data.total, 0);
  const resources = (await queryDemo('list_resources')).data;
  assert.equal(resources.resourceCoverage, 'host_bound_resources');
  assert.deepEqual(
    resources.resources.map(resource => [resource.displayName, resource.outsideGuard, resource.sensitivity]),
    [
      ['Quarterly report', 'unknown', 'confidential'],
      ['Report archive', 'yes', 'internal'],
    ],
  );
  assert.equal((await queryDemo('list_resources', { sourceId: 'other-source' })).data.total, 0);
  assert.equal((await queryDemo('list_resources', { ownerId: 'alex.chen' })).data.total, 1);
  const [report, archive] = resources.resources;
  const linked = (await queryDemo('get_resource_access', { sourceId, resourceId: report.id, offset: 1, limit: 1 }))
    .data;
  assert.deepEqual([linked.total, linked.agents.length], [3, 1]);
  assert.equal(linked.outsideGuard.status, 'unknown');
  assert.ok(linked.outsideGuard.unknownReasons.includes('direct_access_undeclared'));
  // Each answer is a fresh copy: changing one never changes the next.
  linked.resource.displayName = 'mutated';
  assert.equal((await queryDemo('list_resources')).data.resources[0].displayName, 'Quarterly report');
  const reach = (await queryDemo('get_resource_access', { sourceId, resourceId: archive.id })).data;
  assert.deepEqual(
    reach.agents.map(agent => agent.name),
    ['Research assistant'],
  );
  assert.equal(reach.outsideGuard.status, 'yes');
  assert.deepEqual(
    reach.outsideGuard.directAccess.map(path => [path.kind, path.description, path.evidenceKind]),
    [['sdk', 'Direct S3 SDK client in the worker', 'declared']],
  );
});

test('discovery and health report the undeclared activity and the IAM candidates', async t => {
  local(t);
  const health = (await queryDemo('get_inventory_health')).data;
  assert.equal(health.sources.length, 1);
  const [source] = health.sources;
  assert.equal(source.id, sourceId);
  assert.equal(source.stale, false);
  assert.equal(undeclaredActivityLabel(source.undeclaredActivity).text, '2 tasks and 1 caller with no declared agent');
  // Freshness is the service's own judgement of the fixture's capture times.
  assert.deepEqual(
    Object.fromEntries(Object.entries(source.coverage).map(([name, value]) => [name, [value.status, value.stale]])),
    {
      tasks: ['complete', false],
      tools: ['complete', false],
      manifest: ['complete', false],
      mcp: ['partial', true],
      cloud: ['complete', false],
      policy: ['partial', undefined],
    },
  );
  const tasks = (await queryDemo('list_undeclared_activity', { sourceId, limit: 1 })).data;
  assert.deepEqual([tasks.items.length, tasks.total, tasks.truncated], [1, 2, true]);
  assert.deepEqual(
    [tasks.items[0].taskId, tasks.items[0].assessment, tasks.items[0].evidenceKind],
    ['nightly-export', 'unknown', 'observed'],
  );
  const later = (await queryDemo('list_undeclared_activity', { sourceId, limit: 1, offset: 1 })).data;
  assert.equal(later.items[0].parentDeclared, true);
  const callers = (await queryDemo('list_undeclared_activity', { sourceId, kind: 'principals' })).data;
  assert.equal(callers.items[0].principalId, 'batch-scheduler');
  const identities = (await queryDemo('list_unclaimed_identities', {})).data;
  assert.equal(
    identities.identities.every(identity => identity.candidate === true),
    true,
  );
  assert.deepEqual(
    identities.identities.map(identity => identity.name),
    ['batch-runner', 'ci-deployer'],
  );
  assert.equal(unclaimedSummary(identities).text, '2 candidates to review');
  assert.equal(identities.accounts[0].stale, false);
  assert.equal(identities.bindingsWithoutIdentity, true);
});

test('an open demo never drifts into stale: capture times follow each read', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.mock.timers.setTime(Date.now() + 6 * 3_600_000);
  const [source] = (await queryDemo('get_inventory_health')).data.sources;
  assert.equal(source.stale, false);
  assert.equal(source.ageSeconds, 120);
  assert.equal((await access('agent-research')).data.boundaryFlags[0].status, 'exposed');
});

test('the demo is its own file with the service in it, and neither file has a Node-only import', async () => {
  const output = async (options, name) => {
    const result = await build({ ...options, write: false, logLevel: 'silent' });
    const script = result.outputFiles.find(file => file.path.endsWith(name));
    assert.ok(script, `the build writes ${name}`);
    assert.equal(/\bfrom\s*["']node:|\brequire\(\s*["']node:|\bimport\(\s*["']node:/.test(script.text), false);
    // A quoted `node:<built-in>` specifier; cytoscape's own `node:selected` selector is not one.
    assert.equal(
      /["']node:(?:buffer|crypto|util|fs|http|https|net|tls|path|url|module|os|stream|events|child_process|zlib)\b/.test(
        script.text,
      ),
      false,
    );
    assert.equal(/neo4j/i.test(script.text), false);
    return script;
  };
  const app = await output(viewerBuildOptions, 'app.js'),
    demo = await output(demoBuildOptions, 'demo.js');
  // The service's own wording is in the demo file, not a copy of it, and not in the page's script.
  const wording = 'Explanation only; no action was prepared or executed.';
  assert.ok(demo.text.includes(wording));
  assert.equal(app.text.includes(wording), false);
  // The page asks for the demo by the one name the map service serves it under.
  assert.equal(app.text.match(/import\(\s*["']([^"']+)["']\s*\)/g)?.length, 1);
  assert.match(app.text, /import\(\s*["']\.\/demo\.js["']\s*\)/);
  assert.equal(/\bimport\s*\(/.test(demo.text), false);
  // The page's script was 809 KB before the demo existed; the bounds leave little room for more.
  assert.ok(app.contents.byteLength < 820 * 1024, `app.js is ${app.contents.byteLength} bytes`);
  assert.ok(demo.contents.byteLength < 120 * 1024, `demo.js is ${demo.contents.byteLength} bytes`);
});
