import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import cytoscape from 'cytoscape';
import {
  assignBoxes,
  boundaryFlagRows,
  boxCrossing,
  changeIsDeclared,
  flagBadge,
  flagFilterArgs,
  FLAG_FILTERS,
  isOutsideGuardEdge,
  onlyOutsideGuard,
  outsideGuardLabel,
  outsideGuardRows,
} from '../src/boundary-model.mjs';
import { graphElements, kindName, nodeName } from '../src/view-model.mjs';
import { queryDemo } from '../src/demo.mjs';
import { DEMO_SOURCE_ID } from '../src/demo-store.mjs';

const edgesOf = elements => elements.filter(element => typeof element.data.target === 'string');
const nodesOf = elements => elements.filter(element => typeof element.data.target !== 'string');

test('dangerous-three badges pair colour with text and hide only absent or unrequested flags', () => {
  assert.deepEqual(
    ['exposed', 'mitigated', 'unknown'].map(status => [flagBadge(status).label, flagBadge(status).tone]),
    [
      ['Dangerous three: Exposed', 'exposed'],
      ['Dangerous three: Mitigated', 'mitigated'],
      ['Dangerous three: Unknown', 'unknown'],
    ],
  );
  assert.equal(flagBadge('absent'), null);
  assert.equal(flagBadge(undefined), null);
  assert.equal(flagBadge({}), null);
  assert.equal(flagBadge({ dangerousThree: 'exposed' }).label, 'Dangerous three: Exposed');
  assert.equal(flagBadge({ dangerousThree: 'absent' }), null);
  // An unrecognized status never disappears or reads as a lower risk: it is unknown.
  assert.equal(flagBadge('safe').label, 'Dangerous three: Unknown');
  for (const value of ['exposed', 'mitigated', 'unknown'])
    assert.doesNotMatch(flagBadge(value).label, /safe|confirmed/i);
});

test('the flag filter always requests flags and maps to flag or flagStatus', () => {
  assert.deepEqual(flagFilterArgs(''), { includeFlags: true });
  assert.deepEqual(flagFilterArgs('flagged'), { includeFlags: true, flag: 'dangerous_three' });
  for (const status of ['exposed', 'mitigated', 'unknown', 'absent'])
    assert.deepEqual(flagFilterArgs(status), { includeFlags: true, flagStatus: status });
  assert.deepEqual(flagFilterArgs('anything-else'), { includeFlags: true });
  assert.deepEqual(
    FLAG_FILTERS.map(([value]) => value),
    ['', 'flagged', 'exposed', 'mitigated', 'unknown', 'absent'],
  );
});

test('flag rows list each leg once with its own evidence, notes and limitations', () => {
  const rows = boundaryFlagRows([
    {
      kind: 'dangerous_three',
      status: 'mitigated',
      legs: { privateData: 'present', outsideContent: 'present', externalSend: 'present' },
      evidence: [
        { leg: 'privateData', taskId: 't', reason: 'binding_restricted', tool: 'read', resourceBindingId: 'rb' },
        { leg: 'outsideContent', taskId: 't', reason: 'task_untrusted' },
        { leg: 'externalSend', taskId: 't', reason: 'tool_sends_external', tool: 'send' },
        { leg: 'mitigation', taskId: 't', reason: 'untrusted_context_require_approval', tool: 'send' },
      ],
      notes: ['ancestor_evidence_outside_visible_scope'],
      liveTasks: 2,
      limitations: ['Declared grants and labels; not proof that data can leave.'],
    },
  ]);
  assert.deepEqual(
    rows.legs.map(leg => [leg.label, leg.stateLabel, leg.evidence.length]),
    [
      ['Private data', 'Present', 1],
      ['Outside content', 'Present', 1],
      ['Can send out', 'Present', 1],
    ],
  );
  assert.deepEqual(rows.legs[0].evidence[0], {
    leg: 'privateData',
    taskId: 't',
    tool: 'read',
    resourceBindingId: 'rb',
    reason: 'binding_restricted',
    reasonLabel: 'Resource binding labelled restricted',
  });
  assert.equal(rows.mitigation.length, 1);
  assert.match(rows.mitigation[0].reasonLabel, /requires approval/);
  assert.equal(rows.badge.label, 'Dangerous three: Mitigated');
  assert.equal(rows.liveTasks, 2);
  assert.deepEqual(rows.notes, ['A delegating ancestor task is outside your visible scope.']);
  const empty = boundaryFlagRows([{ kind: 'dangerous_three', status: 'unknown', notes: ['no_live_tasks'] }]);
  assert.deepEqual(
    empty.legs.map(leg => leg.state),
    ['unknown', 'unknown', 'unknown'],
  );
  assert.deepEqual(empty.notes, ['No live tasks in this snapshot.']);
  assert.equal(boundaryFlagRows([{ kind: 'dangerous_three', status: 'absent' }]).badge, null);
  assert.equal(boundaryFlagRows(undefined), null);
});

test('outside-guard rows keep direct paths and identity scope separate and never default to none', () => {
  const rows = outsideGuardRows({
    directAccess: [
      {
        id: 'd1',
        deploymentId: 'prod',
        status: 'found',
        entries: [{ id: 'a', accessId: 'opaque:a', kind: 'shell', targetRef: null, description: 'Ops shell' }],
      },
      { id: 'd2', deploymentId: 'dev', status: 'none_declared', entries: [] },
      { id: 'd3', deploymentId: 'old', entries: [] },
    ],
    identityScope: [
      {
        executionBindingId: 'x',
        tool: 'read',
        identityId: 'role',
        status: 'broader_than_grants',
        extraResources: [
          {
            resourceId: 'arn:aws:s3:::b',
            bucketName: 'b',
            relationship: 'CAN_WRITE',
            hasCondition: true,
            conditionKeys: ['k'],
          },
        ],
        truncated: true,
      },
    ],
  });
  assert.deepEqual(
    rows.directAccess.map(row => row.status),
    ['found', 'none_declared', 'unknown'],
  );
  assert.match(rows.directAccess[1].statusLabel, /host claim, not checked/);
  assert.equal(rows.directAccess[0].entries[0].kind, 'shell');
  assert.equal(rows.identityScope[0].extraResources[0].relationshipLabel, 'Can write');
  assert.equal(rows.identityScope[0].extraResources[0].hasCondition, true);
  assert.equal(rows.identityScope[0].truncated, true);
  assert.deepEqual(outsideGuardRows(undefined), { directAccess: [], identityScope: [] });
  assert.deepEqual(['yes', 'none_found', 'unknown', undefined].map(outsideGuardLabel), [
    'Yes',
    'None found',
    'Unknown',
    'Unknown',
  ]);
  assert.equal(changeIsDeclared({ categories: ['outside_guard'] }), true);
  assert.equal(changeIsDeclared({ categories: ['permissions'] }), false);
});

const boundaryGraph = {
  nodes: [
    { id: 'agent', entityId: 'agent', label: 'GuardAgent', properties: { name: 'Agent', team_id: 'Research' } },
    { id: 'dep', entityId: 'dep', label: 'GuardDeployment', properties: { deployment_id: 'prod' } },
    { id: 'task', entityId: 'task', label: 'GuardTask', properties: { task_id: 't' } },
    { id: 'exec', entityId: 'exec', label: 'GuardExecutionBinding', properties: { binding_id: 'b', tool: 'read' } },
    { id: 'role', entityId: 'role', label: 'GuardExternalIdentity', properties: { arn: 'arn:aws:iam::1:role/r' } },
    {
      id: 'path',
      entityId: 'path',
      label: 'GuardDirectAccess',
      properties: { access_id: 'opaque:p', deployment_id: 'prod', kind: 'shell', description: 'Ops shell' },
    },
  ],
  edges: [
    { source: 'dep', target: 'agent', kind: 'G_INSTANCE_OF' },
    { source: 'task', target: 'dep', kind: 'G_ASSIGNED_TO' },
    { source: 'exec', target: 'dep', kind: 'G_EXECUTES_FOR' },
    { source: 'exec', target: 'role', kind: 'G_USES_IDENTITY' },
    { source: 'path', target: 'dep', kind: 'G_DIRECT_ACCESS_FOR' },
  ],
};
const boundaryOutside = {
  directAccess: [
    {
      id: 'dep',
      deploymentId: 'prod',
      status: 'found',
      entries: [
        { id: 'path', accessId: 'opaque:p', kind: 'shell', targetRef: 'opaque:target', description: 'Ops shell' },
      ],
    },
  ],
  identityScope: [
    {
      executionBindingId: 'exec',
      tool: 'read',
      identityId: 'role',
      status: 'broader_than_grants',
      extraResources: [
        {
          resourceId: 'arn:aws:s3:::payroll',
          bucketName: 'payroll',
          relationship: 'CAN_READ',
          hasCondition: false,
          conditionKeys: [],
        },
      ],
      truncated: false,
    },
  ],
};

test('direct paths are red outside-guard edges, identity reach is amber and guarded edges stay solid', () => {
  const plain = graphElements(boundaryGraph);
  const direct = edgesOf(plain).find(edge => edge.data.source === 'path');
  assert.equal(direct.classes, 'outside-guard');
  assert.equal(direct.data.label, 'outside guard · shell');
  assert.equal(kindName('GuardDirectAccess'), 'Direct access (outside guard)');
  assert.equal(nodeName(boundaryGraph.nodes[5]), 'Ops shell');
  for (const edge of edgesOf(plain).filter(edge => edge.data.source !== 'path'))
    assert.equal(isOutsideGuardEdge(edge), false);
  assert.match(edgesOf(plain).find(edge => edge.data.source === 'task').classes, /^declared$/);

  const elements = graphElements(boundaryGraph, [], { outsideGuard: boundaryOutside, flagStatus: 'exposed' });
  const reach = edgesOf(elements).filter(edge => edge.classes === 'identity-reach');
  assert.equal(reach.length, 1);
  assert.equal(reach[0].data.source, 'exec');
  assert.equal(reach[0].data.label, 'tool identity reaches this · can read');
  const bucket = nodesOf(elements).find(node => node.data.id === reach[0].data.target);
  assert.equal(bucket.data.fullLabel, 'payroll');
  assert.equal(bucket.data.source.label, 'OutsideGuardBucket');
  // The declared target is drawn as a synthetic node reached by a second outside-guard edge.
  const target = edgesOf(elements).find(edge => edge.data.target === 'outside-target:opaque:target');
  assert.equal(target.classes, 'outside-guard');
  assert.match(target.data.label, /^outside guard/);
  // The existing direct-access node is reused, not duplicated.
  assert.equal(nodesOf(elements).filter(node => node.data.id.startsWith('outside-access:')).length, 0);
  const agent = nodesOf(elements).find(node => node.data.id === 'agent');
  assert.match(agent.classes, /flag-exposed/);
  assert.equal(agent.data.label, 'Agent\nDangerous three: Exposed');
  assert.doesNotMatch(
    nodesOf(graphElements(boundaryGraph, [], { flagStatus: 'absent' })).find(node => node.data.id === 'agent').classes,
    /flag-/,
  );
});

test('outside-guard toggle keeps only those edges, their endpoints and enclosing boxes', () => {
  const elements = graphElements(boundaryGraph, [], { outsideGuard: boundaryOutside, tenantId: 'acme', boxes: true });
  const only = onlyOutsideGuard(elements);
  assert.ok(edgesOf(only).length >= 3);
  assert.ok(edgesOf(only).every(isOutsideGuardEdge));
  const ids = new Set(nodesOf(only).map(node => node.data.id));
  for (const edge of edgesOf(only)) assert.ok(ids.has(edge.data.source) && ids.has(edge.data.target));
  assert.equal(ids.has('task'), false);
  assert.equal(ids.has('box:team:acme:Research'), true);
  assert.equal(ids.has('box:tenant:acme'), true);
  assert.deepEqual(onlyOutsideGuard(graphElements({ nodes: [boundaryGraph.nodes[0]], edges: [] })), []);
  // Parents come before their children so Cytoscape can attach them.
  const cy = cytoscape({ headless: true, elements: only });
  try {
    assert.equal(cy.getElementById('dep').parent().id(), 'box:team:acme:Research');
    assert.equal(cy.edges().length, edgesOf(only).length);
  } finally {
    cy.destroy();
  }
});

test('tenant and team boxes: shared and provider nodes sit outside the team, crossing edges are marked', () => {
  const nodes = [
    { id: 'a1', label: 'GuardAgent', properties: { team_id: 'Research' } },
    { id: 'a2', label: 'GuardAgent', properties: { team_id: 'Finance' } },
    { id: 'd1', label: 'GuardDeployment', properties: {} },
    { id: 'd2', label: 'GuardDeployment', properties: {} },
    { id: 'tool', label: 'GuardTool', properties: {} },
    { id: 'cloud', label: 'GuardExternalResource', properties: {} },
    { id: 'lonely', label: 'GuardOwner', properties: {} },
  ];
  const edges = [
    { source: 'd1', target: 'a1' },
    { source: 'd2', target: 'a2' },
    { source: 'd1', target: 'tool' },
    { source: 'd2', target: 'tool' },
    { source: 'd1', target: 'cloud' },
  ];
  const { parents, assignment } = assignBoxes(nodes, edges, { tenantId: 'acme' });
  assert.deepEqual(
    parents.map(parent => [parent.id, parent.parent]),
    [
      ['box:tenant:acme', null],
      ['box:team:acme:Research', 'box:tenant:acme'],
      ['box:team:acme:Finance', 'box:tenant:acme'],
    ],
  );
  assert.equal(assignment.get('d1'), 'box:team:acme:Research');
  assert.equal(assignment.get('d2'), 'box:team:acme:Finance');
  assert.equal(assignment.get('tool'), 'box:tenant:acme');
  assert.equal(assignment.get('lonely'), 'box:tenant:acme');
  assert.equal(assignment.has('cloud'), false);
  assert.equal(boxCrossing('d1', 'a1', assignment, parents), null);
  assert.equal(boxCrossing('d1', 'tool', assignment, parents), 'team');
  assert.equal(boxCrossing('d1', 'd2', assignment, parents), 'team');
  assert.equal(boxCrossing('d1', 'cloud', assignment, parents), null, 'a provider node is in no box');
  assert.equal(boxCrossing('cloud', 'cloud', assignment, parents), null);
  // A missing tenant or team stays visibly unknown.
  const unknown = assignBoxes([{ id: 'a', label: 'GuardAgent', properties: {} }], []);
  assert.deepEqual(
    unknown.parents.map(parent => parent.label),
    ['Tenant · unknown', 'Team · unknown'],
  );

  const elements = graphElements(boundaryGraph, [], { outsideGuard: boundaryOutside, tenantId: 'acme', boxes: true });
  // A one-agent, one-tenant graph has no box border to cross: edges to provider and
  // candidate nodes leave every box rather than crossing between two.
  const crossing = edgesOf(elements).filter(edge => / crosses-box/.test(edge.classes));
  assert.deepEqual(crossing, []);
  assert.equal(edgesOf(elements).find(edge => edge.data.source === 'task').classes, 'declared');
  // Without boxes the element list is unchanged in shape: no parents, no crossing marks.
  assert.equal(
    graphElements(boundaryGraph).some(element => element.data.parent),
    false,
  );
});

// React stays external and resolves to the test's own copy, so hooks and the server renderer agree.
const compiled = await build({
  entryPoints: [fileURLToPath(new URL('../src/boundaries.jsx', import.meta.url))],
  bundle: true,
  write: false,
  platform: 'browser',
  format: 'esm',
  external: ['react'],
  define: { 'process.env.NODE_ENV': '"production"' },
});
const ui = await import(
  `data:text/javascript;base64,${Buffer.from(
    compiled.outputFiles[0].text.replaceAll(/from\s*"react"/g, `from ${JSON.stringify(import.meta.resolve('react'))}`),
  ).toString('base64')}`
);
const render = (Component, props) => renderToStaticMarkup(React.createElement(Component, props));

test('boundary sections render accessible tables with text labels and inert identifiers', async () => {
  const access = await queryDemo('get_agent_access', { sourceId: DEMO_SOURCE_ID, agentId: 'research-assistant' });
  const flags = render(ui.BoundaryFlags, {
    flags: access.data.boundaryFlags,
    graph: access.graph,
    onNode: () => {},
  });
  for (const text of ['Boundary flags', 'Exposed', 'Private data', 'Outside content', 'Can send out', 'Show in graph'])
    assert.ok(flags.includes(text), text);
  assert.match(flags, /<table class="evidence-table"><caption>Dangerous three legs<\/caption>/);
  const outside = render(ui.OutsideGuard, { outsideGuard: access.data.outsideGuard, graph: access.graph });
  for (const text of [
    'Declared direct paths',
    'Tool identity scope',
    'Ops shell for debugging',
    'company-payroll',
    'aws:SourceVpce',
  ])
    assert.ok(outside.includes(text), text);
  const legend = render(ui.FlagLegend, {});
  for (const text of ['Exposed', 'Mitigated', 'Unknown']) assert.ok(legend.includes(text), text);
  assert.equal(render(ui.FlagBadge, { value: { dangerousThree: 'absent' } }), '');
  for (const html of [flags, outside, legend]) assert.doesNotMatch(html, /\bsafe\b|confirmed/i);
  const hostile = render(ui.OutsideGuard, {
    outsideGuard: {
      directAccess: [
        {
          id: 'd',
          deploymentId: '<img src=x onerror=alert(1)>',
          status: 'found',
          entries: [{ id: 'e', kind: 'shell', description: '<script>x</script>' }],
        },
      ],
    },
  });
  // Hostile text is rendered escaped: no tag opens, in any letter case.
  const lowered = hostile.toLowerCase();
  for (const tag of ['<script', '<img']) assert.equal(lowered.includes(tag), false, tag);
});

test('identity scope rows flag withheld out-of-scope buckets without naming them', async () => {
  const { outsideGuardRows } = await import('../src/boundary-model.mjs');
  const rows = outsideGuardRows({
    identityScope: [
      { id: 'e', status: 'broader_than_grants', extraResources: [], notes: ['evidence_outside_visible_scope'] },
    ],
  });
  assert.equal(rows.identityScope[0].withheld, true);
  assert.equal(
    outsideGuardRows({ identityScope: [{ id: 'e', status: 'matches_grants' }] }).identityScope[0].withheld,
    false,
  );
});

test('a flag without a status renders as unknown instead of failing', async () => {
  const { boundaryFlagRows } = await import('../src/boundary-model.mjs');
  for (const status of [undefined, null, 'surprising']) {
    const rows = boundaryFlagRows([{ kind: 'dangerous_three', status, legs: {}, evidence: [] }]);
    assert.equal(rows.status, 'unknown');
    assert.equal(typeof rows.statusLabel, 'string');
  }
});

test('a withheld direct-path target is labelled, not shown as undeclared', async () => {
  const { outsideGuardRows } = await import('../src/boundary-model.mjs');
  const rows = outsideGuardRows({
    directAccess: [
      {
        id: 'd',
        status: 'found',
        entries: [
          { id: 'x', kind: 'database', targetRef: null, targetStatus: 'outside_visible_scope', description: 'db' },
        ],
      },
    ],
  });
  const [entry] = rows.directAccess.flatMap(item => item.entries ?? [item]).filter(item => item.kind === 'database');
  assert.equal(entry.targetWithheld, true);
  assert.equal(entry.targetRef, null);
});

test('unavailable page flags get a plain explanation', async () => {
  const { flagsUnavailableLabel } = await import('../src/boundary-model.mjs');
  assert.match(flagsUnavailableLabel('flags_limit_exceeded'), /too large/);
  assert.match(flagsUnavailableLabel('flags_timeout'), /too long/);
  assert.match(flagsUnavailableLabel('anything'), /unavailable/);
});

test('the graph draws a few extra buckets per binding and summarises the rest', async () => {
  const { outsideGuardElements, GRAPH_BUCKETS_PER_BINDING, GRAPH_BUCKET_EDGES } =
    await import('../src/boundary-model.mjs');
  const extras = count =>
    Array.from({ length: count }, (_, index) => ({
      resourceId: `arn:aws:s3:::bucket-${index}`,
      bucketName: `bucket-${index}`,
      relationship: 'CAN_READ',
      hasCondition: false,
      conditionKeys: [],
    }));
  const graphNodes = Array.from({ length: 80 }, (_, index) => ({ id: `exec-${index}`, entityId: `exec-${index}` }));
  const identityScope = graphNodes.map(node => ({
    id: node.id,
    executionBindingId: node.id,
    status: 'unknown',
    extraResources: extras(100),
  }));
  const { nodes, edges } = outsideGuardElements({ identityScope }, graphNodes);
  const more = edges.filter(edge => edge.data.target.startsWith('outside-more:'));
  assert.equal(more.length, 80, 'every binding with undrawn buckets says so');
  assert.ok(edges.length - more.length <= GRAPH_BUCKET_EDGES);
  assert.ok(edges.length < 1000, 'far below the display limit');
  assert.match(nodes.find(node => node.data.id === 'outside-more:exec-0').data.fullLabel, /^\+92 more buckets/);
  const small = outsideGuardElements(
    {
      identityScope: [
        {
          id: 'exec-0',
          executionBindingId: 'exec-0',
          status: 'broader_than_grants',
          extraResources: extras(GRAPH_BUCKETS_PER_BINDING),
        },
      ],
    },
    graphNodes,
  );
  assert.equal(small.edges.length, GRAPH_BUCKETS_PER_BINDING, 'a short list is drawn in full');
  assert.equal(
    small.nodes.some(node => node.data.id.startsWith('outside-more:')),
    false,
  );
});

test('label lookups ignore inherited object members', async () => {
  const { reasonLabel, noteLabel, unknownReasonLabel } = await import('../src/boundary-model.mjs');
  for (const label of [reasonLabel, noteLabel, unknownReasonLabel]) {
    assert.equal(label('constructor'), 'Constructor');
    assert.equal(typeof label('toString'), 'string');
  }
});

test('the "+N more" node counts buckets, not relationship entries, and notes a shortened list', async () => {
  const { outsideGuardElements, flagBadge, relationshipName, outsideGuardLabel } =
    await import('../src/boundary-model.mjs');
  const { kindName } = await import('../src/view-model.mjs');
  const entries = buckets =>
    Array.from({ length: buckets }, (_, index) =>
      ['CAN_LIST', 'CAN_READ', 'CAN_WRITE'].map(relationship => ({
        resourceId: `arn:aws:s3:::bucket-${index}`,
        bucketName: `bucket-${index}`,
        relationship,
        hasCondition: false,
        conditionKeys: [],
      })),
    ).flat();
  const graphNodes = [{ id: 'exec', entityId: 'exec' }];
  const drawn = (count, truncated = false) =>
    outsideGuardElements(
      {
        identityScope: [
          {
            id: 'exec',
            executionBindingId: 'exec',
            status: 'broader_than_grants',
            truncated,
            extraResources: entries(count),
          },
        ],
      },
      graphNodes,
    );
  const nine = drawn(9);
  assert.equal(nine.nodes.filter(node => node.data.id.startsWith('outside-bucket:')).length, 8);
  assert.equal(nine.edges.filter(edge => edge.data.target.startsWith('outside-bucket:')).length, 24);
  assert.match(nine.nodes.find(node => node.data.id === 'outside-more:exec').data.fullLabel, /^\+1 more bucket \(/);
  assert.equal(
    drawn(8).nodes.some(node => node.data.id.startsWith('outside-more:')),
    false,
  );
  assert.match(drawn(2, true).nodes.find(node => node.data.id === 'outside-more:exec').data.fullLabel, /not listed/);
  // Own keys only for every label table.
  assert.equal(flagBadge('constructor').label, flagBadge('unknown').label);
  assert.equal(relationshipName('constructor'), 'Constructor');
  assert.equal(outsideGuardLabel('toString'), outsideGuardLabel('unknown'));
  assert.equal(kindName('constructor'), 'Evidence');
});

test('the flag model carries the evidence-truncated marker', async () => {
  const { boundaryFlagRows } = await import('../src/boundary-model.mjs');
  const flag = { kind: 'dangerous_three', status: 'mitigated', legs: {}, evidence: [] };
  assert.equal(boundaryFlagRows([{ ...flag, evidenceTruncated: true }]).evidenceTruncated, true);
  assert.equal(boundaryFlagRows([flag]).evidenceTruncated, false);
});

test('reach that was never judged is told apart from an empty result', async () => {
  const { reachNotEvaluated, unknownReasonLabel } = await import('../src/boundary-model.mjs');
  assert.equal(reachNotEvaluated({ status: 'unknown', unknownReasons: ['reach_not_evaluated'] }), true);
  assert.equal(reachNotEvaluated({ status: 'unknown', unknownReasons: ['identity_scope_unknown'] }), false);
  assert.equal(reachNotEvaluated({ status: 'none_found', unknownReasons: [] }), false);
  for (const value of [null, undefined, {}, { unknownReasons: 'reach_not_evaluated' }])
    assert.equal(reachNotEvaluated(value), false);
  assert.notEqual(unknownReasonLabel('reach_not_evaluated'), 'reach_not_evaluated');
});
