import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import cytoscape from 'cytoscape';
import { graphElements, policyEvidenceRows } from '../src/view-model.mjs';
import { queryDemo } from '../src/demo.mjs';

async function fixture() {
  const result = await queryDemo('get_agent_access', { agentId: 'agent-research' });
  return { graph: result.graph, record: result.data.policyEvidence[0] };
}
const compiled = await build({ entryPoints: [new URL('../src/policy-evidence.jsx', import.meta.url).pathname],
  bundle: true, write: false, platform: 'browser', format: 'esm', define: { 'process.env.NODE_ENV': '"production"' } });
const { PolicyEvidence } = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputFiles[0].text).toString('base64')}`);
const render = (evidence, graph, compact = false) => renderToStaticMarkup(React.createElement(PolicyEvidence, { evidence, graph, compact }));

test('policy graph draws a distinct candidate only between visible exact binding endpoints', async () => {
  const { graph, record } = await fixture();
  const elements = graphElements(graph, [record]);
  const [candidate] = elements.filter(item => item.classes === 'policy-candidate');
  assert.equal(candidate.data.source, 'identity');
  assert.equal(candidate.data.target, 'external-resource');
  assert.match(candidate.data.label, /s3:GetObject · policy candidate · condition unresolved/);
  assert.equal(candidate.data.label.includes('allowed'), false);
  const cy = cytoscape({ headless: true, elements });
  try { assert.equal(cy.edges('.policy-candidate').length, 1); }
  finally { cy.destroy(); }
  assert.equal(graphElements(graph, [record, record]).filter(item => item.classes === 'policy-candidate').length, 1);
});

test('hidden endpoints or another deployment never become policy graph neighbors', async () => {
  const { graph, record } = await fixture();
  const foreign = { ...record, resourceId: 'hidden-resource-canary' };
  assert.deepEqual(policyEvidenceRows([foreign], graph), []);
  assert.equal(JSON.stringify(graphElements(graph, [foreign])).includes('hidden-resource-canary'), false);
  graph.nodes.push({ id: 'other', entityId: 'other', label: 'GuardDeployment', properties: { deployment_id: 'other-deployment-canary' } });
  assert.deepEqual(policyEvidenceRows([{ ...record, deploymentId: 'other' }], graph), []);
  const changed = structuredClone(graph);
  changed.edges = changed.edges.filter(edge => edge.kind !== 'G_USES_IDENTITY');
  assert.deepEqual(policyEvidenceRows([record], changed), []);
});

test('visible endpoints still require the same task grant, resource selector and execution tool', async () => {
  const { graph, record } = await fixture();
  for (const kind of ['G_HAS_GRANT', 'G_TARGETS', 'G_BINDS_SELECTOR', 'G_FOR_TOOL', 'G_EXECUTES_TOOL']) {
    const changed = structuredClone(graph);
    changed.edges = changed.edges.filter(edge => edge.kind !== kind);
    assert.deepEqual(policyEvidenceRows([record], changed), []);
  }
  const changed = structuredClone(graph);
  changed.nodes.find(node => node.label === 'GuardResourceBinding').properties.tool = 'another.tool';
  assert.deepEqual(policyEvidenceRows([record], changed), []);
});

test('missing and unresolved policy evidence never draw a positive candidate', async () => {
  const { graph, record } = await fixture();
  for (const [status, reason] of [['unavailable', 'stale'], ['unavailable', 'boundary_unresolved'],
    ['unavailable', 'unsupported_policy'], ['unavailable', 'changed'], ['not_collected', 'disabled'], ['complete', 'no_candidate']]) {
    const unresolved = { ...record, status, reason, candidates: [] };
    assert.equal(graphElements(graph, [unresolved]).filter(item => item.classes === 'policy-candidate').length, 0);
    const html = render([unresolved], graph);
    assert.match(html, /Access unknown/);
    assert.match(html, /does not establish denial/);
  }
  assert.match(render([{ ...record, status: 'unavailable', reason: 'boundary_unresolved', candidates: [] }], graph), /Permissions boundary unresolved/);
  assert.match(render([{ ...record, status: 'unavailable', reason: 'unsupported_policy', candidates: [] }], graph), /Unsupported policy expression/);
});

test('policy presentation preserves exact object scope and its independent observation time', async () => {
  const { graph, record } = await fixture();
  const observedAt = '2026-10-30T01:02:03Z';
  const html = render([{ ...record, observedAt }], graph);
  assert.match(html, /arn:aws:s3:::company-reports\/quarterly\/summary.pdf/);
  assert.match(html, /exact · object/);
  assert.match(html, /Bucket-summary evidence/);
  assert.match(html, /original object or prefix restriction still applies/);
  assert.match(html, /datetime="2026-10-30T01:02:03Z"/i);
  assert.match(html, /aws:PrincipalTag\/team/);
  assert.match(html, /Policy candidates do not authorize execution/);
});

test('policy rendering treats condition keys as text and discards all unrecognized provider fields', async () => {
  const { graph, record } = await fixture();
  const candidate = { ...record.candidates[0], conditionKeys: ['<img src=x onerror=alert(1)>'], conditions: 'condition-value-canary' };
  const extra = { ...record, candidates: [candidate], policyHash: 'global-hash-canary', document: 'raw-policy-canary' };
  const html = render([extra], graph);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.equal(html.includes('<img'), false);
  assert.doesNotMatch(html, /condition-value-canary|global-hash-canary|raw-policy-canary/);
  const invalidReason = { ...record, status: 'unavailable', reason: 'private-error-canary', candidates: [] };
  assert.equal(render([invalidReason], graph).includes('private-error-canary'), false);
});

test('malformed policy records cannot be displayed as collected candidates', async () => {
  const { graph, record } = await fixture();
  for (const value of [
    { ...record, assessment: 'allowed' }, { ...record, status: 'unavailable' },
    { ...record, action: 's3:DeleteObject' }, { ...record, observedAt: 'invalid' }, { ...record, observedAt: null },
    { ...record, candidates: [{ ...record.candidates[0], hasCondition: false }] },
    { ...record, candidates: [{ ...record.candidates[0], resourceScope: 'all_objects' }] },
    { ...record, candidates: [{ ...record.candidates[0], conditionKeys: ['x'.repeat(257)] }] },
  ]) {
    assert.throws(() => policyEvidenceRows([value], graph), /VIEWER_POLICY_INVALID/);
    assert.match(render([value], graph), /could not be displayed safely/);
  }
});

test('policy presentation refuses pair and graph edge overflow without partial results', async () => {
  const { graph, record } = await fixture();
  assert.throws(() => policyEvidenceRows(Array(513).fill(record), graph), /VIEWER_POLICY_INVALID/);
  assert.throws(() => policyEvidenceRows([{ ...record, candidates: [record.candidates[0], record.candidates[0]] }], graph), /VIEWER_POLICY_INVALID/);
  const fullGraph = { ...graph, edges: Array(5000).fill(graph.edges[0]) };
  // Preserve the binding links while reaching the fixed graph edge budget.
  fullGraph.edges.splice(0, graph.edges.length, ...graph.edges);
  assert.throws(() => graphElements(fullGraph, [record]), /VIEWER_GRAPH_INVALID/);
});

test('synthetic demo supplies conditional, absent and boundary evidence without history claims', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('Demo must stay local'));
  const research = await queryDemo('get_agent_access', { agentId: 'agent-research' });
  const release = await queryDemo('get_agent_access', { agentId: 'agent-release' });
  const finance = await queryDemo('get_agent_access', { agentId: 'agent-finance' });
  assert.equal(research.data.policyEvidence[0].candidates[0].hasCondition, true);
  assert.equal(release.data.policyEvidence[0].reason, 'no_candidate');
  assert.equal(finance.data.policyEvidence[0].reason, 'boundary_unresolved');
  const explanation = await queryDemo('explain_access', { taskId: research.data.tasks[0].taskId });
  assert.deepEqual(explanation.data.externalEvidence.policyEvidence, research.data.policyEvidence);
  const changes = await queryDemo('get_changes');
  assert.equal(changes.data.policyHistory, 'not_collected');
});
