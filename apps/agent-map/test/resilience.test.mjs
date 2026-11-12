import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  graphTooLarge,
  policyNotEvaluated,
  policySectionNotEvaluated,
  readInventoryHealth,
} from '../src/view-model.mjs';
import { debounced, SEARCH_DEBOUNCE_MS } from '../src/inventory-model.mjs';
import { CHANGE_FILTERS, changeCategoryLabel, changeKindLabel, changeValueLabel } from '../src/boundary-model.mjs';
import { queryDemo } from '../src/demo.mjs';

const source = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
// React stays external and resolves to the test's own copy, so hooks and the server renderer agree.
async function bundle(name) {
  const compiled = await build({
    entryPoints: [fileURLToPath(new URL(`../src/${name}`, import.meta.url))],
    bundle: true,
    write: false,
    platform: 'browser',
    format: 'esm',
    external: ['react'],
    define: { 'process.env.NODE_ENV': '"production"' },
  });
  return import(
    `data:text/javascript;base64,${Buffer.from(
      compiled.outputFiles[0].text.replaceAll(
        /from\s*"react"/g,
        `from ${JSON.stringify(import.meta.resolve('react'))}`,
      ),
    ).toString('base64')}`
  );
}

test('a failed health read leaves the workspace open: it resolves to unavailable with a plain reason', async () => {
  const sources = [{ id: 'source', tenantId: 'alpha' }];
  const calls = [];
  const ready = await readInventoryHealth(async (operation, args, options) => {
    calls.push([operation, args, options]);
    return { data: { sources } };
  }, 'options');
  assert.deepEqual(ready, { status: 'ready', sources });
  assert.deepEqual(calls, [['get_inventory_health', {}, 'options']]);
  // A response without the list reads as no sources, never as a failure to connect.
  assert.deepEqual(await readInventoryHealth(async () => ({ data: {} })), { status: 'ready', sources: [] });
  for (const [error, message] of [
    [
      Object.assign(new Error('MAP_LIMIT_EXCEEDED'), { code: 'MAP_LIMIT_EXCEEDED', status: 413 }),
      'This view is too large. Narrow the source or agent selection and try again.',
    ],
    [
      Object.assign(new Error('<b>remote</b>'), { code: 'MAP_UNAVAILABLE', status: 503 }),
      'The reference service could not complete this request. Try again shortly.',
    ],
  ]) {
    const failed = await readInventoryHealth(async () => {
      throw error;
    });
    assert.equal(failed.status, 'unavailable');
    assert.equal(failed.message, message);
    // The caller still sees the error, so a rejected session (401/403) can end the workspace.
    assert.equal(failed.error, error);
    assert.equal(failed.sources, undefined);
  }
});

test('connecting sends the agent listing once and never waits for health', async () => {
  const sessions = await source('hooks/use-session.mjs');
  const connect = sessions.slice(
    sessions.indexOf('const openWorkspace = useCallback'),
    sessions.indexOf('const companyWorkspace'),
  );
  assert.equal(connect.match(/\.query\(/g).length, 1);
  assert.match(connect, /next\.query\('list_agents'/);
  assert.equal(connect.includes('get_inventory_health'), false);
  // Health has its own read with a retry, and the listing hook uses the page connect just loaded.
  const inventory = await source('hooks/use-inventory.mjs');
  assert.match(inventory, /readInventoryHealth\(session\.query/);
  assert.match(inventory, /if \(session\.listing && adopted\.current !== session\) \{\s+adopted\.current = session;/);
  assert.match(await source('views/health.jsx'), /Retry health/);
  // The explanation form takes the grants the Permissions table already loaded.
  const explain = await source('views/explain.jsx');
  const explanation = explain.slice(explain.indexOf('export function AgentExplanation'));
  assert.equal(explanation.match(/\.query\(|query\(\s*'/g).length, 1);
  assert.match(explanation, /section: 'tasks'/);
  assert.equal(explanation.includes("'permissions'"), false);
});

test('a graph the service left out for size is told apart from a missing one', () => {
  assert.equal(graphTooLarge({ data: { graphStatus: 'too_large', boundaryFlags: [] } }), true);
  // An included graph, an older service, or a marker contradicted by an actual graph.
  assert.equal(graphTooLarge({ data: { graphStatus: 'included' }, graph: { nodes: [], edges: [] } }), false);
  assert.equal(graphTooLarge({ data: {} }), false);
  assert.equal(graphTooLarge({ data: { graphStatus: 'too_large' }, graph: { nodes: [], edges: [] } }), false);
  for (const value of [null, undefined, {}, 'too_large']) assert.equal(graphTooLarge(value), false);
});

test('a failed or interrupted agent selection does not stay highlighted', async () => {
  const inventory = await source('hooks/use-inventory.mjs');
  const select = inventory.slice(
    inventory.indexOf('const select = useCallback'),
    inventory.indexOf('const mine = owner === session'),
  );
  assert.match(
    select,
    /catch \(failure\) \{\s+if \(run === generation\.current\) \{\s+focusRequest\.current = false;\s+setSelection\(null\);/,
  );
  // The failure is shown where the agent would have opened, not in a page-level banner.
  assert.match(select, /reportError\(failure, \{ shown: true \}\)/);
  // Leaving the tab while a selection is still loading clears it too.
  const workspace = await source('hooks/use-workspace.mjs');
  assert.match(workspace, /selected\.cancel\(\);\s+if \(!selected\.access\) selected\.clear\(\);/);
});

test('search waits 300 ms after the last key and sends only the final text', t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  assert.equal(SEARCH_DEBOUNCE_MS, 300);
  const sent = [];
  const search = debounced(value => sent.push(value));
  for (const text of ['p', 'pl', 'pla']) {
    search(text);
    t.mock.timers.tick(299);
  }
  assert.deepEqual(sent, []);
  t.mock.timers.tick(1);
  assert.deepEqual(sent, ['pla']);
  // Leaving the view drops a pending search.
  search('platform');
  search.cancel();
  t.mock.timers.tick(1000);
  assert.deepEqual(sent, ['pla']);
  search('team');
  t.mock.timers.tick(300);
  assert.deepEqual(sent, ['pla', 'team']);
});

test('owner and resource searches are debounced; other filters apply at once', async () => {
  const owners = await source('views/owners.jsx'),
    resources = await source('views/resources.jsx');
  assert.match(owners, /usePage\(\s*query,\s*'list_owners',\s*\{ \.\.\.\(term \? \{ search: term \} : \{\}\)/);
  assert.match(
    resources,
    /\.\.\.\(term \? \{ search: term \} : \{\}\),\s*\.\.\.\(sensitivity \? \{ sensitivity \} : \{\}\)/,
  );
  for (const view of [owners, resources]) assert.equal(/\(search \? \{ search \}/.test(view), false);
});

test('change categories, kinds and status values are shown in words', async () => {
  for (const [value, label] of [
    ['permissions', 'Declared permissions'],
    ['ownership', 'Ownership'],
    ['bindings', 'Bindings and connections'],
    ['outside_guard', 'Outside-guard paths (declared)'],
    ['inventory', 'Other inventory details'],
    // A category this viewer does not know yet is still words, never a raw code.
    ['new_category', 'New category'],
    [undefined, 'Unknown'],
    ['constructor', 'Constructor'],
  ])
    assert.equal(changeCategoryLabel(value), label);
  assert.deepEqual(['added', 'removed', 'changed', 'renamed_later', null].map(changeKindLabel), [
    'Added',
    'Removed',
    'Changed',
    'Renamed later',
    'Unknown',
  ]);
  assert.equal(changeValueLabel('direct_access_status', 'none_declared'), 'None declared (host claim, not checked)');
  assert.equal(changeValueLabel('direct_access_status', 'found'), 'Direct paths declared');
  // Only that status field is translated: an identifier that happens to read the same is left alone.
  assert.equal(changeValueLabel('name', 'none_declared'), 'none_declared');
  assert.equal(changeValueLabel('direct_access_status', null), null);
  // Every category the service can emit is one the filter offers, under the same words.
  assert.deepEqual(
    CHANGE_FILTERS.map(([value]) => value),
    ['all', 'permissions', 'ownership', 'bindings', 'outside_guard', 'inventory'],
  );
  const { ChangesView } = await bundle('views/changes.jsx');
  const html = renderToStaticMarkup(
    React.createElement(ChangesView, { sources: [{ id: 'source', tenantId: 'alpha' }], query: queryDemo }),
  );
  for (const [value, label] of CHANGE_FILTERS) {
    assert.ok(html.includes(`<option value="${value}"`), value);
    assert.ok(html.includes(`>${label}</option>`), label);
  }
  assert.equal(html.includes('>outside_guard<'), false);
  const changes = await source('views/changes.jsx');
  assert.match(changes, /changeKindLabel\(item\.kind\)/);
  assert.match(changes, /\.map\(changeCategoryLabel\)/);
  assert.match(changes, /changeValueLabel\(field, value\)/);
  // Field names and yes/no values are words too.
  assert.match(changes, /fieldLabel\(x\.field\)/);
  assert.equal(changeValueLabel('revoked', true), 'Revoked');
  assert.equal(changeValueLabel('reads_untrusted', false), 'No');
});

test('policy evidence that was not evaluated is not described as not collected', async () => {
  assert.equal(policyNotEvaluated({ status: 'unknown', reason: 'limit_exceeded' }), true);
  for (const coverage of [{ status: 'not_collected' }, { status: 'unknown' }, { status: 'complete' }, null, undefined])
    assert.equal(policyNotEvaluated(coverage), false);
  const { PolicyEvidence } = await bundle('policy-evidence.jsx');
  const render = props =>
    renderToStaticMarkup(React.createElement(PolicyEvidence, { evidence: [], compact: true, ...props }));
  assert.match(render({ notEvaluated: true }), /Policy evidence was not evaluated: too many tasks and bindings match/);
  assert.match(render({}), /No policy evidence was collected for these visible bindings/);
  for (const html of [render({ notEvaluated: true }), render({})]) assert.match(html, /Access remains unknown/);
});

test('an agent whose policy evidence was not loaded shows "not evaluated", never zero or an empty list', async () => {
  const notLoaded = { status: 'unknown', reason: 'limit_exceeded', observedAt: null, assessment: 'unknown' };
  const page = { section: 'policies', items: [], offset: 0, limit: 20 };
  const shapes = {
    // What the service sends today: an empty complete page, and only the coverage says why.
    today: { ...page, total: 0, counts: { tasks: 3, policies: 0 }, policyCoverage: notLoaded },
    // What it sends next: the size of what was never loaded is null, in the page and in the counts.
    next: { ...page, total: null, counts: { tasks: 3, policies: null }, policyCoverage: notLoaded },
    // Either null alone is enough, whatever the coverage says.
    countOnly: { ...page, total: 0, counts: { policies: null }, policyCoverage: { status: 'complete' } },
    totalOnly: { ...page, total: null, counts: { policies: 0 } },
  };
  for (const [name, data] of Object.entries(shapes)) assert.equal(policySectionNotEvaluated(data), true, name);
  const none = { ...page, total: 0, counts: { tasks: 3, policies: 0 }, policyCoverage: { status: 'complete' } };
  const some = { ...page, section: 'tasks', total: null, counts: { tasks: 3, policies: 2 } };
  for (const data of [none, some, { counts: {} }, {}, null, undefined])
    assert.equal(policySectionNotEvaluated(data), false, JSON.stringify(data));
  const { PolicySection } = await bundle('policy-evidence.jsx');
  const render = data =>
    renderToStaticMarkup(React.createElement(PolicySection, { data, onPage() {}, label: 'mapped policy candidates' }));
  for (const [name, data] of Object.entries(shapes)) {
    const html = render(data);
    assert.match(html, /Policy evidence was not evaluated/, name);
    assert.match(html, /Access remains unknown/, name);
    // No size is claimed for what was not evaluated: no pager, no "0 of 0", no "no results".
    assert.equal(
      /inventory-pagination|0 of 0|No visible results|No policy evidence was collected/.test(html),
      false,
      name,
    );
  }
  // Evidence that was evaluated and found nothing still says so, with its count.
  const evaluated = render(none);
  assert.match(evaluated, /No policy evidence was collected for these visible bindings/);
  assert.match(evaluated, /0 of 0/);
  // A not-evaluated answer never lists rows, even if some arrive with it.
  const record = {
    taskId: 't',
    deploymentId: 'd',
    executionBindingId: 'e',
    resourceBindingId: 'r',
    action: 's3:GetObject',
    identityId: null,
    resourceId: null,
    status: 'not_collected',
    assessment: 'unknown',
    reason: 'disabled',
    observedAt: null,
    candidates: [],
  };
  assert.match(render({ ...none, items: [record], total: 1 }), /Policy collection disabled/);
  assert.equal(/Policy collection disabled/.test(render({ ...shapes.next, items: [record] })), false);
});
