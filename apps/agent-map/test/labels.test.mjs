import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MAP_INPUT_SCHEMAS, MAP_LABELS, MAP_PROPERTIES, MAP_RELATIONSHIPS } from '@shieldaai/agent-map/service';
import {
  LABELS,
  booleanLabel,
  codeText,
  displayValue,
  fieldLabel,
  fieldText,
  fieldValue,
  hasLabel,
  label,
  words,
} from '../src/labels.mjs';
import { activeFilterCount, agentOptions, componentHealth, shortIdentifier } from '../src/view-model.mjs';
import { KNOWN_ACTIONS, resourceReferences } from '../src/inventory-model.mjs';
import { FLAG_FILTERS, flagBadge } from '../src/boundary-model.mjs';
import { listingArgs, NO_FILTERS } from '../src/hooks/use-inventory.mjs';
import { queryDemo } from '../src/demo.mjs';
import { DEMO_SOURCE_ID } from '../src/demo-store.mjs';

const choices = (operation, argument) => MAP_INPUT_SCHEMAS[operation].properties[argument].enum;

test('every code the service can send has a label, and no label is a raw code', () => {
  for (const [table, values] of [
    ['nodeKind', MAP_LABELS],
    ['relation', MAP_RELATIONSHIPS],
    ['ownership', choices('list_agents', 'ownershipStatus')],
    ['ownershipFilter', choices('list_agents', 'ownershipStatus')],
    ['lifecycle', choices('list_agents', 'lifecycleState')],
    ['flagStatus', choices('list_agents', 'flagStatus').filter(status => status !== 'absent')],
    ['changeCategory', choices('get_changes', 'changeKind').filter(kind => kind !== 'all')],
    ['ownerKind', choices('list_owners', 'kind')],
    ['sensitivity', choices('list_resources', 'sensitivity')],
    ['field', [...new Set(Object.values(MAP_PROPERTIES).flat())]],
    ['healthComponent', ['tasks', 'tools', 'manifest', 'mcp', 'cloud', 'policy']],
    ['coverageStatus', ['complete', 'partial', 'unavailable', 'not_collected', 'unknown']],
    ['changeKind', ['added', 'removed', 'changed']],
    ['reach', ['yes', 'none_found', 'unknown']],
    ['directAccessStatus', ['found', 'none_declared', 'unknown']],
    ['directAccessKind', ['shell', 'database', 'network', 'sdk', 'mcp', 'other']],
    ['identityScopeStatus', ['broader_than_grants', 'matches_grants', 'unknown']],
    ['flagsUnavailable', ['flags_limit_exceeded', 'flags_timeout', 'flags_read_unavailable']],
    ['activityReason', ['read_unavailable', 'read_timeout', 'limit_exceeded', 'publication_changed', 'not_reported']],
    ['accountReason', ['collection_invalid', 'stale', 'changed', 'limit_exceeded', 'claims_limit_exceeded']],
    [
      'policyReason',
      [
        'no_candidate',
        'binding_ambiguous',
        'cloud_unresolved',
        'provider_missing',
        'collection_invalid',
        'stale',
        'changed',
        'boundary_unresolved',
        'unsupported_policy',
        'evidence_invalid',
        'unsupported_action',
        'identity_not_static',
        'unsupported_binding',
        'cloud_not_collected',
        'collection_missing',
        'disabled',
      ],
    ],
    [
      'identityScopeReason',
      ['unsupported_identity', 'not_evaluated', 'wildcard_grant', 'binding_narrower_than_candidate', 'truncated'],
    ],
    [
      'reachUnknownReason',
      [
        'binding_ambiguous',
        'resource_not_collected',
        'direct_access_undeclared',
        'direct_access_untargeted',
        'direct_access_target_unresolved',
        'identity_scope_not_collected_for_resource',
        'identity_scope_not_collected',
        'identity_scope_unknown',
        'identity_scope_other_account',
        'execution_identity_undeclared',
        'outside_visible_scope',
        'reach_not_evaluated',
      ],
    ],
  ])
    for (const value of values) assert.ok(hasLabel(table, value), `${table}.${value} has no label`);
  // Whatever table it is in, a label reads as words: no snake_case, no bare true / false.
  for (const [table, entries] of Object.entries(LABELS))
    for (const [code, text] of Object.entries(entries)) {
      assert.equal(typeof text, 'string', `${table}.${code}`);
      assert.doesNotMatch(text, /_|^(?:true|false)$/i, `${table}.${code}: ${text}`);
      assert.ok(text.trim().length > 0, `${table}.${code}`);
    }
});

test('the explanation codes the real service returns are all labelled', async () => {
  const source = { sourceId: DEMO_SOURCE_ID };
  const tasks = (await queryDemo('get_agent_inventory', { ...source, agentId: 'research-assistant', section: 'tasks' }))
    .data.items;
  const grants = (
    await queryDemo('get_agent_inventory', { ...source, agentId: 'research-assistant', section: 'permissions' })
  ).data.items;
  const granted = await queryDemo('explain_access', {
    ...source,
    taskId: tasks[0].taskId,
    tool: grants[0].tool,
    resourceId: grants[0].resources[0],
  });
  const missing = await queryDemo('explain_access', {
    ...source,
    taskId: tasks[0].taskId,
    tool: grants[0].tool,
    resourceId: 'out-of-scope',
  });
  assert.ok(granted.data.unknownChecks.length > 0);
  for (const code of [...granted.data.unknownChecks, ...missing.data.unknownChecks])
    assert.ok(hasLabel('unknownCheck', code), code);
  assert.ok(missing.data.blockers.length > 0);
  for (const code of missing.data.blockers) assert.ok(hasLabel('blocker', code), code);
});

test('an unknown code reads as words, a boolean as yes or no, and identifiers are left alone', () => {
  assert.equal(label('lifecycle', 'being_retired'), 'Being retired');
  assert.equal(label('lifecycle', undefined), 'Unknown');
  assert.equal(label('lifecycle', 'constructor'), 'Constructor');
  assert.equal(words('not_collected'), 'Not collected');
  assert.deepEqual(
    [true, false, null].map(value => booleanLabel(value)),
    ['Yes', 'No', 'Unknown'],
  );
  assert.equal(fieldValue('registered', false), 'Not registered');
  assert.equal(fieldValue('requires_approval', true), 'Required');
  // A property named like an inherited member is an ordinary unknown property, not a crash.
  for (const name of ['constructor', 'toString', '__proto__', 'valueOf', 'hasOwnProperty']) {
    assert.equal(fieldValue(name, true), 'Yes', name);
    assert.equal(fieldValue(name, false), 'No', name);
    assert.equal(fieldText(name, true), 'Yes', name);
    assert.equal(fieldValue(name, 'kept_as_is'), 'kept_as_is', name);
    assert.doesNotMatch(fieldLabel(name), /function|object/, name);
  }
  assert.equal(fieldValue('sends_external', true), 'Yes');
  assert.equal(fieldValue('lifecycle_state', 'active'), 'Active');
  assert.equal(fieldValue('untrusted_context', 'require_approval'), 'Approval required');
  // A name or id that happens to look like a code is not translated.
  assert.equal(fieldValue('name', 'not_collected'), 'not_collected');
  assert.equal(fieldValue('max_calls', 100), 100);
  assert.equal(fieldText('allowed_recipients', []), 'None recorded');
  assert.equal(fieldLabel('direct_access_status'), 'Direct paths');
  assert.doesNotMatch(fieldLabel('some_new_field'), /_/);
  assert.equal(displayValue(true), 'Yes');
  assert.equal(displayValue(''), 'Empty');
  assert.equal(codeText('company_registry'), 'Company registry');
  assert.equal(codeText('Company registry'), 'Company registry');
  // Health components and their statuses.
  assert.equal(componentHealth({ status: 'not_collected' }).status, 'Not collected');
  assert.equal(
    componentHealth({ status: 'unknown', reason: 'limit_exceeded' }).reason,
    'too many task and binding pairs to evaluate',
  );
  // The flag reads the same on a badge, in the filter and on the graph.
  assert.equal(flagBadge('exposed').label, 'Dangerous three: Exposed');
  assert.deepEqual(
    FLAG_FILTERS.map(([value]) => value),
    ['', 'flagged', 'exposed', 'mitigated', 'unknown', 'absent'],
  );
  for (const [, text] of FLAG_FILTERS) assert.doesNotMatch(text, /\bleg\b/);
});

test('a long identifier is shortened to its first ten and last six characters; a short one is not', () => {
  const opaque = `opaque:${'a1'.repeat(32)}`;
  assert.equal(shortIdentifier(opaque), 'opaque:a1a…a1a1a1');
  assert.equal(shortIdentifier('arn:aws:iam::111122223333:role/service/batch-runner'), 'arn:aws:ia…runner');
  assert.equal(shortIdentifier('a'.repeat(64)), `${'a'.repeat(10)}…${'a'.repeat(6)}`);
  for (const value of ['legacy-reported-owner', 'records-0', 'x'.repeat(24), '', null, undefined, 42])
    assert.equal(shortIdentifier(value), null);
  // Counted in characters, so an astral character is never cut in half.
  assert.equal(shortIdentifier('😀'.repeat(30)), `${'😀'.repeat(10)}…${'😀'.repeat(6)}`);
});

test('sidebar filters suggest what is loaded, keep earlier suggestions and count the active filters', () => {
  const first = agentOptions([{ ownerId: 'owner-b', environments: ['production'] }]);
  const merged = agentOptions([{ ownerId: 'owner-a', environments: ['staging', 'production'] }], first);
  assert.deepEqual(merged, { owners: ['owner-a', 'owner-b'], environments: ['production', 'staging'] });
  assert.equal(activeFilterCount(NO_FILTERS), 0);
  // Search has its own box, and the source filter rides on the owner filter.
  assert.equal(activeFilterCount({ ...NO_FILTERS, search: 'x', owner: 'o', source: 's', flag: 'exposed' }), 2);
  assert.deepEqual(listingArgs(NO_FILTERS, 0), { includeFlags: true, offset: 0, limit: 20 });
  assert.deepEqual(
    listingArgs(
      {
        search: 'cat',
        owner: 'o',
        environment: 'e',
        ownership: 'assigned',
        lifecycle: 'active',
        flag: 'flagged',
        source: 's',
      },
      20,
    ),
    {
      search: 'cat',
      ownerId: 'o',
      environment: 'e',
      sourceId: 's',
      ownershipStatus: 'assigned',
      lifecycleState: 'active',
      includeFlags: true,
      flag: 'dangerous_three',
      offset: 20,
      limit: 20,
    },
  );
});

test('the potential-access lookup offers loaded references and the mapped actions', () => {
  assert.deepEqual(KNOWN_ACTIONS, ['s3:GetObject', 's3:PutObject', 's3:ListBucket']);
  assert.deepEqual(
    resourceReferences([
      { resourceRef: 'opaque:b', targets: [{ arn: 'arn:aws:s3:::bucket/key' }, { host_resource_id: 'opaque:h' }] },
      { resourceRef: 'opaque:a', targets: [] },
      { resourceRef: 'opaque:b' },
      null,
    ]),
    ['arn:aws:s3:::bucket/key', 'opaque:a', 'opaque:b'],
  );
  assert.deepEqual(resourceReferences(undefined), []);
});

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
const render = (Component, props) => renderToStaticMarkup(React.createElement(Component, props));

test('a long identifier renders shortened with its full value, a copy button and its display name first', async () => {
  const { Identifier } = await bundle('components/identifier.jsx');
  const opaque = `opaque:${'0'.repeat(64)}`;
  const long = render(Identifier, { value: opaque, name: 'Company records' });
  assert.match(long, /<strong class="identifier-name">Company records<\/strong>/);
  assert.ok(long.includes(`<summary title="${opaque}">opaque:000…000000</summary>`));
  assert.ok(long.includes(`<span class="full-reference">${opaque}</span>`));
  assert.match(long, /<button type="button" class="copy-button" aria-label="Copy full identifier">Copy<\/button>/);
  assert.match(long, /role="status"/);
  // A short value is plain text: nothing to expand or copy.
  assert.equal(render(Identifier, { value: 'records-0' }), '<span class="full-reference">records-0</span>');
  assert.equal(render(Identifier, { value: null }), '<span class="full-reference">Unknown</span>');
  assert.equal(render(Identifier, { value: [] }), '<span class="full-reference">None recorded</span>');
  // Markup in an identifier is text.
  assert.equal(render(Identifier, { value: '<img src=x>' }).includes('<img'), false);
  const list = render(Identifier, { value: [opaque, 'short'] });
  assert.equal(list.match(/copy-button/g).length, 1);
  assert.ok(list.includes('<span class="full-reference">short</span>'));
});

test('the sidebar keeps filters behind a counted disclosure and explains an empty inventory', async () => {
  const { AgentSidebar } = await bundle('views/agent-sidebar.jsx');
  const base = {
    listing: { agents: [], page: { offset: 0, limit: 20, total: 0 }, state: 'ready', message: '' },
    filters: NO_FILTERS,
    options: { owners: ['owner-a'], environments: ['production'] },
    onFilter() {},
    onClearOwner() {},
    onSelect() {},
    onPage() {},
    selection: null,
  };
  const empty = render(AgentSidebar, base);
  assert.match(empty, /<details class="filter-panel"><summary>Filters<\/summary>/);
  assert.match(empty, /once a host manifest declares it/);
  assert.equal(empty.includes('No agents match these visible filters.'), false);
  // The flag is explained where the badges are used.
  assert.match(
    empty,
    /An agent is flagged when one live task can read private data, read outside content and send data out\./,
  );
  assert.match(empty, /No badge means at least one of the three is known not to apply\./);
  for (const word of ['Exposed', 'Mitigated', 'Unknown']) assert.ok(empty.includes(`Dangerous three: ${word}`));
  // Owner and environment are typed, so a value no loaded agent names can still be filtered on;
  // what is loaded is offered as suggestions through a datalist the input refers to.
  for (const [name, known] of [
    ['Filter by owner ID', 'owner-a'],
    ['Filter by environment', 'production'],
  ]) {
    const input = new RegExp(`<input aria-label="${name}" list="([^"]+)"[^>]*value=""`).exec(empty);
    assert.ok(input, name);
    assert.ok(empty.includes(`<datalist id="${input[1]}"><option value="${known}"></option></datalist>`), name);
    assert.equal(new RegExp(`<select[^>]*aria-label="${name}"`).test(empty), false);
  }
  const filtered = render(AgentSidebar, {
    ...base,
    filters: { ...NO_FILTERS, owner: 'owner-z', source: 'source', lifecycle: 'retired' },
  });
  assert.match(filtered, /<details class="filter-panel" open=""><summary>Filters \(2\)/);
  // A value set from another view, which no loaded agent names, is shown as it is.
  assert.match(filtered, /<input aria-label="Filter by owner ID"[^>]*value="owner-z"/);
  assert.match(filtered, /<option value="retired" selected="">Retired<\/option>/);
  assert.ok(filtered.includes('No agents match these visible filters.'));
  assert.ok(filtered.includes('Clear owner filter'));
  assert.ok(render(AgentSidebar, { ...base, filters: { ...NO_FILTERS, search: 'x' } }).includes('No agents match'));
  const failed = render(AgentSidebar, {
    ...base,
    listing: { ...base.listing, state: 'error', message: 'Too many requests. Wait a moment, then try again.' },
  });
  assert.ok(failed.includes('Inventory could not be loaded. Select Refresh evidence to retry.'));
  assert.ok(failed.includes('Too many requests.'));
});

test('the orientation panel says what the map lists, what the three statuses mean and that it decides nothing', async () => {
  const { HelpPanel, SessionWarning } = await bundle('views/shell.jsx');
  const help = render(HelpPanel, {});
  assert.match(help, /^<details class="help-panel"><summary>What am I looking at\?<\/summary>/);
  for (const text of [
    'declared in a host manifest',
    'Exposed',
    'Mitigated',
    'Unknown',
    'never grants or blocks anything',
  ])
    assert.ok(help.includes(text), text);
  assert.match(render(SessionWarning, {}), /role="status">Your company session ends in about a minute/);
});
