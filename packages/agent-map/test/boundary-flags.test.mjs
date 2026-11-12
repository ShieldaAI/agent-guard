import test from 'node:test';
import assert from 'node:assert/strict';
import { MapService } from '../dist/index.js';

const now = Date.parse('2030-01-02T00:00:00Z');
const plain = value => JSON.parse(JSON.stringify(value));
const scope = { subject: 'reader', companyId: 'company', tenantIds: ['tenant'], teamIds: ['blue'], allTeams: false };

/**
 * One agent with one live task. The task reads `inbox` with `mail.read` and sends with
 * `mail.send`; `records.read` reaches a restricted binding. Options change one fact at a time.
 */
function build(options = {}) {
  const nodes = [],
    edges = [];
  const node = (key, label, properties) =>
    nodes.push({
      id: `n:${key}`,
      entityId: `e:${key}`,
      sourceId: 'source',
      projectionId: 'current',
      label,
      properties,
    });
  const edge = (a, b, kind) => edges.push({ source: `n:${a}`, target: `n:${b}`, kind });
  const v2 = options.v2 ?? true;
  const tool = (name, labels) =>
    node(`tool-${name}`, 'GuardTool', {
      name,
      registered: options.unregistered === name ? false : true,
      known_metadata: options.unregistered === name ? false : true,
      approved: true,
      // A v1 core lifted by a v3 manifest has v2 shapes but null labels and no default.
      ...(v2 && !options.lifted ? { untrusted_context_default: options.defaultMode ?? 'allow', ...labels } : {}),
    });
  tool('mail.read', { reads_untrusted: true, sends_external: false });
  tool('mail.send', {
    reads_untrusted: false,
    ...(options.sendDeclared === false ? {} : { sends_external: true }),
    ...(options.sendMode ? { untrusted_context: options.sendMode } : {}),
  });
  tool('records.read', {
    ...(options.recordsUndeclared ? {} : { reads_untrusted: false }),
    sends_external: false,
  });
  node('agent', 'GuardAgent', { agent_id: 'agent', name: 'Agent', team_id: 'blue' });
  node('deployment', 'GuardDeployment', { deployment_id: 'deployment' });
  edge('deployment', 'agent', 'G_INSTANCE_OF');
  const task = (key, properties) => {
    node(key, 'GuardTask', {
      task_id: key,
      revoked: false,
      sensitive: false,
      deadline: now + 60_000,
      allowed_recipients: ['partner'],
      delegated: false,
      derived: false,
      ...(v2 ? { untrusted: false } : {}),
      ...properties,
    });
    // `undefined` in options removes a property, as an older import would.
    const added = nodes.at(-1).properties;
    for (const name of Object.keys(added)) if (added[name] === undefined) delete added[name];
  };
  task('task', {
    ...(options.task ?? {}),
    ...(options.parent ? { delegated: true } : {}),
  });
  edge('task', 'deployment', 'G_ASSIGNED_TO');
  if (options.parent) {
    task('parent', options.parent);
    if (options.parentVisible !== false) edge('task', 'parent', 'G_DELEGATED_FROM');
    else nodes.pop();
  }
  // A chain of `depth` visible ancestors above the task.
  for (let level = 1; level <= (options.depth ?? 0); level++) {
    task(`ancestor-${level}`, { delegated: true });
    edge(level === 1 ? 'task' : `ancestor-${level - 1}`, `ancestor-${level}`, 'G_DELEGATED_FROM');
  }
  if (options.depth) {
    nodes.find(item => item.id === 'n:task').properties.delegated = true;
    nodes.find(item => item.id === `n:ancestor-${options.depth}`).properties.delegated = false;
  }
  const grant = (name, resources) => {
    node(`grant-${name}`, 'GuardGrant', { task_id: 'task', tool: name, resources });
    edge('task', `grant-${name}`, 'G_HAS_GRANT');
    edge(`grant-${name}`, `tool-${name}`, 'G_FOR_TOOL');
    for (const resource of resources) {
      node(`selector-${name}-${resource}`, 'GuardResource', { resource_id: resource, tool: name });
      edge(`grant-${name}`, `selector-${name}-${resource}`, 'G_TARGETS');
    }
  };
  const readsMail = options.readsMail ?? true;
  if (readsMail) grant('mail.read', ['inbox']);
  grant('mail.send', ['outbox']);
  grant('records.read', [options.wildcard ? '*' : 'record']);
  const sensitivity = 'sensitivity' in options ? options.sensitivity : 'restricted';
  node('binding-record', 'GuardResourceBinding', {
    binding_id: 'binding-record',
    tool: 'records.read',
    resource_ref: 'record',
    ...(sensitivity === null ? {} : { sensitivity }),
  });
  node('selector-records.read-record-bound', 'GuardResource', { resource_id: 'record', tool: 'records.read' });
  if (options.wildcard) edge('binding-record', 'selector-records.read-record-bound', 'G_BINDS_SELECTOR');
  else edge('binding-record', 'selector-records.read-record', 'G_BINDS_SELECTOR');
  for (const [name, resource] of [
    ['mail.read', 'inbox'],
    ['mail.send', 'outbox'],
  ]) {
    if (name === 'mail.read' && !readsMail) continue;
    node(`binding-${name}`, 'GuardResourceBinding', {
      binding_id: `binding-${name}`,
      tool: name,
      resource_ref: resource,
      sensitivity: 'internal',
    });
    edge(`binding-${name}`, `selector-${name}-${resource}`, 'G_BINDS_SELECTOR');
  }
  const current = {
    id: 'current',
    snapshotId: 'snapshot',
    generatedAt: new Date(now).toISOString(),
    status: 'published',
    nodes,
    edges,
    coverage: {},
  };
  return { id: 'source', sourceId: 'source', tenantId: 'tenant', profile: 'host', current, previous: null };
}
const service = source => new MapService({ read: async () => ({ sources: [source] }) }, { clock: () => now });
async function flag(options) {
  const response = await service(build(options)).query(scope, 'get_agent_access', {
    sourceId: 'source',
    agentId: 'agent',
  });
  return JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
}

test('all three legs with an allow-mode sender is exposed, with evidence per leg', async () => {
  const result = await flag();
  assert.equal(result.status, 'exposed');
  assert.deepEqual(result.legs, { privateData: 'present', outsideContent: 'present', externalSend: 'present' });
  const reasons = result.evidence.map(item => `${item.leg}:${item.reason}`);
  assert.ok(reasons.includes('privateData:binding_restricted'));
  assert.ok(reasons.includes('outsideContent:tool_reads_untrusted'));
  assert.ok(reasons.includes('externalSend:tool_sends_external'));
  assert.equal(result.evidence.find(item => item.leg === 'privateData').resourceBindingId, 'e:binding-record');
  assert.equal(result.evidenceKind, 'declared');
  assert.match(result.limitations[0], /not proof that data can leave/);
});

test('switching the sender to require_approval or deny makes it mitigated', async () => {
  for (const mode of ['require_approval', 'deny']) {
    const result = await flag({ sendMode: mode });
    assert.equal(result.status, 'mitigated', mode);
    assert.ok(result.evidence.some(item => item.leg === 'mitigation' && item.tool === 'mail.send'));
  }
  assert.equal((await flag({ defaultMode: 'require_approval' })).status, 'mitigated', 'the executor default applies');
});

test('private data: present, absent and unknown', async () => {
  assert.equal((await flag({ sensitivity: 'confidential' })).legs.privateData, 'present');
  assert.equal((await flag({ sensitivity: 'internal' })).legs.privateData, 'absent');
  const absent = await flag({ sensitivity: 'public' });
  assert.equal(absent.status, 'absent');
  assert.equal((await flag({ sensitivity: 'unknown' })).legs.privateData, 'unknown');
  assert.equal((await flag({ sensitivity: null })).legs.privateData, 'unknown', 'a v1 binding has no sensitivity');
  assert.equal((await flag({ sensitivity: 'public', task: { sensitive: true } })).legs.privateData, 'present');
});

test('a * grant counts every visible binding of that tool', async () => {
  assert.equal((await flag({ wildcard: true })).legs.privateData, 'present');
  assert.equal(
    (await flag({ wildcard: true, sensitivity: 'public' })).legs.privateData,
    'unknown',
    '* also covers resources the host never described',
  );
});

test('outside content: present, absent and unknown; a v1 inventory is never absent', async () => {
  assert.equal((await flag({ readsMail: false })).legs.outsideContent, 'absent');
  assert.equal((await flag({ readsMail: false, task: { untrusted: true } })).legs.outsideContent, 'present');
  assert.equal((await flag({ readsMail: false, unregistered: 'records.read' })).legs.outsideContent, 'unknown');
  const v1 = await flag({ v2: false });
  assert.equal(v1.legs.outsideContent, 'unknown');
  assert.notEqual(v1.status, 'absent');
});

test('external send: undeclared is unknown, recipients follow every ancestor', async () => {
  assert.equal((await flag({ sendDeclared: false })).legs.externalSend, 'unknown');
  assert.equal((await flag({ task: { allowed_recipients: [] } })).legs.externalSend, 'absent');
  const intersected = await flag({ parent: { allowed_recipients: [] } });
  assert.equal(intersected.legs.externalSend, 'absent', 'a parent with no recipients removes the leg');
  assert.ok(intersected.evidence.some(item => item.reason === 'no_effective_recipients'));
  assert.equal((await flag({ parent: { allowed_recipients: ['partner'] } })).status, 'exposed');
  const hidden = await flag({ parent: { allowed_recipients: ['partner'] }, parentVisible: false });
  assert.equal(hidden.legs.externalSend, 'unknown', 'an ancestor outside the read is unknown');
  assert.ok(hidden.notes.includes('ancestor_evidence_outside_visible_scope'));
  assert.equal(
    (await flag({ task: { delegated: undefined } })).legs.externalSend,
    'unknown',
    'an older import cannot say whether a parent exists',
  );
});

test('an undeclared readsUntrusted stays unknown even when other tools are labelled', async () => {
  const result = await flag({ readsMail: false, recordsUndeclared: true });
  assert.equal(result.legs.outsideContent, 'unknown', 'a resolver may still mark its calls untrusted');
  assert.notEqual(result.status, 'absent');
});

test('a sensitive task cannot send declared external calls', async () => {
  const result = await flag({ task: { sensitive: true } });
  assert.equal(result.legs.externalSend, 'absent');
  assert.ok(result.evidence.some(item => item.reason === 'sensitive_egress_denied' && item.tool === 'mail.send'));
  const undeclared = await flag({ task: { sensitive: true }, sendDeclared: false });
  assert.equal(undeclared.legs.externalSend, 'unknown', 'an unmarked send is not stopped');
});

test('legs and evidence describe the same task', async () => {
  const result = await flag({ parent: { allowed_recipients: ['partner'] } });
  assert.ok(result.taskId);
  assert.ok(result.evidence.every(item => item.taskId === result.taskId));
  assert.equal(result.evidenceTruncated, false);
});

test('an older import without delegation data gets its own note, not a scope note', async () => {
  const result = await flag({ task: { delegated: undefined } });
  assert.deepEqual(result.notes, ['delegation_not_recorded']);
});

test('a v1 core lifted by a v3 manifest never reads as absent', async () => {
  const lifted = await flag({ lifted: true, readsMail: false });
  assert.equal(lifted.legs.outsideContent, 'unknown');
  assert.notEqual(lifted.status, 'absent');
  assert.equal((await flag({ readsMail: false })).legs.outsideContent, 'absent', 'v2 reports the default');
});

test('empty recipients stop only declared external sends', async () => {
  const declared = await flag({ task: { allowed_recipients: [] } });
  assert.equal(declared.legs.externalSend, 'absent');
  const undeclared = await flag({ sendDeclared: false, task: { allowed_recipients: [] } });
  assert.equal(undeclared.legs.externalSend, 'unknown', 'an undeclared tool may send unmarked');
  assert.notEqual(undeclared.status, 'absent');
  const unregistered = await flag({ unregistered: 'mail.send', task: { allowed_recipients: [] } });
  assert.equal(unregistered.legs.externalSend, 'unknown');
});

test('a chain deeper than 16 ancestors is unknown with its own note, not a scope note', async () => {
  const exact = await flag({ depth: 16 });
  assert.equal(exact.status, 'exposed', '16 ancestors are read in full');
  const deep = await flag({ depth: 17 });
  assert.equal(deep.legs.externalSend, 'unknown');
  assert.deepEqual(deep.notes, ['delegation_depth_exceeded']);
});

test('revoked or expired tasks are ignored; an agent with none live is unknown with a note', async () => {
  for (const task of [{ revoked: true }, { deadline: now - 1 }]) {
    const result = await flag({ task });
    assert.deepEqual([result.status, result.liveTasks, result.notes], ['unknown', 0, ['no_live_tasks']]);
  }
  const parentRevoked = await flag({ parent: { revoked: true } });
  assert.equal(parentRevoked.liveTasks, 0, 'a revoked ancestor stops the child too');
});

test('list_agents reports the same status and filters by flag', async () => {
  const run = async (options, args) =>
    (await service(build(options)).query(scope, 'list_agents', args)).data.agents.map(agent => [
      agent.agentId,
      agent.boundaryFlags?.dangerousThree,
    ]);
  assert.deepEqual(await run({}, {}), [['agent', undefined]], 'the plain index does not compute flags');
  assert.deepEqual(await run({}, { includeFlags: true }), [['agent', 'exposed']]);
  assert.deepEqual(await run({}, { flag: 'dangerous_three' }), [['agent', 'exposed']]);
  assert.deepEqual(await run({ sensitivity: 'public' }, { flag: 'dangerous_three' }), [], 'absent is not listed');
  assert.deepEqual(await run({ sensitivity: 'public' }, { flagStatus: 'absent' }), [['agent', 'absent']]);
  assert.deepEqual(await run({ sendMode: 'deny' }, { flagStatus: 'exposed' }), []);
  await assert.rejects(service(build()).query(scope, 'list_agents', { includeFlags: 'yes' }), {
    code: 'MAP_REQUEST_INVALID',
  });
  await assert.rejects(
    service(build()).query(scope, 'list_agents', { flag: 'dangerous_three', flagStatus: 'absent' }),
    { code: 'MAP_REQUEST_INVALID' },
    'flag lists flagged agents only',
  );
});

test('list_agents asks the store for a flags read only when flags are requested', async () => {
  const requests = [];
  const map = new MapService(
    {
      read: async (_scope, request) => {
        requests.push(request);
        return { sources: [build()] };
      },
    },
    { clock: () => now },
  );
  await map.query(scope, 'list_agents', {});
  await map.query(scope, 'list_agents', { includeFlags: true });
  await map.query(scope, 'list_agents', { flag: 'dangerous_three' });
  await map.query(scope, 'list_resources', {});
  assert.deepEqual(plain(requests), [
    { summary: true },
    { summary: true },
    { flags: true, agentIds: ['e:agent'] },
    { flags: true },
    // A listing shows no policy evidence, so it asks the store for none.
    { outsideGuard: true, policy: false },
  ]);
  // Showing flags reads only the page's agents; filtering by flag needs the whole index.
});

test('an unknown task outranks a mitigated one for the agent status', async () => {
  const source = build({ sendMode: 'require_approval' });
  const { nodes, edges } = source.current;
  // A second live task whose only sender does not declare sendsExternal.
  const add = (id, label, properties) =>
    nodes.push({ id: `n:${id}`, entityId: `e:${id}`, sourceId: 'source', projectionId: 'current', label, properties });
  add('tool-other', 'GuardTool', {
    name: 'other.send',
    registered: true,
    known_metadata: true,
    reads_untrusted: true,
    untrusted_context_default: 'allow',
  });
  add('task-2', 'GuardTask', {
    task_id: 'task-2',
    revoked: false,
    sensitive: true,
    deadline: now + 60_000,
    allowed_recipients: ['partner'],
    delegated: false,
    derived: false,
    untrusted: false,
  });
  add('grant-2', 'GuardGrant', { task_id: 'task-2', tool: 'other.send', resources: ['x'] });
  edges.push(
    { source: 'n:task-2', target: 'n:deployment', kind: 'G_ASSIGNED_TO' },
    { source: 'n:task-2', target: 'n:grant-2', kind: 'G_HAS_GRANT' },
    { source: 'n:grant-2', target: 'n:tool-other', kind: 'G_FOR_TOOL' },
  );
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
  assert.equal(result.status, 'unknown');
  assert.equal(result.taskId, 'e:task-2');
});

test('a granted resource without a selector in the read is unknown, not absent', async () => {
  const source = build({ sensitivity: 'public' });
  // The records grant names a second resource whose selector is missing from the read.
  const grant = source.current.nodes.find(item => item.id === 'n:grant-records.read');
  grant.properties.resources = ['record', 'orphan'];
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  assert.equal(response.data.boundaryFlags[0].legs.privateData, 'unknown');
});

test('a page flags read that is too large leaves the listing intact with unknown flags', async () => {
  const map = new MapService(
    {
      read: async (_scope, request) => {
        if (request.agentIds) {
          const error = new Error('MAP_LIMIT_EXCEEDED');
          error.code = 'MAP_LIMIT_EXCEEDED';
          Object.setPrototypeOf(error, (await import('../dist/types.js')).MapQueryError.prototype);
          throw error;
        }
        return { sources: [build()] };
      },
    },
    { clock: () => now },
  );
  const response = await map.query(scope, 'list_agents', { includeFlags: true });
  assert.deepEqual(
    response.data.agents.map(agent => [agent.agentId, agent.boundaryFlags.dangerousThree]),
    [['agent', 'unknown']],
  );
  assert.equal(response.data.flagsUnavailable, 'flags_limit_exceeded');
});

test('page flags that run out of time leave the listing intact with unknown flags', async () => {
  const map = new MapService(
    {
      read: async (_scope, request) => {
        if (request.agentIds) await new Promise(resolve => setTimeout(resolve, 400));
        return { sources: [build()] };
      },
    },
    { clock: () => now, queryTimeoutMs: 200 },
  );
  const response = await map.query(scope, 'list_agents', { includeFlags: true });
  assert.deepEqual(
    response.data.agents.map(agent => agent.boundaryFlags.dangerousThree),
    ['unknown'],
  );
  assert.equal(response.data.flagsUnavailable, 'flags_timeout');
});

test('ancestors left out for size get their own note, for every reader', async () => {
  for (const reader of [scope, { ...scope, allTeams: true }]) {
    const source = build({ parent: { allowed_recipients: ['partner'] }, parentVisible: false });
    source.current.ancestorsNotLoaded = true;
    const response = await service(source).query(reader, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
    const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
    assert.deepEqual(result.notes, ['delegation_ancestors_not_loaded']);
    assert.equal(result.legs.externalSend, 'unknown');
  }
});

test('a task whose chain is read only in part is never absent', async () => {
  // Absent on its own legs (a sensitive task cannot send), but its parent was not read.
  for (const ancestorsNotLoaded of [true, false]) {
    const source = build({ task: { sensitive: true }, parent: { revoked: true }, parentVisible: false });
    if (ancestorsNotLoaded) source.current.ancestorsNotLoaded = true;
    const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
    assert.equal(response.data.boundaryFlags[0].status, 'unknown');
  }
  const visible = await flag({ task: { sensitive: true }, parent: { revoked: true } });
  assert.deepEqual([visible.status, visible.notes], ['unknown', ['no_live_tasks']], 'the full chain shows it is dead');
  const live = await flag({ task: { sensitive: true }, parent: { allowed_recipients: ['partner'] } });
  assert.equal(live.status, 'absent', 'a fully read chain can still be absent');
});

test('a task with two delegation parents is ambiguous, never absent', async () => {
  const source = build({ task: { sensitive: true }, parent: { revoked: true } });
  // A second parent edge for the same task: malformed.
  source.current.nodes.push({
    id: 'n:other-parent',
    entityId: 'e:other-parent',
    sourceId: 'source',
    projectionId: 'current',
    label: 'GuardTask',
    properties: {
      task_id: 'other',
      revoked: false,
      deadline: now + 60_000,
      delegated: false,
      derived: false,
      allowed_recipients: [],
    },
  });
  source.current.edges.push({ source: 'n:task', target: 'n:other-parent', kind: 'G_DELEGATED_FROM' });
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
  assert.equal(result.status, 'unknown');
  assert.ok(result.notes.includes('delegation_evidence_ambiguous'));
});

test('an all-teams reader is told when a parent is missing from the read', async () => {
  const source = build({ parent: { allowed_recipients: ['partner'] }, parentVisible: false });
  const response = await service(source).query({ ...scope, allTeams: true }, 'get_agent_access', {
    sourceId: 'source',
    agentId: 'agent',
  });
  assert.deepEqual(JSON.parse(JSON.stringify(response.data.boundaryFlags[0].notes)), ['delegation_parent_missing']);
});

test('a revoked handoff source makes the task dead; a hidden one leaves it unknown', async () => {
  const withSource = (sourceProperties, visible) => {
    const source = build({ task: { derived: true } });
    if (visible) {
      source.current.nodes.push({
        id: 'n:handoff',
        entityId: 'e:handoff',
        sourceId: 'source',
        projectionId: 'current',
        label: 'GuardTask',
        properties: {
          task_id: 'handoff',
          deadline: now + 60_000,
          delegated: false,
          derived: false,
          ...sourceProperties,
        },
      });
      source.current.edges.push({ source: 'n:task', target: 'n:handoff', kind: 'G_DERIVED_FROM' });
    }
    return service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  };
  const dead = JSON.parse(JSON.stringify((await withSource({ revoked: true }, true)).data.boundaryFlags[0]));
  assert.deepEqual([dead.status, dead.notes], ['unknown', ['no_live_tasks']]);
  const live = JSON.parse(JSON.stringify((await withSource({ revoked: false }, true)).data.boundaryFlags[0]));
  assert.equal(live.status, 'exposed', 'a live source keeps the task live');
  const hidden = JSON.parse(JSON.stringify((await withSource({}, false)).data.boundaryFlags[0]));
  assert.equal(hidden.status, 'unknown');
  assert.ok(hidden.notes.includes('ancestor_evidence_outside_visible_scope'));
});

test('an expired handoff source does not stop the task; an expired delegation parent does', async () => {
  // The executor checks deadlines along delegation parents only; a handoff may outlive its source.
  const source = build({ task: { derived: true } });
  source.current.nodes.push({
    id: 'n:handoff',
    entityId: 'e:handoff',
    sourceId: 'source',
    projectionId: 'current',
    label: 'GuardTask',
    properties: { task_id: 'handoff', revoked: false, deadline: now - 1000, delegated: false, derived: false },
  });
  source.current.edges.push({ source: 'n:task', target: 'n:handoff', kind: 'G_DERIVED_FROM' });
  const handoff = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  assert.equal(handoff.data.boundaryFlags[0].status, 'exposed');
  const parent = await flag({ parent: { allowed_recipients: ['partner'], deadline: now - 1000 } });
  assert.deepEqual([parent.status, parent.liveTasks], ['unknown', 0]);
});

test('a chain cut at 16 hops gets the depth note whether or not the 17th task was read', async () => {
  const full = await flag({ depth: 17 });
  // The store's ancestor read stops at 16 hops: the 17th task is not in a one-agent read.
  const cut = build({ depth: 17 });
  cut.current.nodes = cut.current.nodes.filter(item => item.id !== 'n:ancestor-17');
  cut.current.edges = cut.current.edges.filter(edge => edge.target !== 'n:ancestor-17');
  for (const reader of [scope, { ...scope, allTeams: true }]) {
    const response = await service(cut).query(reader, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
    const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
    assert.deepEqual(result.notes, full.notes);
    assert.deepEqual(result.notes, ['delegation_depth_exceeded']);
  }
});

test('a lineage too large to evaluate degrades the flag, not get_agent_access', async () => {
  // 1,200 tasks, each delegated from the previous one and handed off from the one before.
  const source = build();
  const { nodes, edges } = source.current;
  for (let index = 0; index < 1200; index++) {
    nodes.push({
      id: `n:chain-${index}`,
      entityId: `e:chain-${index}`,
      sourceId: 'source',
      projectionId: 'current',
      label: 'GuardTask',
      properties: {
        task_id: `chain-${index}`,
        revoked: false,
        deadline: now + 60_000,
        delegated: index > 0,
        derived: index > 1,
        allowed_recipients: ['partner'],
      },
    });
    edges.push({ source: `n:chain-${index}`, target: 'n:deployment', kind: 'G_ASSIGNED_TO' });
    if (index > 0) edges.push({ source: `n:chain-${index}`, target: `n:chain-${index - 1}`, kind: 'G_DELEGATED_FROM' });
    if (index > 1) edges.push({ source: `n:chain-${index}`, target: `n:chain-${index - 2}`, kind: 'G_DERIVED_FROM' });
  }
  const map = new MapService(
    { read: async () => ({ sources: [source] }) },
    { clock: () => now, maxGraphNodes: 2000, maxGraphEdges: 5000 },
  );
  const response = await map.query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
  assert.equal(result.status, 'unknown');
  assert.deepEqual(result.notes, ['flags_limit_exceeded']);
  assert.ok(response.data.tasks.length > 1000, 'the rest of the response still answers');
});

test('a diamond read in full within 16 links is not a depth cut', async () => {
  // The task is delegated from Y and handed off along 16 sources, the last delegated from Y.
  const source = build({ task: { derived: true, delegated: true } });
  const { nodes, edges } = source.current;
  const add = (key, properties) =>
    nodes.push({
      id: `n:${key}`,
      entityId: `e:${key}`,
      sourceId: 'source',
      projectionId: 'current',
      label: 'GuardTask',
      properties: {
        task_id: key,
        revoked: false,
        deadline: now + 60_000,
        allowed_recipients: ['partner'],
        ...properties,
      },
    });
  add('y', { delegated: false, derived: false });
  edges.push({ source: 'n:task', target: 'n:y', kind: 'G_DELEGATED_FROM' });
  for (let level = 1; level <= 16; level++) {
    add(`s${level}`, { delegated: level === 16, derived: level < 16 });
    edges.push({ source: level === 1 ? 'n:task' : `n:s${level - 1}`, target: `n:s${level}`, kind: 'G_DERIVED_FROM' });
  }
  edges.push({ source: 'n:s16', target: 'n:y', kind: 'G_DELEGATED_FROM' });
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
  assert.equal(result.notes.includes('delegation_depth_exceeded'), false);
  assert.equal(result.status, 'exposed');
});

test("a task's own revocation stands even when its links are malformed", async () => {
  const source = build({ task: { revoked: true }, parent: { allowed_recipients: ['partner'] } });
  source.current.nodes.push({
    id: 'n:other-parent',
    entityId: 'e:other-parent',
    sourceId: 'source',
    projectionId: 'current',
    label: 'GuardTask',
    properties: { task_id: 'other', revoked: false, deadline: now + 60_000, delegated: false, derived: false },
  });
  source.current.edges.push({ source: 'n:task', target: 'n:other-parent', kind: 'G_DELEGATED_FROM' });
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  assert.equal(response.data.boundaryFlags[0].liveTasks, 0);
});

test('a tool named like an Object.prototype member reads as any other tool', async () => {
  for (const name of ['constructor', '__proto__', 'toString']) {
    const source = build();
    const { nodes, edges } = source.current;
    nodes.push(
      {
        id: 'n:tool-odd',
        entityId: 'e:tool-odd',
        sourceId: 'source',
        projectionId: 'current',
        label: 'GuardTool',
        properties: { name, registered: true, known_metadata: true, reads_untrusted: false, sends_external: false },
      },
      {
        id: 'n:grant-odd',
        entityId: 'e:grant-odd',
        sourceId: 'source',
        projectionId: 'current',
        label: 'GuardGrant',
        properties: { task_id: 'task', tool: name, resources: ['*'] },
      },
    );
    edges.push(
      { source: 'n:task', target: 'n:grant-odd', kind: 'G_HAS_GRANT' },
      { source: 'n:grant-odd', target: 'n:tool-odd', kind: 'G_FOR_TOOL' },
    );
    // A host-written store may hand back a plain object for the wildcard answers.
    source.current.wildcardSensitivity = {};
    const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
    assert.equal(response.data.boundaryFlags[0].status, 'exposed', name);
  }
});

test('contradictory flag arguments are refused before any read', async () => {
  let reads = 0;
  const map = new MapService(
    {
      read: async () => {
        reads++;
        return { sources: [build()] };
      },
    },
    { clock: () => now },
  );
  await assert.rejects(map.query(scope, 'list_agents', { flag: 'dangerous_three', flagStatus: 'absent' }), {
    code: 'MAP_REQUEST_INVALID',
  });
  assert.equal(reads, 0);
});

test('a store that refuses the page flags read leaves the listing intact', async () => {
  const { MapQueryError } = await import('../dist/types.js');
  const map = new MapService(
    {
      read: async (_scope, request) => {
        if (request.agentIds) throw new MapQueryError('MAP_REQUEST_INVALID');
        return { sources: [build()] };
      },
    },
    { clock: () => now },
  );
  const response = await map.query(scope, 'list_agents', { includeFlags: true });
  assert.deepEqual(
    response.data.agents.map(agent => agent.boundaryFlags.dangerousThree),
    ['unknown'],
  );
  assert.equal(response.data.flagsUnavailable, 'flags_read_unavailable');
});

test('a task without revocation or expiry facts, or a snapshot without a time, is never absent', async () => {
  for (const task of [{ revoked: undefined }, { deadline: undefined }]) {
    const result = await flag({ sensitivity: 'public', task });
    assert.equal(result.status, 'unknown', JSON.stringify(task));
    assert.ok(result.notes.includes('task_liveness_unverified'));
  }
  assert.equal((await flag({ sensitivity: 'public' })).status, 'absent', 'known facts can still be absent');
  const source = build({ sensitivity: 'public', task: { deadline: now - 1 } });
  source.current.generatedAt = 'not a time';
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  assert.equal(response.data.boundaryFlags[0].status, 'unknown');
});

test('every present leg keeps evidence when one leg has more than the cap', async () => {
  // 30 restricted bindings on one task: private-data evidence alone would fill any flat cap.
  const source = build({ sendMode: 'require_approval' });
  const { nodes, edges } = source.current;
  const grant = nodes.find(item => item.id === 'n:grant-records.read');
  for (let index = 0; index < 30; index++) {
    const resource = `bulk-${index}`;
    grant.properties.resources = [...grant.properties.resources, resource];
    nodes.push(
      {
        id: `n:selector-bulk-${index}`,
        entityId: `e:selector-bulk-${index}`,
        sourceId: 'source',
        projectionId: 'current',
        label: 'GuardResource',
        properties: { resource_id: resource, tool: 'records.read' },
      },
      {
        id: `n:binding-bulk-${index}`,
        entityId: `e:binding-bulk-${index}`,
        sourceId: 'source',
        projectionId: 'current',
        label: 'GuardResourceBinding',
        properties: { binding_id: resource, tool: 'records.read', resource_ref: resource, sensitivity: 'restricted' },
      },
    );
    edges.push(
      { source: 'n:grant-records.read', target: `n:selector-bulk-${index}`, kind: 'G_TARGETS' },
      { source: `n:binding-bulk-${index}`, target: `n:selector-bulk-${index}`, kind: 'G_BINDS_SELECTOR' },
    );
  }
  const response = await service(source).query(scope, 'get_agent_access', { sourceId: 'source', agentId: 'agent' });
  const result = JSON.parse(JSON.stringify(response.data.boundaryFlags[0]));
  assert.equal(result.status, 'mitigated');
  const count = leg => result.evidence.filter(item => item.leg === leg).length;
  assert.equal(count('privateData'), 8, 'capped per leg');
  assert.ok(count('outsideContent') >= 1 && count('externalSend') >= 1 && count('mitigation') >= 1);
  assert.equal(result.evidenceTruncated, true);
  assert.equal((await flag()).evidenceTruncated, false);
});
