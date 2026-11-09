// Explicit browser-only demonstration. These values are never presented as live inventory.
const sourceId = 'a'.repeat(64);
const capturedAt = Date.now();
const readTool = 'mcp:documents:read';
const selector = 'opaque:' + 'd'.repeat(64);
const reportArn = 'arn:aws:s3:::company-reports/quarterly/summary.pdf';
const readAction = 's3:GetObject';
const capture = (status, ageSeconds, stale) => ({
  status,
  observedAt: new Date(capturedAt - ageSeconds * 1000).toISOString(),
  ageSeconds,
  stale,
});
const sources = [
  {
    id: sourceId,
    sourceId,
    tenantId: 'acme-research',
    profile: 'host-mcp',
    generatedAt: new Date(capturedAt - 120_000).toISOString(),
    snapshotId: 'demo-current',
    projectionId: 'b'.repeat(64),
    stale: false,
    coverage: {
      tasks: capture('complete', 120, false),
      tools: capture('complete', 120, false),
      manifest: capture('complete', 420, false),
      mcp: capture('partial', 1800, true),
      cloud: capture('complete', 300, false),
      policy: capture('partial', 300, false),
    },
  },
];
const agents = [
  {
    id: 'agent-research',
    agentId: 'research-assistant',
    sourceId,
    name: 'Research assistant',
    ownerId: 'alex.chen',
    teamId: 'Research',
    environments: ['production'],
    deployments: [{ id: 'deployment-research', deploymentId: 'research-eu-1', environment: 'production' }],
  },
  {
    id: 'agent-release',
    agentId: 'release-assistant',
    sourceId,
    name: 'Release assistant',
    ownerId: 'sam.rivera',
    teamId: 'Platform',
    environments: ['staging'],
    deployments: [{ id: 'deployment-release', deploymentId: 'release-staging', environment: 'staging' }],
  },
  {
    id: 'agent-finance',
    agentId: 'finance-reviewer',
    sourceId,
    name: 'Finance reviewer',
    ownerId: 'morgan.lee',
    teamId: 'Finance',
    environments: ['production'],
    deployments: [{ id: 'deployment-finance', deploymentId: 'finance-us-1', environment: 'production' }],
  },
];
const owners = [
  {
    id: 'owner-alex',
    ownerId: 'alex.chen',
    name: 'Alex Chen',
    kind: 'person',
    sourceId,
    agentCount: 1,
    resourceCount: 1,
  },
  {
    id: 'owner-sam',
    ownerId: 'sam.rivera',
    name: 'Platform team',
    kind: 'team',
    sourceId,
    agentCount: 1,
    resourceCount: 0,
  },
];
for (const agent of agents)
  Object.assign(agent, {
    purpose: `Help ${agent.teamId.toLowerCase()} with scoped records`,
    lifecycleState: 'active',
    ownershipStatus: agent.id === 'agent-finance' ? 'unknown' : 'assigned',
    ownershipSource: agent.id === 'agent-finance' ? null : 'Company service catalog',
    ownerName: owners.find(owner => owner.ownerId === agent.ownerId)?.name ?? null,
    ownerId: agent.id === 'agent-finance' ? null : agent.ownerId,
    authorityId: 'company-catalog',
    ownershipObservedAt: sources[0].coverage.manifest.observedAt,
  });
const resources = [
  {
    id: 'resource-binding',
    bindingId: 'reports-object',
    sourceId,
    displayName: 'Quarterly report',
    tool: readTool,
    resourceRef: selector,
    scope: 'exact',
    actions: [readAction],
    ownerId: 'alex.chen',
    ownerName: 'Alex Chen',
    ownershipStatus: 'assigned',
    ownershipSource: 'Company service catalog',
    sensitivity: 'confidential',
    approvedDestinations: [],
    targets: [{ id: 'external-resource', provider: 'aws', arn: reportArn, kind: 'object' }],
    dependencies: [],
    authorityId: 'company-catalog',
    observedAt: sources[0].coverage.manifest.observedAt,
  },
];
const credential = {
  id: 'credential',
  credentialId: 'opaque:' + 'e'.repeat(64),
  name: 'Documents service identity',
  issuerRef: 'opaque:' + 'f'.repeat(64),
  audienceRefs: ['opaque:' + '1'.repeat(64)],
  recipientRefs: ['opaque:' + '2'.repeat(64)],
  lifecycleState: 'rotating',
  rotationStatus: 'due',
  expiresAt: new Date(capturedAt + 86_400_000).toISOString(),
  authorityId: 'company-catalog',
  observedAt: sources[0].coverage.manifest.observedAt,
};
const collection = {
  approvals: 'not_collected',
  requestTimeDecisions: 'not_collected',
  backendReceipts: 'not_collected',
  externalPolicyHistory: 'not_collected',
};
function paged(items, args) {
  const offset = args.offset ?? 0,
    limit = args.limit ?? 20;
  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    offset,
    limit,
    truncated: offset + limit < items.length,
  };
}
function access(agent) {
  const taskId = `${agent.agentId}-task`;
  const tool = readTool,
    resource = selector;
  const node = (id, label, properties) => ({ id, entityId: id, label, properties });
  const nodes = [
    node(agent.id, 'GuardAgent', {
      agent_id: agent.agentId,
      name: agent.name,
      team_id: agent.teamId,
      owner_id: agent.ownerId,
      purpose: agent.purpose,
      lifecycle_state: agent.lifecycleState,
      ownership_status: agent.ownershipStatus,
      ownership_source: agent.ownershipSource,
      authority_id: agent.authorityId,
      manifest_schema_version: 2,
    }),
    node('deployment', 'GuardDeployment', {
      deployment_id: agent.deployments[0].deploymentId,
      environment: agent.environments[0],
    }),
    node('task', 'GuardTask', {
      task_id: taskId,
      principal_id: 'application',
      revoked: false,
      calls: 12,
      max_calls: 100,
    }),
    node('grant', 'GuardGrant', {
      task_id: taskId,
      tool,
      resources: [resource],
      assessment: 'unknown',
      evidence_kind: 'declared',
    }),
    node('tool', 'GuardTool', { name: tool, registered: true, approved: true, requires_approval: false }),
    node('resource', 'GuardResource', { resource_id: resource, tool, selector_kind: 'exact' }),
    node('connection', 'GuardMcpConnection', {
      connection_id: 'documents-eu',
      state: 'ready',
      metadata_state: 'current',
      metadata_revision: 3,
    }),
    node('operation', 'GuardMcpOperation', { name: tool, kind: 'tool', assessment: 'unknown' }),
    node('binding', 'GuardExecutionBinding', {
      binding_id: 'documents-reader',
      tool,
      identity_selection: 'static',
      evidence_kind: 'host_asserted',
    }),
    node('identity', 'GuardExternalIdentity', {
      arn: `arn:aws:iam::111122223333:role/${agent.agentId}`,
      cloud_status: 'resolved',
      assessment: 'unknown',
    }),
    node('resource-binding', 'GuardResourceBinding', {
      binding_id: 'reports-object',
      tool,
      resource_ref: resource,
      actions: [readAction],
      scope: 'exact',
      evidence_kind: 'host_asserted',
      assessment: 'unknown',
    }),
    node('external-resource', 'GuardExternalResource', {
      arn: reportArn,
      kind: 'object',
      cloud_status: 'resolved',
      cloud_match_kind: 'containment',
      assessment: 'unknown',
    }),
  ];
  const edges = [
    ['deployment', agent.id, 'G_INSTANCE_OF'],
    ['task', 'deployment', 'G_ASSIGNED_TO'],
    ['task', 'grant', 'G_HAS_GRANT'],
    ['grant', 'tool', 'G_FOR_TOOL'],
    ['grant', 'resource', 'G_TARGETS'],
    ['binding', 'deployment', 'G_EXECUTES_FOR'],
    ['binding', 'tool', 'G_EXECUTES_TOOL'],
    ['binding', 'connection', 'G_VIA_CONNECTION'],
    ['connection', 'operation', 'G_EXPOSES_OPERATION'],
    ['operation', 'tool', 'G_OPERATION_TOOL'],
    ['binding', 'identity', 'G_USES_IDENTITY'],
    ['resource-binding', 'resource', 'G_BINDS_SELECTOR'],
    ['resource-binding', 'external-resource', 'G_MAPS_TO'],
  ].map(([source, target, kind]) => ({ source, target, kind }));
  const policyEvidence = [
    {
      taskId: 'task',
      deploymentId: 'deployment',
      executionBindingId: 'binding',
      resourceBindingId: 'resource-binding',
      identityId: 'identity',
      resourceId: 'external-resource',
      action: readAction,
      status: agent.id === 'agent-finance' ? 'unavailable' : 'complete',
      reason:
        agent.id === 'agent-finance' ? 'boundary_unresolved' : agent.id === 'agent-release' ? 'no_candidate' : null,
      observedAt: sources[0].coverage.policy.observedAt,
      assessment: 'unknown',
      candidates:
        agent.id === 'agent-research'
          ? [
              {
                relationship: 'CAN_READ',
                hasCondition: true,
                conditionKeys: ['aws:PrincipalTag/team', 'aws:SecureTransport'],
                resourceScope: 'bucket_summary',
              },
            ]
          : [],
    },
  ];
  return {
    data: {
      agent,
      deployments: agent.deployments,
      tasks: [
        {
          id: 'task',
          taskId,
          principalId: 'application',
          revoked: false,
          sensitive: false,
          usage: { calls: 12, concurrent: 0, spent: 0, reserved: 0 },
          budget: { maxCalls: 100, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 3_600_000 },
        },
      ],
      grants: [{ id: 'grant', taskId, tool, resources: [resource], evidenceKind: 'declared' }],
      connections: [nodes[6]],
      bindings: [nodes[8], nodes[10]],
      policyEvidence,
      receipt: sources[0],
      assessment: 'unknown',
      limitations: [
        'A declared grant is evidence, not an execution decision.',
        'Live policy, arguments and backend authorization still apply.',
      ],
    },
    graph: { nodes, edges },
  };
}
export async function queryDemo(operation, args = {}) {
  let result;
  if (operation === 'list_agents') {
    const filtered = agents.filter(
      agent =>
        (!args.search || `${agent.name} ${agent.agentId}`.toLowerCase().includes(args.search.toLowerCase())) &&
        (!args.ownerId || agent.ownerId === args.ownerId) &&
        (!args.environment || agent.environments.includes(args.environment)),
    );
    const page = paged(
      filtered.filter(
        agent =>
          (!args.sourceId || args.sourceId === sourceId) &&
          (!args.ownershipStatus || agent.ownershipStatus === args.ownershipStatus) &&
          (!args.lifecycleState || agent.lifecycleState === args.lifecycleState),
      ),
      args,
    );
    result = { data: { ...page, agents: page.items } };
  } else if (operation === 'list_owners') {
    const page = paged(
      owners.filter(
        x =>
          (!args.sourceId || x.sourceId === args.sourceId) &&
          (!args.search || `${x.name} ${x.ownerId}`.toLowerCase().includes(args.search.toLowerCase())) &&
          (!args.kind || x.kind === args.kind),
      ),
      args,
    );
    result = { data: { ...page, owners: page.items } };
  } else if (operation === 'list_resources') {
    const page = paged(
      resources.filter(
        x =>
          (!args.sourceId || x.sourceId === args.sourceId) &&
          (!args.ownerId || x.ownerId === args.ownerId) &&
          (!args.search || x.displayName.toLowerCase().includes(args.search.toLowerCase())) &&
          (!args.sensitivity || x.sensitivity === args.sensitivity),
      ),
      args,
    );
    result = {
      data: {
        ...page,
        resources: page.items,
        resourceCoverage: 'host_bound_resources',
        limitations: ['Unbound declared selectors appear in agent permissions, not this resource index.'],
      },
    };
  } else if (operation === 'get_resource_access') {
    const resource = resources.find(x => x.id === args.resourceId);
    if (!resource || args.sourceId !== sourceId) throw new Error('REFERENCE_NOT_FOUND');
    const page = paged(agents, args);
    result = {
      data: { ...page, resource, agents: page.items, receipt: sources[0], assessment: 'unknown', collection },
    };
  } else if (operation === 'get_agent_inventory') {
    const agent = agents.find(x => x.id === args.agentId || x.agentId === args.agentId);
    if (!agent || args.sourceId !== sourceId) throw new Error('REFERENCE_NOT_FOUND');
    const detail = access(agent);
    const rows = {
      overview: [agent],
      owners: owners.filter(x => x.ownerId === agent.ownerId),
      deployments: agent.deployments.map(x => ({
        ...x,
        runtimeRef: 'opaque:' + '3'.repeat(64),
        buildRef: 'opaque:' + '4'.repeat(64),
        workloadGeneration: '2026.11.06',
        bindingAuthority: 'company-catalog',
      })),
      tasks: detail.data.tasks,
      permissions: detail.data.grants,
      resources,
      connections: detail.graph.nodes
        .filter(x => x.label === 'GuardMcpConnection')
        .map(x => ({ id: x.entityId, ...x.properties })),
      credentials: [credential],
      tools: detail.graph.nodes.filter(x => x.label === 'GuardTool').map(x => ({ id: x.entityId, ...x.properties })),
      bindings: detail.graph.nodes
        .filter(x => ['GuardExecutionBinding', 'GuardResourceBinding'].includes(x.label))
        .map(x => ({ id: x.entityId, kind: x.label, ...x.properties })),
      identities: detail.graph.nodes
        .filter(x => x.label === 'GuardExternalIdentity')
        .map(x => ({ id: x.entityId, ...x.properties })),
      policies: detail.data.policyEvidence,
      relationships: detail.graph.edges.map(edge => {
        const source = detail.graph.nodes.find(x => x.id === edge.source),
          target = detail.graph.nodes.find(x => x.id === edge.target);
        const name = x =>
          x.properties.name ??
          x.properties.agent_id ??
          x.properties.task_id ??
          x.properties.deployment_id ??
          x.properties.binding_id ??
          x.properties.connection_id ??
          x.properties.arn ??
          x.properties.resource_id ??
          x.entityId;
        return {
          ...edge,
          sourceName: name(source),
          sourceLabel: source.label,
          targetName: name(target),
          targetLabel: target.label,
        };
      }),
    };
    const section = args.section ?? 'overview';
    result = {
      data: {
        agent,
        section,
        ...paged(rows[section] ?? [], args),
        counts: Object.fromEntries(Object.entries(rows).map(([k, v]) => [k, v.length])),
        receipt: sources[0],
        assessment: 'unknown',
        graphStatus: 'not_requested',
        policyEvidence: section === 'policies' ? paged(rows.policies, args).items : [],
        collection,
      },
    };
  } else if (operation === 'get_inventory_health') result = { data: { sources } };
  else if (operation === 'get_agent_access') {
    const agent = agents.find(agent => agent.id === args.agentId || agent.agentId === args.agentId);
    if (!agent || (args.sourceId && args.sourceId !== sourceId)) throw new Error('REFERENCE_NOT_FOUND');
    result = access(agent);
  } else if (operation === 'explain_access') {
    const agent = agents.find(item => `${item.agentId}-task` === args.taskId);
    if (!agent || (args.sourceId && args.sourceId !== sourceId)) throw new Error('REFERENCE_NOT_FOUND');
    const { grants, policyEvidence } = access(agent).data;
    const matchedGrants = grants.filter(grant => grant.tool === args.tool && grant.resources.includes(args.resourceId));
    result = {
      data: {
        ...args,
        assessment: matchedGrants.length ? 'unknown' : 'blocked',
        blockers: matchedGrants.length ? [] : ['declared_grant_missing'],
        unknownChecks: [
          'Current custom policy',
          'Resolved request arguments',
          'Backend authorization',
          'Concurrent reservations',
        ],
        delegation: [{ id: 'task', taskId: args.taskId }],
        matchedGrants,
        externalEvidence: { policyEvidence: matchedGrants.length ? policyEvidence : [] },
      },
    };
  } else if (operation === 'find_agents_with_access') {
    const matches =
      (!args.sourceId || args.sourceId === sourceId) &&
      args.action === readAction &&
      [selector, reportArn].includes(args.resourceRef)
        ? agents
        : [];
    const limit = args.limit ?? 50;
    result = {
      data: {
        candidates: matches.slice(0, limit).map(agent => ({
          agent,
          assessment: 'unknown',
          evidence: [{ policyEvidence: access(agent).data.policyEvidence, scope: 'exact' }],
        })),
        truncated: matches.length > limit,
      },
    };
  } else if (operation === 'get_changes') {
    const changes = [
      {
        entityId: 'new-task',
        label: 'GuardTask',
        name: 'research-followup',
        kind: 'added',
        categories: ['permissions'],
        changedFields: ['task_id'],
        before: null,
        after: { properties: { task_id: 'research-followup' }, relationships: [] },
        affectedAgents: [agents[0]],
      },
      {
        entityId: 'agent-research',
        label: 'GuardAgent',
        name: 'Research assistant owner transfer',
        kind: 'changed',
        categories: ['ownership'],
        changedFields: ['owner_id'],
        before: { properties: { owner_id: 'sam.rivera' }, relationships: [] },
        after: { properties: { owner_id: 'alex.chen' }, relationships: [] },
        affectedAgents: [agents[0]],
      },
      {
        entityId: 'connection',
        label: 'GuardMcpConnection',
        name: 'documents-eu',
        kind: 'changed',
        categories: ['bindings'],
        changedFields: ['state'],
        before: { properties: { state: 'ready' }, relationships: [] },
        after: { properties: { state: 'quarantined' }, relationships: [] },
        affectedAgents: [agents[0]],
      },
    ].filter(
      x =>
        (!args.changeKind || args.changeKind === 'all' || x.categories.includes(args.changeKind)) &&
        (!args.agentId || x.affectedAgents.some(a => [a.id, a.agentId].includes(args.agentId))),
    );
    const page = paged(changes, args);
    result = {
      data: {
        ...page,
        sourceId,
        from: { snapshotId: 'demo-previous', generatedAt: new Date(capturedAt - 420_000).toISOString() },
        to: sources[0],
        changes: {
          added: page.items.filter(x => x.kind === 'added'),
          changed: page.items.filter(x => x.kind === 'changed'),
          removed: [],
        },
        details: page.items,
        changeSummaryScope: 'page',
        relationships: { added: [], removed: [] },
        affectedAgents: changes.length ? [agents[0]] : [],
        collection,
        coverageGap: false,
        policyHistory: 'not_collected',
        limitations: ['Snapshot differences show net changes, not an event history.'],
      },
    };
  } else throw new Error('VIEWER_OPERATION_INVALID');
  return structuredClone({ operation, observedAt: new Date().toISOString(), ...result });
}
