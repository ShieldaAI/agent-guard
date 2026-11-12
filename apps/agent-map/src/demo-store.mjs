// The demo's inventory: one synthetic source, held in memory as the nodes and edges a store
// would return. The real MapService reads it, so every demo response is a service response.
// Nothing here is live inventory, and the page says so.

export const DEMO_SOURCE_ID = 'a'.repeat(64);
const PROJECTION_ID = 'b'.repeat(64);
const PREVIOUS_ID = 'c'.repeat(64);
const TENANT = 'acme-research';
const opaque = character => `opaque:${character.repeat(64)}`;

const READ_TOOL = 'mcp:documents:read';
const READ_ACTION = 's3:GetObject';
const REPORT_SELECTOR = opaque('d');
const ARCHIVE_SELECTOR = opaque('9');
const REPORT_ARN = 'arn:aws:s3:::company-reports/quarterly/summary.pdf';
const ARCHIVE_HOST = opaque('7');
const RECIPIENTS = opaque('5');
const ACCOUNT = '111122223333';

// One agent per "dangerous three" status. What differs is the tool each one may send with and
// what its host declared about paths around the guard.
const AGENTS = [
  {
    key: 'research',
    agentId: 'research-assistant',
    name: 'Research assistant',
    team: 'Research',
    owner: { id: 'owner-alex', ownerId: 'alex.chen' },
    environment: 'production',
    deploymentId: 'research-eu-1',
    directAccess: 'found',
    // Declares external sends and allows them with untrusted context: exposed.
    send: { name: 'mcp:mail:send', sends_external: true, untrusted_context: 'allow' },
    untrusted: false,
  },
  {
    key: 'release',
    agentId: 'release-assistant',
    name: 'Release assistant',
    team: 'Platform',
    owner: { id: 'owner-sam', ownerId: 'sam.rivera' },
    environment: 'staging',
    deploymentId: 'release-staging',
    directAccess: 'none_declared',
    // The same kind of send, but approval is required with untrusted context: mitigated.
    send: { name: 'mcp:announce:post', sends_external: true, untrusted_context: 'require_approval' },
    untrusted: false,
  },
  {
    key: 'finance',
    agentId: 'finance-reviewer',
    name: 'Finance reviewer',
    team: 'Finance',
    owner: null,
    environment: 'production',
    deploymentId: 'finance-us-1',
    directAccess: null,
    // The tool never says whether it sends externally: unknown.
    send: { name: 'mcp:ledger:export' },
    untrusted: true,
  },
];

const UNDECLARED_TASKS = [
  {
    id: 'demo-undeclared-export',
    taskId: 'nightly-export',
    principalId: 'batch-scheduler',
    delegated: false,
    derived: false,
    revoked: false,
    parentDeclared: false,
    tools: ['reports.read'],
    toolsTruncated: false,
  },
  {
    id: 'demo-undeclared-followup',
    taskId: 'research-followup-unbound',
    principalId: 'research-application',
    delegated: true,
    derived: false,
    revoked: false,
    parentDeclared: true,
    tools: ['reports.read'],
    toolsTruncated: false,
  },
];
const UNDECLARED_CALLERS = [
  { id: 'demo-undeclared-caller', principalId: 'batch-scheduler', tasks: 1, tasksCapped: false },
];
const CLOUD_ACCOUNT = { tenantId: TENANT, partition: 'aws', accountId: ACCOUNT };
const UNCLAIMED_IDENTITIES = [
  { arn: `arn:aws:iam::${ACCOUNT}:role/service/batch-runner`, kind: 'role', name: 'batch-runner', path: '/service/' },
  { arn: `arn:aws:iam::${ACCOUNT}:user/ci-deployer`, kind: 'user', name: 'ci-deployer', path: '/' },
].map(identity => ({ ...identity, ...CLOUD_ACCOUNT }));

/** The current projection, with every capture time counted back from `now`. */
function currentProjection(now) {
  const at = secondsAgo => new Date(now - secondsAgo * 1000).toISOString();
  const nodes = [],
    edges = [];
  const add = (id, label, properties) =>
    nodes.push({ id, entityId: id, label, sourceId: DEMO_SOURCE_ID, projectionId: PROJECTION_ID, properties });
  const link = (source, target, kind) => edges.push({ source, target, kind });
  const host = {
    evidence_kind: 'host_asserted',
    assessment: 'unknown',
    manifest_id: 'company-catalog-agents',
    manifest_revision: 7,
    manifest_observed_at: at(420),
    authority_id: 'company-catalog',
    manifest_schema_version: 3,
  };
  const cloud = {
    cloud_status: 'resolved',
    cloud_observed_at: at(300),
    cloud_assessment: 'unknown',
  };

  add('owner-alex', 'GuardOwner', { ...host, owner_id: 'alex.chen', name: 'Alex Chen', kind: 'person' });
  add('owner-sam', 'GuardOwner', { ...host, owner_id: 'sam.rivera', name: 'Platform team', kind: 'team' });

  add('tool', 'GuardTool', {
    name: READ_TOOL,
    revision: 3,
    registered: true,
    approved: true,
    known_metadata: true,
    requires_approval: false,
    control_plane: false,
    max_cost: 1,
    reads_untrusted: true,
    sends_external: false,
  });
  add('connection', 'GuardMcpConnection', {
    connection_id: 'documents-eu',
    capture_status: 'observed',
    capture_observed_at: at(300),
    server_id: 'documents',
    transport_ref: opaque('a'),
    state: 'ready',
    metadata_state: 'current',
    observed_at: at(300),
    evidence_kind: 'mcp_observation',
    assessment: 'unknown',
  });
  // The mail server was quarantined after its last capture, half an hour ago: MCP coverage is
  // partial and stale, and the research agent's mail tool has no usable connection evidence.
  add('connection-mail', 'GuardMcpConnection', {
    connection_id: 'mail-eu',
    capture_status: 'unavailable',
    unavailable_reason: 'quarantined',
    capture_observed_at: at(1800),
    server_id: 'mail',
    transport_ref: opaque('b'),
    state: 'quarantined',
    metadata_state: 'stale',
    evidence_kind: 'mcp_observation',
    assessment: 'unknown',
  });
  add('operation', 'GuardMcpOperation', {
    connection_id: 'documents-eu',
    name: READ_TOOL,
    kind: 'tool',
    evidence_kind: 'mcp_observation',
    assessment: 'unknown',
  });
  link('connection', 'operation', 'G_EXPOSES_OPERATION');
  link('operation', 'tool', 'G_OPERATION_TOOL');

  // The report every agent may read through the guard: one S3 object, marked confidential.
  add('resource', 'GuardResource', { resource_id: REPORT_SELECTOR, tool: READ_TOOL, selector_kind: 'exact' });
  add('resource-binding', 'GuardResourceBinding', {
    ...host,
    binding_id: 'reports-object',
    tool: READ_TOOL,
    resource_ref: REPORT_SELECTOR,
    actions: [READ_ACTION],
    scope: 'exact',
    display_name: 'Quarterly report',
    owner_id: 'alex.chen',
    ownership_status: 'assigned',
    ownership_source: 'Company service catalog',
    sensitivity: 'confidential',
    approved_destinations: [],
  });
  add('external-resource', 'GuardExternalResource', {
    ...host,
    ...cloud,
    provider: 'aws',
    partition: 'aws',
    account_id: ACCOUNT,
    arn: REPORT_ARN,
    kind: 'object',
    cloud_match_kind: 'containment',
  });
  link('resource-binding', 'resource', 'G_BINDS_SELECTOR');
  link('resource-binding', 'external-resource', 'G_MAPS_TO');
  link('resource-binding', 'owner-alex', 'G_RESOURCE_OWNED_BY');

  // A host storage resource that only the research agent is granted, and that its worker also
  // reaches with an SDK client the guard never sees.
  add('archive-selector', 'GuardResource', { resource_id: ARCHIVE_SELECTOR, tool: READ_TOOL, selector_kind: 'exact' });
  add('archive-binding', 'GuardResourceBinding', {
    ...host,
    binding_id: 'reports-archive',
    tool: READ_TOOL,
    resource_ref: ARCHIVE_SELECTOR,
    actions: ['read'],
    scope: 'exact',
    display_name: 'Report archive',
    owner_id: null,
    ownership_status: 'unassigned',
    ownership_source: 'Company service catalog',
    sensitivity: 'internal',
    approved_destinations: [],
  });
  add('archive-storage', 'GuardExternalResource', {
    ...host,
    provider: 'host',
    host_resource_id: ARCHIVE_HOST,
    name: 'Report archive storage',
    kind: 'storage',
  });
  link('archive-binding', 'archive-selector', 'G_BINDS_SELECTOR');
  link('archive-binding', 'archive-storage', 'G_MAPS_TO');

  add('credential', 'GuardCredentialReference', {
    ...host,
    credential_id: opaque('e'),
    name: 'Documents service identity',
    issuer_ref: opaque('f'),
    audience_refs: [opaque('1')],
    recipient_refs: [opaque('2')],
    lifecycle_state: 'rotating',
    rotation_status: 'due',
    expires_at: new Date(now + 86_400_000).toISOString(),
  });

  for (const agent of AGENTS) {
    const id = name => `${name}-${agent.key}`;
    const taskId = `${agent.agentId}-task`;
    add(id('agent'), 'GuardAgent', {
      ...host,
      agent_id: agent.agentId,
      name: agent.name,
      owner_id: agent.owner?.ownerId ?? null,
      team_id: agent.team,
      purpose: `Help ${agent.team.toLowerCase()} with scoped records`,
      lifecycle_state: 'active',
      ownership_status: agent.owner ? 'assigned' : 'unknown',
      ownership_source: agent.owner ? 'Company service catalog' : null,
    });
    if (agent.owner) link(id('agent'), agent.owner.id, 'G_OWNED_BY');
    add(id('deployment'), 'GuardDeployment', {
      ...host,
      deployment_id: agent.deploymentId,
      environment: agent.environment,
      runtime_ref: opaque('3'),
      build_ref: opaque('4'),
      workload_generation: '2026.11.06',
      binding_authority: 'company-catalog',
      // Manifest v3: absent means the host has not said, which reads as unknown.
      ...(agent.directAccess ? { direct_access_status: agent.directAccess } : {}),
    });
    link(id('deployment'), id('agent'), 'G_INSTANCE_OF');
    link(id('deployment'), 'credential', 'G_USES_CREDENTIAL');
    add(id('task'), 'GuardTask', {
      task_id: taskId,
      principal_id: `${agent.key}-application`,
      revoked: false,
      delegated: false,
      derived: false,
      sensitive: false,
      untrusted: agent.untrusted,
      allowed_recipients: [RECIPIENTS],
      allow_control_plane: false,
      max_calls: 100,
      max_concurrent: 2,
      max_cost: 100,
      deadline: now + 3_600_000,
      calls: 12,
      concurrent: 0,
      spent: 0,
      reserved: 0,
    });
    link(id('task'), id('deployment'), 'G_ASSIGNED_TO');

    // Reading documents: a declared grant on the report (and, for research, the archive).
    add(id('grant'), 'GuardGrant', {
      task_id: taskId,
      tool: READ_TOOL,
      resources: agent.key === 'research' ? [REPORT_SELECTOR, ARCHIVE_SELECTOR] : [REPORT_SELECTOR],
      evidence_kind: 'declared',
      assessment: 'unknown',
    });
    link(id('task'), id('grant'), 'G_HAS_GRANT');
    link(id('grant'), 'tool', 'G_FOR_TOOL');
    link(id('grant'), 'resource', 'G_TARGETS');
    if (agent.key === 'research') link(id('grant'), 'archive-selector', 'G_TARGETS');

    // Sending: one tool per agent, each declaring something different about external sends.
    add(id('tool-send'), 'GuardTool', {
      revision: 1,
      registered: true,
      approved: true,
      known_metadata: true,
      requires_approval: false,
      control_plane: false,
      max_cost: 1,
      reads_untrusted: false,
      ...agent.send,
    });
    add(id('grant-send'), 'GuardGrant', {
      task_id: taskId,
      tool: agent.send.name,
      resources: [RECIPIENTS],
      evidence_kind: 'declared',
      assessment: 'unknown',
    });
    link(id('task'), id('grant-send'), 'G_HAS_GRANT');
    link(id('grant-send'), id('tool-send'), 'G_FOR_TOOL');

    // How the read tool runs for this deployment: one static cloud identity each.
    add(id('binding'), 'GuardExecutionBinding', {
      ...host,
      binding_id: `documents-reader-${agent.key}`,
      tool: READ_TOOL,
      connection_id: 'documents-eu',
      identity_selection: 'static',
    });
    add(id('identity'), 'GuardExternalIdentity', {
      ...host,
      ...cloud,
      provider: 'aws',
      partition: 'aws',
      account_id: ACCOUNT,
      arn: `arn:aws:iam::${ACCOUNT}:role/${agent.agentId}`,
    });
    link(id('binding'), id('deployment'), 'G_EXECUTES_FOR');
    link(id('binding'), 'tool', 'G_EXECUTES_TOOL');
    link(id('binding'), 'connection', 'G_VIA_CONNECTION');
    link(id('binding'), id('identity'), 'G_USES_IDENTITY');
  }

  // Research only: how its mail tool runs (through the quarantined connection, with an identity
  // chosen at run time), a follow-up task delegated since the last snapshot, and two paths its
  // host declared around the guard.
  add('binding-mail-research', 'GuardExecutionBinding', {
    ...host,
    binding_id: 'mail-sender-research',
    tool: 'mcp:mail:send',
    connection_id: 'mail-eu',
    identity_selection: 'dynamic',
  });
  link('binding-mail-research', 'deployment-research', 'G_EXECUTES_FOR');
  link('binding-mail-research', 'tool-send-research', 'G_EXECUTES_TOOL');
  link('binding-mail-research', 'connection-mail', 'G_VIA_CONNECTION');
  add('task-research-followup', 'GuardTask', {
    task_id: 'research-followup',
    principal_id: 'research-application',
    revoked: false,
    delegated: true,
    derived: false,
    sensitive: false,
    untrusted: false,
    allowed_recipients: [RECIPIENTS],
    allow_control_plane: false,
    max_calls: 20,
    max_concurrent: 1,
    max_cost: 20,
    deadline: now + 3_600_000,
    calls: 0,
    concurrent: 0,
    spent: 0,
    reserved: 0,
  });
  link('task-research-followup', 'deployment-research', 'G_ASSIGNED_TO');
  link('task-research-followup', 'task-research', 'G_DELEGATED_FROM');
  add('direct-sdk', 'GuardDirectAccess', {
    ...host,
    evidence_kind: 'declared',
    access_id: opaque('6'),
    deployment_id: 'research-eu-1',
    kind: 'sdk',
    target_ref: ARCHIVE_HOST,
    description: 'Direct S3 SDK client in the worker',
  });
  add('direct-shell', 'GuardDirectAccess', {
    ...host,
    evidence_kind: 'declared',
    access_id: opaque('8'),
    deployment_id: 'research-eu-1',
    kind: 'shell',
    description: 'Ops shell for debugging',
  });
  link('direct-sdk', 'deployment-research', 'G_DIRECT_ACCESS_FOR');
  link('direct-shell', 'deployment-research', 'G_DIRECT_ACCESS_FOR');

  // IAM policy evidence for the report, one record per agent: a conditional candidate, no
  // candidate, and a boundary the collection could not resolve.
  const policyRecord = (agent, fields) => ({
    taskId: `task-${agent}`,
    deploymentId: `deployment-${agent}`,
    executionBindingId: `binding-${agent}`,
    resourceBindingId: 'resource-binding',
    identityId: `identity-${agent}`,
    resourceId: 'external-resource',
    action: READ_ACTION,
    observedAt: at(300),
    assessment: 'unknown',
    candidates: [],
    ...fields,
  });
  const policyEvidence = [
    policyRecord('research', {
      status: 'complete',
      reason: null,
      candidates: [
        {
          relationship: 'CAN_READ',
          hasCondition: true,
          conditionKeys: ['aws:PrincipalTag/team', 'aws:SecureTransport'],
          resourceScope: 'bucket_summary',
        },
      ],
    }),
    // The archive is a host resource with a generic action: no cloud policy applies to it.
    policyRecord('research', {
      resourceBindingId: 'archive-binding',
      identityId: null,
      resourceId: 'archive-storage',
      action: 'read',
      status: 'not_collected',
      reason: 'unsupported_action',
      observedAt: null,
    }),
    policyRecord('release', { status: 'complete', reason: 'no_candidate' }),
    policyRecord('finance', { status: 'unavailable', reason: 'boundary_unresolved' }),
  ];

  // What each read tool's cloud identity reaches compared with what its grants bind.
  const scopeRecord = (agent, fields) => ({
    executionBindingId: `binding-${agent}`,
    deploymentId: `deployment-${agent}`,
    tool: READ_TOOL,
    identityId: `identity-${agent}`,
    accountId: ACCOUNT,
    reason: null,
    observedAt: at(300),
    boundBuckets: ['company-reports'],
    extraResources: [],
    truncated: false,
    evidenceKind: 'iam_identity_policy_candidate',
    assessment: 'unknown',
    ...fields,
  });
  const unresolved = { status: 'unknown', reason: 'boundary_unresolved', boundBuckets: [] };
  // The mail tool's identity is chosen at run time, so there is nothing static to compare.
  const mailScope = scopeRecord('research', {
    executionBindingId: 'binding-mail-research',
    tool: 'mcp:mail:send',
    identityId: null,
    accountId: null,
    status: 'unknown',
    reason: 'identity_not_static',
    observedAt: null,
    boundBuckets: [],
  });
  const identityScope = [
    scopeRecord('research', {
      status: 'broader_than_grants',
      extraResources: [
        {
          resourceId: 'arn:aws:s3:::company-payroll',
          bucketName: 'company-payroll',
          relationship: 'CAN_READ',
          hasCondition: false,
          conditionKeys: [],
        },
        {
          resourceId: 'arn:aws:s3:::company-hr-exports',
          bucketName: 'company-hr-exports',
          relationship: 'CAN_WRITE',
          hasCondition: true,
          conditionKeys: ['aws:SourceVpce'],
        },
      ],
    }),
    mailScope,
    scopeRecord('release', { status: 'matches_grants' }),
    scopeRecord('finance', unresolved),
  ];
  // The same comparison limited to buckets that visible bindings map to (only company-reports,
  // which every one of these identities is bound to): nothing extra to list.
  const identityReach = [
    scopeRecord('research', { status: 'matches_grants' }),
    mailScope,
    scopeRecord('release', { status: 'matches_grants' }),
    scopeRecord('finance', unresolved),
  ];

  return {
    projection: {
      id: PROJECTION_ID,
      snapshotId: 'demo-current',
      generatedAt: at(120),
      status: 'published',
      nodes,
      edges,
      coverage: {
        tasks: { status: 'complete', observedAt: at(120) },
        tools: { status: 'complete', observedAt: at(120) },
        manifest: { status: 'complete', observedAt: at(420) },
        // One of the two MCP connections was captured; the other capture is half an hour old.
        mcp: { status: 'partial', observedAt: at(1800) },
        cloud: { status: 'complete', observedAt: at(300) },
      },
    },
    policyEvidence,
    identityScope,
    identityReach,
  };
}

/**
 * The snapshot before: the follow-up task and the SDK path did not exist, the research agent
 * belonged to the platform team, and the mail connection was still ready.
 */
function previousProjection(current, now) {
  const added = new Set(['task-research-followup', 'direct-sdk']);
  const rename = id => `previous:${id}`;
  const nodes = current.nodes
    .filter(node => !added.has(node.id))
    .map(node => ({
      ...node,
      id: rename(node.id),
      projectionId: PREVIOUS_ID,
      properties:
        node.id === 'agent-research'
          ? { ...node.properties, owner_id: 'sam.rivera' }
          : node.id === 'connection-mail'
            ? { ...node.properties, state: 'ready', metadata_state: 'current' }
            : node.properties,
    }));
  const edges = current.edges
    .filter(edge => !added.has(edge.source) && !added.has(edge.target))
    .map(edge =>
      edge.source === 'agent-research' && edge.kind === 'G_OWNED_BY'
        ? { ...edge, source: rename(edge.source), target: rename('owner-sam') }
        : { ...edge, source: rename(edge.source), target: rename(edge.target) },
    );
  return {
    id: PREVIOUS_ID,
    snapshotId: 'demo-previous',
    generatedAt: new Date(now - 420_000).toISOString(),
    status: 'published',
    nodes,
    edges,
    coverage: current.coverage,
  };
}

/** A discovery read loads no nodes: counts, one page, or the IAM candidates. */
function discoveryView(request, source, now) {
  const page = request.page;
  const slice = items => items.slice(page.offset, page.offset + page.limit);
  const bare = extra => ({
    ...source,
    previous: null,
    current: {
      id: source.current.id,
      snapshotId: source.current.snapshotId,
      generatedAt: source.current.generatedAt,
      status: 'published',
      nodes: [],
      edges: [],
      coverage: { tasks: source.current.coverage.tasks },
      ...extra,
    },
  });
  if (request.undeclared)
    return {
      sources: [
        bare({
          undeclared: {
            tasks: UNDECLARED_TASKS.length,
            tasksCapped: false,
            principals: UNDECLARED_CALLERS.length,
            principalsCapped: false,
            ...(page
              ? {
                  page: {
                    kind: page.kind,
                    items: slice(page.kind === 'tasks' ? UNDECLARED_TASKS : UNDECLARED_CALLERS),
                  },
                }
              : {}),
          },
        }),
      ],
    };
  return {
    sources: [bare({})],
    unclaimedIdentities: {
      accounts: [
        {
          ...CLOUD_ACCOUNT,
          status: 'complete',
          reason: null,
          observedAt: new Date(now - 300_000).toISOString(),
          observed: 6,
          unclaimed: UNCLAIMED_IDENTITIES.length,
        },
      ],
      identities: page ? slice(UNCLAIMED_IDENTITIES) : [],
      total: UNCLAIMED_IDENTITIES.length,
      // The research mail binding names no identity, so a listed role may be its own.
      bindingsWithoutIdentity: true,
    },
  };
}

/**
 * A MapStore over the fixture. It answers every read with the whole source and leaves
 * focusing, paging and filtering to the service, as a small host-provided store may. Capture
 * times are counted back from each read, so an open demo never drifts into "stale".
 */
export function createDemoStore({ clock = Date.now } = {}) {
  return {
    async read(_scope, request = {}) {
      if (request.sourceId !== undefined && request.sourceId !== DEMO_SOURCE_ID) return { sources: [] };
      const now = clock();
      const { projection, policyEvidence, identityScope, identityReach } = currentProjection(now);
      const source = {
        id: DEMO_SOURCE_ID,
        tenantId: TENANT,
        sourceId: 'acme-research-executor',
        profile: 'host-mcp',
        current: projection,
        previous: null,
      };
      if (request.undeclared || request.unclaimedIdentities) return discoveryView(request, source, now);
      // Evidence goes only where a store would load it: policy evidence unless the caller asked
      // for none, identity scope for one agent's boundary, reach for the resource views.
      const evidenceRead = !request.summary && !request.history && !request.flags && !request.owners;
      return {
        sources: [
          {
            ...source,
            current: {
              ...projection,
              ...(evidenceRead && request.policy !== false ? { policyEvidence } : {}),
              ...(request.boundary ? { identityScope } : {}),
              ...(request.outsideGuard ? { identityReach } : {}),
            },
            previous: request.history ? previousProjection(projection, now) : null,
          },
        ],
      };
    },
  };
}
