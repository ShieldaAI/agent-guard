// Explicit browser-only demonstration. These values are never presented as live inventory.
const sourceId = 'a'.repeat(64);
const capturedAt = Date.now();
const capture = (status, ageSeconds, stale) => ({ status, observedAt: new Date(capturedAt - ageSeconds * 1000).toISOString(), ageSeconds, stale });
const sources = [{ id: sourceId, sourceId, tenantId: 'acme-research', profile: 'host-mcp',
  generatedAt: new Date(capturedAt - 120_000).toISOString(), snapshotId: 'demo-current', projectionId: 'b'.repeat(64), stale: false,
  coverage: { tasks: capture('complete', 120, false), tools: capture('complete', 120, false), manifest: capture('complete', 420, false),
    mcp: capture('partial', 1800, true), cloud: capture('complete', 300, false), policy: capture('partial', 300, false) } }];
const agents = [
  { id: 'agent-research', agentId: 'research-assistant', sourceId, name: 'Research assistant', ownerId: 'alex.chen', teamId: 'Research',
    environments: ['production'], deployments: [{ id: 'deployment-research', deploymentId: 'research-eu-1', environment: 'production' }] },
  { id: 'agent-release', agentId: 'release-assistant', sourceId, name: 'Release assistant', ownerId: 'sam.rivera', teamId: 'Platform',
    environments: ['staging'], deployments: [{ id: 'deployment-release', deploymentId: 'release-staging', environment: 'staging' }] },
  { id: 'agent-finance', agentId: 'finance-reviewer', sourceId, name: 'Finance reviewer', ownerId: 'morgan.lee', teamId: 'Finance',
    environments: ['production'], deployments: [{ id: 'deployment-finance', deploymentId: 'finance-us-1', environment: 'production' }] },
];
function access(agent) {
  const taskId = `${agent.agentId}-task`;
  const tool = 'mcp:documents:read';
  const resource = 'opaque:' + 'd'.repeat(64);
  const node = (id, label, properties) => ({ id, entityId: id, label, properties });
  const nodes = [
    node(agent.id, 'GuardAgent', { agent_id: agent.agentId, name: agent.name, team_id: agent.teamId, owner_id: agent.ownerId }),
    node('deployment', 'GuardDeployment', { deployment_id: agent.deployments[0].deploymentId, environment: agent.environments[0] }),
    node('task', 'GuardTask', { task_id: taskId, principal_id: 'application', revoked: false, calls: 12, max_calls: 100 }),
    node('grant', 'GuardGrant', { task_id: taskId, tool, resources: [resource], assessment: 'unknown', evidence_kind: 'declared' }),
    node('tool', 'GuardTool', { name: tool, registered: true, approved: true, requires_approval: false }),
    node('resource', 'GuardResource', { resource_id: resource, tool, selector_kind: 'exact' }),
    node('connection', 'GuardMcpConnection', { connection_id: 'documents-eu', state: 'ready', metadata_state: 'current', metadata_revision: 3 }),
    node('operation', 'GuardMcpOperation', { name: tool, kind: 'tool', assessment: 'unknown' }),
    node('binding', 'GuardExecutionBinding', { binding_id: 'documents-reader', tool, identity_selection: 'static', evidence_kind: 'host_asserted' }),
    node('identity', 'GuardExternalIdentity', { arn: `arn:aws:iam::111122223333:role/${agent.agentId}`, cloud_status: 'resolved', assessment: 'unknown' }),
    node('resource-binding', 'GuardResourceBinding', { binding_id: 'reports-object', tool, resource_ref: resource,
      actions: ['s3:GetObject'], scope: 'exact', evidence_kind: 'host_asserted', assessment: 'unknown' }),
    node('external-resource', 'GuardExternalResource', { arn: 'arn:aws:s3:::company-reports/quarterly/summary.pdf',
      kind: 'object', cloud_status: 'resolved', cloud_match_kind: 'containment', assessment: 'unknown' }),
  ];
  const edges = [
    ['deployment', agent.id, 'G_INSTANCE_OF'], ['task', 'deployment', 'G_ASSIGNED_TO'],
    ['task', 'grant', 'G_HAS_GRANT'], ['grant', 'tool', 'G_FOR_TOOL'], ['grant', 'resource', 'G_TARGETS'],
    ['binding', 'deployment', 'G_EXECUTES_FOR'], ['binding', 'tool', 'G_EXECUTES_TOOL'],
    ['binding', 'connection', 'G_VIA_CONNECTION'], ['connection', 'operation', 'G_EXPOSES_OPERATION'],
    ['operation', 'tool', 'G_OPERATION_TOOL'], ['binding', 'identity', 'G_USES_IDENTITY'],
    ['resource-binding', 'resource', 'G_BINDS_SELECTOR'], ['resource-binding', 'external-resource', 'G_MAPS_TO'],
  ].map(([source, target, kind]) => ({ source, target, kind }));
  const policyEvidence = [{ taskId: 'task', deploymentId: 'deployment', executionBindingId: 'binding',
    resourceBindingId: 'resource-binding', identityId: 'identity', resourceId: 'external-resource', action: 's3:GetObject',
    status: agent.id === 'agent-finance' ? 'unavailable' : 'complete',
    reason: agent.id === 'agent-finance' ? 'boundary_unresolved' : agent.id === 'agent-release' ? 'no_candidate' : null,
    observedAt: sources[0].coverage.policy.observedAt, assessment: 'unknown',
    candidates: agent.id === 'agent-research' ? [{ relationship: 'CAN_READ', hasCondition: true,
      conditionKeys: ['aws:PrincipalTag/team', 'aws:SecureTransport'], resourceScope: 'bucket_summary' }] : [] }];
  return { data: { agent, deployments: agent.deployments,
    tasks: [{ id: 'task', taskId, principalId: 'application', revoked: false, sensitive: false,
      usage: { calls: 12, concurrent: 0, spent: 0, reserved: 0 },
      budget: { maxCalls: 100, maxConcurrent: 2, maxCost: 0, deadline: Date.now() + 3_600_000 } }],
    grants: [{ id: 'grant', taskId, tool, resources: [resource], evidenceKind: 'declared' }],
    connections: [nodes[6]], bindings: [nodes[8], nodes[10]], policyEvidence, receipt: sources[0], assessment: 'unknown',
    limitations: ['A declared grant is evidence, not an execution decision.', 'Live policy, arguments and backend authorization still apply.'] }, graph: { nodes, edges } };
}
export async function queryDemo(operation, args = {}) {
  let result;
  if (operation === 'list_agents') {
    const filtered = agents.filter(agent => (!args.search || `${agent.name} ${agent.agentId}`.toLowerCase().includes(args.search.toLowerCase())) &&
      (!args.ownerId || agent.ownerId === args.ownerId) && (!args.environment || agent.environments.includes(args.environment)));
    result = { data: { agents: filtered, truncated: false } };
  } else if (operation === 'get_inventory_health') result = { data: { sources } };
  else if (operation === 'get_agent_access') {
    const agent = agents.find(agent => agent.id === args.agentId || agent.agentId === args.agentId);
    if (!agent) throw new Error('REFERENCE_NOT_FOUND');
    result = access(agent);
  } else if (operation === 'explain_access') result = { data: { ...args, assessment: 'unknown', blockers: [],
    unknownChecks: ['Current custom policy', 'Resolved request arguments', 'Backend authorization', 'Concurrent reservations'],
    delegation: [{ id: 'task', taskId: args.taskId }], matchedGrants: [{ tool: args.tool, resources: [args.resourceId] }],
    externalEvidence: { policyEvidence: access(agents.find(agent => `${agent.agentId}-task` === args.taskId) ?? agents[0]).data.policyEvidence } } };
  else if (operation === 'find_agents_with_access') result = { data: { candidates: [{ agent: agents[0], assessment: 'unknown',
    evidence: [{ policyEvidence: access(agents[0]).data.policyEvidence.filter(item => item.action === args.action) }],
    resourceRef: args.resourceRef, action: args.action, scope: 'exact' }],
    limitations: ['Candidates have declared or mapped access. They are not guaranteed to execute this action.'] } };
  else if (operation === 'get_changes') result = { data: { sourceId, from: { snapshotId: 'demo-previous', generatedAt: new Date(Date.now() - 420_000).toISOString() },
    to: sources[0], changes: { added: [{ entityId: 'new-task', label: 'GuardTask', name: 'research-followup' }], removed: [],
      changed: [{ entityId: 'connection', label: 'GuardMcpConnection', name: 'documents-eu' }, { entityId: 'tool', label: 'GuardTool', name: 'mcp:documents:read' }] },
    coverageGap: false, policyHistory: 'not_collected', limitations: ['Snapshot differences show net changes, not an event history.'] } };
  else throw new Error('VIEWER_OPERATION_INVALID');
  return structuredClone({ operation, observedAt: new Date().toISOString(), ...result });
}
