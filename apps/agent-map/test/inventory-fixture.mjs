/** Synthetic projection evidence for the real MapService/browser walkthrough. No executor is connected. */
export function inventoryBrowserFixture() {
  const sourceId = 'fixture', observedAt = new Date().toISOString();
  const source = { id: sourceId, sourceId: 'observer', tenantId: 'fixture', profile: 'host-mcp', previous: null,
    current: { id: 'current', snapshotId: 'current-snapshot', generatedAt: observedAt, status: 'published',
      coverage: Object.fromEntries(['manifest', 'tasks', 'tools', 'mcp'].map(k => [k, { status: 'complete', observedAt }])), nodes: [], edges: [] } };
  const host = { evidence_kind: 'host_asserted', assessment: 'unknown', manifest_observed_at: observedAt,
    authority_id: 'fixture-company-catalog', manifest_id: 'company-catalog', manifest_revision: 4, manifest_schema_version: 2 };
  const add = (id, label, properties) => source.current.nodes.push({ id, entityId: id, label, sourceId,
    projectionId: 'current', properties });
  const link = (from, to, kind) => { source.current.edges.push({ source: from, target: to, kind }); };
  const opaque = n => `opaque:${n.toString(16).padStart(64, '0')}`;
  add('tool', 'GuardTool', { name: 'catalog.read', revision: 4, registered: true, approved: true, known_metadata: true, requires_approval: true, max_cost: 0 });
  for (let i = 0; i < 25; i++) {
    const id = `agent-${i}`, owner = `owner-${i}`, deployment = `deployment-${i}`, task = `task-${i}`, binding = `resource-${i}`;
    const agent = { agent_id: `catalog-agent-${i}`, name: i === 0 ? 'Catalog assistant' : i === 24 ? 'Large catalog agent' : `Directory agent ${String(i + 1).padStart(2, '0')}`,
      team_id: 'Platform', owner_id: i === 1 ? null : i === 2 ? 'legacy-reported-owner' : owner,
      ...(i === 2 ? {} : { ...host, purpose: 'Read company records within declared boundaries', lifecycle_state: 'active', ownership_status: i === 1 ? 'unassigned' : 'assigned', ownership_source: 'Company registry' }) };
    add(id, 'GuardAgent', agent);
    if (i !== 1 && i !== 2) { add(owner, 'GuardOwner', { ...host, owner_id: owner, name: i === 0 ? 'Accountable platform team' : `Owner ${String(i + 1).padStart(2, '0')}`, kind: 'team' }); link(id, owner, 'G_OWNED_BY'); }
    add(deployment, 'GuardDeployment', { ...host, deployment_id: deployment, environment: 'production', runtime_ref: opaque(100 + i), build_ref: opaque(200 + i), workload_generation: '2026.11.06', binding_authority: 'Workload registry' });
    link(deployment, id, 'G_INSTANCE_OF');
    add(task, 'GuardTask', { task_id: task, principal_id: 'service-reader', revoked: false, sensitive: false, calls: 1, max_calls: 100, max_concurrent: 2, max_cost: 0, deadline: Date.now() + 3600000 });
    link(task, deployment, 'G_ASSIGNED_TO');
    add(`grant-${i}`, 'GuardGrant', { task_id: task, tool: 'catalog.read', resources: [opaque(300 + i)], evidence_kind: 'declared', assessment: 'unknown' });
    add(`selector-${i}`, 'GuardResource', { resource_id: opaque(300 + i), tool: 'catalog.read', selector_kind: 'exact' });
    link(task, `grant-${i}`, 'G_HAS_GRANT'); link(`grant-${i}`, 'tool', 'G_FOR_TOOL'); link(`grant-${i}`, `selector-${i}`, 'G_TARGETS');
    add(binding, 'GuardResourceBinding', { ...host, binding_id: `records-${i}`, display_name: i === 0 ? 'Company records' : `Record store ${String(i + 1).padStart(2, '0')}`, tool: 'catalog.read', resource_ref: opaque(300 + i), actions: ['read'], scope: 'exact', owner_id: agent.owner_id,
      ownership_status: agent.ownership_status ?? 'unknown', ownership_source: agent.ownership_source ?? null, sensitivity: 'confidential', approved_destinations: [opaque(400 + i)] });
    add(`target-${i}`, 'GuardExternalResource', { ...host, provider: 'host', host_resource_id: opaque(500 + i), name: i === 0 ? 'Company database' : `Database ${i + 1}`, kind: 'database' });
    link(binding, `selector-${i}`, 'G_BINDS_SELECTOR'); link(binding, `target-${i}`, 'G_MAPS_TO');
    if (i !== 1 && i !== 2) link(binding, owner, 'G_RESOURCE_OWNED_BY');
    add(`execution-${i}`, 'GuardExecutionBinding', { ...host, binding_id: `reader-${i}`, tool: 'catalog.read', connection_id: 'catalog-mcp', identity_selection: 'unknown' });
    link(`execution-${i}`, deployment, 'G_EXECUTES_FOR'); link(`execution-${i}`, 'tool', 'G_EXECUTES_TOOL'); link(`execution-${i}`, 'mcp', 'G_VIA_CONNECTION');
    if (i === 0) {
      add('credential', 'GuardCredentialReference', { ...host, credential_id: opaque(600), name: 'Company service reference', issuer_ref: opaque(601), audience_refs: [opaque(602)], recipient_refs: [opaque(603)], lifecycle_state: 'rotating', rotation_status: 'due', expires_at: new Date(Date.now() + 86400000).toISOString() });
      link(deployment, 'credential', 'G_USES_CREDENTIAL');
    }
    if (i === 24) for (let n = 0; n < 510; n++) {
      const extra = `large-task-${String(n).padStart(3, '0')}`;
      add(extra, 'GuardTask', { task_id: extra, principal_id: 'service-reader', revoked: false }); link(extra, deployment, 'G_ASSIGNED_TO');
    }
  }
  add('mcp', 'GuardMcpConnection', { connection_id: 'catalog-mcp', server_id: 'company-catalog', transport_ref: opaque(700), state: 'ready', metadata_state: 'current', observed_at: observedAt, capture_status: 'complete', capture_observed_at: observedAt, evidence_kind: 'mcp_observation', assessment: 'unknown' });
  add('operation', 'GuardMcpOperation', { connection_id: 'catalog-mcp', name: 'catalog.read', kind: 'tool', evidence_kind: 'mcp_observation', assessment: 'unknown' });
  link('mcp', 'operation', 'G_EXPOSES_OPERATION'); link('operation', 'tool', 'G_OPERATION_TOOL'); link('resource-0', 'resource-1', 'G_DEPENDS_ON');
  source.previous = structuredClone(source.current); source.previous.id = 'previous'; source.previous.snapshotId = 'previous-snapshot'; source.previous.generatedAt = new Date(Date.now() - 600000).toISOString();
  for (const node of source.previous.nodes) { node.id = `previous:${node.entityId}`; node.projectionId = 'previous'; }
  for (const relation of source.previous.edges) { relation.source = `previous:${relation.source}`; relation.target = `previous:${relation.target}`; }
  const previousAgent = source.previous.nodes.find(n => n.entityId === 'agent-0'); previousAgent.properties.owner_id = 'owner-3';
  source.previous.edges = source.previous.edges.filter(e => !(e.source === 'previous:agent-0' && e.kind === 'G_OWNED_BY'));
  source.previous.edges.push({ source: 'previous:agent-0', target: 'previous:owner-3', kind: 'G_OWNED_BY' });
  for (const node of source.previous.nodes.filter(n => n.label === 'GuardTask' && n.entityId.startsWith('task-'))) node.properties.revoked = true;
  return source;
}
