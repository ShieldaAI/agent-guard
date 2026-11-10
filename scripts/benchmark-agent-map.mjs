// Agent map scale benchmark: synthetic sources with many agents, every operation.
// Usage: node scripts/benchmark-agent-map.mjs [agentsPerSource=10] [sources=20] [tasksPerAgent=3]
import { MapService, MAP_OPERATIONS } from '../packages/agent-map/dist/service.js';

const [agentsPerSource = 10, sourceCount = 20, tasksPerAgent = 3] = process.argv.slice(2).map(Number);
const NOW = Date.parse('2030-01-02T00:00:00Z');
const task = {
  principal_id: 'p',
  revoked: false,
  sensitive: false,
  allow_control_plane: false,
  max_calls: 10,
  max_concurrent: 1,
  max_cost: 10,
  deadline: NOW + 60_000,
  calls: 1,
  concurrent: 0,
  spent: 1,
  reserved: 0,
};

export function buildSources(agents, sources, tasks) {
  return Array.from({ length: sources }, (_, s) => {
    const nodes = [],
      edges = [];
    const node = (id, label, properties) =>
      nodes.push({
        id,
        entityId: `entity:${s}:${id}`,
        label,
        sourceId: `source-${s}`,
        projectionId: `p${s}`,
        properties,
      });
    const edge = (source, target, kind) => edges.push({ source, target, kind });
    node('tool', 'GuardTool', {
      name: 'reports.read',
      fingerprint: 'a'.repeat(64),
      revision: 1,
      known_metadata: true,
      registered: true,
      approved: true,
      requires_approval: false,
      control_plane: false,
      max_cost: 1,
    });
    node('principal', 'GuardPrincipal', { principal_id: 'p' });
    for (let a = 0; a < agents; a++) {
      node(`a${a}`, 'GuardAgent', {
        agent_id: `agent-${s}-${a}`,
        name: `Agent ${s}-${a}`,
        team_id: 'team-one',
        owner_id: `owner-${a % 5}`,
      });
      node(`d${a}`, 'GuardDeployment', {
        deployment_id: `deploy-${s}-${a}`,
        environment: a % 2 ? 'production' : 'staging',
      });
      edge(`d${a}`, `a${a}`, 'G_INSTANCE_OF');
      for (let t = 0; t < tasks; t++) {
        const id = `${a}-${t}`;
        node(`t${id}`, 'GuardTask', { ...task, task_id: `task-${s}-${id}` });
        node(`g${id}`, 'GuardGrant', { task_id: `task-${s}-${id}`, tool: 'reports.read', resources: [`r${id}`] });
        node(`r${id}`, 'GuardResource', { resource_id: `r${id}`, tool: 'reports.read', selector_kind: 'exact' });
        edge(`t${id}`, `d${a}`, 'G_ASSIGNED_TO');
        edge(`t${id}`, 'principal', 'G_ACTS_AS');
        edge(`t${id}`, `g${id}`, 'G_HAS_GRANT');
        edge(`g${id}`, 'tool', 'G_FOR_TOOL');
        edge(`g${id}`, `r${id}`, 'G_TARGETS');
        node(`b${id}`, 'GuardResourceBinding', {
          binding_id: `b${id}`,
          tool: 'reports.read',
          resource_ref: `r${id}`,
          actions: ['s3:GetObject'],
          scope: 'exact',
        });
        edge(`b${id}`, `r${id}`, 'G_BINDS_SELECTOR');
      }
    }
    const current = {
      id: `p${s}`,
      snapshotId: `snap-${s}`,
      generatedAt: new Date(NOW - 10_000).toISOString(),
      status: 'published',
      nodes,
      edges,
      coverage: { tasks: { status: 'visible_scope' }, mcp: { status: 'observed' } },
    };
    const previous = structuredClone(current);
    previous.id = `old${s}`;
    previous.snapshotId = `old-${s}`;
    previous.nodes.forEach(n => {
      n.id = `old:${n.id}`;
      n.projectionId = previous.id;
    });
    previous.edges.forEach(e => {
      e.source = `old:${e.source}`;
      e.target = `old:${e.target}`;
    });
    return { id: `source-${s}`, sourceId: `executor-${s}`, tenantId: 'alpha', profile: 'core', current, previous };
  });
}

export async function runBenchmark(agents, sources, tasks) {
  const all = buildSources(agents, sources, tasks);
  const service = new MapService(
    {
      async read(_scope, request) {
        return { sources: request?.sourceId ? all.filter(x => x.id === request.sourceId) : all };
      },
    },
    { clock: () => NOW },
  );
  const scope = {
    subject: 'bench',
    companyId: 'company',
    tenantIds: ['alpha'],
    teamIds: ['team-one'],
    allTeams: false,
  };
  const args = {
    list_agents: { limit: 100 },
    list_owners: { limit: 100 },
    list_resources: { limit: 100 },
    get_inventory_health: {},
    get_changes: { sourceId: 'source-0' },
    get_agent_access: { sourceId: 'source-0', agentId: 'agent-0-0' },
    get_agent_inventory: { sourceId: 'source-0', agentId: 'agent-0-0' },
    explain_access: { sourceId: 'source-0', taskId: 'task-0-0-0', tool: 'reports.read', resourceId: 'r0-0' },
    find_agents_with_access: { resourceRef: 'b0-0', action: 's3:GetObject' },
    get_resource_access: { sourceId: 'source-0', resourceId: 'b0-0' },
  };
  const results = {};
  // The flagged index adds a second read of the returned page; this in-memory store has no
  // node cap, so it measures computation only (the store tests cover the cap).
  const runs = [...MAP_OPERATIONS.map(operation => [operation, operation]), ['list_agents_flags', 'list_agents']];
  args.list_agents_flags = { limit: 100, includeFlags: true };
  for (const [name, operation] of runs) {
    const started = performance.now();
    try {
      await service.query(scope, operation, args[name]);
      results[name] = { ok: true, ms: +(performance.now() - started).toFixed(1) };
    } catch (error) {
      results[name] = {
        ok: false,
        code: error.code ?? String(error),
        ms: +(performance.now() - started).toFixed(1),
      };
    }
  }
  return { agents: agents * sources, sources, tasksPerAgent: tasks, results };
}

if (import.meta.url === `file://${process.argv[1]}`)
  console.log(JSON.stringify(await runBenchmark(agentsPerSource, sourceCount, tasksPerAgent), null, 2));
