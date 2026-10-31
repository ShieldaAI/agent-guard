import { randomUUID } from 'node:crypto';
import { immutableJson, type Json } from '@shieldaai/agent-guard';
import { ExecutorError } from './store.js';
import type { InventorySnapshot } from './inventory.js';

const INVALID = 'INVENTORY_MANIFEST_INVALID';
const LIMIT = 'INVENTORY_MANIFEST_LIMIT_EXCEEDED';
function fail(code = INVALID): never { throw new ExecutorError(code); }
function copy(value: unknown, maximum: number, values = 200_000): Json {
  try { return immutableJson(value, 32, values, maximum); }
  catch (error) {
    if (error instanceof Error && error.message.includes('limit')) return fail(LIMIT);
    return fail();
  }
}
function object(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  const record = value as Record<string, unknown>;
  if (keys.some(key => !Object.hasOwn(record, key)) ||
      Object.keys(record).some(key => !keys.includes(key) && !optional.includes(key))) return fail();
  return record;
}
function identifier(value: unknown): string {
  if (typeof value !== 'string' || /^[\s\u001c-\u001f\u0085]*$/u.test(value) || value.includes('\0') ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value) ||
      [...value].length > 4096) return fail();
  return value;
}
function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return fail();
  return value;
}
function timestamp(value: unknown): string {
  if (typeof value !== 'string' || !/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)) return fail();
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19)) return fail();
  return value;
}
function array(value: unknown, maximum: number): readonly unknown[] {
  if (!Array.isArray(value)) return fail();
  if (value.length > maximum) return fail(LIMIT);
  return value;
}
function source(value: unknown): InventorySnapshot['source'] {
  const input = object(value, ['companyId', 'sourceId', 'enrollmentGeneration', 'inventoryInstanceId', 'tenantId']);
  for (const item of Object.values(input)) identifier(item);
  return input as unknown as InventorySnapshot['source'];
}

export interface InventoryAwsReference {
  readonly provider: 'aws';
  readonly partition: 'aws' | 'aws-cn' | 'aws-us-gov';
  readonly accountId: string;
  readonly region: string;
  readonly arn: string;
}
export interface InventoryAwsResourceReference extends InventoryAwsReference {
  readonly kind: 'bucket' | 'object' | 'prefix' | 'resource';
}
export interface InventoryManifestAgent {
  readonly id: string; readonly name: string; readonly ownerId: string | null; readonly teamId: string | null;
}
export interface InventoryManifestDeployment {
  readonly id: string; readonly agentId: string; readonly environment: string | null;
}
export interface InventoryManifestTaskBinding { readonly taskId: string; readonly deploymentId: string }
export interface InventoryManifestResourceBinding {
  readonly id: string; readonly tool: string; readonly resourceRef: string;
  readonly target: InventoryAwsResourceReference;
  readonly actions: readonly string[];
  readonly scope: 'exact' | 'prefix';
}
export interface InventoryManifestExecutionBinding {
  readonly id: string; readonly tool: string; readonly deploymentId: string;
  readonly connectionId: string | null;
  readonly identitySelection: 'static' | 'dynamic' | 'unknown';
  readonly identity: InventoryAwsReference | null;
}
/** Host assertions are inventory evidence. They never grant executor or backend authority. */
export interface InventoryManifest {
  readonly schemaVersion: 1;
  readonly evidenceKind: 'host_asserted';
  readonly source: InventorySnapshot['source'];
  readonly manifestId: string;
  readonly revision: number;
  readonly observedAt: string;
  readonly agents: readonly InventoryManifestAgent[];
  readonly deployments: readonly InventoryManifestDeployment[];
  readonly taskBindings: readonly InventoryManifestTaskBinding[];
  readonly resourceBindings: readonly InventoryManifestResourceBinding[];
  readonly executionBindings: readonly InventoryManifestExecutionBinding[];
}
export interface HostInventorySnapshot extends Omit<InventorySnapshot, 'profile' | 'coverage'> {
  readonly profile: 'host';
  readonly manifest: InventoryManifest;
  readonly coverage: Omit<InventorySnapshot['coverage'], 'manifest'> & {
    readonly manifest: { readonly status: 'complete'; readonly observedAt: string };
  };
}

function nullableIdentifier(value: unknown): void { if (value !== null) identifier(value); }
function unique(values: readonly string[], code = INVALID): void {
  if (new Set(values).size !== values.length) fail(code);
}
function awsReference(value: unknown, resource: boolean): { service: string; resource: string } {
  const reference = object(value, ['provider', 'partition', 'accountId', 'region', 'arn', ...(resource ? ['kind'] : [])]);
  if (reference.provider !== 'aws' || typeof reference.partition !== 'string' || !['aws', 'aws-cn', 'aws-us-gov'].includes(reference.partition) ||
      typeof reference.accountId !== 'string' || !/^\d{12}$/.test(reference.accountId) ||
      typeof reference.region !== 'string' || !/^[a-z0-9-]*$/.test(reference.region)) fail();
  const arn = identifier(reference.arn);
  if (/[\s\u001c-\u001f\u0085*?]/u.test(arn)) fail();
  const match = /^arn:(aws|aws-cn|aws-us-gov):([a-z0-9][a-z0-9-]*):([^:]*):([^:]*):(.+)$/.exec(arn);
  if (!match || match[1] !== reference.partition || match[3] !== reference.region) return fail();
  const service = match[2]!; const native = match[5]!;
  if (service === 's3') {
    // The account on an S3 binding is a host ownership assertion; S3 ARNs omit it.
    if (match[3] !== '' || match[4] !== '') fail();
  } else if (match[4] !== reference.accountId) fail();
  if (resource) {
    const slash = native.indexOf('/');
    if (service === 's3') {
      if (reference.kind === 'bucket') { if (slash !== -1) fail(); }
      else if (reference.kind === 'object' || reference.kind === 'prefix') {
        if (slash <= 0 || slash === native.length - 1 || (reference.kind === 'prefix' && !native.endsWith('/'))) fail();
      } else fail();
    } else if (reference.kind !== 'resource') fail();
  } else if (reference.region !== '' || !((service === 'iam' && /^(?:role|user)\/(?:[^/]+\/)*[^/]+$/.test(native)) ||
      (service === 'sts' && /^assumed-role\/[^/]+\/[^/]+$/.test(native)))) fail();
  return { service, resource: native };
}

/** Validate a complete host-owned configuration without executing accessors or retaining mutable input. */
export function validateInventoryManifest(value: unknown): InventoryManifest {
  const manifest = object(copy(value, 2 * 1024 * 1024), ['schemaVersion', 'evidenceKind', 'source', 'manifestId',
    'revision', 'observedAt', 'agents', 'deployments', 'taskBindings', 'resourceBindings', 'executionBindings']);
  if (manifest.schemaVersion !== 1 || manifest.evidenceKind !== 'host_asserted') fail();
  source(manifest.source); identifier(manifest.manifestId); integer(manifest.revision); timestamp(manifest.observedAt);
  const agents = array(manifest.agents, 1000).map(value => {
    const item = object(value, ['id', 'name', 'ownerId', 'teamId']);
    identifier(item.id); identifier(item.name); nullableIdentifier(item.ownerId); nullableIdentifier(item.teamId);
    return item as unknown as InventoryManifestAgent;
  });
  unique(agents.map(agent => agent.id));
  const agentIds = new Set(agents.map(agent => agent.id));
  const deployments = array(manifest.deployments, 1000).map(value => {
    const item = object(value, ['id', 'agentId', 'environment']);
    identifier(item.id); identifier(item.agentId); nullableIdentifier(item.environment);
    if (!agentIds.has(item.agentId as string)) fail('INVENTORY_MANIFEST_REFERENCE_INVALID');
    return item as unknown as InventoryManifestDeployment;
  });
  unique(deployments.map(deployment => deployment.id));
  const deploymentIds = new Set(deployments.map(deployment => deployment.id));
  const tasks = array(manifest.taskBindings, 10_000).map(value => {
    const item = object(value, ['taskId', 'deploymentId']); identifier(item.taskId); identifier(item.deploymentId);
    if (!deploymentIds.has(item.deploymentId as string)) fail('INVENTORY_MANIFEST_REFERENCE_INVALID');
    return item as unknown as InventoryManifestTaskBinding;
  });
  unique(tasks.map(binding => binding.taskId));
  const resources = array(manifest.resourceBindings, 10_000).map(value => {
    const item = object(value, ['id', 'tool', 'resourceRef', 'target', 'actions', 'scope']);
    identifier(item.id); identifier(item.tool); identifier(item.resourceRef);
    if (item.resourceRef === '*') fail();
    const target = awsReference(item.target, true);
    const kind = (item.target as InventoryAwsResourceReference).kind;
    if (item.scope !== (kind === 'prefix' ? 'prefix' : 'exact')) fail();
    const actions = array(item.actions, 128).map(value => {
      const action = identifier(value);
      if (!/^[a-z0-9][a-z0-9-]*:[A-Za-z][A-Za-z0-9]*$/.test(action) || action.split(':')[0] !== target.service) fail();
      return action;
    });
    if (!actions.length) fail(); unique(actions);
    return item as unknown as InventoryManifestResourceBinding;
  });
  unique(resources.map(binding => binding.id));
  unique(resources.map(binding => JSON.stringify([binding.tool, binding.resourceRef])));
  const executions = array(manifest.executionBindings, 10_000).map(value => {
    const item = object(value, ['id', 'tool', 'deploymentId', 'connectionId', 'identitySelection', 'identity']);
    identifier(item.id); identifier(item.tool); identifier(item.deploymentId); nullableIdentifier(item.connectionId);
    if (!deploymentIds.has(item.deploymentId as string)) fail('INVENTORY_MANIFEST_REFERENCE_INVALID');
    if (item.identitySelection === 'static') awsReference(item.identity, false);
    else if (typeof item.identitySelection !== 'string' || !['dynamic', 'unknown'].includes(item.identitySelection) || item.identity !== null) fail();
    return item as unknown as InventoryManifestExecutionBinding;
  });
  unique(executions.map(binding => binding.id));
  unique(executions.map(binding => JSON.stringify([binding.deploymentId, binding.tool])));
  return manifest as unknown as InventoryManifest;
}

function boolean(value: unknown): void { if (typeof value !== 'boolean') fail(); }
function strings(value: unknown, maximum: number): readonly string[] {
  const values = array(value, maximum).map(identifier); unique(values); return values;
}
function validateCore(value: unknown): InventorySnapshot {
  try {
    const snapshot = object(copy(value, 8 * 1024 * 1024, 500_000), ['schemaVersion', 'profile', 'source', 'snapshotId',
      'generatedAt', 'ledgerRevision', 'policyEpoch', 'coverage', 'tasks', 'tools']);
    if (snapshot.schemaVersion !== 1 || snapshot.profile !== 'core') fail();
    const scope = source(snapshot.source);
    identifier(snapshot.snapshotId); timestamp(snapshot.generatedAt); integer(snapshot.ledgerRevision); integer(snapshot.policyEpoch);
    const coverage = object(snapshot.coverage, ['tasks', 'tools', 'manifest', 'mcp', 'cloud']);
    for (const key of ['tasks', 'tools']) {
      const item = object(coverage[key], ['status', 'observedAt']);
      if (item.status !== 'complete') fail(); timestamp(item.observedAt);
    }
    for (const key of ['manifest', 'mcp', 'cloud']) {
      const item = object(coverage[key], ['status']);
      if (typeof item.status !== 'string' || !['not_collected', 'unavailable'].includes(item.status)) fail();
    }
    let selectors = 0;
    const tasks = array(snapshot.tasks, 10_000).map(value => {
      const task = object(value, ['id', 'tenantId', 'principalId', 'parentTaskId', 'sourceTaskId', 'familyId', 'grants',
        'budget', 'allowedRecipients', 'allowControlPlane', 'revoked', 'sensitive', 'usage']);
      for (const key of ['id', 'tenantId', 'principalId', 'familyId']) identifier(task[key]);
      if (task.tenantId !== scope.tenantId) fail();
      nullableIdentifier(task.parentTaskId); nullableIdentifier(task.sourceTaskId);
      const grants = array(task.grants, 2048).map(value => {
        const grant = object(value, ['tool', 'resources']); identifier(grant.tool);
        selectors += strings(grant.resources, 1024).length;
        if (selectors > 100_000) fail(LIMIT);
        return grant.tool as string;
      });
      unique(grants); strings(task.allowedRecipients, 1024);
      const budget = object(task.budget, ['maxCalls', 'maxConcurrent', 'maxCost', 'deadline']);
      for (const key of ['maxCalls', 'maxConcurrent', 'maxCost']) integer(budget[key]);
      if (typeof budget.deadline !== 'number' || !Number.isFinite(budget.deadline) || budget.deadline < 0 || budget.deadline > Number.MAX_SAFE_INTEGER) fail();
      const usage = object(task.usage, ['calls', 'concurrent', 'spent', 'reserved']);
      for (const amount of Object.values(usage)) integer(amount);
      boolean(task.allowControlPlane); boolean(task.revoked); boolean(task.sensitive);
      return task as unknown as InventorySnapshot['tasks'][number];
    });
    unique(tasks.map(task => task.id));
    const byId = new Map(tasks.map(task => [task.id, task]));
    const families = new Map<string, boolean>();
    for (const task of tasks) {
      if (families.has(task.familyId) && families.get(task.familyId) !== task.sensitive) fail();
      families.set(task.familyId, task.sensitive);
      for (const [kind, relatedId] of [['parent', task.parentTaskId], ['source', task.sourceTaskId]] as const) {
        if (relatedId === null) continue;
        const related = byId.get(relatedId);
        if (!related || related.familyId !== task.familyId || (kind === 'parent' && related.principalId !== task.principalId)) fail();
      }
    }
    const visited = new Map<string, number>();
    for (const task of tasks) {
      const stack: [string, boolean][] = [[task.id, false]];
      while (stack.length) {
        const [current, done] = stack.pop()!;
        if (done) { visited.set(current, 2); continue; }
        if (visited.get(current) === 1) fail();
        if (visited.get(current) === 2) continue;
        visited.set(current, 1); stack.push([current, true]);
        const related = byId.get(current)!;
        if (related.parentTaskId !== null) stack.push([related.parentTaskId, false]);
        if (related.sourceTaskId !== null) stack.push([related.sourceTaskId, false]);
      }
    }
    const tools = array(snapshot.tools, 10_000).map(value => {
      const tool = object(value, ['name', 'fingerprint', 'revision', 'registered', 'approved', 'requiresApproval', 'controlPlane', 'maxCost']);
      identifier(tool.name); integer(tool.revision); boolean(tool.registered); boolean(tool.approved);
      if (typeof tool.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(tool.fingerprint)) fail();
      if (tool.registered) { boolean(tool.requiresApproval); boolean(tool.controlPlane); integer(tool.maxCost); }
      else if (tool.requiresApproval !== null || tool.controlPlane !== null || tool.maxCost !== null) fail();
      return tool.name as string;
    });
    unique(tools);
    return snapshot as unknown as InventorySnapshot;
  } catch (error) {
    if (error instanceof ExecutorError && error.code === LIMIT) fail('INVENTORY_LIMIT_EXCEEDED');
    return fail('INVENTORY_SNAPSHOT_INVALID');
  }
}

/** Compose separately captured host evidence with complete executor authority; neither input is mutated. */
export function composeInventorySnapshot(core: InventorySnapshot, value: InventoryManifest): HostInventorySnapshot {
  const snapshot = validateCore(core);
  const manifest = validateInventoryManifest(value);
  for (const key of ['companyId', 'sourceId', 'enrollmentGeneration', 'inventoryInstanceId', 'tenantId'] as const) {
    if (manifest.source[key] !== snapshot.source[key]) fail('INVENTORY_MANIFEST_SOURCE_MISMATCH');
  }
  const tasks = new Set(snapshot.tasks.map(task => task.id));
  const tools = new Set(snapshot.tools.map(tool => tool.name));
  const resources = new Set<string>();
  for (const task of snapshot.tasks) for (const grant of task.grants) {
    tools.add(grant.tool);
    for (const resource of grant.resources) resources.add(JSON.stringify([grant.tool, resource]));
  }
  for (const binding of manifest.taskBindings) if (!tasks.has(binding.taskId)) fail('INVENTORY_MANIFEST_REFERENCE_INVALID');
  for (const binding of manifest.resourceBindings) {
    if (!tools.has(binding.tool) || !resources.has(JSON.stringify([binding.tool, binding.resourceRef]))) fail('INVENTORY_MANIFEST_REFERENCE_INVALID');
  }
  for (const binding of manifest.executionBindings) if (!tools.has(binding.tool)) fail('INVENTORY_MANIFEST_REFERENCE_INVALID');
  const now = Date.now();
  if (!Number.isSafeInteger(now) || now < 0 || now > 253_402_300_799_999) fail('INVENTORY_CLOCK_INVALID');
  const composed: HostInventorySnapshot = {
    ...snapshot, profile: 'host', snapshotId: randomUUID(), generatedAt: new Date(now).toISOString(),
    coverage: { ...snapshot.coverage, manifest: { status: 'complete', observedAt: manifest.observedAt } }, manifest,
  };
  try { return immutableJson(composed, 32, 500_000, 8 * 1024 * 1024 - 16 * snapshot.tasks.length) as unknown as HostInventorySnapshot; }
  catch { return fail('INVENTORY_LIMIT_EXCEEDED'); }
}
