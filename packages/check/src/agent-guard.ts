import type { Location } from './types.js';
import { isRecord, lineOf } from './text.js';

/**
 * Agent Guard's own records, read from files: `guard.describe()` output, executor inventory
 * snapshots (`agent-guard-inventory-v1`/`-v2`) and host manifests (`agent-guard-inventory-manifest-v1`
 * to `-v3`). Files are recognised by content, not by name. Only the fields the rules use are
 * validated; a file that is recognised but malformed is reported, never guessed at.
 */

export type UntrustedMode = 'allow' | 'require_approval' | 'deny';

export interface GuardTool {
  readonly name: string;
  readonly fingerprint: string | null;
  readonly registered: boolean;
  readonly approved: boolean;
  readonly requiresApproval: boolean | null;
  readonly readsUntrusted: boolean | null;
  readonly untrustedContext: UntrustedMode | null;
  readonly sendsExternal: boolean | null;
  readonly location: Location;
}

export interface GuardTask {
  readonly id: string;
  readonly principalId: string;
  readonly parentTaskId: string | null;
  readonly grants: readonly { readonly tool: string; readonly resources: readonly string[] }[];
  readonly budget: {
    readonly maxCalls: number;
    readonly maxConcurrent: number;
    readonly maxCost: number;
    readonly deadline: number;
  };
  /** null when the record does not say; [] means the core refuses every external send. */
  readonly allowedRecipients: readonly string[] | null;
  readonly revoked: boolean;
  readonly sensitive: boolean | null;
  readonly untrusted: boolean | null;
  readonly location: Location;
}

export interface GuardResourceBinding {
  readonly id: string;
  readonly tool: string;
  readonly resourceRef: string | null;
  readonly scope: 'exact' | 'prefix';
  readonly sensitivity: string;
}

export interface GuardManifestAgent {
  readonly id: string;
  readonly name: string;
  readonly ownerId: string | null;
  readonly lifecycleState: string;
  readonly ownershipStatus: string;
  readonly location: Location;
}

export interface GuardDirectAccess {
  readonly id: string;
  readonly deploymentId: string;
  readonly kind: string;
  readonly targetRef: string | null;
  readonly description: string;
  readonly location: Location;
}

export interface GuardMcpConnection {
  readonly serverId: string;
  readonly state: string;
}

/** Everything read from Agent Guard files in one scan. */
export interface AgentGuardEvidence {
  readonly files: readonly { readonly path: string; readonly kind: 'description' | 'inventory' | 'manifest' }[];
  readonly untrustedContextDefault: UntrustedMode | null;
  readonly tools: readonly GuardTool[];
  readonly tasks: readonly GuardTask[];
  /** When the snapshot was taken (ms), for judging deadlines; null when no snapshot gave it. */
  readonly observedAt: number | null;
  readonly agents: readonly GuardManifestAgent[];
  readonly deployments: readonly { readonly id: string; readonly agentId: string }[];
  readonly taskBindings: readonly { readonly taskId: string; readonly deploymentId: string }[];
  readonly resourceBindings: readonly GuardResourceBinding[];
  readonly directAccess: readonly GuardDirectAccess[];
  /** MCP connections the guard mediates; null when no inventory reported MCP at all. */
  readonly mcpConnections: readonly GuardMcpConnection[] | null;
}

export const EMPTY_EVIDENCE: AgentGuardEvidence = Object.freeze({
  files: [],
  untrustedContextDefault: null,
  tools: [],
  tasks: [],
  observedAt: null,
  agents: [],
  deployments: [],
  taskBindings: [],
  resourceBindings: [],
  directAccess: [],
  mcpConnections: null,
});

const MODES = new Set(['allow', 'require_approval', 'deny']);

class Malformed extends Error {}

function str(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value) throw new Malformed(`${what} must be a non-empty string`);
  return value;
}
function optStr(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null;
}
function bool(value: unknown, what: string): boolean {
  if (typeof value !== 'boolean') throw new Malformed(`${what} must be a boolean`);
  return value;
}
function optBool(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}
function num(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Malformed(`${what} must be a number`);
  return value;
}
function list(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Malformed(`${what} must be an array`);
  return value;
}
function mode(value: unknown): UntrustedMode | null {
  return typeof value === 'string' && MODES.has(value) ? (value as UntrustedMode) : null;
}

export type ArtifactKind = 'description' | 'inventory' | 'manifest';

/** What kind of Agent Guard file this is, or undefined when it is not one. */
export function artifactKind(data: unknown): ArtifactKind | undefined {
  if (!isRecord(data)) return undefined;
  if (data['kind'] === 'agent-guard-description') return 'description';
  if (data['evidenceKind'] === 'host_asserted' && Array.isArray(data['agents'])) return 'manifest';
  if (typeof data['profile'] === 'string' && Array.isArray(data['tools']) && Array.isArray(data['tasks']))
    return 'inventory';
  return undefined;
}

function readTool(raw: unknown, path: string, text: string, i: number): GuardTool {
  if (!isRecord(raw)) throw new Malformed(`tools[${i}] must be an object`);
  const name = str(raw['name'], `tools[${i}].name`);
  return {
    name,
    fingerprint: optStr(raw['fingerprint']),
    registered: raw['registered'] === undefined ? true : bool(raw['registered'], `tools[${i}].registered`),
    approved: bool(raw['approved'], `tools[${i}].approved`),
    requiresApproval: optBool(raw['requiresApproval']),
    readsUntrusted: optBool(raw['readsUntrusted']),
    untrustedContext: mode(raw['untrustedContext']),
    sendsExternal: optBool(raw['sendsExternal']),
    location: { file: path, line: lineOf(text, JSON.stringify(name)) },
  };
}

function readTask(raw: unknown, path: string, text: string, i: number): GuardTask {
  if (!isRecord(raw)) throw new Malformed(`tasks[${i}] must be an object`);
  const id = str(raw['id'], `tasks[${i}].id`);
  const budget = raw['budget'];
  if (!isRecord(budget)) throw new Malformed(`tasks[${i}].budget must be an object`);
  return {
    id,
    principalId: str(raw['principalId'], `tasks[${i}].principalId`),
    parentTaskId: optStr(raw['parentTaskId']),
    grants: list(raw['grants'], `tasks[${i}].grants`).map((grant, g) => {
      if (!isRecord(grant)) throw new Malformed(`tasks[${i}].grants[${g}] must be an object`);
      return {
        tool: str(grant['tool'], `tasks[${i}].grants[${g}].tool`),
        resources: list(grant['resources'], `tasks[${i}].grants[${g}].resources`).map((r, k) =>
          str(r, `tasks[${i}].grants[${g}].resources[${k}]`),
        ),
      };
    }),
    budget: {
      maxCalls: num(budget['maxCalls'], `tasks[${i}].budget.maxCalls`),
      maxConcurrent: num(budget['maxConcurrent'], `tasks[${i}].budget.maxConcurrent`),
      maxCost: num(budget['maxCost'], `tasks[${i}].budget.maxCost`),
      deadline: num(budget['deadline'], `tasks[${i}].budget.deadline`),
    },
    allowedRecipients:
      raw['allowedRecipients'] === undefined || raw['allowedRecipients'] === null
        ? null
        : list(raw['allowedRecipients'], `tasks[${i}].allowedRecipients`).map((r, k) =>
            str(r, `tasks[${i}].allowedRecipients[${k}]`),
          ),
    revoked: bool(raw['revoked'], `tasks[${i}].revoked`),
    sensitive: optBool(raw['sensitive']),
    untrusted: optBool(raw['untrusted']),
    location: { file: path, line: lineOf(text, JSON.stringify(id)) },
  };
}

function readManifest(data: Record<string, unknown>, path: string, text: string) {
  const agents = list(data['agents'], 'agents').map((raw, i): GuardManifestAgent => {
    if (!isRecord(raw)) throw new Malformed(`agents[${i}] must be an object`);
    const id = str(raw['id'], `agents[${i}].id`);
    return {
      id,
      name: optStr(raw['name']) ?? id,
      ownerId: optStr(raw['ownerId']),
      lifecycleState: optStr(raw['lifecycleState']) ?? 'unknown',
      ownershipStatus: optStr(raw['ownershipStatus']) ?? 'unknown',
      location: { file: path, line: lineOf(text, JSON.stringify(id)) },
    };
  });
  const deployments = list(data['deployments'] ?? [], 'deployments').map((raw, i) => {
    if (!isRecord(raw)) throw new Malformed(`deployments[${i}] must be an object`);
    return { id: str(raw['id'], `deployments[${i}].id`), agentId: str(raw['agentId'], `deployments[${i}].agentId`) };
  });
  const taskBindings = list(data['taskBindings'] ?? [], 'taskBindings').map((raw, i) => {
    if (!isRecord(raw)) throw new Malformed(`taskBindings[${i}] must be an object`);
    return {
      taskId: str(raw['taskId'], `taskBindings[${i}].taskId`),
      deploymentId: str(raw['deploymentId'], `taskBindings[${i}].deploymentId`),
    };
  });
  const resourceBindings = list(data['resourceBindings'] ?? [], 'resourceBindings').map(
    (raw, i): GuardResourceBinding => {
      if (!isRecord(raw)) throw new Malformed(`resourceBindings[${i}] must be an object`);
      return {
        id: str(raw['id'], `resourceBindings[${i}].id`),
        tool: str(raw['tool'], `resourceBindings[${i}].tool`),
        resourceRef: optStr(raw['resourceRef']),
        scope: raw['scope'] === 'prefix' ? 'prefix' : 'exact',
        sensitivity: optStr(raw['sensitivity']) ?? 'unknown',
      };
    },
  );
  const directAccess = list(data['directAccess'] ?? [], 'directAccess').map((raw, i): GuardDirectAccess => {
    if (!isRecord(raw)) throw new Malformed(`directAccess[${i}] must be an object`);
    const id = str(raw['id'], `directAccess[${i}].id`);
    return {
      id,
      deploymentId: str(raw['deploymentId'], `directAccess[${i}].deploymentId`),
      kind: str(raw['kind'], `directAccess[${i}].kind`),
      targetRef: optStr(raw['targetRef']),
      description: optStr(raw['description']) ?? '',
      location: { file: path, line: lineOf(text, JSON.stringify(id)) },
    };
  });
  return { agents, deployments, taskBindings, resourceBindings, directAccess };
}

/** Merges every Agent Guard file into one evidence set. Malformed files go to `errors`. */
export function readAgentGuardFiles(
  files: readonly { readonly path: string; readonly text: string; readonly data: unknown }[],
  errors: { file: string; message: string }[],
): AgentGuardEvidence {
  const out = {
    files: [] as { path: string; kind: ArtifactKind }[],
    untrustedContextDefault: null as UntrustedMode | null,
    tools: new Map<string, GuardTool>(),
    tasks: [] as GuardTask[],
    observedAt: null as number | null,
    agents: [] as GuardManifestAgent[],
    deployments: [] as { id: string; agentId: string }[],
    taskBindings: [] as { taskId: string; deploymentId: string }[],
    resourceBindings: [] as GuardResourceBinding[],
    directAccess: [] as GuardDirectAccess[],
    mcpConnections: null as GuardMcpConnection[] | null,
  };
  for (const file of files) {
    const kind = artifactKind(file.data);
    if (!kind || !isRecord(file.data)) continue;
    const data = file.data;
    try {
      if (kind === 'description' || kind === 'inventory') {
        if (kind === 'description' && data['schemaVersion'] !== 1)
          throw new Malformed(`unsupported describe() schemaVersion ${String(data['schemaVersion'])}`);
        if (kind === 'inventory' && data['schemaVersion'] !== 1 && data['schemaVersion'] !== 2)
          throw new Malformed(`unsupported inventory schemaVersion ${String(data['schemaVersion'])}`);
        const tools = list(data['tools'], 'tools').map((raw, i) => readTool(raw, file.path, file.text, i));
        const tasks =
          kind === 'inventory'
            ? list(data['tasks'], 'tasks').map((raw, i) => readTask(raw, file.path, file.text, i))
            : [];
        out.untrustedContextDefault ??= mode(data['untrustedContextDefault']);
        for (const tool of tools) out.tools.set(tool.name, tool);
        out.tasks.push(...tasks);
        const at = typeof data['generatedAt'] === 'string' ? Date.parse(data['generatedAt']) : NaN;
        if (Number.isFinite(at)) out.observedAt = Math.max(out.observedAt ?? 0, at);
        if (kind === 'inventory' && isRecord(data['mcp']) && Array.isArray(data['mcp']['connections'])) {
          out.mcpConnections ??= [];
          for (const record of data['mcp']['connections']) {
            if (!isRecord(record) || record['status'] !== 'observed' || !isRecord(record['inventory'])) continue;
            const identity = record['inventory']['identity'];
            if (isRecord(identity) && typeof identity['serverId'] === 'string')
              out.mcpConnections.push({
                serverId: identity['serverId'],
                state: String(record['inventory']['state'] ?? ''),
              });
          }
        }
        if (kind === 'inventory' && isRecord(data['manifest'])) {
          const embedded = readManifest(data['manifest'], file.path, file.text);
          out.agents.push(...embedded.agents);
          out.deployments.push(...embedded.deployments);
          out.taskBindings.push(...embedded.taskBindings);
          out.resourceBindings.push(...embedded.resourceBindings);
          out.directAccess.push(...embedded.directAccess);
        }
      } else {
        if (![1, 2, 3].includes(data['schemaVersion'] as number))
          throw new Malformed(`unsupported manifest schemaVersion ${String(data['schemaVersion'])}`);
        const manifest = readManifest(data, file.path, file.text);
        out.agents.push(...manifest.agents);
        out.deployments.push(...manifest.deployments);
        out.taskBindings.push(...manifest.taskBindings);
        out.resourceBindings.push(...manifest.resourceBindings);
        out.directAccess.push(...manifest.directAccess);
      }
      out.files.push({ path: file.path, kind });
    } catch (error) {
      errors.push({
        file: file.path,
        message: `Agent Guard ${kind}: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  return {
    ...out,
    tools: [...out.tools.values()].sort((a, b) => a.name.localeCompare(b.name)),
  };
}

/** The mode a tool runs in after untrusted content: its own, else the guard default. */
export function effectiveMode(tool: GuardTool, evidence: AgentGuardEvidence): UntrustedMode | null {
  return tool.untrustedContext ?? evidence.untrustedContextDefault;
}

export type Leg = 'present' | 'absent' | 'unknown';

export interface TaskExposure {
  readonly task: GuardTask;
  readonly status: 'exposed' | 'mitigated' | 'unknown' | 'absent';
  readonly legs: { readonly privateData: Leg; readonly outsideContent: Leg; readonly externalSend: Leg };
  readonly evidence: readonly string[];
  readonly senders: readonly string[];
}

const SENSITIVE = new Set(['confidential', 'restricted']);

function combine(legs: readonly Leg[]): Leg {
  return legs.includes('present') ? 'present' : legs.includes('unknown') ? 'unknown' : 'absent';
}

/**
 * The dangerous three for one live task, following Agent Map's rules: private data from a sensitive
 * task or a confidential/restricted binding; outside content from an untrusted task or a tool that
 * reads untrusted content; sending from a tool that declares `sendsExternal: true`, unless the task
 * is sensitive or has no recipients (the core refuses those sends). Undeclared means unknown.
 */
export function taskExposure(task: GuardTask, evidence: AgentGuardEvidence): TaskExposure {
  const tools = new Map(evidence.tools.map(tool => [tool.name, tool]));
  const privateLegs: Leg[] = [];
  const outsideLegs: Leg[] = [];
  const sendLegs: Leg[] = [];
  const notes: string[] = [];
  const senders: { tool: string; mode: UntrustedMode | null }[] = [];
  if (task.sensitive === true) {
    privateLegs.push('present');
    notes.push('task is sensitive');
  } else if (task.sensitive === null) privateLegs.push('unknown');
  if (task.untrusted === true) {
    outsideLegs.push('present');
    notes.push('task has read untrusted content');
  }
  const granted = new Set<string>();
  for (const grant of task.grants) {
    granted.add(grant.tool);
    const bindings = evidence.resourceBindings.filter(binding => binding.tool === grant.tool);
    const judge = (binding: GuardResourceBinding): void => {
      if (SENSITIVE.has(binding.sensitivity)) {
        privateLegs.push('present');
        notes.push(`${grant.tool} reaches ${binding.sensitivity} binding ${binding.id}`);
      } else
        privateLegs.push(binding.sensitivity === 'public' || binding.sensitivity === 'internal' ? 'absent' : 'unknown');
    };
    if (grant.resources.includes('*')) {
      // `*` covers resources nobody described: present on a sensitive binding, else unknown.
      const sensitive = bindings.filter(binding => SENSITIVE.has(binding.sensitivity));
      sensitive.forEach(judge);
      if (!sensitive.length) privateLegs.push('unknown');
    }
    for (const resource of grant.resources) {
      if (resource === '*') continue;
      const matched = bindings.filter(binding =>
        binding.resourceRef === null
          ? false
          : binding.scope === 'prefix'
            ? resource.startsWith(binding.resourceRef)
            : binding.resourceRef === resource,
      );
      if (!matched.length) privateLegs.push('unknown');
      matched.forEach(judge);
    }
  }
  for (const name of granted) {
    const tool = tools.get(name);
    if (!tool || !tool.registered) {
      outsideLegs.push('unknown');
      sendLegs.push('unknown');
      continue;
    }
    if (tool.readsUntrusted === true) {
      outsideLegs.push('present');
      notes.push(`${tool.name} reads untrusted content`);
    } else outsideLegs.push(tool.readsUntrusted === false ? 'absent' : 'unknown');
    if (tool.sendsExternal === false) sendLegs.push('absent');
    else if (tool.sendsExternal === true) {
      if (task.sensitive === true || task.allowedRecipients?.length === 0) {
        sendLegs.push('absent');
        continue;
      }
      sendLegs.push(task.sensitive === null || task.allowedRecipients === null ? 'unknown' : 'present');
      senders.push({ tool: tool.name, mode: effectiveMode(tool, evidence) });
      notes.push(`${tool.name} sends data out`);
    } else sendLegs.push('unknown');
  }
  const legs = {
    privateData: combine(privateLegs),
    outsideContent: combine(outsideLegs),
    externalSend: combine(sendLegs),
  };
  const values = Object.values(legs);
  const status = values.includes('absent')
    ? 'absent'
    : values.includes('unknown')
      ? 'unknown'
      : senders.some(sender => sender.mode === 'allow')
        ? 'exposed'
        : senders.length && senders.every(sender => sender.mode === 'require_approval' || sender.mode === 'deny')
          ? 'mitigated'
          : 'unknown';
  return { task, status, legs, evidence: notes, senders: senders.map(sender => sender.tool) };
}

/**
 * Whether a task can still run: it and every delegation ancestor in the snapshot are not revoked
 * and, when the snapshot time is known, not past their deadlines (the core checks the whole chain).
 */
export function isLive(task: GuardTask, evidence: AgentGuardEvidence): boolean {
  const byId = new Map(evidence.tasks.map(item => [item.id, item]));
  let current: GuardTask | undefined = task;
  for (let depth = 0; current && depth <= 16; depth += 1) {
    if (current.revoked) return false;
    if (evidence.observedAt !== null && current.budget.deadline <= evidence.observedAt) return false;
    current = current.parentTaskId === null ? undefined : byId.get(current.parentTaskId);
  }
  return true;
}
