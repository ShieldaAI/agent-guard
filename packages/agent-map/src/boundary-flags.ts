import type { GuardRelation, JsonObject, MapNode } from './types.js';

/**
 * "Dangerous three": a live task of an agent that can read private data, read outside
 * content and send data out. Declared evidence only; a flag is never a permission decision,
 * and missing or old data reads as `unknown`, never as safe.
 */
export type Leg = 'present' | 'absent' | 'unknown';
export type DangerousThreeStatus = 'exposed' | 'mitigated' | 'unknown' | 'absent';
type Mode = 'allow' | 'require_approval' | 'deny';

/** The read-only graph access the computation needs; the service supplies its bounded index. */
export interface FlagGraph {
  linked(node: MapNode, kind: GuardRelation, reverse?: boolean): MapNode[];
  /** In-scope bindings of a tool marked confidential or restricted (at most five), for `*` grants. */
  sensitiveBindings(tool: string): readonly { readonly id: string; readonly sensitivity: string }[];
  step(amount?: number): void;
}
export interface FlagEvidence {
  readonly leg: 'privateData' | 'outsideContent' | 'externalSend' | 'mitigation';
  readonly taskId: string;
  readonly reason: string;
  readonly tool?: string;
  readonly resourceBindingId?: string;
}
export interface DangerousThree {
  readonly kind: 'dangerous_three';
  readonly status: DangerousThreeStatus;
  /** The task that decides the status; legs and evidence both describe this task. */
  readonly taskId: string | null;
  readonly legs: { readonly privateData: Leg; readonly outsideContent: Leg; readonly externalSend: Leg };
  readonly evidence: readonly FlagEvidence[];
  readonly evidenceTruncated: boolean;
  readonly notes: readonly string[];
  readonly liveTasks: number;
  readonly evidenceKind: 'declared';
  readonly assessment: 'unknown';
  readonly limitations: readonly string[];
}

// An unknown task may be exposed, so it outranks a mitigated one: amber never hides grey.
const RANK: Readonly<Record<DangerousThreeStatus, number>> = { absent: 0, mitigated: 1, unknown: 2, exposed: 3 };
const SENSITIVE = new Set(['confidential', 'restricted']);
const MITIGATING = new Set<Mode | null>(['require_approval', 'deny']);
/** Evidence items kept per leg (and for mitigation), so no present leg loses all of its evidence. */
const MAX_EVIDENCE_PER_LEG = 8;
function cappedEvidence(evidence: readonly FlagEvidence[]): { items: FlagEvidence[]; truncated: boolean } {
  const kept = new Map<FlagEvidence['leg'], number>();
  const items = evidence.filter(item => {
    const count = (kept.get(item.leg) ?? 0) + 1;
    kept.set(item.leg, count);
    return count <= MAX_EVIDENCE_PER_LEG;
  });
  return { items, truncated: items.length < evidence.length };
}
const MAX_DEPTH = 16;
export const DANGEROUS_THREE_LIMITATIONS: readonly string[] = Object.freeze([
  'Declared grants and labels; not proof that data can leave.',
  'Only sends that the resolver marks external are checked; a tool that does not declare sendsExternal is unknown.',
]);

const text = (node: MapNode, key: string): string | null =>
  typeof node.properties[key] === 'string' ? (node.properties[key] as string) : null;
const list = (node: MapNode, key: string): readonly string[] | null => {
  const value = node.properties[key];
  return Array.isArray(value) && value.every(item => typeof item === 'string') ? (value as string[]) : null;
};
/** present beats unknown beats absent; an empty set of contributions is absent. */
function combine(legs: readonly Leg[]): Leg {
  return legs.includes('present') ? 'present' : legs.includes('unknown') ? 'unknown' : 'absent';
}

interface Lineage {
  readonly live: boolean;
  readonly recipients: readonly string[] | null;
  /** A delegation parent exists but this read cannot see it. */
  readonly hidden: boolean;
  readonly depthExceeded: boolean;
  /** An older import never recorded whether the task has a parent. */
  readonly unrecorded: boolean;
  /** More than one parent edge: malformed, so the chain says nothing. */
  readonly ambiguous: boolean;
  /** A `revoked` or `deadline` on the chain is missing, or the snapshot time does not parse. */
  readonly unverified: boolean;
}
const LINEAGE: Lineage = {
  live: true,
  recipients: null,
  hidden: false,
  depthExceeded: false,
  unrecorded: false,
  ambiguous: false,
  unverified: false,
};

/** Follows one link kind from a task to the tasks it names (delegation parent, handoff source). */
export type TaskLinks = (node: MapNode, kind: 'G_DELEGATED_FROM' | 'G_DERIVED_FROM') => MapNode[];
export interface TaskLiveness {
  readonly live: boolean;
  /** A linked task exists but this read cannot see it. */
  readonly hidden: boolean;
  readonly depthExceeded: boolean;
  /** An older import never recorded whether the task has a parent or a source. */
  readonly unrecorded: boolean;
  /** More than one parent or source: malformed, so the chain says nothing. */
  readonly ambiguous: boolean;
  /**
   * A task on the chain lacks a boolean `revoked`, or one on the delegation chain lacks a
   * numeric `deadline`: it is treated as live, but that was not established.
   */
  readonly unverified: boolean;
}

/**
 * The executor refuses a task when it or any task it descends from (delegation parents and
 * handoff sources, transitively) is revoked, and when it or a delegation ancestor has expired;
 * a handoff source's deadline does not bind the task. Walk up to MAX_DEPTH hops, the same reach
 * as the store's ancestor read, so the one-agent and team-wide reads stop at the same place. A
 * link that leaves the read makes liveness incomplete; the caller treats that as unknown.
 */
export function taskLiveness(links: TaskLinks, task: MapNode, observedAt: number, step: () => void): TaskLiveness {
  const result = {
    live: true,
    hidden: false,
    depthExceeded: false,
    unrecorded: false,
    ambiguous: false,
    unverified: false,
  };
  let dead = false;
  // The task's own state needs no chain: malformed links cannot make it live again.
  const own =
    task.properties.revoked === true ||
    (typeof task.properties.deadline === 'number' && task.properties.deadline <= observedAt);
  // Deadlines: the task and its delegation parents only.
  for (let current = task, depth = 0; ; depth++) {
    step();
    const deadline = current.properties.deadline;
    if (typeof deadline !== 'number') result.unverified = true;
    else if (deadline <= observedAt) dead = true;
    const parents = links(current, 'G_DELEGATED_FROM').filter(item => item.label === 'GuardTask');
    if (parents.length !== 1 || depth >= MAX_DEPTH) break;
    current = parents[0]!;
  }
  // Revocation, and whether the chain is complete: every task reachable through both links.
  const seen = new Set([task.id]);
  let frontier = [task];
  for (let depth = 0; frontier.length; depth++) {
    const next: MapNode[] = [];
    for (const node of frontier) {
      step();
      if (node.properties.revoked === true) dead = true;
      else if (node.properties.revoked !== false) result.unverified = true;
      for (const [kind, recorded] of [
        ['G_DELEGATED_FROM', node.properties.delegated],
        ['G_DERIVED_FROM', node.properties.derived],
      ] as const) {
        if (recorded !== true && recorded !== false) result.unrecorded = true;
        // Past MAX_DEPTH hops nothing new is read, in either read, so a recorded link is a cut
        // unless it leads back to a task already read within reach.
        if (depth >= MAX_DEPTH) {
          const known = links(node, kind).filter(item => item.label === 'GuardTask');
          if (recorded === true && !(known.length === 1 && seen.has(known[0]!.id))) result.depthExceeded = true;
          continue;
        }
        const linked = links(node, kind).filter(item => item.label === 'GuardTask');
        // Two visible links of one kind are malformed. (A second one outside a team reader's
        // read is not seen; the collector writes one parent and one source per task.)
        if (linked.length > 1) result.ambiguous = true;
        if (!linked.length && recorded === true) result.hidden = true;
        for (const item of linked) {
          if (seen.has(item.id)) continue;
          seen.add(item.id);
          next.push(item);
        }
      }
    }
    frontier = next;
  }
  // A revoked or expired task on a malformed chain proves nothing about this task: unknown.
  return own || (dead && !result.ambiguous) ? { ...result, live: false } : result;
}

/**
 * Liveness over delegation parents and handoff sources, and the effective recipient set: the
 * core checks recipients against every delegation ancestor, so any gap leaves it unknown.
 */
function lineage(graph: FlagGraph, task: MapNode, observedAt: number): Lineage {
  const life = taskLiveness(
    (node, kind) => graph.linked(node, kind),
    task,
    observedAt,
    () => graph.step(),
  );
  if (!life.live) return { ...LINEAGE, live: false };
  const complete = !life.hidden && !life.unrecorded && !life.depthExceeded && !life.ambiguous;
  let recipients: Set<string> | null = complete ? new Set(list(task, 'allowed_recipients') ?? []) : null;
  if (list(task, 'allowed_recipients') === null) recipients = null;
  for (let current = task, depth = 0; recipients !== null && depth <= MAX_DEPTH; depth++) {
    const parent = graph.linked(current, 'G_DELEGATED_FROM').find(node => node.label === 'GuardTask');
    if (!parent) break;
    const allowed = list(parent, 'allowed_recipients');
    recipients = allowed === null ? null : new Set([...recipients].filter(item => allowed.includes(item)));
    current = parent;
  }
  return {
    live: true,
    recipients: recipients === null ? null : [...recipients].sort(),
    hidden: life.hidden,
    depthExceeded: life.depthExceeded,
    unrecorded: life.unrecorded,
    ambiguous: life.ambiguous,
    // Without a snapshot time expiry cannot be judged at all.
    unverified: life.unverified || Number.isNaN(observedAt),
  };
}

interface TaskResult {
  readonly taskId: string;
  readonly status: DangerousThreeStatus;
  readonly legs: DangerousThree['legs'];
  readonly evidence: FlagEvidence[];
  readonly chain: Lineage;
}

function evaluateTask(graph: FlagGraph, task: MapNode, observedAt: number): TaskResult | null {
  const chain = lineage(graph, task, observedAt);
  if (!chain.live) return null;
  const taskId = task.entityId;
  const evidence: FlagEvidence[] = [];
  const grants = graph.linked(task, 'G_HAS_GRANT').filter(node => node.label === 'GuardGrant');
  const privateLegs: Leg[] = [],
    outsideLegs: Leg[] = [],
    sendLegs: Leg[] = [];

  // Private data: the task is already sensitive, or a granted binding is marked sensitive.
  const sensitiveTask = task.properties.sensitive === true;
  // A missing or malformed `sensitive` may hide private data and a send block alike.
  const sensitiveKnown = typeof task.properties.sensitive === 'boolean';
  if (sensitiveTask) {
    privateLegs.push('present');
    evidence.push({ leg: 'privateData', taskId, reason: 'task_sensitive' });
  } else if (!sensitiveKnown) privateLegs.push('unknown');
  const binding = (node: MapNode, tool: string): void => {
    const sensitivity = text(node, 'sensitivity');
    if (sensitivity !== null && SENSITIVE.has(sensitivity)) {
      privateLegs.push('present');
      evidence.push({
        leg: 'privateData',
        taskId,
        reason: `binding_${sensitivity}`,
        tool,
        resourceBindingId: node.entityId,
      });
    } else privateLegs.push(sensitivity === 'public' || sensitivity === 'internal' ? 'absent' : 'unknown');
  };
  const tools = new Map<string, MapNode | null>();
  for (const grant of grants) {
    const tool = text(grant, 'tool');
    const resources = list(grant, 'resources');
    if (tool === null || resources === null) {
      // A malformed grant says nothing about any leg.
      privateLegs.push('unknown');
      outsideLegs.push('unknown');
      sendLegs.push('unknown');
      continue;
    }
    const toolNodes = graph
      .linked(grant, 'G_FOR_TOOL')
      .filter(node => node.label === 'GuardTool' && text(node, 'name') === tool);
    if (!tools.has(tool) || toolNodes.length === 1) tools.set(tool, toolNodes.length === 1 ? toolNodes[0]! : null);
    if (resources.includes('*')) {
      // `*` covers every resource of the tool, including ones the host never described: present
      // when an in-scope binding of the tool is sensitive, otherwise unknown.
      const matches = graph.sensitiveBindings(tool);
      graph.step(matches.length + 1);
      for (const match of matches) {
        privateLegs.push('present');
        evidence.push({
          leg: 'privateData',
          taskId,
          reason: `binding_${match.sensitivity}`,
          tool,
          resourceBindingId: match.id,
        });
      }
      if (!matches.length) privateLegs.push('unknown');
    }
    const reached = new Set<string>();
    for (const selector of graph.linked(grant, 'G_TARGETS').filter(node => node.label === 'GuardResource')) {
      const selected = text(selector, 'resource_id');
      if (selected === '*' || selected === null || !resources.includes(selected)) continue;
      reached.add(selected);
      const bindings = graph
        .linked(selector, 'G_BINDS_SELECTOR', true)
        .filter(node => node.label === 'GuardResourceBinding' && text(node, 'tool') === tool);
      // A granted resource the host never described has unknown sensitivity.
      if (!bindings.length) privateLegs.push('unknown');
      for (const node of bindings) binding(node, tool);
    }
    // A granted resource with no selector in the read says nothing about its data.
    if (resources.some(resource => resource !== '*' && !reached.has(resource))) privateLegs.push('unknown');
  }

  // Outside content and sending, per granted tool. A resolver can mark any call untrusted, so
  // only an explicit `readsUntrusted: false` rules a tool out; undeclared stays unknown.
  if (task.properties.untrusted === true) {
    outsideLegs.push('present');
    evidence.push({ leg: 'outsideContent', taskId, reason: 'task_untrusted' });
  }
  // The core refuses every external send from a sensitive family, and from a task whose
  // effective recipient set is empty. Both stop only sends a resolver marks external, which
  // is what `sendsExternal: true` promises; an undeclared tool may send unmarked.
  const noRecipients = chain.recipients !== null && chain.recipients.length === 0;
  const senders: { tool: string; declared: boolean; mode: Mode | null }[] = [];
  for (const [tool, node] of tools) {
    graph.step();
    const registered = node !== null && node.properties.registered === true && node.properties.known_metadata !== false;
    if (!registered) {
      outsideLegs.push('unknown');
      sendLegs.push('unknown');
      senders.push({ tool, declared: false, mode: null });
      continue;
    }
    const reads = node.properties.reads_untrusted;
    if (reads === true) {
      outsideLegs.push('present');
      evidence.push({ leg: 'outsideContent', taskId, reason: 'tool_reads_untrusted', tool });
    } else outsideLegs.push(reads === false ? 'absent' : 'unknown');
    const mode = (text(node, 'untrusted_context') ?? text(node, 'untrusted_context_default')) as Mode | null;
    const sends = node.properties.sends_external;
    if (sends === false) sendLegs.push('absent');
    else if (sends === true) {
      const blocked = sensitiveTask ? 'sensitive_egress_denied' : noRecipients ? 'no_effective_recipients' : null;
      if (blocked) {
        sendLegs.push('absent');
        evidence.push({ leg: 'externalSend', taskId, reason: blocked, tool });
        continue;
      }
      sendLegs.push(chain.recipients === null || !sensitiveKnown ? 'unknown' : 'present');
      senders.push({ tool, declared: true, mode });
      evidence.push({ leg: 'externalSend', taskId, reason: 'tool_sends_external', tool });
    } else {
      sendLegs.push('unknown');
      senders.push({ tool, declared: false, mode });
    }
  }

  const legs = {
    privateData: combine(privateLegs),
    outsideContent: combine(outsideLegs),
    externalSend: combine(sendLegs),
  };
  const values = Object.values(legs);
  let status: DangerousThreeStatus;
  if (values.includes('absent')) status = 'absent';
  else if (values.includes('unknown')) status = 'unknown';
  else if (senders.some(sender => sender.declared && sender.mode === 'allow')) status = 'exposed';
  else if (senders.every(sender => MITIGATING.has(sender.mode))) {
    status = 'mitigated';
    for (const sender of senders)
      evidence.push({ leg: 'mitigation', taskId, reason: `untrusted_context_${sender.mode}`, tool: sender.tool });
  } else status = 'unknown';
  // A chain read only in part (an ancestor hidden, not loaded, unrecorded or too deep), or
  // one whose revocation or expiry facts are missing, may hold a revoked or expired ancestor,
  // so the task may not be live: never call it absent.
  if (
    status === 'absent' &&
    (chain.hidden || chain.unrecorded || chain.depthExceeded || chain.ambiguous || chain.unverified)
  )
    status = 'unknown';
  return { taskId, status, legs, evidence, chain };
}

/** One status per agent: the worst of its live tasks. Legs and evidence describe that task. */
export function dangerousThree(
  graph: FlagGraph,
  agent: MapNode,
  observedAt: number,
  allTeams: boolean,
  /** The read had no room for delegation ancestors: missing parents are not a scope matter. */
  ancestorsNotLoaded = false,
): DangerousThree {
  const deployments = graph.linked(agent, 'G_INSTANCE_OF', true).filter(node => node.label === 'GuardDeployment');
  const tasks = deployments.flatMap(deployment =>
    graph.linked(deployment, 'G_ASSIGNED_TO', true).filter(node => node.label === 'GuardTask'),
  );
  const results = tasks
    .map(task => evaluateTask(graph, task, observedAt))
    .filter((item): item is TaskResult => item !== null)
    // A stable choice among equally bad tasks, independent of read order.
    .sort((a, b) => RANK[b.status] - RANK[a.status] || (a.taskId < b.taskId ? -1 : a.taskId > b.taskId ? 1 : 0));
  const notes: string[] = [];
  if (!results.length) notes.push('no_live_tasks');
  if (results.some(item => item.chain.hidden)) {
    if (ancestorsNotLoaded) notes.push('delegation_ancestors_not_loaded');
    else notes.push(allTeams ? 'delegation_parent_missing' : 'ancestor_evidence_outside_visible_scope');
  }
  if (results.some(item => item.chain.ambiguous)) notes.push('delegation_evidence_ambiguous');
  if (results.some(item => item.chain.unverified)) notes.push('task_liveness_unverified');
  if (results.some(item => item.chain.unrecorded)) notes.push('delegation_not_recorded');
  if (results.some(item => item.chain.depthExceeded)) notes.push('delegation_depth_exceeded');
  const worst = results[0] ?? null;
  const listed = cappedEvidence(worst?.evidence ?? []);
  return {
    kind: 'dangerous_three',
    status: worst?.status ?? 'unknown',
    taskId: worst?.taskId ?? null,
    legs: worst?.legs ?? { privateData: 'unknown', outsideContent: 'unknown', externalSend: 'unknown' },
    evidence: listed.items,
    evidenceTruncated: listed.truncated,
    notes,
    liveTasks: results.length,
    evidenceKind: 'declared',
    assessment: 'unknown',
    limitations: DANGEROUS_THREE_LIMITATIONS,
  };
}

export const dangerousThreeJson = (value: DangerousThree): JsonObject => value as unknown as JsonObject;
