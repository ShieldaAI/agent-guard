import { CAPABILITIES, type Agent, type Capability, type CapabilityState, type Grant, type Mediator } from './types.js';

/** Tool names a matcher must accept to count as seeing every call (an allow rule of `*`). */
const EVERY_TOOL_PROBES = ['Bash', 'WebFetch', 'WebSearch', 'Edit', 'Write', 'AgcProbeTool', 'mcp__agcprobe__agcprobe'];

/** Whether a Claude Code hook matcher accepts a tool name. Matchers are case-sensitive and match the whole name. */
function matcherAccepts(matcher: string, name: string): boolean {
  const value = matcher.trim();
  if (value === '' || value === '*') return true;
  try {
    return new RegExp(`^(?:${value})$`).test(name);
  } catch {
    return false;
  }
}

/**
 * Whether a runtime check sees calls of one tool, as grants name tools (`Bash`, `WebFetch`,
 * `mcp__server`, `*`). A hook must accept every tool of an MCP server (`mcp__server__.*`), not
 * just one of them; a guard or gateway reached over MCP sees only the calls made through it.
 * A grant with no tool (a workflow token, a sandbox setting) is never seen.
 */
export function mediates(mediator: Mediator, tool: string | undefined): boolean {
  if (tool === undefined) return false;
  if (mediator.kind !== 'pre-tool-hook') return mediator.server !== undefined && tool === `mcp__${mediator.server}`;
  const matcher = mediator.matcher ?? '';
  if (tool === '*') return EVERY_TOOL_PROBES.every(name => matcherAccepts(matcher, name));
  if (tool.startsWith('mcp__')) return matcherAccepts(matcher, `${tool}__agcprobe`);
  return matcherAccepts(matcher, tool);
}

/** Whether any of an agent's runtime checks sees this grant's calls. */
export function isMediated(agent: Agent, grant: Grant): boolean {
  return agent.mediators.some(mediator => mediates(mediator, grant.tool));
}

/** What an agent can do for one capability, after headless agents lose their prompt-only paths. */
export function capabilityState(agent: Agent, capability: Capability): CapabilityState {
  const grants = agent.grants.filter(
    grant => grant.capability === capability && !(agent.headless && grant.approval === 'ask'),
  );
  const yes = grants.filter(grant => grant.certainty === 'yes');
  if (yes.length) return { value: 'yes', approval: yes.some(g => g.approval === 'auto') ? 'auto' : 'ask', grants: yes };
  if (grants.length)
    return { value: 'unknown', approval: grants.some(g => g.approval === 'auto') ? 'auto' : 'ask', grants };
  return { value: 'no', approval: null, grants: [] };
}

export function authority(agent: Agent): Record<Capability, CapabilityState> {
  const out = {} as Record<Capability, CapabilityState>;
  for (const capability of CAPABILITIES) out[capability] = capabilityState(agent, capability);
  return out;
}

/** The grant a fix should target: the first one that needs no approval, else the first one. */
export function primaryGrant(state: CapabilityState): Grant | undefined {
  return state.grants.find(grant => grant.approval === 'auto') ?? state.grants[0];
}

/** Ranks how much an agent can do, for diffs: 0 none, 1 unknown, 2 behind approval, 3 without approval. */
export function level(state: CapabilityState): number {
  if (state.value === 'no') return 0;
  if (state.value === 'unknown') return 1;
  return state.approval === 'auto' ? 3 : 2;
}

export function describeLevel(state: CapabilityState): string {
  if (state.value === 'no') return 'no';
  if (state.value === 'unknown') return 'unknown';
  return state.approval === 'auto' ? 'yes, no approval' : 'yes, with approval';
}
