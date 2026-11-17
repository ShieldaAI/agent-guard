import { CAPABILITIES, type Agent, type Capability, type CapabilityState, type Grant, type Mediator } from './types.js';

/** Longer matchers are not credited: real ones are short, and a long one is not worth evaluating. */
const MAX_MATCHER_LENGTH = 512;
/** Alternatives that accept every tool name. */
const EVERY_TOOL = new Set(['', '*', '.*', '.+', '(.*)', '(.+)', '(?:.*)', '(?:.+)']);

/**
 * A matcher Claude Code would run, or undefined. It must be a valid regular expression on its own:
 * `Bash)|(?:.*` is invalid, so Claude Code never fires that hook, even though wrapping it would
 * make it match everything.
 */
function validMatcher(matcher: string): string | undefined {
  const value = matcher.trim();
  if (value === '' || value === '*') return value;
  if (value.length > MAX_MATCHER_LENGTH) return undefined;
  try {
    new RegExp(value);
    return value;
  } catch {
    return undefined;
  }
}

/** Splits a valid pattern at its top-level `|`, unwrapping groups that span a whole alternative. */
function alternatives(pattern: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let inClass = false;
  let start = 0;
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i]!;
    if (char === '\\') {
      i += 1;
      continue;
    }
    if (inClass) {
      if (char === ']') inClass = false;
      continue;
    }
    if (char === '[') inClass = true;
    else if (char === '(') depth += 1;
    else if (char === ')') depth -= 1;
    else if (char === '|' && depth === 0) {
      parts.push(pattern.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(pattern.slice(start));
  return parts.flatMap(part => {
    const trimmed = part.trim();
    const group = /^\((?:\?:)?([\s\S]*)\)$/.exec(trimmed);
    // Unwrap only when the parentheses enclose the whole alternative: `(a)|(b)` is not one group.
    if (group && balanced(group[1]!)) return alternatives(group[1]!);
    return [trimmed];
  });
}

function balanced(pattern: string): boolean {
  let depth = 0;
  for (let i = 0; i < pattern.length; i += 1) {
    if (pattern[i] === '\\') i += 1;
    else if (pattern[i] === '(') depth += 1;
    else if (pattern[i] === ')' && (depth -= 1) < 0) return false;
  }
  return depth === 0;
}

/**
 * Whether a runtime check sees calls of one tool, as grants name tools (`Bash`, `WebFetch`,
 * `mcp__server`, `*`). A guard or gateway reached over MCP sees only the calls made through it.
 * A grant with no tool (a workflow token, a sandbox setting) is never seen.
 *
 * A hook matcher is a regular expression from the repository. It is only ever run against the
 * scanner's own short tool names (`Bash`, `WebFetch`), never against a name the repository chose,
 * so it cannot make the scan hang. For an MCP server and for `*`, coverage is decided from the
 * matcher's shape instead: an alternative must accept every tool (`.*`), every MCP tool
 * (`mcp__.*`) or every tool of that server (`mcp__server__.*`). One named tool is not the server.
 */
export function mediates(mediator: Mediator, tool: string | undefined): boolean {
  if (tool === undefined) return false;
  if (mediator.kind !== 'pre-tool-hook') return mediator.server !== undefined && tool === `mcp__${mediator.server}`;
  const matcher = validMatcher(mediator.matcher ?? '');
  if (matcher === undefined) return false;
  if (matcher === '' || matcher === '*') return true;
  const alts = alternatives(matcher);
  if (alts.some(alt => EVERY_TOOL.has(alt))) return true;
  if (tool === '*') return false;
  if (tool.startsWith('mcp__')) {
    const server = tool.slice('mcp__'.length);
    return alts.some(alt => ['mcp__.*', 'mcp__.+', `${tool}__.*`, `${tool}__.+`].includes(alt) && server !== '');
  }
  return new RegExp(`^(?:${matcher})$`).test(tool);
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
