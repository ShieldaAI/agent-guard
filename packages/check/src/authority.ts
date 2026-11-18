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

/** An alternative the scanner can read without running it: a tool name, or a name prefix with `.*` / `.+`. */
const SHAPE = /^([A-Za-z0-9_-]*)(\.\*|\.\+)?$/;

/** Whether one alternative accepts this tool name, read from its shape. Anything else is not credited. */
function shapeAccepts(alt: string, tool: string): boolean {
  const shape = SHAPE.exec(alt);
  if (!shape) return false;
  const [, literal = '', rest] = shape;
  if (rest === undefined) return literal === tool;
  return tool.startsWith(literal) && (rest === '.*' || tool.length > literal.length);
}

/**
 * Whether a runtime check sees calls of one tool, as grants name tools (`Bash`, `WebFetch`,
 * `mcp__server`, `*`). A guard or gateway reached over MCP sees only the calls made through it.
 * A grant with no tool (a workflow token, a sandbox setting) is never seen.
 *
 * A hook matcher is a regular expression from the repository, so the scanner never runs it: a
 * short pattern can backtrack for hours even on a short name. It only checks that the matcher
 * compiles (Claude Code skips one that does not), then reads its alternatives: an exact tool name
 * (`Bash`), a name prefix (`Notebook.*`, `mcp__db__.*`), or every tool (`.*`). An MCP server is
 * covered only by a prefix that takes in all of its tools, never by one named tool. Any other
 * shape, such as a character class, is not credited: under-crediting a check only adds a finding.
 */
export function mediates(mediator: Mediator, tool: string | undefined): boolean {
  if (tool === undefined) return false;
  if (mediator.kind === 'safe-outputs') return tool === 'safe-outputs';
  // Auto mode's safety review sees every tool call the agent makes.
  if (mediator.kind === 'auto-mode') return tool !== 'safe-outputs';
  if (mediator.kind !== 'pre-tool-hook') return mediator.server !== undefined && tool === `mcp__${mediator.server}`;
  const matcher = validMatcher(mediator.matcher ?? '');
  if (matcher === undefined) return false;
  if (matcher === '' || matcher === '*') return true;
  const alts = alternatives(matcher);
  if (alts.some(alt => EVERY_TOOL.has(alt))) return true;
  if (tool === '*') return false;
  // Every tool of a server is `mcp__<server>__<tool>`: a prefix must hold for all of them.
  if (tool.startsWith('mcp__'))
    return alts.some(alt => /\.[*+]$/.test(alt) && shapeAccepts(alt.replace(/\.[*+]$/, '.*'), `${tool}__`));
  return alts.some(alt => shapeAccepts(alt, tool));
}

/** Whether any of an agent's runtime checks sees this grant's calls. */
export function isMediated(agent: Agent, grant: Grant): boolean {
  return agent.mediators.some(mediator =>
    // Calls that match an allow rule are resolved before auto mode's safety review: it sees only
    // the calls the mode itself lets through.
    mediator.kind === 'auto-mode' ? AUTO_MODE_GRANT.test(grant.via) : mediates(mediator, grant.tool),
  );
}

/** The `via` of a grant that auto mode approves (rather than an allow rule). */
const AUTO_MODE_GRANT = /\((defaultMode|permissionMode): auto\)$|\(permission-mode auto\)$/;

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
