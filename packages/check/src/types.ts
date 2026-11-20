/** The seven things an agent can be able to do. */
export const CAPABILITIES = [
  'privateData',
  'untrustedInput',
  'write',
  'exec',
  'egress',
  'spend',
  'selfModify',
] as const;
export type Capability = (typeof CAPABILITIES)[number];

export const CAPABILITY_LABELS: Readonly<Record<Capability, string>> = Object.freeze({
  privateData: 'reads private data',
  untrustedInput: 'reads untrusted input',
  write: 'writes',
  exec: 'runs code',
  egress: 'sends data out',
  spend: 'spends money',
  selfModify: 'changes itself',
});

/**
 * How a capability is reached.
 * - `auto`: no person approves each use.
 * - `ask`: a person approves each use (interactive tools prompt by default).
 */
export type Approval = 'auto' | 'ask';

/** Where a statement in a file comes from. Lines are 1-based. */
export interface Location {
  readonly file: string;
  readonly line: number;
}

/** One reason an agent has a capability. */
export interface Grant {
  readonly capability: Capability;
  readonly via: string;
  /** The tool that carries the grant (`Bash`, `WebFetch`, `mcp__github`), when one does. */
  readonly tool?: string;
  readonly approval: Approval;
  /** `unknown` when the scanner cannot tell whether the path gives the capability. */
  readonly certainty: 'yes' | 'unknown';
  readonly location: Location;
}

export type AgentKind =
  | 'claude-code'
  | 'subagent'
  | 'workflow'
  | 'mcp-client'
  | 'codex'
  | 'gemini'
  | 'opencode'
  | 'cursor'
  | 'copilot'
  | 'kiro'
  | 'plugin';

/**
 * A setting the scanner does not model: an unknown value, or a feature it does not evaluate. The
 * result says what was assumed, which is never safer than the worst case it could stand for.
 */
export interface Unrecognized {
  readonly agent: string;
  readonly setting: string;
  readonly value: string;
  readonly assumed: string;
  readonly location: Location;
  /**
   * Set when the gap is one a change could use to hide authority (a file outside the repository,
   * an import at a moving ref, a model endpoint redirect): reported at this severity, not as a note.
   */
  readonly severity?: Severity;
}

/**
 * Something that mediates tool calls at runtime, and which calls it sees. A pre-tool hook sees the
 * tools its `matcher` names; Agent Guard or a gateway reached as an MCP server sees only the calls
 * made through that `server`; gh-aw safe outputs see only what the agent asks to post. Every other
 * call bypasses it.
 */
export interface Mediator {
  readonly kind: 'agent-guard' | 'pre-tool-hook' | 'mcp-gateway' | 'safe-outputs' | 'auto-mode';
  readonly location: Location;
  /** For a hook: its matcher (`''` or `*` means every tool). */
  readonly matcher?: string;
  /** For Agent Guard or a gateway reached over MCP: the server's name in the agent's config. */
  readonly server?: string;
}

export interface Agent {
  /** Stable across commits: kind plus the file that defines it (and the job/step for workflows). */
  readonly id: string;
  readonly kind: AgentKind;
  readonly name: string;
  readonly location: Location;
  readonly grants: readonly Grant[];
  readonly mediators: readonly Mediator[];
  /** Headless agents have no person to answer a prompt: `ask` paths are not reachable. */
  readonly headless: boolean;
}

export type CapabilityValue = 'yes' | 'no' | 'unknown';

export interface CapabilityState {
  readonly value: CapabilityValue;
  /** `auto` when at least one `yes` grant needs no approval. */
  readonly approval: Approval | null;
  readonly grants: readonly Grant[];
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'low';
export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export interface RuleMeta {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly owasp: readonly string[];
  readonly help: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly message: string;
  readonly location: Location;
  /** The agent the finding is about, when there is one. */
  readonly agentId?: string;
  /** A stable key: rule, agent, file and subject. Line numbers are left out so moved text keeps its key. */
  readonly fingerprint: string;
  readonly fix?: string;
  /** Set on findings imported from another tool's SARIF: that tool and its rule title. */
  readonly origin?: { readonly tool: string; readonly title?: string };
}

export interface Suppressed {
  readonly finding: Finding;
  readonly reason: string;
  readonly source: 'inline' | 'config' | 'baseline';
}

/** A file read during the scan. */
export interface SourceFile {
  readonly path: string;
  readonly text: string;
}

export interface ScanStats {
  readonly filesRead: number;
  readonly filesSkipped: number;
}

/** One entry of `.agc-reviews.yaml` as the scan read it. */
export interface ReviewSummary {
  /** What the entry names: an agent ID, an agent name, or the file that defines agents. */
  readonly agent: string;
  readonly owner: string;
  /** `YYYY-MM-DD`. */
  readonly reviewBy: string;
  /** What the review approved. */
  readonly capabilities: readonly Capability[];
  readonly location: Location;
  /** IDs of the agents the entry speaks for. */
  readonly agents: readonly string[];
}

export interface ScanResult {
  readonly root: string;
  readonly agents: readonly Agent[];
  readonly findings: readonly Finding[];
  readonly suppressed: readonly Suppressed[];
  readonly errors: readonly { readonly file: string; readonly message: string }[];
  readonly stats: ScanStats;
  /** Which modes ran: files always; Agent Guard records when found; live Agent Map when asked. */
  readonly modes: {
    readonly agentGuard: readonly { readonly path: string; readonly kind: string }[];
    readonly live: { readonly url: string; readonly notes: readonly string[] } | null;
  };
  /**
   * gh-aw lock files judged from their source, with digests of both. `diffScans` reports a lock
   * that changed while its source did not: what runs is the lock, and only the source was judged.
   */
  readonly compiledLocks?: readonly { readonly lock: string; readonly lockHash: string; readonly sourceHash: string }[];
  /** Entries of `.agc-reviews.yaml` that could be read; empty when there is none. */
  readonly reviews?: readonly ReviewSummary[];
}
