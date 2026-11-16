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

export type AgentKind = 'claude-code' | 'subagent' | 'workflow' | 'mcp-client';

/** Something that mediates tool calls at runtime. */
export interface Mediator {
  readonly kind: 'agent-guard' | 'pre-tool-hook' | 'mcp-gateway';
  readonly location: Location;
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

export interface ScanResult {
  readonly root: string;
  readonly agents: readonly Agent[];
  readonly findings: readonly Finding[];
  readonly suppressed: readonly Suppressed[];
  readonly errors: readonly { readonly file: string; readonly message: string }[];
  readonly stats: ScanStats;
}
