import type { AgentGuard, GuardOptions } from '@shieldaai/agent-guard';
import type { ScenarioId } from './catalog.js';

/** Methods an adapter must provide to run the conformance suite. */
export type GuardLike = Pick<
  AgentGuard,
  | 'registerTool'
  | 'approveTool'
  | 'createTask'
  | 'delegateTask'
  | 'revokeTask'
  | 'setPolicy'
  | 'prepare'
  | 'approve'
  | 'execute'
  | 'snapshot'
> &
  // Optional since catalog 1.4.0: an adapter that has it also runs the S06 definition-diff checks.
  Partial<Pick<AgentGuard, 'toolChanges'>>;

export type ConformanceGuardFactory = (options: GuardOptions) => GuardLike;

export interface ConformanceOptions {
  /** Omit to execute every catalog scenario. Each selected scenario runs both variants. */
  readonly scenarioIds?: readonly ScenarioId[];
  /** Time limit per variant in milliseconds; defaults to 5000. Timeout does not cancel adapter work. */
  readonly caseTimeoutMs?: number;
  /**
   * Return a new guard for each call. Defaults to the public AgentGuard implementation.
   * Compatible adapters must preserve these APIs and throw a GuardError (from any installed
   * copy of core; checked with isGuardError) with the documented reason codes. The provided clock and secret configuration must be honored.
   */
  readonly createGuard?: ConformanceGuardFactory;
}

export interface ConformanceCaseResult {
  readonly scenarioId: ScenarioId;
  readonly variant: 'malicious' | 'benign';
  readonly passed: boolean;
  readonly assertions: number;
  readonly handlerInvocations: number;
  readonly denialCodes: readonly string[];
  /** A fixed assertion label or sanitized error class; never raw argument values. */
  readonly failure?: string;
}

export interface ConformanceReport {
  /** Catalog semver: versioned independently of the package; compare reports by this value. */
  readonly catalogVersion: string;
  readonly passed: boolean;
  readonly scenarioCount: number;
  readonly caseCount: number;
  readonly passedCases: number;
  readonly failedCases: number;
  readonly results: readonly ConformanceCaseResult[];
}
