export { scan, diffScans } from './scan.js';
export type { ScanOptions, ScanDiff, CapabilityChange } from './scan.js';
export { DirectorySource, GitSource, MemorySource, isCandidate } from './source.js';
export type { FileSource } from './source.js';
export { authority, capabilityState } from './authority.js';
export { RULES, RULES_BY_ID } from './rules/index.js';
export { fetchLiveEvidence, AgentMapError } from './agent-map.js';
export type { LiveEvidence, LiveOptions, LiveSource } from './agent-map.js';
export { artifactKind, taskExposure } from './agent-guard.js';
export type { AgentGuardEvidence, GuardTool, GuardTask, TaskExposure } from './agent-guard.js';
export { parseConfig, shouldFail, parseBaseline, formatBaseline, DEFAULT_CONFIG } from './config.js';
export type {
  AgentGuardLimits,
  AgentMapConfig,
  CheckConfig,
  FailOn,
  ForbiddenCombination,
  IgnoreEntry,
  PolicyConfig,
} from './config.js';
export { formatText, formatMarkdown, formatSarif, formatJson, TOOL_NAME, TOOL_VERSION } from './report.js';
export { runCli } from './cli.js';
export type { CliIo } from './cli.js';
export * from './types.js';
