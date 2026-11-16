import type { Finding, ScanResult } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { DirectorySource, GitSource, safeRelative, type FileSource } from './source.js';
import type { LiveEvidence } from './agent-map.js';
import { buildProject, type TextFile } from './model.js';
import { runRules } from './rules/index.js';
import { applySuppressions, DEFAULT_CONFIG, parseConfig, type CheckConfig } from './config.js';
import { authority, level } from './authority.js';
import { CAPABILITIES, type Agent, type Capability, type CapabilityState } from './types.js';

export interface ScanOptions {
  /** Repository root. Used for paths in the result and as the git directory for `ref`. */
  readonly root: string;
  /** Read files at this git ref instead of the working tree. */
  readonly ref?: string;
  /** Use this source instead of reading `root` or `ref`. */
  readonly source?: FileSource;
  /** Use this config instead of the repo's `.agc.yaml`. */
  readonly config?: CheckConfig;
  readonly baseline?: ReadonlySet<string>;
  /** Agent Guard records outside the repository (describe() output, inventory, manifest). */
  readonly agentGuardFiles?: readonly TextFile[];
  /** Live evidence from a running Agent Map (Mode C), fetched by `fetchLiveEvidence`. */
  readonly live?: LiveEvidence;
  /** Findings from other tools (see `importSarif`), reported and suppressed like this tool's own. */
  readonly imported?: readonly Finding[];
}

function bySeverity(a: Finding, b: Finding): number {
  return (
    SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity) ||
    a.location.file.localeCompare(b.location.file) ||
    a.location.line - b.location.line ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

/**
 * Scans one repository state. Never runs code from the repository and makes no network calls:
 * live evidence, when wanted, is fetched beforehand with `fetchLiveEvidence` and passed in.
 */
export function scan(options: ScanOptions): ScanResult {
  const source =
    options.source ?? (options.ref ? new GitSource(options.root, options.ref) : new DirectorySource(options.root));
  const errors: { file: string; message: string }[] = [];
  let config = options.config ?? DEFAULT_CONFIG;
  if (!options.config) {
    const text = source.read('.agc.yaml');
    if (text !== undefined) {
      try {
        config = parseConfig(text);
      } catch (error) {
        errors.push({ file: '.agc.yaml', message: error instanceof Error ? error.message : String(error) });
      }
    }
  }
  // Agent Guard records named in .agc.yaml are read from the same source (repo-relative paths).
  const named: TextFile[] = [];
  for (const path of config.agentGuard.files) {
    const clean = safeRelative(path);
    const text = clean === undefined ? undefined : source.readNamed(clean);
    if (clean === undefined || text === undefined)
      errors.push({
        file: '.agc.yaml',
        message: `agent_guard.files: ${path} was not found, or is not a plain file inside the repository under 1 MiB`,
      });
    else named.push({ path: clean, text });
  }
  const project = buildProject(source, [...named, ...(options.agentGuardFiles ?? [])]);
  errors.unshift(...project.errors);
  const { kept, suppressed } = applySuppressions(
    [...runRules(project, errors, { config, live: options.live }), ...(options.imported ?? [])],
    config,
    path => source.read(path),
    options.baseline ?? new Set(),
  );
  return {
    root: options.root,
    agents: project.agents,
    findings: kept.sort(bySeverity),
    suppressed,
    errors,
    stats: { filesRead: project.filesRead, filesSkipped: source.skipped },
    modes: {
      agentGuard: project.agentGuard.files,
      live: options.live ? { url: options.live.url, notes: options.live.notes } : null,
    },
  };
}

export interface CapabilityChange {
  readonly agent: Agent;
  readonly capability: Capability;
  readonly before: CapabilityState | undefined;
  readonly after: CapabilityState;
}

export interface ScanDiff {
  readonly added: readonly Finding[];
  readonly resolved: readonly Finding[];
  /** Capabilities that grew: from none to unknown or yes, or from behind approval to no approval. */
  readonly widened: readonly CapabilityChange[];
  readonly newAgents: readonly Agent[];
}

/** What a change did to agent authority. Only growth is reported as widened. */
export function diffScans(base: ScanResult, head: ScanResult): ScanDiff {
  const before = new Set(base.findings.map(finding => finding.fingerprint));
  const after = new Set(head.findings.map(finding => finding.fingerprint));
  const widened: CapabilityChange[] = [];
  const newAgents: Agent[] = [];
  for (const agent of head.agents) {
    const old = base.agents.find(item => item.id === agent.id);
    if (!old) newAgents.push(agent);
    const now = authority(agent);
    const then = old ? authority(old) : undefined;
    for (const capability of CAPABILITIES) {
      const previous = then?.[capability];
      if (level(now[capability]) > (previous ? level(previous) : 0))
        widened.push({ agent, capability, before: previous, after: now[capability] });
    }
  }
  return {
    added: head.findings.filter(finding => !before.has(finding.fingerprint)),
    resolved: base.findings.filter(finding => !after.has(finding.fingerprint)),
    widened,
    newAgents,
  };
}
