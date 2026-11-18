import { resolve } from 'node:path';
import type { Finding, ScanResult } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { DirectorySource, GitSource, safeRelative, type FileSource } from './source.js';
import type { LiveEvidence } from './agent-map.js';
import { buildProject, type TextFile } from './model.js';
import { createHash } from 'node:crypto';
import { fingerprint, runRules } from './rules/index.js';
import { applySuppressions, DEFAULT_CONFIG, parseConfig, type CheckConfig } from './config.js';
import { authority, level } from './authority.js';
import { withScriptReader } from './claude.js';
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
  /** Settings outside the repository that apply to the person running the scan (`readUserConfig`). */
  readonly userFiles?: readonly TextFile[];
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
  // Bash rules for a repository script are judged by what the script does with its arguments.
  return withScriptReader(
    path => {
      const clean = safeRelative(path.replace(/^\.\//, ''));
      return clean === undefined ? undefined : source.readNamed(clean);
    },
    () => scanSource(options, source),
  );
}

function scanSource(options: ScanOptions, source: FileSource): ScanResult {
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
  const project = buildProject(source, [...named, ...(options.agentGuardFiles ?? [])], {
    declaredServers: config.mcpServers,
    ...(options.userFiles ? { userFiles: options.userFiles, root: resolve(options.root) } : {}),
  });
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
    compiledLocks: project.compiledLocks.map(item => ({
      lock: item.lock,
      lockHash: digest(item.lockText),
      sourceHash: digest(item.sourceText),
    })),
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

const rank = (finding: Finding) => SEVERITY_ORDER.indexOf(finding.severity);

/**
 * What a change did to agent authority. Only growth is reported as widened. A finding counts as
 * added when it is new, when its severity rose (the same configuration made more dangerous), or when
 * the change introduced it (or raised its severity) and silenced it with an inline `agc-ignore` comment.
 */
function digest(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * gh-aw lock files the change edited while their source stayed the same (or that it added beside
 * an existing source). The lock is what Actions runs, and the scan judges only its source, so the
 * edit could add anything: reported as unread configuration (AGC-CFG-002, high).
 */
function lockEditedAlone(base: ScanResult, head: ScanResult): Finding[] {
  const before = new Map((base.compiledLocks ?? []).map(item => [item.lock, item]));
  const out: Finding[] = [];
  for (const item of head.compiledLocks ?? []) {
    const old = before.get(item.lock);
    if (old ? old.lockHash === item.lockHash || old.sourceHash !== item.sourceHash : true) continue;
    const message = `${item.lock} changed while its source did not. Actions runs the lock, and the scan judges only its source, so this edit was not judged.`;
    out.push({
      ruleId: 'AGC-CFG-002',
      severity: 'high',
      confidence: 'high',
      message,
      location: { file: item.lock, line: 1 },
      fingerprint: fingerprint('AGC-CFG-002', '', item.lock, `lock:${item.lockHash}`),
      fix: 'Change the .md source and run gh aw compile, so the lock and its source agree.',
    });
  }
  return out;
}

export function diffScans(base: ScanResult, head: ScanResult): ScanDiff {
  const baseSeverity = new Map<string, number>();
  for (const finding of [...base.findings, ...base.suppressed.map(item => item.finding)])
    baseSeverity.set(finding.fingerprint, Math.max(rank(finding), baseSeverity.get(finding.fingerprint) ?? -1));
  const before = new Set(base.findings.map(finding => finding.fingerprint));
  const baseInline = new Set(
    base.suppressed.filter(item => item.source === 'inline').map(item => item.finding.fingerprint),
  );
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
    added: [
      ...lockEditedAlone(base, head),
      ...head.findings.filter(
        finding => !before.has(finding.fingerprint) || rank(finding) > (baseSeverity.get(finding.fingerprint) ?? -1),
      ),
      // Silencing a finding the base already had is accepting known debt; silencing one this change
      // introduced (or made more severe) is not.
      ...head.suppressed
        .filter(
          item =>
            item.source === 'inline' &&
            !baseInline.has(item.finding.fingerprint) &&
            rank(item.finding) > (baseSeverity.get(item.finding.fingerprint) ?? -1),
        )
        .map(item => item.finding),
    ].sort(bySeverity),
    resolved: base.findings.filter(finding => !after.has(finding.fingerprint)),
    widened,
    newAgents,
  };
}
