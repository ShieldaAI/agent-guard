import { parse as parseYaml } from 'yaml';
import type { Capability, Confidence, Finding, Severity, Suppressed } from './types.js';
import { CAPABILITIES, SEVERITY_ORDER } from './types.js';
import { isRecord } from './text.js';
import type { DeclaredServer } from './mcp.js';

export type FailOn = Severity | 'none';

export interface IgnoreEntry {
  readonly rule: string;
  readonly path?: string;
  readonly reason: string;
}

/** Ceilings for Agent Guard task budgets (AGC-AGX-007). `maxCost: null` means no ceiling. */
export interface AgentGuardLimits {
  readonly files: readonly string[];
  readonly maxDeadlineHours: number;
  readonly maxCalls: number;
  readonly maxCost: number | null;
}

/** Where to read live evidence (Mode C). The token is read from the named environment variable. */
export interface AgentMapConfig {
  readonly url: string;
  readonly tokenEnv: string;
}

export type CapabilityLevel = 'auto' | 'any';

/** A capability combination no agent may hold, for example untrusted input plus unasked egress. */
export interface ForbiddenCombination {
  readonly name: string;
  readonly when: Readonly<Partial<Record<Capability, CapabilityLevel>>>;
  readonly severity: Severity;
  readonly agents?: readonly string[];
}

export interface PolicyConfig {
  /** MCP servers any agent may use, by config name, catalog ID or package name; null: no allowlist. */
  readonly allowedMcpServers: readonly string[] | null;
  /** Hosts remote MCP servers may use; null: no allowlist. */
  readonly allowedMcpHosts: readonly string[] | null;
  readonly forbid: readonly ForbiddenCombination[];
}

export interface CheckConfig {
  readonly failOn: FailOn;
  readonly minConfidence: Confidence;
  readonly severity: Readonly<Record<string, Severity>>;
  readonly ignore: readonly IgnoreEntry[];
  readonly agentGuard: AgentGuardLimits;
  readonly agentMap: AgentMapConfig | null;
  readonly policy: PolicyConfig;
  /** What MCP servers the catalog does not know (or knows differently) can do, as the team declares. */
  readonly mcpServers: readonly DeclaredServer[];
}

export const DEFAULT_CONFIG: CheckConfig = Object.freeze({
  failOn: 'high',
  minConfidence: 'high',
  severity: Object.freeze({}),
  ignore: Object.freeze([]),
  agentGuard: Object.freeze({ files: Object.freeze([]), maxDeadlineHours: 24, maxCalls: 1000, maxCost: null }),
  agentMap: null,
  policy: Object.freeze({ allowedMcpServers: null, allowedMcpHosts: null, forbid: Object.freeze([]) }),
  mcpServers: Object.freeze([]),
});

const SEVERITIES = new Set<string>(SEVERITY_ORDER);
const TOP_KEYS = [
  'fail_on',
  'min_confidence',
  'severity',
  'ignore',
  'agent_guard',
  'agent_map',
  'policy',
  'mcp_servers',
];

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[], where: string): void {
  for (const key of Object.keys(value))
    if (!allowed.includes(key)) throw new Error(`.agc.yaml: unknown key "${where}${key}"`);
}

function stringList(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string' && item.trim()))
    throw new Error(`.agc.yaml: ${where} must be a list of strings`);
  return value.map(item => (item as string).trim());
}

function positive(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0)
    throw new Error(`.agc.yaml: ${where} must be a positive number`);
  return value;
}

function parseAgentGuard(value: unknown): AgentGuardLimits {
  if (value === undefined) return DEFAULT_CONFIG.agentGuard;
  if (!isRecord(value)) throw new Error('.agc.yaml: agent_guard must be a mapping');
  onlyKeys(value, ['files', 'max_deadline_hours', 'max_calls', 'max_cost'], 'agent_guard.');
  const defaults = DEFAULT_CONFIG.agentGuard;
  return {
    files: value['files'] === undefined ? [] : stringList(value['files'], 'agent_guard.files'),
    maxDeadlineHours:
      value['max_deadline_hours'] === undefined
        ? defaults.maxDeadlineHours
        : positive(value['max_deadline_hours'], 'agent_guard.max_deadline_hours'),
    maxCalls:
      value['max_calls'] === undefined ? defaults.maxCalls : positive(value['max_calls'], 'agent_guard.max_calls'),
    maxCost: value['max_cost'] === undefined ? null : positive(value['max_cost'], 'agent_guard.max_cost'),
  };
}

function parseAgentMap(value: unknown): AgentMapConfig | null {
  if (value === undefined) return null;
  if (!isRecord(value)) throw new Error('.agc.yaml: agent_map must be a mapping');
  if (Object.keys(value).some(key => /token$/i.test(key) && key !== 'token_env'))
    throw new Error('.agc.yaml: never put an Agent Map token in the file; name its environment variable in token_env');
  onlyKeys(value, ['url', 'token_env'], 'agent_map.');
  const url = value['url'];
  if (typeof url !== 'string') throw new Error('.agc.yaml: agent_map.url is required');
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('.agc.yaml: agent_map.url must be a URL');
  }
  const local = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local))
    throw new Error('.agc.yaml: agent_map.url must use https (http only for localhost)');
  const tokenEnv = value['token_env'] ?? 'AGENT_MAP_TOKEN';
  // The file is part of the repository, so it may not pick an arbitrary secret to send.
  if (typeof tokenEnv !== 'string' || !/^([A-Z][A-Z0-9_]*_)?AGENT_MAP_TOKEN$/.test(tokenEnv))
    throw new Error('.agc.yaml: agent_map.token_env must be an environment variable name ending in AGENT_MAP_TOKEN');
  return { url: parsed.href.replace(/\/$/, ''), tokenEnv };
}

const LEVELS = new Set(['auto', 'any']);

function parsePolicy(value: unknown): PolicyConfig {
  if (value === undefined) return DEFAULT_CONFIG.policy;
  if (!isRecord(value)) throw new Error('.agc.yaml: policy must be a mapping');
  onlyKeys(value, ['allowed_mcp_servers', 'allowed_mcp_hosts', 'forbid'], 'policy.');
  const forbid: ForbiddenCombination[] = [];
  if (value['forbid'] !== undefined) {
    if (!Array.isArray(value['forbid'])) throw new Error('.agc.yaml: policy.forbid must be a list');
    value['forbid'].forEach((entry, i) => {
      const where = `policy.forbid[${i}]`;
      if (!isRecord(entry)) throw new Error(`.agc.yaml: ${where} must be a mapping`);
      onlyKeys(entry, ['name', 'when', 'severity', 'agents'], `${where}.`);
      if (typeof entry['name'] !== 'string' || !entry['name'].trim())
        throw new Error(`.agc.yaml: ${where}.name is required`);
      if (!isRecord(entry['when']) || !Object.keys(entry['when']).length)
        throw new Error(`.agc.yaml: ${where}.when must map capabilities to auto or any`);
      for (const [capability, level] of Object.entries(entry['when'])) {
        if (!(CAPABILITIES as readonly string[]).includes(capability))
          throw new Error(
            `.agc.yaml: ${where}.when: unknown capability "${capability}" (use ${CAPABILITIES.join(', ')})`,
          );
        if (typeof level !== 'string' || !LEVELS.has(level))
          throw new Error(`.agc.yaml: ${where}.when.${capability} must be auto or any`);
      }
      const severity = entry['severity'] ?? 'high';
      if (typeof severity !== 'string' || !SEVERITIES.has(severity))
        throw new Error(`.agc.yaml: ${where}.severity is invalid`);
      forbid.push({
        name: entry['name'].trim(),
        when: entry['when'] as Partial<Record<Capability, CapabilityLevel>>,
        severity: severity as Severity,
        ...(entry['agents'] === undefined ? {} : { agents: stringList(entry['agents'], `${where}.agents`) }),
      });
    });
  }
  return {
    allowedMcpServers:
      value['allowed_mcp_servers'] === undefined
        ? null
        : stringList(value['allowed_mcp_servers'], 'policy.allowed_mcp_servers'),
    allowedMcpHosts:
      value['allowed_mcp_hosts'] === undefined
        ? null
        : stringList(value['allowed_mcp_hosts'], 'policy.allowed_mcp_hosts'),
    forbid,
  };
}

function capabilityList(value: unknown, where: string): Capability[] {
  if (value === undefined) return [];
  const list = Array.isArray(value) ? value : null;
  if (!list || !list.every(item => typeof item === 'string'))
    throw new Error(`.agc.yaml: ${where} must be a list of capabilities (${CAPABILITIES.join(', ')})`);
  for (const item of list)
    if (!(CAPABILITIES as readonly string[]).includes(item))
      throw new Error(`.agc.yaml: ${where}: unknown capability "${item}" (use ${CAPABILITIES.join(', ')})`);
  return list as Capability[];
}

/**
 * `mcp_servers`: what a server can do, keyed by its config name, catalog ID, package, image or host.
 * `capabilities` lists what it can do; `unknown` lists what it may do. Anything not listed is no.
 */
function parseMcpServers(value: unknown): DeclaredServer[] {
  if (value === undefined) return [];
  if (!isRecord(value)) throw new Error('.agc.yaml: mcp_servers must map a server to its capabilities');
  const out: DeclaredServer[] = [];
  for (const [match, entry] of Object.entries(value)) {
    const where = `mcp_servers.${match}`;
    if (!match.trim()) throw new Error('.agc.yaml: mcp_servers keys must not be empty');
    if (!isRecord(entry) || entry['capabilities'] === undefined)
      throw new Error(`.agc.yaml: ${where} needs a capabilities list ([] for none)`);
    onlyKeys(entry, ['capabilities', 'unknown'], `${where}.`);
    const yes = capabilityList(entry['capabilities'], `${where}.capabilities`);
    const maybe = capabilityList(entry['unknown'], `${where}.unknown`);
    const both = yes.find(item => maybe.includes(item));
    if (both) throw new Error(`.agc.yaml: ${where}: ${both} is listed as both a capability and unknown`);
    const capabilities: Partial<Record<Capability, 'yes' | 'unknown'>> = {};
    for (const item of yes) capabilities[item] = 'yes';
    for (const item of maybe) capabilities[item] = 'unknown';
    out.push({ match: match.trim(), capabilities });
  }
  return out;
}

/** Parses `.agc.yaml`. Unknown keys and invalid values are errors, so a typo never silently disables a check. */
export function parseConfig(text: string): CheckConfig {
  const data = parseYaml(text, { maxAliasCount: 20 }) as unknown;
  if (data === null || data === undefined) return DEFAULT_CONFIG;
  if (!isRecord(data)) throw new Error('.agc.yaml must be a mapping');
  onlyKeys(data, TOP_KEYS, '');
  const failOn = data['fail_on'] ?? DEFAULT_CONFIG.failOn;
  if (typeof failOn !== 'string' || (failOn !== 'none' && !SEVERITIES.has(failOn)))
    throw new Error('.agc.yaml: fail_on must be critical, high, medium, low, info or none');
  const minConfidence = data['min_confidence'] ?? DEFAULT_CONFIG.minConfidence;
  if (minConfidence !== 'high' && minConfidence !== 'low')
    throw new Error('.agc.yaml: min_confidence must be high or low');
  const severity: Record<string, Severity> = {};
  if (data['severity'] !== undefined) {
    if (!isRecord(data['severity'])) throw new Error('.agc.yaml: severity must map rule IDs to severities');
    for (const [rule, value] of Object.entries(data['severity'])) {
      if (typeof value !== 'string' || !SEVERITIES.has(value))
        throw new Error(`.agc.yaml: invalid severity for ${rule}`);
      severity[rule] = value as Severity;
    }
  }
  const ignore: IgnoreEntry[] = [];
  if (data['ignore'] !== undefined) {
    if (!Array.isArray(data['ignore'])) throw new Error('.agc.yaml: ignore must be a list');
    for (const entry of data['ignore']) {
      if (!isRecord(entry) || typeof entry['rule'] !== 'string')
        throw new Error('.agc.yaml: each ignore entry needs a rule');
      if (typeof entry['reason'] !== 'string' || !entry['reason'].trim())
        throw new Error(`.agc.yaml: ignore entry for ${entry['rule']} needs a reason`);
      ignore.push({
        rule: entry['rule'],
        reason: entry['reason'].trim(),
        ...(typeof entry['path'] === 'string' ? { path: entry['path'] } : {}),
      });
    }
  }
  return {
    failOn: failOn as FailOn,
    minConfidence,
    severity,
    ignore,
    agentGuard: parseAgentGuard(data['agent_guard']),
    agentMap: parseAgentMap(data['agent_map']),
    policy: parsePolicy(data['policy']),
    mcpServers: parseMcpServers(data['mcp_servers']),
  };
}

const INLINE = /agc-ignore\s+(AGC-[A-Z]+-\d{3})\s*:\s*(\S.*?)\s*(?:-->|\*\/)?\s*$/;

/**
 * Applies inline `agc-ignore AGC-XXX-000: reason` comments (same line or the line above),
 * config ignores and the baseline. A suppression without a reason does not count.
 */
export function applySuppressions(
  findings: readonly Finding[],
  config: CheckConfig,
  readText: (path: string) => string | undefined,
  baseline: ReadonlySet<string>,
): { kept: Finding[]; suppressed: Suppressed[] } {
  const kept: Finding[] = [];
  const suppressed: Suppressed[] = [];
  const lines = new Map<string, string[]>();
  // One match per line: a long line with many findings is read once.
  const inlineCache = new Map<string, RegExpExecArray | null>();
  for (const original of findings) {
    const severity = config.severity[original.ruleId];
    const finding = severity ? { ...original, severity } : original;
    let file = lines.get(finding.location.file);
    if (!file) {
      file = (readText(finding.location.file) ?? '').split('\n');
      lines.set(finding.location.file, file);
    }
    const lineMatch = (index: number): RegExpExecArray | null => {
      const key = `${finding.location.file}\0${index}`;
      if (!inlineCache.has(key)) {
        const line = file![index];
        inlineCache.set(key, line && line.includes('agc-ignore') ? INLINE.exec(line) : null);
      }
      return inlineCache.get(key)!;
    };
    const inline = [lineMatch(finding.location.line - 1), lineMatch(finding.location.line - 2)].find(
      match => match && match[1] === finding.ruleId,
    );
    if (inline) {
      suppressed.push({ finding, reason: inline[2]!, source: 'inline' });
      continue;
    }
    const entry = config.ignore.find(
      item =>
        item.rule === finding.ruleId &&
        (!item.path ||
          finding.location.file === item.path ||
          finding.location.file.startsWith(`${item.path.replace(/\/$/, '')}/`)),
    );
    if (entry) {
      suppressed.push({ finding, reason: entry.reason, source: 'config' });
      continue;
    }
    if (baseline.has(finding.fingerprint)) {
      suppressed.push({ finding, reason: 'in baseline', source: 'baseline' });
      continue;
    }
    kept.push(finding);
  }
  return { kept, suppressed };
}

/** Whether a set of findings should fail the run. */
export function shouldFail(findings: readonly Finding[], failOn: FailOn, minConfidence: Confidence): boolean {
  if (failOn === 'none') return false;
  const floor = SEVERITY_ORDER.indexOf(failOn);
  return findings.some(
    finding =>
      SEVERITY_ORDER.indexOf(finding.severity) >= floor && (minConfidence === 'low' || finding.confidence === 'high'),
  );
}

export function parseBaseline(text: string): Set<string> {
  const data = JSON.parse(text) as unknown;
  if (!isRecord(data) || data['version'] !== 1 || !Array.isArray(data['fingerprints']))
    throw new Error('baseline must be {"version": 1, "fingerprints": [...]}');
  return new Set(data['fingerprints'].filter((item): item is string => typeof item === 'string'));
}

export function formatBaseline(findings: readonly Finding[]): string {
  return `${JSON.stringify({ version: 1, fingerprints: [...new Set(findings.map(f => f.fingerprint))].sort() }, null, 2)}\n`;
}
