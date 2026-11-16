import { parse as parseYaml } from 'yaml';
import type { Confidence, Finding, Severity, Suppressed } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { isRecord } from './text.js';

export type FailOn = Severity | 'none';

export interface IgnoreEntry {
  readonly rule: string;
  readonly path?: string;
  readonly reason: string;
}

export interface CheckConfig {
  readonly failOn: FailOn;
  readonly minConfidence: Confidence;
  readonly severity: Readonly<Record<string, Severity>>;
  readonly ignore: readonly IgnoreEntry[];
}

export const DEFAULT_CONFIG: CheckConfig = Object.freeze({
  failOn: 'high',
  minConfidence: 'high',
  severity: Object.freeze({}),
  ignore: Object.freeze([]),
});

const SEVERITIES = new Set<string>(SEVERITY_ORDER);

/** Parses `.agc.yaml`. Unknown keys and invalid values are errors, so a typo never silently disables a check. */
export function parseConfig(text: string): CheckConfig {
  const data = parseYaml(text, { maxAliasCount: 20 }) as unknown;
  if (data === null || data === undefined) return DEFAULT_CONFIG;
  if (!isRecord(data)) throw new Error('.agc.yaml must be a mapping');
  for (const key of Object.keys(data))
    if (!['fail_on', 'min_confidence', 'severity', 'ignore'].includes(key))
      throw new Error(`.agc.yaml: unknown key "${key}"`);
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
  return { failOn: failOn as FailOn, minConfidence, severity, ignore };
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
  for (const original of findings) {
    const severity = config.severity[original.ruleId];
    const finding = severity ? { ...original, severity } : original;
    let file = lines.get(finding.location.file);
    if (!file) {
      file = (readText(finding.location.file) ?? '').split('\n');
      lines.set(finding.location.file, file);
    }
    const near = [file[finding.location.line - 1], file[finding.location.line - 2]];
    const inline = near
      .map(line => (line ? INLINE.exec(line) : null))
      .find(match => match && match[1] === finding.ruleId);
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
