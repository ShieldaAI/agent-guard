import { createHash } from 'node:crypto';
import type { Finding, Severity } from './types.js';
import { isRecord } from './text.js';

/**
 * Reads findings from other scanners' SARIF 2.1.0 files so one report, one baseline and one
 * fail-on cover them all (for example an MCP scanner next to this one). Imported findings keep
 * their tool's name and rule ID, and go through the same suppressions. Text is treated as data.
 */

export const MAX_IMPORTED_RESULTS = 10_000;
const MAX_TEXT = 2_000;

const clip = (text: string) => (text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}…` : text);
// eslint-disable-next-line no-control-regex
const clean = (text: string) => clip(text.replace(/[\u0000-\u0008\u000b-\u001f\u007f‪-‮⁦-⁩]/g, ''));

function severityOf(result: Record<string, unknown>, rule: Record<string, unknown> | undefined): Severity {
  const properties = isRecord(result['properties']) ? result['properties'] : {};
  const ruleProperties = rule && isRecord(rule['properties']) ? rule['properties'] : {};
  const score = Number(properties['security-severity'] ?? ruleProperties['security-severity']);
  if (Number.isFinite(score) && score > 0)
    return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score >= 0.1 ? 'low' : 'info';
  const fallback = rule && isRecord(rule['defaultConfiguration']) ? rule['defaultConfiguration']['level'] : undefined;
  const level = result['level'] ?? fallback ?? 'warning';
  return level === 'error' ? 'high' : level === 'warning' ? 'medium' : level === 'note' ? 'low' : 'info';
}

function uriOf(result: Record<string, unknown>): { file: string; line: number } {
  const location = Array.isArray(result['locations']) ? result['locations'][0] : undefined;
  const physical = isRecord(location) && isRecord(location['physicalLocation']) ? location['physicalLocation'] : {};
  const artifact = isRecord(physical['artifactLocation']) ? physical['artifactLocation'] : {};
  const region = isRecord(physical['region']) ? physical['region'] : {};
  let file = typeof artifact['uri'] === 'string' ? artifact['uri'] : '(no location)';
  file = file.replace(/^file:\/\//, '');
  try {
    file = decodeURIComponent(file);
  } catch {
    // keep as written
  }
  const line =
    typeof region['startLine'] === 'number' && region['startLine'] >= 1 ? Math.floor(region['startLine']) : 1;
  return { file: clean(file.replace(/^\.\//, '')), line };
}

/** Parses one SARIF file into findings. Throws on a file that is not SARIF 2.1.0. */
export function importSarif(text: string, label: string): Finding[] {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`${label}: not JSON`);
  }
  if (!isRecord(data) || data['version'] !== '2.1.0' || !Array.isArray(data['runs']))
    throw new Error(`${label}: not a SARIF 2.1.0 log`);
  const findings: Finding[] = [];
  for (const run of data['runs']) {
    if (!isRecord(run)) continue;
    const driver = isRecord(run['tool']) && isRecord(run['tool']['driver']) ? run['tool']['driver'] : {};
    const tool = clean(typeof driver['name'] === 'string' && driver['name'] ? driver['name'] : 'unknown-tool');
    const rules = Array.isArray(driver['rules']) ? driver['rules'].filter(isRecord) : [];
    for (const result of Array.isArray(run['results']) ? run['results'] : []) {
      if (!isRecord(result)) continue;
      if (findings.length >= MAX_IMPORTED_RESULTS)
        throw new Error(`${label}: more than ${MAX_IMPORTED_RESULTS} results`);
      // Results a tool itself suppressed or marked fixed are not findings.
      if (Array.isArray(result['suppressions']) && result['suppressions'].length) continue;
      if (result['baselineState'] === 'absent' || result['kind'] === 'pass' || result['kind'] === 'notApplicable')
        continue;
      const index = typeof result['ruleIndex'] === 'number' ? result['ruleIndex'] : -1;
      const ruleId = typeof result['ruleId'] === 'string' ? result['ruleId'] : undefined;
      const rule = rules[index] ?? rules.find(item => item['id'] === ruleId);
      const id = clean(ruleId ?? (typeof rule?.['id'] === 'string' ? rule['id'] : 'unknown-rule'));
      const message =
        isRecord(result['message']) && typeof result['message']['text'] === 'string' ? result['message']['text'] : id;
      const location = uriOf(result);
      const partial = isRecord(result['partialFingerprints'])
        ? Object.values(result['partialFingerprints'])[0]
        : undefined;
      const key = typeof partial === 'string' ? partial : `${location.file}\0${location.line}\0${message}`;
      const title =
        rule && isRecord(rule['shortDescription']) && typeof rule['shortDescription']['text'] === 'string'
          ? clean(rule['shortDescription']['text'])
          : undefined;
      findings.push({
        ruleId: `${tool}/${id}`,
        severity: severityOf(result, rule),
        confidence: 'high',
        message: clean(message),
        location,
        fingerprint: createHash('sha256').update(`${tool}\0${id}\0${key}`).digest('hex').slice(0, 20),
        origin: { tool, ...(title ? { title } : {}) },
      });
    }
  }
  return findings;
}
