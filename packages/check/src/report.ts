import type { Agent, Finding, ScanResult, Severity } from './types.js';
import { CAPABILITIES, CAPABILITY_LABELS, SEVERITY_ORDER } from './types.js';
import { authority, describeLevel } from './authority.js';
import { RULES, RULES_BY_ID } from './rules.js';
import type { ScanDiff } from './scan.js';

export const TOOL_NAME = 'agent-guard-check';
export const TOOL_VERSION = '0.1.0-alpha.0';
const INFO_URI = 'https://github.com/ShieldaAI/agent-guard/tree/main/packages/check';

function counts(findings: readonly Finding[]): string {
  const parts = [...SEVERITY_ORDER]
    .reverse()
    .map(severity => [severity, findings.filter(f => f.severity === severity).length] as const)
    .filter(([, n]) => n > 0)
    .map(([severity, n]) => `${n} ${severity}`);
  return parts.length ? parts.join(', ') : 'no findings';
}

function where(finding: Finding): string {
  return `${finding.location.file}:${finding.location.line}`;
}

function authorityLines(agent: Agent): string[] {
  const a = authority(agent);
  const lines: string[] = [];
  for (const capability of CAPABILITIES) {
    const state = a[capability];
    if (state.value === 'no') continue;
    const ordered = [...state.grants].sort((a, b) => (a.approval === b.approval ? 0 : a.approval === 'auto' ? -1 : 1));
    const via = [...new Set(ordered.map(grant => grant.via))].slice(0, 3).join(', ');
    lines.push(`${CAPABILITY_LABELS[capability].padEnd(22)} ${describeLevel(state).padEnd(19)} via ${via}`);
  }
  return lines;
}

/** Plain text for a terminal. */
export function formatText(result: ScanResult, diff?: ScanDiff): string {
  const out: string[] = [];
  out.push(`${TOOL_NAME} ${TOOL_VERSION}: ${result.agents.length} agent(s), ${counts(result.findings)}`);
  if (diff) {
    out.push('');
    out.push(diff.widened.length ? 'Authority widened by this change:' : 'No agent gained authority in this change.');
    for (const change of diff.widened)
      out.push(
        `  ${change.agent.name}: ${CAPABILITY_LABELS[change.capability]} ${change.before ? describeLevel(change.before) : 'no'} -> ${describeLevel(change.after)}`,
      );
    if (diff.resolved.length) out.push(`Resolved by this change: ${diff.resolved.length} finding(s).`);
  }
  for (const agent of result.agents) {
    const lines = authorityLines(agent);
    out.push('');
    out.push(`${agent.name}  (${agent.location.file})`);
    if (!lines.length) out.push('  no risky capabilities found');
    for (const line of lines) out.push(`  ${line}`);
    if (agent.kind !== 'subagent')
      out.push(
        `  runtime check: ${agent.mediators.length ? [...new Set(agent.mediators.map(m => m.kind))].join(', ') : 'none'}`,
      );
  }
  const shown = diff ? diff.added : result.findings;
  if (shown.length) {
    out.push('');
    out.push(diff ? 'New findings:' : 'Findings:');
    for (const finding of shown) {
      const confidence = finding.confidence === 'low' ? ' (low confidence)' : '';
      out.push(`  ${finding.severity.toUpperCase().padEnd(8)} ${finding.ruleId}  ${where(finding)}${confidence}`);
      out.push(`           ${finding.message}`);
      if (finding.fix) out.push(`           Fix: ${finding.fix}`);
    }
  }
  if (result.suppressed.length)
    out.push('', `Suppressed: ${result.suppressed.length} (see --format json for reasons).`);
  for (const error of result.errors) out.push(`Could not read ${error.file}: ${error.message}`);
  return `${out.join('\n')}\n`;
}

const ICON: Readonly<Record<Severity, string>> = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪', info: 'ℹ️' };

/** Text inside a code span: backslashes are literal there, so only pipes and backticks need handling. */
function codeSpan(text: string): string {
  return text.replace(/`/g, "'").replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Escapes text for a Markdown table cell: backslashes first, then the characters that end a cell or open HTML. */
function escapeMd(text: string): string {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/([|<>`*_[\]])/g, '\\$1')
    .replace(/\r?\n/g, ' ');
}

/** A pull-request comment. With a diff it shows only what the change made worse. */
export function formatMarkdown(result: ScanResult, diff?: ScanDiff): string {
  const out: string[] = [];
  const shown = diff ? diff.added : result.findings;
  const title = diff
    ? diff.widened.length || diff.added.length
      ? `Agent authority changed: ${diff.widened.length} widened, ${diff.added.length} new finding(s)`
      : 'No agent gained authority in this change'
    : `${result.agents.length} agent(s), ${counts(result.findings)}`;
  out.push(`### Agent Guard Check: ${title}`);
  if (diff?.widened.length) {
    out.push('', '| Agent | Capability | Before | After | Via |', '| --- | --- | --- | --- | --- |');
    for (const change of diff.widened) {
      // Show the grants that produced the new level: no-approval grants first, one entry per path.
      const relevant = change.after.grants.filter(
        grant => change.after.approval !== 'auto' || grant.approval === 'auto',
      );
      const seen = new Set<string>();
      const via = relevant
        .filter(grant => !seen.has(grant.via) && seen.add(grant.via))
        .slice(0, 2)
        .map(grant => `\`${codeSpan(grant.via)}\` (${escapeMd(grant.location.file)}:${grant.location.line})`)
        .join(', ');
      out.push(
        `| ${escapeMd(change.agent.name)} | ${CAPABILITY_LABELS[change.capability]} | ${change.before ? describeLevel(change.before) : 'no'} | **${describeLevel(change.after)}** | ${via} |`,
      );
    }
  }
  if (shown.length) {
    out.push('', '| | Rule | Where | Finding | Fix |', '| --- | --- | --- | --- | --- |');
    for (const finding of shown)
      out.push(
        `| ${ICON[finding.severity]} ${finding.severity} | ${finding.ruleId} | \`${codeSpan(where(finding))}\` | ${escapeMd(finding.message)}${finding.confidence === 'low' ? ' _(low confidence)_' : ''} | ${escapeMd(finding.fix ?? '')} |`,
      );
  }
  if (diff?.resolved.length) out.push('', `Resolved by this change: ${diff.resolved.length} finding(s).`);
  if (result.errors.length)
    out.push(
      '',
      ...result.errors.map(error => `- Could not read \`${codeSpan(error.file)}\`: ${escapeMd(error.message)}`),
    );
  return `${out.join('\n')}\n`;
}

const SARIF_LEVEL: Readonly<Record<Severity, 'error' | 'warning' | 'note'>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};
const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '1.0',
};

/** SARIF 2.1.0 for GitHub code scanning and other tools. */
export function formatSarif(result: ScanResult, findings: readonly Finding[] = result.findings): string {
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: INFO_URI,
            rules: RULES.map(rule => ({
              id: rule.id,
              name: rule.id.replace(/-/g, ''),
              shortDescription: { text: rule.title },
              fullDescription: { text: rule.help },
              helpUri: `${INFO_URI}#rules`,
              defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
              properties: {
                tags: ['security', 'ai-agents', ...rule.owasp],
                'security-severity': SECURITY_SEVERITY[rule.severity],
                precision: rule.confidence === 'high' ? 'high' : 'medium',
              },
            })),
          },
        },
        results: findings.map(finding => ({
          ruleId: finding.ruleId,
          ruleIndex: RULES.findIndex(rule => rule.id === finding.ruleId),
          level: SARIF_LEVEL[finding.severity],
          message: { text: finding.fix ? `${finding.message} Fix: ${finding.fix}` : finding.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.location.file },
                region: { startLine: Math.max(1, finding.location.line) },
              },
            },
          ],
          partialFingerprints: { 'agcFingerprint/v1': finding.fingerprint },
          properties: {
            severity: finding.severity,
            confidence: finding.confidence,
            'security-severity': SECURITY_SEVERITY[finding.severity],
            ...(finding.agentId ? { agent: finding.agentId } : {}),
          },
        })),
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/** Machine-readable output with each agent's computed authority. */
export function formatJson(result: ScanResult, diff?: ScanDiff): string {
  const agents = result.agents.map(agent => ({
    id: agent.id,
    kind: agent.kind,
    name: agent.name,
    location: agent.location,
    headless: agent.headless,
    mediators: agent.mediators,
    authority: Object.fromEntries(
      CAPABILITIES.map(capability => {
        const state = authority(agent)[capability];
        return [
          capability,
          {
            value: state.value,
            approval: state.approval,
            via: state.grants.map(g => ({ via: g.via, approval: g.approval, location: g.location })),
          },
        ];
      }),
    ),
  }));
  const body = {
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    summary: Object.fromEntries(
      [...SEVERITY_ORDER].reverse().map(s => [s, result.findings.filter(f => f.severity === s).length]),
    ),
    agents,
    findings: result.findings.map(finding => ({ ...finding, title: RULES_BY_ID[finding.ruleId]?.title })),
    suppressed: result.suppressed,
    errors: result.errors,
    stats: result.stats,
    ...(diff
      ? {
          diff: {
            added: diff.added.map(f => f.fingerprint),
            resolved: diff.resolved.map(f => f.fingerprint),
            widened: diff.widened.map(change => ({
              agent: change.agent.id,
              capability: change.capability,
              before: change.before ? describeLevel(change.before) : 'no',
              after: describeLevel(change.after),
            })),
          },
        }
      : {}),
  };
  return `${JSON.stringify(body, null, 2)}\n`;
}
