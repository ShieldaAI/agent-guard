import type { Agent, Finding, ScanResult, Severity } from './types.js';
import { CAPABILITIES, CAPABILITY_LABELS, SEVERITY_ORDER } from './types.js';
import { authority, describeLevel } from './authority.js';
import { RULES, RULES_BY_ID } from './rules/index.js';
import type { ScanDiff } from './scan.js';
import { readFileSync } from 'node:fs';
import { isRecord, oneLine } from './text.js';

export const TOOL_NAME = 'agent-guard-check';
/** The package version, read once from package.json next to dist/. */
export const TOOL_VERSION: string = (() => {
  try {
    const data = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as unknown;
    return isRecord(data) && typeof data['version'] === 'string' ? data['version'] : 'unknown';
  } catch {
    return 'unknown';
  }
})();
const INFO_URI = 'https://github.com/ShieldaAI/agent-guard/tree/main/packages/check';
export const RULES_URI = 'https://github.com/ShieldaAI/agent-guard/blob/main/packages/check/docs/rules.md';

function counts(findings: readonly Finding[]): string {
  const parts = [...SEVERITY_ORDER]
    .reverse()
    .map(severity => [severity, findings.filter(f => f.severity === severity).length] as const)
    .filter(([, n]) => n > 0)
    .map(([severity, n]) => `${n} ${severity}`);
  return parts.length ? parts.join(', ') : 'no findings';
}

/** Which evidence the scan used, in one line. */
function modes(result: ScanResult): string {
  const parts = ['repository files'];
  if (result.modes.agentGuard.length)
    parts.push(
      `Agent Guard records (${result.modes.agentGuard.map(file => `${file.path} [${file.kind}]`).join(', ')})`,
    );
  if (result.modes.live) parts.push(`live Agent Map (${result.modes.live.url})`);
  return parts.join(' + ');
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
  out.push(`Evidence: ${modes(result)}`);
  for (const note of result.modes.live?.notes ?? []) out.push(`  note: ${note}`);
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
  // Names, paths and messages come from repository files: one entry is exactly one log line.
  return `${out.map(oneLine).join('\n')}\n`;
}

const ICON: Readonly<Record<Severity, string>> = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪', info: 'ℹ️' };

/**
 * Escapes untrusted text for a Markdown table cell: line breaks and controls become spaces, backslashes
 * are escaped first, then the characters that end a cell, open HTML or start formatting. A word joiner
 * (U+2060) after `@`, `#` and `:` stops GitHub from turning the text into a mention, a reference or a
 * link. Untrusted text is never put in code spans, where backslashes are literal.
 */
export function escapeMd(text: string): string {
  return oneLine(text)
    .replace(/\\/g, '\\\\')
    .replace(/([|<>`*_[\]~!])/g, '\\$1')
    .replace(/([@#])(?=\w)/g, '$1\u2060')
    .replace(/:\/\//g, ':\u2060//')
    .replace(/\bwww\./gi, match => `${match.slice(0, 3)}\u2060.`);
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
  out.push('', `_Evidence: ${escapeMd(modes(result))}_`);
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
        .map(grant => `${escapeMd(grant.via)} (${escapeMd(grant.location.file)}:${grant.location.line})`)
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
        `| ${ICON[finding.severity]} ${finding.severity} | ${escapeMd(finding.ruleId)} | ${escapeMd(where(finding))} | ${escapeMd(finding.message)}${finding.confidence === 'low' ? ' _(low confidence)_' : ''} | ${escapeMd(finding.fix ?? '')} |`,
      );
  }
  if (diff?.resolved.length) out.push('', `Resolved by this change: ${diff.resolved.length} finding(s).`);
  if (result.errors.length)
    out.push('', ...result.errors.map(error => `- Could not read ${escapeMd(error.file)}: ${escapeMd(error.message)}`));
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
  const own = findings.filter(finding => !finding.origin);
  const imported = new Map<string, Finding[]>();
  for (const finding of findings)
    if (finding.origin) imported.set(finding.origin.tool, [...(imported.get(finding.origin.tool) ?? []), finding]);
  const location = (finding: Finding) => [
    {
      physicalLocation: {
        artifactLocation: { uri: finding.location.file },
        region: { startLine: Math.max(1, finding.location.line) },
      },
    },
  ];
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
              helpUri: `${RULES_URI}#${rule.id.toLowerCase()}`,
              defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
              properties: {
                tags: ['security', 'ai-agents', ...rule.owasp],
                'security-severity': SECURITY_SEVERITY[rule.severity],
                precision: rule.confidence === 'high' ? 'high' : 'medium',
              },
            })),
          },
        },
        results: own.map(finding => ({
          ruleId: finding.ruleId,
          ruleIndex: RULES.findIndex(rule => rule.id === finding.ruleId),
          level: SARIF_LEVEL[finding.severity],
          message: { text: finding.fix ? `${finding.message} Fix: ${finding.fix}` : finding.message },
          locations: location(finding),
          partialFingerprints: { 'agcFingerprint/v1': finding.fingerprint },
          properties: {
            severity: finding.severity,
            confidence: finding.confidence,
            'security-severity': SECURITY_SEVERITY[finding.severity],
            ...(finding.agentId ? { agent: finding.agentId } : {}),
          },
        })),
      },
      // Imported findings keep their own tool's run, as SARIF expects.
      ...[...imported].map(([tool, items]) => {
        const ids = [...new Set(items.map(finding => finding.ruleId.slice(tool.length + 1)))];
        return {
          tool: { driver: { name: tool, rules: ids.map(id => ({ id })) } },
          results: items.map(finding => {
            const id = finding.ruleId.slice(tool.length + 1);
            return {
              ruleId: id,
              ruleIndex: ids.indexOf(id),
              level: SARIF_LEVEL[finding.severity],
              message: { text: finding.message },
              locations: location(finding),
              partialFingerprints: { 'agcFingerprint/v1': finding.fingerprint },
              properties: { severity: finding.severity, 'security-severity': SECURITY_SEVERITY[finding.severity] },
            };
          }),
        };
      }),
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
    findings: result.findings.map(finding => ({
      ...finding,
      title: RULES_BY_ID[finding.ruleId]?.title ?? finding.origin?.title,
    })),
    suppressed: result.suppressed,
    errors: result.errors,
    stats: result.stats,
    modes: result.modes,
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

/**
 * An auditor's inventory: every agent, what it can do and through what, every MCP server, and
 * the finding count, without finding text. Stable across runs for the same files.
 */
export function formatInventory(result: ScanResult): string {
  const body = {
    kind: 'agent-guard-check-inventory',
    schemaVersion: 1,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    evidence: {
      files: true,
      agentGuard: result.modes.agentGuard,
      live: result.modes.live ? { url: result.modes.live.url } : null,
    },
    agents: result.agents.map(agent => {
      const states = authority(agent);
      const mine = result.findings.filter(finding => finding.agentId === agent.id);
      return {
        id: agent.id,
        kind: agent.kind,
        name: agent.name,
        definedIn: agent.location,
        headless: agent.headless,
        runtimeChecks: [...new Set(agent.mediators.map(mediator => mediator.kind))],
        capabilities: Object.fromEntries(
          CAPABILITIES.filter(capability => states[capability].value !== 'no').map(capability => {
            const state = states[capability];
            return [
              capability,
              {
                level: describeLevel(state),
                via: [...new Set(state.grants.map(grant => grant.via))].sort(),
              },
            ];
          }),
        ),
        tools: [...new Set(agent.grants.map(grant => grant.tool).filter((tool): tool is string => !!tool))].sort(),
        findings: Object.fromEntries(
          [...SEVERITY_ORDER].reverse().map(severity => [severity, mine.filter(f => f.severity === severity).length]),
        ),
      };
    }),
    summary: Object.fromEntries(
      [...SEVERITY_ORDER].reverse().map(s => [s, result.findings.filter(f => f.severity === s).length]),
    ),
    suppressed: result.suppressed.length,
  };
  return `${JSON.stringify(body, null, 2)}\n`;
}
