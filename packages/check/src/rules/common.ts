import { createHash } from 'node:crypto';
import type { Agent, Confidence, Location, RuleMeta, Severity } from '../types.js';
import type { Project } from '../model.js';
import type { PermissionRule } from '../claude.js';
import type { McpServer } from '../mcp.js';
import type { CheckConfig } from '../config.js';
import type { LiveEvidence } from '../agent-map.js';

/** What a rule reports. The rule's own metadata fills in the rest. */
export interface ReportInput {
  readonly message: string;
  readonly location: Location;
  /** Stable key within the rule, agent and file; line numbers are left out so moved text keeps its key. */
  readonly subject: string;
  readonly agent?: Agent | undefined;
  readonly severity?: Severity;
  readonly confidence?: Confidence;
  readonly fix?: string;
}
export type Report = (input: ReportInput) => void;

/** What a rule may consult besides the project: the effective config and live evidence (Mode C). */
export interface RuleContext {
  readonly config: CheckConfig;
  readonly live?: LiveEvidence | undefined;
}

export interface Rule extends RuleMeta {
  readonly mode: 'files' | 'agent-guard' | 'agent-map';
  check(project: Project, report: Report, context: RuleContext): void;
}

export function fingerprint(ruleId: string, agentId: string, file: string, subject: string): string {
  return createHash('sha256').update(`${ruleId}\0${agentId}\0${file}\0${subject}`).digest('hex').slice(0, 20);
}

export const ASI = {
  goal: 'ASI01',
  tools: 'ASI02',
  identity: 'ASI03',
  supply: 'ASI04',
  code: 'ASI05',
  memory: 'ASI06',
  cascade: 'ASI08',
  trust: 'ASI09',
  rogue: 'ASI10',
} as const;

export const DESTRUCTIVE_TOOL =
  /(delete|remove|drop|destroy|truncate|merge|push|publish|deploy|send|post|transfer|pay|charge|refund|payment|wire)/i;
export const DESTRUCTIVE_COMMAND =
  /^(git push|rm\b|npm publish|pnpm publish|yarn publish|terraform (apply|destroy)|kubectl (delete|apply)|docker push|gh (pr merge|release|repo delete)|aws s3 rm|gcloud .* delete)/;
export const PIPE_TO_SHELL =
  /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(bash|sh|zsh)\s+<\(\s*(curl|wget)\b|\b(iex|Invoke-Expression)\b[^\n]*\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i;
export const REMOTE_FETCH = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*https?:\/\//i;
export const IDENTITY_WRITE =
  /(>>?|\btee(\s+-a)?|\bsed\s+-i\S*|\bcp\b|\bmv\b)\s+[^|;&\n]*?\b(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)\b/;
export const SETTINGS_WRITE =
  /(>>?|\btee(\s+-a)?|\bsed\s+-i\S*|\bcp\b|\bmv\b|\bjq\b[^\n]*>)\s+[^|;&\n]*?\.claude\/(settings(\.local)?\.json|hooks|agents|skills)/;

const TOKEN_PATTERNS: readonly [string, RegExp][] = [
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}/],
  ['Stripe live key', /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
];
export const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|^AUTH)/i;
export const PLACEHOLDER =
  /^\$|\$\{|^<.*>$|^\{\{.*\}\}$|your|xxx|changeme|example|placeholder|dummy|redacted|replace|insert|\*\*\*|^(true|false|null|none)$/i;

/** A literal value that looks like a real credential rather than a placeholder or reference. */
export function literalSecret(name: string, value: string): string | undefined {
  for (const [label, pattern] of TOKEN_PATTERNS) if (pattern.test(value)) return label;
  if (!SECRET_NAME.test(name)) return undefined;
  const bare = value.replace(/^(Bearer|Basic|token)\s+/i, '').trim();
  if (bare.length < 16 || PLACEHOLDER.test(bare) || !/[0-9]/.test(bare) || !/[A-Za-z]/.test(bare) || /\s/.test(bare))
    return undefined;
  return 'credential';
}

export function knownToken(text: string): { label: string; index: number; value: string } | undefined {
  for (const [label, pattern] of TOKEN_PATTERNS) {
    const match = pattern.exec(text);
    if (match) return { label, index: match.index, value: match[0] };
  }
  return undefined;
}

export const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/;

/** Defines a rule. `mode` says which evidence it needs: files only, Agent Guard artifacts or a live Agent Map. */
export function rule(meta: RuleMeta, check: Rule['check'], mode: Rule['mode'] = 'files'): Rule {
  return Object.freeze({ ...meta, mode, check });
}

export function serverLabel(server: McpServer): string {
  return `MCP server "${server.name}"`;
}

export function agentServers(project: Project): McpServer[] {
  return [...project.servers, ...project.workflows.flatMap(step => step.servers)];
}

export function allowRules(project: Project): PermissionRule[] {
  return [
    ...project.settings.flatMap(file => file.allow),
    ...project.workflows.flatMap(step => step.allowedTools),
    ...project.otherAllow,
  ];
}

export const hooks = (project: Project) => project.settings.flatMap(file => file.hooks);
