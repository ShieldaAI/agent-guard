import { createHash } from 'node:crypto';
import type { Agent, Confidence, Location, RuleMeta, Severity } from '../types.js';
import type { Project } from '../model.js';
import type { PermissionRule } from '../claude.js';
import type { McpServer } from '../mcp.js';
import type { CheckConfig } from '../config.js';
import type { LiveEvidence } from '../agent-map.js';
import type { BranchRules } from '../github.js';

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
  /** The scan's clock in milliseconds, for review dates. */
  readonly now?: number;
  /** What GitHub enforces on the branch changes merge into (`--github-repo`). */
  readonly github?: BranchRules | undefined;
}

export interface Rule extends RuleMeta {
  readonly mode: 'files' | 'agent-guard' | 'agent-map' | 'github';
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
/** Where a line pipes a download into a shell, or -1. Linear: each line is split on `|` once. */
function pipeInLine(line: string): number {
  const segments = line.split('|');
  let at = 0;
  for (const [i, segment] of segments.entries()) {
    if (i > 0 && /^\s*(sudo\s+)?(ba|z|da|k)?sh\b/i.test(segment)) {
      const previous = segments[i - 1]!;
      const fetch = /\b(curl|wget)\b/i.exec(previous);
      if (fetch) return at - previous.length - 1 + fetch.index;
    }
    at += segment.length + 1;
  }
  const substitution = /\b(bash|sh|zsh)\s+<\(\s*(curl|wget)\b/i.exec(line);
  if (substitution) return substitution.index;
  const iex = /\b(iex|Invoke-Expression)\b/i.exec(line);
  if (iex && /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i.test(line.slice(iex.index))) return iex.index;
  return -1;
}

/**
 * `curl … | sh`, `bash <(curl …)`, `iex (iwr …)`. Checked line by line without backtracking, so a
 * long line of repeated `curl` cannot make the scan slow.
 */
export const PIPE_TO_SHELL = {
  exec(text: string): { index: number } | null {
    let offset = 0;
    for (const line of text.split('\n')) {
      const found = pipeInLine(line);
      if (found >= 0) return { index: offset + found };
      offset += line.length + 1;
    }
    return null;
  },
  test(text: string): boolean {
    return this.exec(text) !== null;
  },
};
/** A download from an http(s) URL on one line: the first fetch command, then a URL after it. */
export const REMOTE_FETCH = {
  test(text: string): boolean {
    return text.split('\n').some(line => {
      const fetch = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.exec(line);
      return fetch !== null && /https?:\/\//i.test(line.slice(fetch.index));
    });
  },
};
const IDENTITY_WRITE_PATTERN =
  /(>>?|\btee(\s+-a)?|\bsed\s+-i\S*|\bcp\b|\bmv\b)\s+[^|;&\n]*?\b(CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md)\b/;
const SETTINGS_WRITE_PATTERN =
  /(>>?|\btee(\s+-a)?|\bsed\s+-i\S*|\bcp\b|\bmv\b|\bjq\b[^\n]*>)\s+[^|;&\n]*?\.claude\/(settings(\.local)?\.json|hooks|agents|skills)/;

/**
 * A pattern matched one command at a time, and only in commands that name the target at all: the
 * pattern backtracks over a command that does not, so a long line of `>` would make it slow.
 */
function perCommand(pattern: RegExp, target: RegExp) {
  return {
    exec(text: string): { index: number } | null {
      let offset = 0;
      for (const part of text.split(/([|;&\n])/)) {
        if (part.length > 1 && target.test(part)) {
          const match = pattern.exec(part);
          if (match) return { index: offset + match.index };
        }
        offset += part.length;
      }
      return null;
    },
    test(text: string): boolean {
      return this.exec(text) !== null;
    },
  };
}
export const IDENTITY_WRITE = perCommand(IDENTITY_WRITE_PATTERN, /CLAUDE(\.local)?\.md|AGENTS\.md|SOUL\.md|MEMORY\.md/);
export const SETTINGS_WRITE = perCommand(SETTINGS_WRITE_PATTERN, /\.claude\//);

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

/** Defines a rule. `mode` says which evidence it needs: files only, Agent Guard artifacts, a live Agent Map or GitHub's branch rules. */
export function rule(meta: RuleMeta, check: Rule['check'], mode: Rule['mode'] = 'files'): Rule {
  return Object.freeze({ ...meta, mode, check });
}

export function serverLabel(server: McpServer): string {
  return `MCP server "${server.name}"`;
}

/**
 * A server in a finding's fingerprint: its name and what it runs. Under `--base`, a server whose
 * program changed is a new finding, even when its name already had one.
 */
export function serverKey(server: McpServer): string {
  const launch = [server.command ?? '', ...server.args, server.url ?? ''].join('\0');
  return `${server.name}@${createHash('sha256').update(launch).digest('hex').slice(0, 12)}`;
}

export function agentServers(project: Project): McpServer[] {
  return [...project.servers, ...project.workflows.flatMap(step => step.servers)];
}

export function allowRules(project: Project): PermissionRule[] {
  return [
    ...project.settings.flatMap(file => file.allow),
    ...project.skillAllow,
    ...project.workflows.flatMap(step => step.allowedTools),
    ...project.otherAllow,
  ];
}

export const hooks = (project: Project) => [...project.settings.flatMap(file => file.hooks), ...project.pluginHooks];
