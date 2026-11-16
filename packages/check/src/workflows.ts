import { LineCounter, parseDocument, isMap, type Node } from 'yaml';
import type { Location } from './types.js';
import { parseRule, type PermissionRule } from './claude.js';
import { serversFromObject, type McpServer } from './mcp.js';
import { asString, isRecord, lineOf } from './text.js';

export type AgentAction = 'claude-code-action' | 'claude-cli' | 'codex-action' | 'codex-cli';

/** One step of a GitHub workflow that runs an AI agent. */
export interface WorkflowAgent {
  readonly path: string;
  readonly job: string;
  readonly step: string;
  readonly action: AgentAction;
  readonly location: Location;
  readonly triggers: readonly string[];
  readonly triggerLocation: Location;
  /** Token scopes with write access. `known` is false when the workflow sets no permissions at all. */
  readonly permissions: { readonly write: readonly string[]; readonly known: boolean; readonly location: Location };
  /** The Claude GitHub App token: the action exchanges an OIDC token for it when `id-token: write` is granted. */
  readonly appToken: boolean;
  readonly allowedTools: readonly PermissionRule[];
  readonly disallowedTools: readonly PermissionRule[];
  readonly skipPermissions?: Location;
  readonly maxTurns: boolean;
  readonly timeout: boolean;
  /** Every secret the step can see, by any route. */
  readonly secrets: readonly { readonly name: string; readonly location: Location }[];
  /** Secrets that reach the agent's own environment or tools, not just the harness (telemetry, model access). */
  readonly agentSecrets: readonly { readonly name: string; readonly location: Location }[];
  readonly nonWriteUsers?: { readonly value: string; readonly location: Location };
  /** `pull_request_target` workflow that checks out the pull request's own code. */
  readonly checksOutPullRequest?: Location;
  readonly servers: readonly McpServer[];
  readonly literalInputs: readonly { readonly key: string; readonly value: string; readonly location: Location }[];
}

/**
 * Events whose text anyone can write and that run with the repository's secrets. Pull-request events
 * from forks get a read-only token and no secrets, so `pull_request` and its review events are not listed.
 */
export const UNTRUSTED_TRIGGERS = new Set([
  'issues',
  'issue_comment',
  'pull_request_target',
  'discussion',
  'discussion_comment',
  'workflow_run',
]);
/** Scopes whose write access lets an agent publish text: comments, issues, commits, discussions. */
export const PUBLISHING_SCOPES = new Set(['issues', 'pull-requests', 'contents', 'discussions']);
const MODEL_SECRETS =
  /^(GITHUB_TOKEN|ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|CODEX_API_KEY|ANTHROPIC_BASE_URL|AWS_ROLE_TO_ASSUME|GCP_WORKLOAD_IDENTITY_PROVIDER|GCP_SERVICE_ACCOUNT|ANTHROPIC_VERTEX_PROJECT_ID|AZURE_OPENAI_API_KEY)$/;

function grantsIdToken(value: unknown): boolean {
  return value === 'write-all' || (isRecord(value) && value['id-token'] === 'write');
}

function triggerNames(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string');
  if (isRecord(value)) return Object.keys(value);
  return [];
}

function writeScopes(value: unknown): { write: string[]; known: boolean } {
  if (value === undefined) return { write: [], known: false };
  if (value === 'write-all') return { write: ['*'], known: true };
  if (typeof value === 'string') return { write: [], known: true };
  if (isRecord(value))
    return {
      write: Object.entries(value)
        .filter(([, level]) => level === 'write')
        .map(([scope]) => scope),
      known: true,
    };
  return { write: [], known: true };
}

/** Splits a shell-like argument string, honouring single and double quotes. */
export function splitArgs(text: string): string[] {
  const out: string[] = [];
  const pattern = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text))) out.push(match[1] ?? match[2] ?? match[3] ?? '');
  return out;
}

interface Flags {
  allowedTools: string[];
  disallowedTools: string[];
  skip: boolean;
  maxTurns: boolean;
  mcpConfig?: string;
}

function toolList(value: string): string[] {
  return value
    .split(/,(?![^(]*\))|\s+(?![^(]*\))/)
    .map(item => item.trim())
    .filter(Boolean);
}

function readFlags(text: string): Flags {
  const args = splitArgs(text.replace(/\\\r?\n/g, ' '));
  const flags: Flags = { allowedTools: [], disallowedTools: [], skip: false, maxTurns: false };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    const [name, inline] =
      arg.includes('=') && arg.startsWith('--') ? (arg.split(/=(.*)/s, 2) as [string, string]) : [arg, undefined];
    const value = () => inline ?? args[++i] ?? '';
    if (name === '--allowedTools' || name === '--allowed-tools') {
      flags.allowedTools.push(...toolList(value()));
    } else if (name === '--disallowedTools' || name === '--disallowed-tools') {
      flags.disallowedTools.push(...toolList(value()));
    } else if (
      name === '--dangerously-skip-permissions' ||
      name === '--dangerously-bypass-approvals-and-sandbox' ||
      name === '--yolo'
    ) {
      flags.skip = true;
    } else if (name === '--permission-mode') {
      if (value() === 'bypassPermissions') flags.skip = true;
    } else if (name === '--sandbox') {
      if (value() === 'danger-full-access') flags.skip = true;
    } else if (name === '--max-turns') {
      flags.maxTurns = true;
      value();
    } else if (name === '--mcp-config') {
      flags.mcpConfig = value();
    }
  }
  return flags;
}

const CLAUDE_ACTION = /^anthropics\/claude-code(-base)?-action@/;
const CODEX_ACTION = /^openai\/codex-action@/;
const CLAUDE_CLI = /(^|[\s;&|(])claude\s+[^\n]*(-p\b|--print\b)/;
const CODEX_CLI = /(^|[\s;&|(])codex\s+exec\b/;
const HARNESS_ENV = /^(OTEL_|CLAUDE_CODE_|ANTHROPIC_|CLAUDE_|DISABLE_|MCP_TIMEOUT|BASH_DEFAULT_TIMEOUT)/;
const SECRET_REF = /\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g;

/** Reads a workflow file and returns its agent steps. Throws on invalid YAML. */
export function parseWorkflow(path: string, text: string): WorkflowAgent[] {
  const counter = new LineCounter();
  const doc = parseDocument(text, { lineCounter: counter, uniqueKeys: false });
  if (doc.errors.length) throw new Error(doc.errors[0]!.message);
  const data = doc.toJS({ maxAliasCount: 50 }) as unknown;
  if (!isRecord(data) || !isRecord(data['jobs'])) return [];
  const nodeLine = (node: unknown, fallback: number): number => {
    const range = (node as Node | null)?.range;
    return range ? counter.linePos(range[0]).line : fallback;
  };
  const triggers = triggerNames(data['on']);
  const onNode = isMap(doc.contents)
    ? doc.contents.items.find(pair => (pair.key as { value?: unknown })?.value === 'on')
    : undefined;
  const triggerLocation: Location = { file: path, line: nodeLine(onNode?.key, 1) };
  const workflowPermissions = writeScopes(data['permissions']);
  const workflowEnv = isRecord(data['env']) ? data['env'] : {};
  const agents: WorkflowAgent[] = [];
  for (const [jobName, job] of Object.entries(data['jobs'])) {
    if (!isRecord(job) || !Array.isArray(job['steps'])) continue;
    const jobPermissions = job['permissions'] === undefined ? workflowPermissions : writeScopes(job['permissions']);
    const permissionsLine =
      job['permissions'] !== undefined
        ? nodeLine(doc.getIn(['jobs', jobName, 'permissions'], true), 1)
        : nodeLine(doc.get('permissions', true), 1);
    const steps = job['steps'] as unknown[];
    const checkout = steps.find(
      step =>
        isRecord(step) &&
        /^actions\/checkout@/.test(asString(step['uses']) ?? '') &&
        isRecord(step['with']) &&
        /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref/.test(String(step['with']['ref'] ?? '')),
    );
    steps.forEach((step, index) => {
      if (!isRecord(step)) return;
      const uses = asString(step['uses']) ?? '';
      const run = asString(step['run']) ?? '';
      const action: AgentAction | undefined = CLAUDE_ACTION.test(uses)
        ? 'claude-code-action'
        : CODEX_ACTION.test(uses)
          ? 'codex-action'
          : CLAUDE_CLI.test(run)
            ? 'claude-cli'
            : CODEX_CLI.test(run)
              ? 'codex-cli'
              : undefined;
      if (!action) return;
      const stepNode = doc.getIn(['jobs', jobName, 'steps', index], true);
      const line = nodeLine(stepNode, 1);
      const inputs = isRecord(step['with']) ? step['with'] : {};
      const input = (key: string): string | undefined => {
        const value = inputs[key];
        return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : undefined;
      };
      const inputLine = (key: string): number =>
        nodeLine(doc.getIn(['jobs', jobName, 'steps', index, 'with', key], true), line);
      const flagText = [
        input('claude_args'),
        input('codex-args'),
        input('codex_args'),
        action.endsWith('cli') ? run : undefined,
      ]
        .filter(Boolean)
        .join(' ');
      const flags = readFlags(flagText);
      const legacyTools = (input('allowed_tools') ?? '')
        .split(/[,\n]/)
        .map(item => item.trim())
        .filter(Boolean);
      const toolsLine =
        input('claude_args') !== undefined
          ? inputLine('claude_args')
          : input('allowed_tools') !== undefined
            ? inputLine('allowed_tools')
            : line;
      const allowedTools = [...flags.allowedTools, ...legacyTools].map(raw =>
        parseRule(raw, { file: path, line: toolsLine }),
      );
      const disallowedTools = [
        ...flags.disallowedTools,
        ...toolList((input('disallowed_tools') ?? '').replace(/\n/g, ',')),
      ].map(raw => parseRule(raw, { file: path, line: toolsLine }));
      const sandbox = input('sandbox') ?? input('safety-strategy') ?? '';
      const skip = flags.skip || sandbox === 'danger-full-access' || sandbox === 'unsafe';
      const skipLine =
        sandbox === 'danger-full-access' || sandbox === 'unsafe'
          ? inputLine(input('sandbox') !== undefined ? 'sandbox' : 'safety-strategy')
          : input('claude_args') !== undefined
            ? inputLine('claude_args')
            : line;
      const secretText = JSON.stringify([step['with'] ?? {}, step['env'] ?? {}, job['env'] ?? {}, workflowEnv]);
      const secrets: { name: string; location: Location }[] = [];
      for (const match of secretText.matchAll(SECRET_REF)) {
        const name = match[1]!;
        if (MODEL_SECRETS.test(name) || secrets.some(item => item.name === name)) continue;
        secrets.push({ name, location: { file: path, line: lineOf(text, `secrets.${name}`) } });
      }
      // Environment variables the harness itself reads (telemetry, model and Claude Code settings) are not
      // handed to the agent as data. Inputs that configure tools (MCP servers, settings) are.
      const agentText = JSON.stringify([
        ...[step['env'], job['env'], workflowEnv].flatMap(env =>
          isRecord(env) ? Object.entries(env).filter(([key]) => !HARNESS_ENV.test(key)) : [],
        ),
        ...['mcp_config', 'settings', 'claude_args'].map(key => inputs[key] ?? ''),
      ]);
      const agentSecrets = secrets.filter(secret => agentText.includes(`secrets.${secret.name}`));
      const mcpText = input('mcp_config') ?? flags.mcpConfig;
      let servers: McpServer[] = [];
      if (mcpText && mcpText.trim().startsWith('{')) {
        try {
          const mcpKey = input('mcp_config') !== undefined ? 'mcp_config' : 'claude_args';
          servers = serversFromObject(JSON.parse(mcpText), path, mcpText, 'workflow', inputLine(mcpKey) - 1);
        } catch {
          servers = [];
        }
      }
      const nonWrite = input('allowed_non_write_users');
      const literalInputs = Object.entries(inputs)
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string' && !entry[1].includes('${{'))
        .map(([key, value]) => ({ key, value, location: { file: path, line: inputLine(key) } }));
      agents.push({
        path,
        job: jobName,
        step: asString(step['name']) ?? asString(step['id']) ?? `step ${index + 1}`,
        action,
        location: { file: path, line },
        triggers,
        triggerLocation,
        permissions: { ...jobPermissions, location: { file: path, line: permissionsLine } },
        appToken:
          action === 'claude-code-action' &&
          input('github_token') === undefined &&
          grantsIdToken(job['permissions'] ?? data['permissions']),
        allowedTools,
        disallowedTools,
        ...(skip ? { skipPermissions: { file: path, line: skipLine } } : {}),
        maxTurns: flags.maxTurns || input('max_turns') !== undefined,
        timeout: job['timeout-minutes'] !== undefined || step['timeout-minutes'] !== undefined,
        secrets,
        agentSecrets,
        ...(nonWrite
          ? { nonWriteUsers: { value: nonWrite, location: { file: path, line: inputLine('allowed_non_write_users') } } }
          : {}),
        ...(checkout && triggers.includes('pull_request_target')
          ? {
              checksOutPullRequest: {
                file: path,
                line: nodeLine(doc.getIn(['jobs', jobName, 'steps', steps.indexOf(checkout)], true), line),
              },
            }
          : {}),
        servers,
        literalInputs,
      });
    });
  }
  return agents;
}
