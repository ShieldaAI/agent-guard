import { LineCounter, parseDocument, isMap, type Node } from 'yaml';
import type { Location } from './types.js';
import { parseRule, type PermissionRule } from './claude.js';
import { serversFromObject, type CatalogContext, NO_CONTEXT, type McpServer } from './mcp.js';
import { asString, asStringArray, isRecord, lineOf } from './text.js';

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
  /**
   * A token from a secret handed to the agent instead of the workflow's GITHUB_TOKEN (`github_token`
   * input, or GH_TOKEN / GITHUB_TOKEN in its environment). Its scopes are not visible in the repository.
   */
  readonly customToken?: { readonly name: string; readonly location: Location };
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
  /** The model the step asks for, from `--model` or a `model` input. */
  readonly model?: { readonly value: string; readonly location: Location };
  /** Whether the job runs in a GitHub environment, which can require a reviewer before it starts. */
  readonly environment: boolean;
  readonly literalInputs: readonly { readonly key: string; readonly value: string; readonly location: Location }[];
  /**
   * For Codex steps: the sandbox (`sandbox` input or CLI flag; undefined when not set here) and the
   * permission profile, whose filesystem and network rules live in Codex's own config.
   */
  readonly codex?: { readonly sandbox?: string; readonly profile?: string; readonly location: Location };
  /** A GitHub token reaches the agent (`github_token`, GH_TOKEN or GITHUB_TOKEN, or claude-code-action's own). */
  readonly githubToken: boolean;
  /** Where auto mode is set: tools run when Claude Code's safety review passes them, not a person. */
  readonly autoMode?: Location;
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
export const MODEL_SECRETS =
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
  model?: string;
  /** Codex sandbox from `--sandbox`, `-s`, `-c sandbox_mode=...` or `--full-auto`. */
  sandbox?: string;
  /** `--permission-mode auto`: Claude Code's safety review, not a person, approves each call. */
  autoMode?: boolean;
}

function toolList(value: string): string[] {
  return value
    .split(/,(?![^(]*\))|\s+(?![^(]*\))/)
    .map(item => item.trim())
    .filter(Boolean);
}

/** Codex sandboxes from narrowest to widest; a value Codex does not name is wider than all of them. */
const SANDBOX_ORDER = ['read-only', 'workspace-write', 'danger-full-access'];

/** The wider of two sandbox settings: when flags and inputs disagree, judge the one that allows more. */
export function widerSandbox(a: string | undefined, b: string): string;
export function widerSandbox(a: string | undefined, b: string | undefined): string | undefined;
export function widerSandbox(a: string | undefined, b: string | undefined): string | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  const rank = (value: string) => (SANDBOX_ORDER.includes(value) ? SANDBOX_ORDER.indexOf(value) : SANDBOX_ORDER.length);
  return rank(b) > rank(a) ? b : a;
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
      // auto: a classifier, not a person, approves; acceptEdits: file edits run without asking.
      const mode = value();
      if (mode === 'bypassPermissions') flags.skip = true;
      else if (mode === 'auto') flags.autoMode = true;
      else if (mode === 'acceptEdits') flags.allowedTools.push('Edit');
    } else if (name === '--sandbox' || name === '-s') {
      flags.sandbox = widerSandbox(flags.sandbox, value());
      if (flags.sandbox === 'danger-full-access') flags.skip = true;
    } else if (name === '--full-auto') {
      flags.sandbox = widerSandbox(flags.sandbox, 'workspace-write');
    } else if (name === '-c' || name === '--config') {
      // Codex config overrides (-c sandbox_mode="danger-full-access"). For Claude, -c is --continue and
      // takes no value, so only a key=value argument is consumed.
      const next = inline ?? args[i + 1];
      if (next !== undefined && !next.startsWith('-') && next.includes('=')) {
        if (inline === undefined) i += 1;
        const [key, setting] = next.split(/=(.*)/s, 2);
        if (key?.trim() === 'sandbox_mode') {
          flags.sandbox = widerSandbox(flags.sandbox, (setting ?? '').trim().replace(/^["']|["']$/g, ''));
          if (flags.sandbox === 'danger-full-access') flags.skip = true;
        }
      }
    } else if (name === '--max-turns') {
      flags.maxTurns = true;
      value();
    } else if (name === '--mcp-config') {
      flags.mcpConfig = value();
    } else if (name === '--model' || name === '-m') {
      flags.model = value();
    }
  }
  return flags;
}

const CLAUDE_ACTION = /^anthropics\/claude-code(-base)?-action@/;
const CODEX_ACTION = /^openai\/codex-action@/;
// The CLI may be started by path or through npx (`npx -y @anthropic-ai/claude-code -p`, `@openai/codex exec`).
const CLAUDE_CLI = /(^|[\s;&|(/])claude(-code(@\S*)?)?\s(?:[^\n]*\s)?(-p|--print)\b/;
const CODEX_CLI = /(^|[\s;&|(/])codex(@\S*)?\s+(exec|e)\b/;
/** Steps that put the pull request's own code in the workspace. */
const PR_REF = /github\.event\.pull_request\.(head\.(sha|ref)|number|merge_commit_sha)|github\.head_ref|refs\/pull\//;
const PR_CHECKOUT_RUN =
  /\bgh\s+pr\s+checkout\b|\bgit\s+(fetch|checkout|pull)\b[^\n]*(refs\/pull\/|pull\/\$\{\{|github\.event\.pull_request\.|github\.head_ref)/;
const ENV_REF = /\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g;
const TOKEN_SECRET = /^\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}$/;

/** Joins shell line continuations, so a command split over several lines is read as one. */
function joinLines(text: string): string {
  return text.replace(/\\\r?\n\s*/g, ' ');
}
const HARNESS_ENV = /^(OTEL_|CLAUDE_CODE_|ANTHROPIC_|CLAUDE_|DISABLE_|MCP_TIMEOUT|BASH_DEFAULT_TIMEOUT)/;
export const SECRET_REF = /\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g;

/** Reads a workflow file and returns its agent steps. Throws on invalid YAML. */
export function parseWorkflow(path: string, text: string, declared: CatalogContext = NO_CONTEXT): WorkflowAgent[] {
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
        ((/^actions\/checkout@/.test(asString(step['uses']) ?? '') &&
          isRecord(step['with']) &&
          PR_REF.test(String(step['with']['ref'] ?? ''))) ||
          PR_CHECKOUT_RUN.test(joinLines(asString(step['run']) ?? ''))),
    );
    const jobEnv = isRecord(job['env']) ? job['env'] : {};
    steps.forEach((step, index) => {
      if (!isRecord(step)) return;
      const uses = asString(step['uses']) ?? '';
      // Workflow, job and step `env` values are static text: resolve ${{ env.X }} before reading flags.
      const stepEnv = isRecord(step['env']) ? step['env'] : {};
      const envValue = (name: string): string | undefined => {
        for (const env of [stepEnv, jobEnv, workflowEnv]) {
          const value = env[name];
          if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')
            return String(value);
        }
        return undefined;
      };
      const resolveEnv = (text: string): string =>
        text.replace(ENV_REF, (match, name: string) => envValue(name) ?? match);
      const run = resolveEnv(joinLines(asString(step['run']) ?? ''));
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
      // Arguments may be given as a YAML list or a JSON array as well as one string.
      const quote = (word: string) => `"${word.replace(/["\\]/g, '\\$&')}"`;
      const input = (key: string): string | undefined => {
        const value = inputs[key];
        if (Array.isArray(value)) return resolveEnv(value.map(item => quote(String(item))).join(' '));
        if (typeof value === 'string' && /^\s*\[/.test(value)) {
          try {
            const list = JSON.parse(value) as unknown;
            if (Array.isArray(list)) return resolveEnv(list.map(item => quote(String(item))).join(' '));
          } catch {
            // Not JSON: read it as one string below.
          }
        }
        return typeof value === 'string' ? resolveEnv(value) : typeof value === 'number' ? String(value) : undefined;
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
      // claude-code-action's `settings` input, given inline as JSON: its permissions apply to the step.
      const inlineSettings = (() => {
        const text = input('settings');
        if (!text || !/^\s*\{/.test(text)) return undefined;
        try {
          const data = JSON.parse(text) as unknown;
          return isRecord(data) && isRecord(data['permissions']) ? data['permissions'] : undefined;
        } catch {
          return undefined;
        }
      })();
      const settingsAllow = inlineSettings ? asStringArray(inlineSettings['allow'] ?? []) : [];
      const settingsDeny = inlineSettings ? asStringArray(inlineSettings['deny'] ?? []) : [];
      const settingsMode = inlineSettings ? asString(inlineSettings['defaultMode']) : undefined;
      if (settingsMode === 'acceptEdits') settingsAllow.push('Edit');
      const settingsLine = input('settings') !== undefined ? inputLine('settings') : toolsLine;
      const allowedTools = [
        ...[...flags.allowedTools, ...legacyTools].map(raw => parseRule(raw, { file: path, line: toolsLine })),
        ...settingsAllow.map(raw => parseRule(raw, { file: path, line: settingsLine })),
      ];
      const disallowedTools = [
        ...[...flags.disallowedTools, ...toolList((input('disallowed_tools') ?? '').replace(/\n/g, ','))].map(raw =>
          parseRule(raw, { file: path, line: toolsLine }),
        ),
        ...settingsDeny.map(raw => parseRule(raw, { file: path, line: settingsLine })),
      ];
      const sandbox = input('sandbox') ?? input('safety-strategy') ?? '';
      const skip =
        flags.skip || sandbox === 'danger-full-access' || sandbox === 'unsafe' || settingsMode === 'bypassPermissions';
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
          servers = serversFromObject(JSON.parse(mcpText), path, mcpText, 'workflow', inputLine(mcpKey) - 1, declared);
        } catch {
          servers = [];
        }
      }
      const tokenInput = asString(inputs['github_token']);
      const tokenEnvValue = ['GH_TOKEN', 'GITHUB_TOKEN']
        .map(name => envValue(name))
        .find(value => value !== undefined && TOKEN_SECRET.test(value.trim()));
      const tokenText = (tokenInput && TOKEN_SECRET.test(tokenInput.trim()) ? tokenInput : tokenEnvValue)?.trim();
      const tokenName = tokenText ? TOKEN_SECRET.exec(tokenText)?.[1] : undefined;
      const customToken =
        tokenName && tokenName !== 'GITHUB_TOKEN'
          ? {
              name: tokenName,
              location: {
                file: path,
                line:
                  tokenInput && tokenText === tokenInput.trim()
                    ? inputLine('github_token')
                    : lineOf(text, `secrets.${tokenName}`),
              },
            }
          : undefined;
      const modelValue = input('model') ?? flags.model;
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
        ...(customToken ? { customToken } : {}),
        allowedTools,
        disallowedTools,
        ...(skip ? { skipPermissions: { file: path, line: skipLine } } : {}),
        ...(!skip && (flags.autoMode || settingsMode === 'auto')
          ? {
              autoMode: {
                file: path,
                line:
                  settingsMode === 'auto'
                    ? settingsLine
                    : input('claude_args') !== undefined
                      ? inputLine('claude_args')
                      : line,
              },
            }
          : {}),
        githubToken:
          action === 'claude-code-action' ||
          tokenInput !== undefined ||
          ['GH_TOKEN', 'GITHUB_TOKEN'].some(name => envValue(name) !== undefined),
        ...(action.startsWith('codex')
          ? {
              codex: {
                ...(widerSandbox(input('sandbox'), flags.sandbox) !== undefined
                  ? { sandbox: widerSandbox(input('sandbox'), flags.sandbox)! }
                  : {}),
                ...(input('permission-profile') !== undefined ? { profile: input('permission-profile')! } : {}),
                location: {
                  file: path,
                  line:
                    input('sandbox') !== undefined
                      ? inputLine('sandbox')
                      : input('permission-profile') !== undefined
                        ? inputLine('permission-profile')
                        : line,
                },
              },
            }
          : {}),
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
        ...(modelValue
          ? {
              model: {
                value: modelValue,
                location: {
                  file: path,
                  line: input('model') !== undefined ? inputLine('model') : inputLine('claude_args'),
                },
              },
            }
          : {}),
        environment: job['environment'] !== undefined,
        literalInputs,
      });
    });
  }
  return agents;
}
