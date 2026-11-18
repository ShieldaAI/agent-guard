import { LineCounter, parseDocument, isMap, type Node } from 'yaml';
import type { Location } from './types.js';
import { parseRule, type PermissionRule } from './claude.js';
import { serversFromObject, type CatalogContext, NO_CONTEXT, type McpServer } from './mcp.js';
import { asString, asStringArray, isRecord, lineLocator, lineOf, parseJsonc } from './text.js';
import {
  agentCalls,
  AGENT_MENTION,
  spawnsAgent,
  spawnsWithAgentFlags,
  USES_AGENT_SDK,
  type AgentCli,
} from './shell.js';
import { parse as parseYaml } from 'yaml';

export type AgentAction =
  | 'claude-code-action'
  | 'claude-cli'
  | 'codex-action'
  | 'codex-cli'
  | 'copilot-cli'
  | 'gemini-cli'
  /** An agent whose permissions the scanner does not model, or one it could not place: unknown reach. */
  | 'other-cli';

/** One step of a GitHub workflow that runs an AI agent. */
export interface WorkflowAgent {
  readonly path: string;
  readonly job: string;
  readonly step: string;
  /** The step's index in its job (and, for a script with several agent calls, which call). */
  readonly stepIndex: string;
  readonly action: AgentAction;
  /** The `uses:` of the step, when the agent runs as an action. */
  readonly uses?: string;
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
  /** Settings named for the step that could not be read: what the step may do is unknown. */
  readonly settingsUnreadable?: { readonly value: string; readonly location: Location };
  /** Model endpoint or proxy variables set for the step (ANTHROPIC_BASE_URL, HTTPS_PROXY, ...). */
  readonly endpoints: readonly { readonly name: string; readonly value: string; readonly location: Location }[];
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
  // A reusable workflow with no caller in this repository: whoever calls it decides the event.
  'workflow_call from outside this repository',
]);
/** Scopes whose write access lets an agent publish text: comments, issues, commits, discussions. */
export const PUBLISHING_SCOPES = new Set(['issues', 'pull-requests', 'contents', 'discussions']);
export const MODEL_SECRETS =
  /^(GITHUB_TOKEN|ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|CODEX_API_KEY|ANTHROPIC_BASE_URL|AWS_ROLE_TO_ASSUME|GCP_WORKLOAD_IDENTITY_PROVIDER|GCP_SERVICE_ACCOUNT|ANTHROPIC_VERTEX_PROJECT_ID|AZURE_OPENAI_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|VERTEX_API_KEY|COPILOT_GITHUB_TOKEN)$/;

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
  mcpConfig: string[];
  model?: string;
  /** Codex sandbox from `--sandbox`, `-s`, `-c sandbox_mode=...` or `--full-auto`. */
  sandbox?: string;
  /** `--permission-mode auto`: Claude Code's safety review, not a person, approves each call. */
  autoMode?: boolean;
  /** `--settings`: inline JSON or a path to a settings file. */
  settings?: string;
  /** Flags whose effect is not modelled: `--permission-prompt-tool` (a tool decides approvals). */
  unmodelled: string[];
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

/** Claude Code CLI flags the scan reads or that change nothing it judges: no value, then with a value. */
const CLAUDE_FLAGS = new Set([
  '-p',
  '--print',
  '--verbose',
  '--debug',
  '-d',
  '--continue',
  '-c',
  '--dangerously-skip-permissions',
  '--allow-dangerously-skip-permissions',
  '--strict-mcp-config',
  '--include-partial-messages',
  '--replay-user-messages',
  '--no-session-persistence',
  '--mcp-debug',
  '--version',
  '-v',
  '--help',
  '-h',
]);
const CLAUDE_VALUE_FLAGS = new Set([
  '--output-format',
  '--input-format',
  '--model',
  '--fallback-model',
  '--max-turns',
  '--allowedTools',
  '--allowed-tools',
  '--disallowedTools',
  '--disallowed-tools',
  '--permission-mode',
  '--mcp-config',
  '--settings',
  '--setting-sources',
  '--append-system-prompt',
  '--system-prompt',
  '--system-prompt-file',
  '--append-system-prompt-file',
  '-r',
  '--resume',
  '--session-id',
  '--agents',
  '--permission-prompt-tool',
  '--json-schema',
  '--max-budget-usd',
  '--betas',
  '--tools',
  '--add-dir',
]);
const CODEX_FLAGS = new Set([
  'exec',
  'e',
  'resume',
  '--full-auto',
  '--dangerously-bypass-approvals-and-sandbox',
  '--skip-git-repo-check',
  '--json',
  '--experimental-json',
  '--oss',
  '--include-plan-tool',
  '--version',
  '--help',
  '-h',
  '-V',
]);
const CODEX_VALUE_FLAGS = new Set([
  '-m',
  '--model',
  '-s',
  '--sandbox',
  '-a',
  '--ask-for-approval',
  '-c',
  '--config',
  '-p',
  '--profile',
  '-C',
  '--cd',
  '-i',
  '--image',
  '-o',
  '--output-last-message',
  '--output-schema',
  '--color',
  '--local-provider',
]);
/** Codex `-c` keys the scan reads; any other override is unknown. */
const CODEX_CONFIG_KEYS =
  /^(sandbox_mode|model|model_reasoning_effort|model_verbosity|approval_policy|web_search|hide_agent_reasoning|show_raw_agent_reasoning|sandbox_workspace_write\.network_access|sandbox_workspace_write\.writable_roots)$/;

/**
 * Flags of the Claude Code or Codex CLI that the scan does not model (`--plugin-dir`, `--add-dir`,
 * `--chrome`, a Codex `-c mcp_servers...` override): what they change is unknown, so the step is
 * unknown reach.
 */
export function unknownFlags(action: AgentAction, args: readonly string[]): string[] {
  const claude = action === 'claude-cli' || action === 'claude-code-action';
  const codex = action === 'codex-cli' || action === 'codex-action';
  if (!claude && !codex) return [];
  const plain = claude ? CLAUDE_FLAGS : CODEX_FLAGS;
  const valued = claude ? CLAUDE_VALUE_FLAGS : CODEX_VALUE_FLAGS;
  const out: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === '--') break;
    if (!arg.startsWith('-') || arg === '-') continue;
    const [name, inline] = arg.startsWith('--') && arg.includes('=') ? arg.split(/=(.*)/s, 2) : [arg, undefined];
    // Codex short options take their value attached too: `-sdanger-full-access`.
    if (codex && /^-[smacpCio]./.test(arg) && !arg.startsWith('--')) {
      if (arg.startsWith('-c') && !CODEX_CONFIG_KEYS.test(arg.slice(2).split('=')[0]!.trim())) out.push(arg);
      continue;
    }
    if (plain.has(name!)) continue;
    if (valued.has(name!)) {
      const value = inline ?? args[i + 1] ?? '';
      if (inline === undefined) i += 1;
      // A folder outside the checkout gives the agent files beyond the repository.
      if (
        name === '--add-dir' &&
        /^(\/|~|\$HOME|\.\.)/.test(value.trim()) &&
        !/^\$\{?(GITHUB_WORKSPACE|RUNNER_TEMP)/.test(value.trim())
      )
        out.push(`--add-dir ${value}`);
      if (codex && (name === '-c' || name === '--config') && !CODEX_CONFIG_KEYS.test(value.split('=')[0]!.trim()))
        out.push(`${name} ${value}`);
      continue;
    }
    // Claude Code's short flags may be clustered: `-cp`.
    if (claude && /^-[a-zA-Z]+$/.test(arg) && [...arg.slice(1)].every(char => plain.has(`-${char}`))) continue;
    out.push(arg);
  }
  return out;
}

/** Flags that take a value that does not change what the agent may do. */
const HARMLESS_VALUE_FLAGS = new Set([
  '--model',
  '-m',
  '--fallback-model',
  '--max-turns',
  '--system-prompt',
  '--append-system-prompt',
  '--output-format',
  '--input-format',
  '--session-id',
  '--resume',
  '-r',
  // Codex `exec resume SESSION_ID`.
  'resume',
]);

/**
 * The arguments that hold a GitHub expression where it could be a flag: `${{ inputs.args }}` may
 * expand to anything. An expression as the value of a harmless flag (`--model ${{ vars.MODEL }}`)
 * or inside a longer quoted text (a prompt) is not counted.
 */
export function expressionFlags(args: readonly string[]): string[] {
  // An expression an outsider can fill (an issue title, a comment) can carry any flag, wherever it
  // is. Any other expression can be a flag only as a word of its own (`claude_args: ${{ x }}`), not
  // inside a longer word (`Bash(gh pr comment ${{ github.event.pull_request.number }}:*)`), and not
  // as the value of a harmless flag (`--model ${{ vars.MODEL }}`). splitArgs breaks `${{ x }}` at
  // its spaces, so the word that opens it is the one judged.
  return args.filter((arg, i) => {
    if (!arg.includes('${{')) return false;
    if (UNTRUSTED_EXPRESSION.test(args.slice(i, i + 4).join(' '))) return true;
    return /^\s*\$\{\{/.test(arg) && !HARMLESS_VALUE_FLAGS.has(args[i - 1] ?? '');
  });
}

function readFlags(args: readonly string[]): Flags {
  const flags: Flags = {
    allowedTools: [],
    disallowedTools: [],
    skip: false,
    maxTurns: false,
    mcpConfig: [],
    unmodelled: [],
  };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    const [name, inline] =
      arg.includes('=') && arg.startsWith('--') ? (arg.split(/=(.*)/s, 2) as [string, string]) : [arg, undefined];
    const value = () => inline ?? args[++i] ?? '';
    // Claude Code list flags are variadic: `--allowedTools Bash Edit` takes every value up to the next flag.
    const values = (): string[] => {
      if (inline !== undefined) return [inline];
      const out: string[] = [];
      while (i + 1 < args.length && !args[i + 1]!.startsWith('-')) out.push(args[++i]!);
      return out;
    };
    if (name === '--allowedTools' || name === '--allowed-tools') {
      flags.allowedTools.push(...values().flatMap(toolList));
    } else if (name === '--disallowedTools' || name === '--disallowed-tools') {
      flags.disallowedTools.push(...values().flatMap(toolList));
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
    } else if (/^-s[a-z]/.test(arg) && !arg.startsWith('--')) {
      // Codex's attached form: `-sdanger-full-access`.
      flags.sandbox = widerSandbox(flags.sandbox, arg.slice(2));
      if (flags.sandbox === 'danger-full-access') flags.skip = true;
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
    } else if (name === '--settings') {
      flags.settings = value();
    } else if (name === '--agents') {
      // Subagents defined inline: one in bypassPermissions runs every tool without asking.
      const agents = value();
      if (/bypassPermissions/.test(agents)) flags.skip = true;
      else if (/permissionMode|"tools"/.test(agents)) flags.unmodelled.push('--agents');
    } else if (name === '--permission-prompt-tool') {
      flags.unmodelled.push(`--permission-prompt-tool ${value()}`);
    } else if (name === '--mcp-config') {
      flags.mcpConfig.push(...values());
    } else if (name === '--model' || name === '-m') {
      flags.model = value();
    }
  }
  return flags;
}

// Action names match regardless of case, as GitHub matches owner and repository names, and under
// any owner: a fork of the action runs the same agent.
const CLAUDE_ACTION = /^[^/@\s]+\/claude-code(-base)?-action(\/[^@]*)?@/i;
const CODEX_ACTION = /^[^/@\s]+\/codex-action(\/[^@]*)?@/i;
const GEMINI_ACTION = /^[^/@\s]+\/run-gemini-cli(\/[^@]*)?@/i;
/** Actions that run an agent the scanner does not model (OpenCode, Gemini's own action, Qwen, Goose, ...). */
const OTHER_AGENT_ACTION =
  /^[^/@\s]+\/(opencode|gemini-cli-action|qwen-code-action|goose-action|aider-action|cursor-agent-action|amp-action|crush-action)(\/[^@]*)?@|^sst\/opencode\/github@/i;
/** An agent CLI named anywhere in text that runs (echo lines included: piped into a shell, they run). */
function namesAgentAnywhere(text: string): boolean {
  return AGENT_MENTION.test(text);
}

/** Agent permission flags or agent settings named in action inputs. */
const AGENT_FLAG_TEXT =
  /--dangerously-skip-permissions|--dangerously-bypass|--allow-all-tools|--yolo|bypassPermissions|--allowedTools|--allowed-tools|--permission-mode|claude_args|allowed_tools|danger-full-access/;
/** A container image named for an agent CLI. */
const AGENT_IMAGE = /(claude|codex|gemini-cli|copilot-cli|opencode|aider|qwen-code)/i;

/** Actions that leave cloud credentials for every later step of the job. */
const CREDENTIAL_ACTION =
  /^(aws-actions\/configure-aws-credentials|google-github-actions\/auth|azure\/login|azure\/aks-set-context|docker\/login-action|hashicorp\/vault-action)@/i;
/** A write (redirect, tee, cp, mv, sed -i, jq into a file) to agent settings or MCP config. */
export const AGENT_CONFIG_WRITE =
  /(>>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b|\bsed\s+-i|\bdd\b)[^\n;&|]*(\.claude\/(settings(\.local)?\.json|agents|commands|skills|hooks)|\.claude\.json|\.mcp\.json|managed-settings\.json|managed-mcp\.json|\.codex\/config\.toml|\.gemini\/settings\.json|\.cursor\/(mcp|cli)\.json|opencode\.jsonc?)/;
/**
 * A write to `$GITHUB_ENV` or `$GITHUB_PATH` that moves the agent's settings, loads code or swaps
 * programs for later steps: a settings-moving or loader variable, or text from a file or command.
 */
const ENV_REDIRECT =
  /\b(CLAUDE_CONFIG_DIR|CLAUDE_CODE_\w+|HOME|XDG_CONFIG_HOME|CODEX_HOME|GEMINI_\w+|ANTHROPIC_\w+|OPENAI_BASE_URL|NODE_OPTIONS|BASH_ENV|LD_PRELOAD|DYLD_\w+|PATH|PYTHONPATH|GIT_CONFIG_\w+)=[^\n]*>>\s*"?\$\{?GITHUB_ENV|\b(cat|envsubst|jq|yq|sed|awk|curl|wget)\b[^\n]*>>\s*"?\$\{?GITHUB_ENV|>>\s*"?\$\{?GITHUB_PATH/;

/** CLI commands that add servers or change settings for a later agent run. */
export const AGENT_CONFIG_COMMAND =
  /\b(claude\s+(mcp\s+(add|add-json|add-from-claude-desktop)|config\s+(set|add)|plugin\s+(install|marketplace\s+add))|codex\s+mcp\s+add|gemini\s+(mcp\s+add|extensions?\s+install))\b/;

/** Untrusted text in an expression: whoever opened the issue or pull request chose it. */
const UNTRUSTED_EXPRESSION =
  /github\.event\.[\w.]*(title|body|message|name|ref|label|comment|description|text|login|email|head_commit|pages)|github\.head_ref|inputs\.|steps\.[^.]+\.outputs\.[^}]*(body|title|comment|message|text|prompt)/i;
/** Shell variable names that hold a prompt: a quoted one is the prompt, not a flag. */
const PROMPT_VARIABLE =
  /^"?\$\{?[A-Za-z_]*(PROMPT|MESSAGE|BODY|TEXT|INPUT|QUERY|TASK|INSTRUCTION|CONTEXT|COMMENT|TITLE|ISSUE|REQUEST|QUESTION)[A-Za-z_]*\}?"?$/i;

const CLI_ACTION: Record<AgentCli, AgentAction> = {
  claude: 'claude-cli',
  codex: 'codex-cli',
  copilot: 'copilot-cli',
  gemini: 'gemini-cli',
  other: 'other-cli',
};

/** The agent action a `uses:` names, if any. */
function actionOf(uses: string): AgentAction | undefined {
  // A container image of an agent action runs that action.
  if (/^docker:\/\/.*(claude|codex|gemini|copilot|opencode|aider|goose|qwen)/i.test(uses))
    return /claude-code-action/i.test(uses) ? 'claude-code-action' : 'other-cli';
  if (OTHER_AGENT_ACTION.test(uses)) return 'other-cli';
  return CLAUDE_ACTION.test(uses)
    ? 'claude-code-action'
    : GEMINI_ACTION.test(uses)
      ? 'gemini-cli'
      : CODEX_ACTION.test(uses)
        ? 'codex-action'
        : undefined;
}

/** The repository path of a local action's metadata file (`./`, `./.github/actions/x`). */
function localActionText(uses: string, readFile: (path: string) => string | undefined): string | undefined {
  const folder = uses.replace(/^\.\//, '').replace(/\/+$/, '');
  if (folder.split('/').includes('..') || folder.includes('${{')) return undefined;
  const base = folder ? `${folder}/` : '';
  return readFile(`${base}action.yml`) ?? readFile(`${base}action.yaml`);
}

/**
 * The agent a local composite action runs, looking through its steps (agent actions and CLI
 * calls) and the local actions those use, three levels deep. `unknown` when the file names an
 * agent the scan could not place in a step.
 */
function compositeAgent(
  uses: string,
  readFile: (path: string) => string | undefined,
  depth = 0,
): AgentAction | 'unknown' | undefined {
  if (depth > 3) return 'unknown';
  const text = localActionText(uses, readFile);
  if (text === undefined) return undefined;
  let data: unknown;
  try {
    data = parseYaml(text, { maxAliasCount: 50 });
  } catch {
    return AGENT_ACTION_TEXT.test(text) ? 'unknown' : undefined;
  }
  const runs = isRecord(data) && isRecord(data['runs']) ? data['runs'] : {};
  const folder = uses.replace(/^\.\//, '').replace(/\/+$/, '');
  const inFolder = (name: string) => (folder ? `${folder}/${name}` : name).replace(/^\.\//, '');
  // A JavaScript action: its entry script. A Docker action: its Dockerfile's commands.
  const using = asString(runs['using']) ?? '';
  if (/^node/.test(using)) {
    const main = asString(runs['main']);
    const code = main === undefined ? undefined : readFile(inFolder(main));
    return code !== undefined && (spawnsAgent(code) || spawnsWithAgentFlags(code) || USES_AGENT_SDK.test(code))
      ? 'unknown'
      : undefined;
  }
  if (using === 'docker') {
    const image = asString(runs['image']) ?? '';
    const dockerfile = /^docker:\/\//.test(image) ? undefined : readFile(inFolder(image || 'Dockerfile'));
    const commands = (dockerfile ?? '')
      .split('\n')
      .filter(line => /^\s*(RUN|CMD|ENTRYPOINT)\s/i.test(line))
      .join('\n');
    const entry = JSON.stringify([runs['entrypoint'] ?? '', runs['args'] ?? '']);
    return AGENT_MENTION.test(commands) || AGENT_MENTION.test(entry) || AGENT_IMAGE.test(image) ? 'unknown' : undefined;
  }
  const steps = Array.isArray(runs['steps']) ? runs['steps'] : [];
  for (const step of steps) {
    if (!isRecord(step)) continue;
    const inner = asString(step['uses']) ?? '';
    const found =
      actionOf(inner) ??
      (/^\.\//.test(inner) ? compositeAgent(inner, readFile, depth + 1) : undefined) ??
      (() => {
        const call = agentCalls(asString(step['run']) ?? '')[0];
        return call ? CLI_ACTION[call.cli] : undefined;
      })();
    if (found) return found;
  }
  // Parsed, and no step runs an agent: text that only mentions one (a comment) is not an agent.
  return undefined;
}
/** An agent action, by name, anywhere in a local composite action's text. */
export const AGENT_ACTION_TEXT =
  /claude-code(-base)?-action|codex-action|run-gemini-cli|\bclaude\s+(-p|--print)\b|\bcodex\s+exec\b/i;
/** Whether a workflow file says it was compiled by gh-aw. Only its name and a source make it a lock. */
export function isAgenticLock(text: string): boolean {
  return /^# gh-aw-metadata:/.test(text);
}
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
/**
 * Variables the harness itself reads to reach its model or telemetry. Matched by exact name: a
 * prefix (`ANTHROPIC_DB`, `CLAUDE_DB`) would let a change hide a secret by naming it. The agent's
 * shell can read these too, but they are the harness's own credentials, not data handed to it.
 */
export const HARNESS_SECRET_VARIABLES = new Set([
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'OPENAI_API_KEY',
  'CODEX_API_KEY',
  'AZURE_OPENAI_API_KEY',
  'GEMINI_API_KEY',
  'GOOGLE_API_KEY',
  'COPILOT_GITHUB_TOKEN',
  'AWS_BEARER_TOKEN_BEDROCK',
  'OTEL_EXPORTER_OTLP_HEADERS',
]);
/**
 * Whether an environment entry is the harness's own model credential: a harness variable name
 * whose value is only a model key (by secret name: `MODEL_SECRETS`, or a name ending in API_KEY or
 * an auth token). `OPENAI_API_KEY: ${{ secrets.NPM_TOKEN }}` is not: naming hides nothing.
 */
export function isHarnessCredential(name: string, value: unknown): boolean {
  if (!HARNESS_SECRET_VARIABLES.has(name)) return false;
  const secrets = secretNames(JSON.stringify(value ?? ''));
  // Telemetry headers carry the telemetry service's own token; any other harness variable holds a
  // model key, named for a model provider. A value with no secret in it hides nothing either way.
  const credential = name === 'OTEL_EXPORTER_OTLP_HEADERS' ? TELEMETRY_SECRET : MODEL_PROVIDER_SECRET;
  return secrets.length > 0 && secrets.every(secret => credential.test(secret));
}

/** A secret named for a model provider and holding a key or token (`ZAI_API_KEY`, `OPENROUTER_TOKEN`). */
const MODEL_PROVIDER_SECRET = new RegExp(
  `^(${MODEL_SECRETS.source.replace(/^\^\(|\)\$$/g, '')})$|^([A-Z0-9]+_)*(ANTHROPIC|CLAUDE|OPENAI|CODEX|GEMINI|VERTEX|BEDROCK|AZURE_OPENAI|ZAI|Z_AI|GLM|DEEPSEEK|MOONSHOT|KIMI|OPENROUTER|MISTRAL|GROQ|TOGETHER|FIREWORKS|XAI|GROK|COHERE|PERPLEXITY|LITELLM|COPILOT|MINIMAX|QWEN|DASHSCOPE|CEREBRAS|OPENCODE)(_[A-Z0-9]+)*_(API_KEY|KEY|TOKEN|AUTH_TOKEN|OAUTH_TOKEN)$`,
);
/** A secret named for a telemetry service (`LOGFIRE_TOKEN`, `HONEYCOMB_API_KEY`). */
const TELEMETRY_SECRET =
  /^([A-Z0-9]+_)*(OTEL|OTLP|TELEMETRY|LOGFIRE|HONEYCOMB|DATADOG|DD|GRAFANA|NEW_RELIC|NEWRELIC|LANGFUSE|LANGSMITH|BRAINTRUST|AXIOM)(_[A-Z0-9]+)*$/;

export const SECRET_REF = /\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g;
/** Stands for every secret of the repository: `toJSON(secrets)`, `secrets[inputs.name]`. */
export const ALL_SECRETS = '*';

/**
 * The secrets a text reads in its `${{ }}` expressions: `secrets.NAME`, `secrets['NAME']`, and
 * `*` (ALL_SECRETS) for any other use of the `secrets` context, such as `toJSON(secrets)`.
 */
export function secretNames(text: string): string[] {
  const out = new Set<string>();
  // indexOf, not a lazy regex: a text full of unclosed `${{` is read once.
  const bodies: string[] = [];
  for (let at = text.indexOf('${{'); at >= 0;) {
    const end = text.indexOf('}}', at + 3);
    if (end < 0) break;
    bodies.push(text.slice(at + 3, end));
    at = text.indexOf('${{', end + 2);
  }
  for (const raw of bodies) {
    const body = raw.replace(/\\(["'])/g, '$1');
    let rest = body;
    for (const match of body.matchAll(/\bsecrets\s*(?:\.\s*([A-Za-z0-9_-]+)|\[\s*(['"])([A-Za-z0-9_-]+)\2\s*\])/gi)) {
      out.add((match[1] ?? match[3]!).toUpperCase());
      rest = rest.replace(match[0], '');
    }
    if (/\bsecrets\b/i.test(rest)) out.add(ALL_SECRETS);
  }
  return [...out];
}

/** claude-code-action and codex-action inputs that carry the harness's own credentials. */
const HARNESS_INPUTS =
  /^(anthropic_api_key|claude_code_oauth_token|github_token|openai[-_]api[-_]key|codex[-_]api[-_]key|gemini_api_key|google_api_key|gcp_workload_identity_provider|gcp_service_account)$/;

/** Stands for the callers of a reusable workflow that are not in this repository: anyone's event. */
export const UNKNOWN_CALLER = 'workflow_call from outside this repository';

/** A workflow's triggers and the reusable workflows in this repository its jobs call. */
export function workflowCalls(text: string): { triggers: string[]; callees: string[] } {
  try {
    // Duplicate keys are not checked here (parseWorkflow reports the file): the check is quadratic.
    const data = parseYaml(text, { maxAliasCount: 50, uniqueKeys: false }) as unknown;
    if (!isRecord(data)) return { triggers: [], callees: [] };
    const jobs = isRecord(data['jobs']) ? Object.values(data['jobs']) : [];
    const callees = jobs
      .map(job => (isRecord(job) ? asString(job['uses']) : undefined))
      .filter((uses): uses is string => uses !== undefined && /^\.\/\.github\/workflows\/[^/]+\.ya?ml$/.test(uses))
      .map(uses => uses.slice(2));
    return { triggers: triggerNames(data['on']), callees };
  } catch {
    return { triggers: [], callees: [] };
  }
}

/**
 * The events that can start a reusable workflow: the triggers of its callers in this repository,
 * through callers that are reusable themselves. With no caller here, any repository may call it
 * (UNKNOWN_CALLER).
 */
/** Callers of each reusable workflow, built once per call map. */
const callerIndex = new WeakMap<object, Map<string, string[]>>();

export function inheritedTriggers(
  path: string,
  calls: ReadonlyMap<string, { readonly triggers: readonly string[]; readonly callees: readonly string[] }>,
  seen = new Set<string>(),
): string[] {
  let callers = callerIndex.get(calls);
  if (!callers) {
    callers = new Map();
    for (const [caller, info] of calls)
      for (const callee of new Set(info.callees)) callers.set(callee, [...(callers.get(callee) ?? []), caller]);
    callerIndex.set(calls, callers);
  }
  // `seen` is shared by the whole walk: each caller is visited once, however many paths lead to it.
  seen.add(path);
  const out = new Set<string>();
  const direct = callers.get(path) ?? [];
  for (const caller of direct) {
    const info = calls.get(caller)!;
    for (const trigger of info.triggers) if (trigger !== 'workflow_call') out.add(trigger);
    if (info.triggers.includes('workflow_call') && !seen.has(caller))
      for (const trigger of inheritedTriggers(caller, calls, seen)) out.add(trigger);
  }
  if (!direct.length) out.add(UNKNOWN_CALLER);
  return [...out];
}

/** Reads a workflow file and returns its agent steps. Throws on invalid YAML. */
export function parseWorkflow(
  path: string,
  text: string,
  declared: CatalogContext = NO_CONTEXT,
  readFile: (path: string) => string | undefined = () => undefined,
): WorkflowAgent[] {
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
  const workingDirectoryOf = (value: unknown): string | undefined =>
    isRecord(value) && isRecord(value['run']) ? asString(value['run']['working-directory']) : undefined;
  const workflowDirectory = workingDirectoryOf(data['defaults']);
  // Line numbers of each secret, found once rather than per step.
  const secretLines = new Map<string, number>();
  // Secrets appear in file order: a moving cursor finds each line without rescanning the file.
  const locate = lineLocator(text);
  const secretLine = (name: string): number => {
    if (!secretLines.has(name))
      secretLines.set(name, name === ALL_SECRETS ? locate('secrets') : locate(`secrets.${name}`));
    return secretLines.get(name)!;
  };
  const agents: WorkflowAgent[] = [];
  for (const [jobName, job] of Object.entries(data['jobs'])) {
    // A reusable workflow from another repository, handed agent flags, a model key, or every secret
    // (for one named for an agent): it runs an agent the scan cannot read.
    if (isRecord(job) && typeof job['uses'] === 'string' && !/^\.\//.test(job['uses'])) {
      const remote = job['uses'];
      const given = JSON.stringify([job['with'] ?? {}, job['secrets'] ?? {}]);
      if (
        AGENT_FLAG_TEXT.test(given) ||
        secretNames(given).some(name => MODEL_PROVIDER_SECRET.test(name) && name !== 'GITHUB_TOKEN') ||
        (job['secrets'] === 'inherit' && AGENT_IMAGE.test(remote))
      ) {
        const line = nodeLine(doc.getIn(['jobs', jobName], true), 1);
        const location = { file: path, line };
        const secrets =
          job['secrets'] === 'inherit'
            ? [{ name: ALL_SECRETS, location }]
            : secretNames(given).map(name => ({ name, location }));
        agents.push({
          path,
          job: jobName,
          step: `reusable workflow ${remote}`,
          stepIndex: '0',
          action: 'other-cli',
          uses: remote,
          location,
          triggers,
          triggerLocation,
          permissions: {
            ...(job['permissions'] === undefined ? workflowPermissions : writeScopes(job['permissions'])),
            location,
          },
          appToken: false,
          allowedTools: [],
          disallowedTools: [],
          ...(AGENT_FLAG_TEXT.test(given) &&
          /dangerously|yolo|bypassPermissions|allow-all|danger-full-access/.test(given)
            ? { skipPermissions: location }
            : {}),
          settingsUnreadable: { value: `reusable workflow ${remote} runs an agent the scan cannot read`, location },
          maxTurns: false,
          timeout: job['timeout-minutes'] !== undefined,
          secrets,
          agentSecrets: secrets,
          servers: [],
          environment: false,
          literalInputs: [],
          githubToken: true,
          endpoints: [],
        });
      }
      continue;
    }
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
    const jobDirectory = workingDirectoryOf(job['defaults']) ?? workflowDirectory;
    // Secrets an earlier step wrote to $GITHUB_ENV: every later step of the job has them in its environment.
    const exported = new Set<string>();
    // An earlier step that writes the agent's settings or adds servers: the agent step's reach then
    // depends on what that step wrote.
    let configuredBefore: string | undefined;
    steps.forEach((step, index) => {
      if (!isRecord(step)) return;
      const configuredByEarlier = configuredBefore;
      const ownRun = asString(step['run']) ?? '';
      const configuredHere =
        AGENT_CONFIG_WRITE.test(ownRun) || AGENT_CONFIG_COMMAND.test(ownRun) || ENV_REDIRECT.test(ownRun)
          ? `step ${index + 1} changes agent settings`
          : undefined;
      const configured = configuredByEarlier ?? configuredHere;
      configuredBefore ??= configuredHere;
      const exportedBefore = [...exported];
      const rawRun = asString(step['run']) ?? '';
      // Secrets an earlier step leaves for later ones: through $GITHUB_ENV or $GITHUB_OUTPUT, in a
      // file in the workspace (`> .env`, `tee`), as cloud credentials, or as a token checkout keeps.
      if (/GITHUB_ENV|GITHUB_OUTPUT|>|\btee\b/.test(rawRun))
        for (const name of secretNames(JSON.stringify([rawRun, /GITHUB_ENV/.test(rawRun) ? (step['env'] ?? {}) : {}])))
          exported.add(name);
      const earlierUses = asString(step['uses']) ?? '';
      if (CREDENTIAL_ACTION.test(earlierUses)) exported.add(`CLOUD_CREDENTIALS (${earlierUses.split('@')[0]})`);
      if (/^actions\/checkout@/i.test(earlierUses) && isRecord(step['with'])) {
        const token = secretNames(JSON.stringify(step['with']['token'] ?? '')).filter(name => name !== 'GITHUB_TOKEN');
        if (
          token.length &&
          step['with']['persist-credentials'] !== false &&
          step['with']['persist-credentials'] !== 'false'
        )
          for (const name of token) exported.add(name);
      }
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
      const run = resolveEnv(joinLines(rawRun));
      // Shell variables the script can expand: static env values of the step, job and workflow.
      const shellVars = new Map<string, string>();
      for (const env of [workflowEnv, jobEnv, stepEnv])
        for (const [name, value] of Object.entries(env))
          if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')
            if (!String(value).includes('${{')) shellVars.set(name, String(value));
      // A local composite action (`uses: ./.github/actions/x`) that wraps an agent is an agent
      // whose settings are in a file the scan does not model: unknown reach.
      const wrapped = /^\.\//.test(uses) ? compositeAgent(uses, readFile) : undefined;
      const stepDirectory = asString(step['working-directory']) ?? jobDirectory ?? '';
      const context = { readFile, cwd: stepDirectory.includes('${{') ? '' : stepDirectory.replace(/^\.\/?/, '') };
      // A custom `shell:` (`bash -c "...; {0}"`) runs its own text too; a non-shell language
      // (`shell: python`) is not read as shell.
      // The step's `shell:`, or the job's or workflow's `defaults.run.shell`.
      const shellOf = (value: unknown) =>
        isRecord(value) && isRecord(value['run']) ? asString(value['run']['shell']) : undefined;
      const shellText = asString(step['shell']) ?? shellOf(job['defaults']) ?? shellOf(data['defaults']) ?? '';
      const posixShell = !shellText || /^(bash|sh|zsh)\b/.test(shellText.trim());
      const calls = uses
        ? []
        : [
            ...(posixShell ? agentCalls(run, shellVars, 0, context) : []),
            ...(shellText && posixShell ? agentCalls(shellText.replace(/\{0\}/g, ''), shellVars, 0, context) : []),
          ];
      // An agent named where the scan cannot follow: a non-shell language, stdin piped into a shell,
      // a command chosen by an expression, a github-script that runs a process.
      // `run: ${{ matrix.cmd }}`: the command is in the job's matrix.
      const matrixText =
        // Only when the expression is the command itself (`run: ${{ matrix.cmd }} --flag`).
        /(^|[;&|]\s*|\n\s*)\$\{\{\s*matrix\./.test(rawRun.trimStart()) && isRecord(job['strategy'])
          ? JSON.stringify(job['strategy']['matrix'] ?? '')
          : '';
      const scriptText = matrixText
        ? `${rawRun}\n${matrixText.replace(/[{}[\],"]/g, '\n')}`
        : uses
          ? /^actions\/github-script@/i.test(uses) && isRecord(step['with'])
            ? (asString(step['with']['script']) ?? '')
            : ''
          : rawRun;
      // Text that runs where the scan cannot follow it: piped into a shell, `python -c` / `node -e`
      // code, a command chosen by an expression (its matrix values), a non-shell `shell:`, or a
      // github-script that starts a process. An agent named there is an agent of unknown reach.
      const dynamicText = [
        ...[...rawRun.matchAll(/^(.*)\|\s*(sudo\s+)?(ba|z|da)?sh\b(?!\s+-c)/gm)].map(match => match[1]!),
        ...[...rawRun.matchAll(/\b(python3?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)\s+(.*)$/gm)]
          .map(match => match[2]!)
          .filter(code => spawnsAgent(code)),
        ...(matrixText ? [matrixText] : []),
        ...(!posixShell && spawnsAgent(rawRun) ? [rawRun] : []),
        ...(/^actions\/github-script@/i.test(uses) && spawnsAgent(scriptText) ? [scriptText] : []),
      ].join('\n');
      // Text decoded and piped into a shell (`base64 -d | bash`) is code no one can read here.
      const opaque =
        !calls.length &&
        /\b(base64\s+(-d|--decode|-D)|xxd\s+-r|openssl\s+(enc\s+)?[^|\n]*-d|gunzip|zcat|uudecode|rev)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/.test(
          rawRun,
        );
      // A remote action (or one in a container) handed agent flags or a model key: it runs an agent
      // the scan cannot read.
      const withText = isRecord(step['with']) ? JSON.stringify(step['with']) : '';
      const remoteAgent =
        uses !== '' &&
        !/^\.\//.test(uses) &&
        !actionOf(uses) &&
        (AGENT_FLAG_TEXT.test(withText) ||
          secretNames(withText).some(name => MODEL_PROVIDER_SECRET.test(name) && !/^GITHUB_TOKEN$/.test(name)) ||
          (/^docker:\/\//.test(uses) &&
            agentCalls(asString((step['with'] as Record<string, unknown> | undefined)?.['args']) ?? '').length > 0));
      const containerAgent = !uses && AGENT_IMAGE.test(JSON.stringify(job['container'] ?? ''));
      // A command built from an expression (`${{ format('{0}{1}', 'cla', 'ude') }} -p … --flags`)
      // that carries agent flags.
      const built = /\$\{\{/.test(rawRun) && AGENT_FLAG_TEXT.test(rawRun);
      const hidden =
        !calls.length && (opaque || containerAgent || built || (dynamicText !== '' && namesAgentAnywhere(dynamicText)));
      const detections: {
        action: AgentAction;
        args: readonly string[];
        unresolved: readonly string[];
        unknown?: string;
      }[] = wrapped
        ? [{ action: wrapped === 'unknown' ? 'claude-cli' : wrapped, args: [], unresolved: [] }]
        : actionOf(uses)
          ? [
              {
                action: actionOf(uses)!,
                args: [],
                unresolved: [],
                ...(actionOf(uses) === 'other-cli' ? { unknown: `action ${uses}` } : {}),
              },
            ]
          : remoteAgent
            ? [
                {
                  action: 'other-cli',
                  args: [],
                  unresolved: [],
                  unknown: `action ${uses} runs an agent the scan cannot read`,
                },
              ]
            : hidden
              ? [
                  {
                    action: 'other-cli',
                    args: [],
                    unresolved: [],
                    unknown: opaque
                      ? 'decoded text piped into a shell'
                      : containerAgent
                        ? 'a step in an agent container'
                        : 'an agent named in a script the scan cannot follow',
                  },
                ]
              : calls.map(call => ({
                  action: CLI_ACTION[call.cli],
                  args: call.args,
                  // A quoted variable may still be one flag, unless it is named for a prompt.
                  unresolved: [
                    ...call.unresolved,
                    ...call.args.filter(
                      arg =>
                        /^\$|\$\{?[A-Za-z_]/.test(arg) &&
                        !call.unresolved.includes(arg) &&
                        !PROMPT_VARIABLE.test(arg) &&
                        !/\s/.test(arg) &&
                        arg.startsWith('$'),
                    ),
                  ],
                  ...(call.unknown
                    ? { unknown: `${call.unknown}` }
                    : call.cli === 'other'
                      ? { unknown: `agent CLI ${call.program}` }
                      : {}),
                }));
      detections.forEach((detected, callIndex) => {
        const action = detected.action;
        const wrapsAgent = wrapped !== undefined;
        const stepNode = doc.getIn(['jobs', jobName, 'steps', index], true);
        const line = nodeLine(stepNode, 1);
        // GitHub matches input names without regard to case: `CLAUDE_ARGS` is `claude_args`.
        const inputs: Record<string, unknown> = isRecord(step['with'])
          ? Object.fromEntries(Object.entries(step['with']).map(([key, value]) => [key.toLowerCase(), value]))
          : {};
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
        const inputArgs = ['claude_args', 'codex-args', 'codex_args'].flatMap(key => {
          const value = input(key);
          return value === undefined ? [] : splitArgs(value.replace(/\\\r?\n/g, ' '));
        });
        const flags = readFlags([...inputArgs, ...detected.args]);
        // Arguments the scan cannot read (`$FLAGS`, `${{ inputs.args }}`) could be any flag.
        let codexHomeBypass = false;
        const codexHomeUnknown = (): string[] => {
          if (!action.startsWith('codex')) return [];
          const raw = resolveEnv(
            envValue('CODEX_HOME') ??
              /\bCODEX_HOME=("?)([^\s";]+)\1/.exec(rawRun)?.[2] ??
              String(inputs['codex-home'] ?? ''),
          ).trim();
          if (!raw) return [];
          const inRepo = raw
            .replace(/^(\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?|\.)(\/|$)/, '')
            .replace(/\/+$/, '');
          const config =
            /^\/|\$|~/.test(inRepo) || inRepo.includes('..') ? undefined : readFile(`${inRepo}/config.toml`);
          if (config === undefined) return [`CODEX_HOME ${raw}`];
          // Read: a config that turns the sandbox off is a bypass, as the flag would be.
          if (/^\s*sandbox_mode\s*=\s*["']danger-full-access["']/m.test(config)) codexHomeBypass = true;
          return [];
        };
        const unknownArgs = [
          ...detected.unresolved,
          ...expressionFlags(inputArgs),
          ...unknownFlags(action, [...inputArgs, ...detected.args]),
          // Codex reads its config from CODEX_HOME (or the action's codex-home): a folder in the
          // repository is read; one elsewhere is unknown.
          ...codexHomeUnknown(),
          ...(configured ? [configured] : []),
        ];
        // A CLI started in another folder reads relative settings and MCP paths from there.
        const directory =
          action.endsWith('cli') && !wrapsAgent ? (asString(step['working-directory']) ?? jobDirectory) : undefined;
        const fromDirectory = (named: string): string | undefined => {
          if (directory === undefined || named.startsWith('/')) return named;
          if (directory.includes('${{') || directory.startsWith('/')) return undefined;
          const parts: string[] = [];
          for (const part of `${directory}/${named}`.split('/')) {
            if (part === '' || part === '.') continue;
            if (part === '..') {
              if (!parts.length) return undefined;
              parts.pop();
            } else parts.push(part);
          }
          return parts.join('/');
        };
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
        // Settings for the step: claude-code-action's `settings` input (inline JSON, a YAML mapping or a
        // path to a file in the repository) and `--settings` (JSON or a path). One that cannot be read
        // is unknown: the step may then do anything.
        // Inputs that replace the agent or add code to it: another binary, plugins and marketplaces.
        const replaced = ['path_to_claude_code_executable', 'path_to_bun_executable', 'plugins', 'plugin_marketplaces']
          .filter(key => typeof inputs[key] === 'string' && (inputs[key] as string).trim())
          .map(key => `${key} ${String(inputs[key]).trim().slice(0, 60)}`);
        let settingsUnreadable: string | undefined = wrapsAgent
          ? `local action ${uses}`
          : detected.unknown !== undefined
            ? detected.unknown
            : replaced.length || flags.unmodelled.length
              ? [...replaced, ...flags.unmodelled].join('; ')
              : unknownArgs.length
                ? `arguments ${unknownArgs.join(' ')}`
                : undefined;
        const settingsEnv: Record<string, unknown>[] = [];
        const readSettings = (value: unknown, relative = false): Record<string, unknown> | undefined => {
          if (value === undefined) return undefined;
          let data: unknown = value;
          if (typeof value === 'string') {
            const trimmed = resolveEnv(value).trim();
            // Inline JSON (comments allowed) starts with `{`, `//` or `/*`; anything else is a path.
            const content = /^(\{|\/\/|\/\*)/.test(trimmed)
              ? trimmed
              : /\$\{\{/.test(trimmed)
                ? undefined
                : (() => {
                    const named = relative ? fromDirectory(trimmed.replace(/^\.\//, '')) : trimmed.replace(/^\.\//, '');
                    return named === undefined ? undefined : readFile(named);
                  })();
            if (content === undefined) {
              settingsUnreadable ??= trimmed;
              return undefined;
            }
            try {
              data = parseJsonc(content);
            } catch {
              settingsUnreadable = trimmed.length > 80 ? `${trimmed.slice(0, 80)}...` : trimmed;
              return undefined;
            }
          }
          if (!isRecord(data)) {
            settingsUnreadable = typeof value === 'string' ? value : JSON.stringify(value);
            return undefined;
          }
          if (isRecord(data['env'])) settingsEnv.push(data['env']);
          return isRecord(data['permissions']) ? data['permissions'] : {};
        };
        // `CLAUDE_CONFIG_DIR` or `HOME` moves Claude Code's own settings: read the file it points to,
        // or count the step as unknown when it is outside the repository.
        const redirected: string[] = [];
        if (action.startsWith('claude')) {
          for (const [name, file] of [
            ['CLAUDE_CONFIG_DIR', 'settings.json'],
            ['HOME', '.claude/settings.json'],
          ] as const) {
            const value = envValue(name) ?? new RegExp(`\\b${name}=("?)([^\\s";]+)\\1`).exec(rawRun)?.[2] ?? undefined;
            if (value === undefined) continue;
            const inRepo = value
              .trim()
              .replace(
                /^(\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?|\$\{?PWD\}?|\$\(pwd\)|\.)(\/|$)/,
                '',
              )
              .replace(/\/+$/, '');
            if (/^\/|\$|~/.test(inRepo) || inRepo.includes('..')) settingsUnreadable ??= `${name} ${value}`;
            else redirected.push(inRepo ? `${inRepo}/${file}` : file);
          }
        }
        const settingsSources = [
          readSettings(inputs['settings']),
          readSettings(flags.settings, true),
          ...redirected.map(path => readSettings(path)),
        ].filter((item): item is Record<string, unknown> => item !== undefined);
        const inlineSettings = settingsSources.length
          ? {
              allow: settingsSources.flatMap(item => asStringArray(item['allow'] ?? [])),
              deny: settingsSources.flatMap(item => asStringArray(item['deny'] ?? [])),
              defaultMode: settingsSources.map(item => asString(item['defaultMode'])).find(Boolean),
            }
          : undefined;
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
        // Copilot CLI and Gemini CLI flags that run every tool without asking.
        const cliArgs = detected.args;
        const cliAllowAll =
          (action === 'other-cli' &&
            cliArgs.some(arg =>
              /^(--yolo|--force|-f|--yes-always|--yes|-y|--dangerously-[\w-]+|--auto-approve|--approval-mode=yolo)$/.test(
                arg,
              ),
            )) ||
          (action === 'copilot-cli' && cliArgs.some(arg => /^--(allow-all-tools|allow-all|yolo)(=|$)/.test(arg))) ||
          (action === 'gemini-cli' &&
            (cliArgs.some(
              (arg, i) =>
                /^(--yolo|-[a-z]*y[a-z]*)$/.test(arg) ||
                /^--approval-mode=yolo$/.test(arg) ||
                (arg === '--approval-mode' && cliArgs[i + 1] === 'yolo'),
            ) ||
              (GEMINI_ACTION.test(uses) &&
                /approval_?mode\\?"?\s*:\s*\\?"?yolo|--yolo\b|approval-mode[= ]yolo/i.test(
                  JSON.stringify(Object.fromEntries(Object.entries(inputs).filter(([key]) => key !== 'prompt'))),
                ))));
        const skip =
          codexHomeBypass ||
          cliAllowAll ||
          flags.skip ||
          sandbox === 'danger-full-access' ||
          sandbox === 'unsafe' ||
          settingsMode === 'bypassPermissions';
        const skipLine =
          sandbox === 'danger-full-access' || sandbox === 'unsafe'
            ? inputLine(input('sandbox') !== undefined ? 'sandbox' : 'safety-strategy')
            : input('claude_args') !== undefined
              ? inputLine('claude_args')
              : line;
        const secretText = JSON.stringify([
          step['with'] ?? {},
          step['env'] ?? {},
          job['env'] ?? {},
          workflowEnv,
          action.endsWith('cli') && !wrapsAgent ? rawRun : '',
        ]);
        const secrets: { name: string; location: Location }[] = [];
        for (const name of new Set([...secretNames(secretText), ...exportedBefore])) {
          if (MODEL_SECRETS.test(name)) continue;
          secrets.push({ name, location: { file: path, line: secretLine(name) } });
        }
        // Environment variables the harness itself reads (telemetry, model and Claude Code settings) are not
        // handed to the agent as data. Inputs that configure tools (MCP servers, settings) are.
        // Every input but the harness's own credentials reaches the agent: its prompt, settings, tools.
        // A script that starts a CLI puts its secrets in the agent's process too.
        const agentText = JSON.stringify([
          ...[step['env'], job['env'], workflowEnv].flatMap(env =>
            isRecord(env) ? Object.entries(env).filter(([key, value]) => !isHarnessCredential(key, value)) : [],
          ),
          ...Object.entries(inputs).filter(([key]) => !HARNESS_INPUTS.test(key)),
          action.endsWith('cli') && !wrapsAgent ? rawRun : '',
        ]);
        const reaching = new Set([...secretNames(agentText), ...exportedBefore]);
        const agentSecrets = secrets.filter(secret => reaching.has(secret.name));
        const mcpText = input('mcp_config') ?? flags.mcpConfig[0];
        const extraMcp = input('mcp_config') !== undefined ? flags.mcpConfig : flags.mcpConfig.slice(1);
        const mcpKey = input('mcp_config') !== undefined ? 'mcp_config' : 'claude_args';
        let servers: McpServer[] = [];
        let mcpUnreadable: string | undefined;
        if (mcpText !== undefined && mcpText.trim()) {
          // Inline JSON, or a path to a file in the repository, as `--settings` is read.
          const trimmed = mcpText.trim();
          const inline = /^(\{|\/\/|\/\*)/.test(trimmed);
          const named = inline || /\$\{\{/.test(trimmed) ? undefined : fromDirectory(trimmed.replace(/^\.\//, ''));
          const content = inline ? trimmed : named === undefined ? undefined : readFile(named);
          try {
            if (content === undefined) throw new Error('not read');
            servers = inline
              ? serversFromObject(parseJsonc(content), path, content, 'workflow', inputLine(mcpKey) - 1, declared)
              : serversFromObject(parseJsonc(content), named!, content, 'workflow', 0, declared);
          } catch {
            mcpUnreadable = trimmed.length > 80 ? `${trimmed.slice(0, 80)}...` : trimmed;
          }
        }
        // `--mcp-config a.json b.json`: every file adds servers.
        for (const extra of extraMcp) {
          const trimmed = extra.trim();
          const inline = /^(\{|\/\/|\/\*)/.test(trimmed);
          const named = inline || /\$\{\{/.test(trimmed) ? undefined : fromDirectory(trimmed.replace(/^\.\//, ''));
          const content = inline ? trimmed : named === undefined ? undefined : readFile(named);
          try {
            if (content === undefined) throw new Error('not read');
            servers = [
              ...servers,
              ...serversFromObject(parseJsonc(content), inline ? path : named!, content, 'workflow', 0, declared),
            ];
          } catch {
            mcpUnreadable ??= trimmed.length > 80 ? `${trimmed.slice(0, 80)}...` : trimmed;
          }
        }
        if (mcpUnreadable !== undefined && settingsUnreadable === undefined)
          settingsUnreadable = `MCP config ${mcpUnreadable}`;
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
                    tokenInput && tokenText === tokenInput.trim() ? inputLine('github_token') : secretLine(tokenName),
                },
              }
            : undefined;
        const modelValue = input('model') ?? flags.model;
        // Any bot (`allowed_bots: "*"`) can start the agent too: an app anyone can install.
        const nonWrite = input('allowed_non_write_users') ?? (input('allowed_bots')?.trim() === '*' ? '*' : undefined);
        const literalInputs = Object.entries(inputs)
          .filter((entry): entry is [string, string] => typeof entry[1] === 'string' && !entry[1].includes('${{'))
          .map(([key, value]) => ({ key, value, location: { file: path, line: inputLine(key) } }));
        agents.push({
          path,
          job: jobName,
          step: asString(step['name']) ?? asString(step['id']) ?? `step ${index + 1}`,
          stepIndex: detections.length > 1 ? `${index + 1}.${callIndex + 1}` : String(index + 1),
          action,
          ...(uses ? { uses } : {}),
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
          ...(settingsUnreadable !== undefined
            ? { settingsUnreadable: { value: settingsUnreadable, location: { file: path, line: settingsLine } } }
            : {}),
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
          endpoints: [step['env'], job['env'], workflowEnv, ...settingsEnv].flatMap(env =>
            isRecord(env)
              ? Object.entries(env).flatMap(([name, value]) =>
                  /^(ANTHROPIC_BASE_URL|ANTHROPIC_BEDROCK_BASE_URL|ANTHROPIC_VERTEX_BASE_URL|OPENAI_BASE_URL|HTTPS?_PROXY|ALL_PROXY|NODE_EXTRA_CA_CERTS)$/i.test(
                    name,
                  )
                    ? [{ name, value: String(value), location: { file: path, line: lineOf(text, `${name}:`) || line } }]
                    : [],
                )
              : [],
          ),
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
            ? {
                nonWriteUsers: {
                  value: nonWrite,
                  location: { file: path, line: inputLine('allowed_non_write_users') },
                },
              }
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
    });
  }
  return agents;
}
