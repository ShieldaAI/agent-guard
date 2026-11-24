import { FLAG_TABLES, npxArgv, readArgs, splitUvRequirements } from './runner-flags.js';
import type { Capability, Location } from './types.js';
import { asString, asStringArray, isRecord, lineLocator, lineOf, parseJsonc } from './text.js';

/** One MCP server as a config file declares it. */
export interface McpServer {
  readonly name: string;
  readonly client:
    | 'claude-code'
    | 'vscode'
    | 'cursor'
    | 'workflow'
    | 'codex'
    | 'gemini'
    | 'subagent'
    | 'opencode'
    | 'copilot'
    | 'kiro'
    | 'plugin';
  readonly command?: string;
  readonly args: readonly string[];
  readonly url?: string;
  readonly env: Readonly<Record<string, string>>;
  readonly headers: Readonly<Record<string, string>>;
  readonly location: Location;
  readonly catalog?: CatalogEntry;
  /**
   * What the server runs, when the command has exactly the expected shape: the package, image or
   * remote host. Policy and declarations match on this, never on the config name.
   */
  readonly identity?: { readonly package?: string; readonly image?: string; readonly host?: string };
}

export interface CatalogEntry {
  readonly id: string;
  readonly label: string;
  readonly capabilities: Readonly<Partial<Record<Capability, 'yes' | 'unknown'>>>;
}

/**
 * What well-known MCP servers can do, from their own documentation. A server that is not listed
 * here has unknown capabilities: the scanner never assumes an unlisted server is harmless.
 */
const CATALOG: readonly (CatalogEntry & {
  readonly packages?: readonly string[];
  readonly images?: readonly string[];
  readonly hosts?: readonly string[];
  /** An installed command and its first argument (`sentry mcp`), found on the PATH, not in the repository. */
  readonly commands?: readonly (readonly [string, string])[];
})[] = [
  {
    id: 'github',
    label: 'GitHub',
    packages: ['@modelcontextprotocol/server-github'],
    images: ['ghcr.io/github/github-mcp-server', 'mcp/github'],
    hosts: ['api.githubcopilot.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', egress: 'yes', write: 'yes' },
  },
  {
    id: 'gitlab',
    label: 'GitLab',
    packages: ['@modelcontextprotocol/server-gitlab'],
    images: ['mcp/gitlab'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', egress: 'yes', write: 'yes' },
  },
  {
    id: 'slack',
    label: 'Slack',
    packages: ['@modelcontextprotocol/server-slack'],
    images: ['mcp/slack'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', egress: 'yes', write: 'yes' },
  },
  {
    id: 'gdrive',
    label: 'Google Drive',
    packages: ['@modelcontextprotocol/server-gdrive'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes' },
  },
  {
    id: 'postgres',
    label: 'PostgreSQL',
    packages: ['@modelcontextprotocol/server-postgres'],
    images: ['mcp/postgres'],
    capabilities: { privateData: 'yes' },
  },
  {
    id: 'sqlite',
    label: 'SQLite',
    packages: ['mcp-server-sqlite'],
    images: ['mcp/sqlite'],
    capabilities: { privateData: 'yes', write: 'yes' },
  },
  {
    id: 'supabase',
    label: 'Supabase',
    packages: ['@supabase/mcp-server-supabase'],
    hosts: ['mcp.supabase.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'filesystem',
    label: 'Filesystem',
    packages: ['@modelcontextprotocol/server-filesystem'],
    images: ['mcp/filesystem'],
    capabilities: { privateData: 'unknown', write: 'yes' },
  },
  {
    id: 'fetch',
    label: 'Fetch',
    packages: ['mcp-server-fetch', '@modelcontextprotocol/server-fetch'],
    images: ['mcp/fetch'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'puppeteer',
    label: 'Puppeteer browser',
    packages: ['@modelcontextprotocol/server-puppeteer'],
    images: ['mcp/puppeteer'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'playwright',
    label: 'Playwright browser',
    packages: ['@playwright/mcp'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'brave-search',
    label: 'Brave Search',
    packages: ['@modelcontextprotocol/server-brave-search'],
    images: ['mcp/brave-search'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'context7',
    label: 'Context7 docs',
    packages: ['@upstash/context7-mcp'],
    hosts: ['mcp.context7.com'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'memory',
    label: 'Memory',
    packages: ['@modelcontextprotocol/server-memory'],
    images: ['mcp/memory'],
    capabilities: { write: 'yes', selfModify: 'yes' },
  },
  {
    id: 'git',
    label: 'Git',
    packages: ['mcp-server-git'],
    images: ['mcp/git'],
    capabilities: { write: 'yes' },
  },
  {
    id: 'sentry',
    label: 'Sentry',
    packages: ['@sentry/mcp-server'],
    hosts: ['mcp.sentry.dev'],
    commands: [['sentry', 'mcp']],
    // It can also update issues and create projects and DSNs.
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'notion',
    label: 'Notion',
    packages: ['@notionhq/notion-mcp-server'],
    hosts: ['mcp.notion.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes', egress: 'unknown' },
  },
  {
    id: 'linear',
    label: 'Linear',
    hosts: ['mcp.linear.app'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'atlassian',
    label: 'Atlassian',
    hosts: ['mcp.atlassian.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'stripe',
    label: 'Stripe',
    packages: ['@stripe/mcp'],
    hosts: ['mcp.stripe.com'],
    capabilities: { privateData: 'yes', write: 'yes', spend: 'yes' },
  },
  // Servers that only think or read the clock: nothing to reach.
  {
    id: 'sequential-thinking',
    label: 'Sequential Thinking',
    packages: ['@modelcontextprotocol/server-sequential-thinking'],
    images: ['mcp/sequentialthinking'],
    capabilities: {},
  },
  {
    id: 'time',
    label: 'Time',
    packages: ['mcp-server-time'],
    images: ['mcp/time'],
    capabilities: {},
  },
  // Documentation servers: they return text written by others, and send only the query to one vendor.
  {
    id: 'microsoft-learn',
    label: 'Microsoft Learn docs',
    hosts: ['learn.microsoft.com'],
    capabilities: { untrustedInput: 'yes' },
  },
  {
    id: 'aws-documentation',
    label: 'AWS documentation',
    packages: ['awslabs.aws-documentation-mcp-server'],
    capabilities: { untrustedInput: 'yes' },
  },
  {
    id: 'cloudflare-docs',
    label: 'Cloudflare docs',
    hosts: ['docs.mcp.cloudflare.com'],
    capabilities: { untrustedInput: 'yes' },
  },
  {
    id: 'shopify-dev',
    label: 'Shopify dev docs',
    packages: ['@shopify/dev-mcp'],
    capabilities: { untrustedInput: 'yes' },
  },
  {
    id: 'huggingface',
    label: 'Hugging Face',
    hosts: ['huggingface.co', 'hf.co'],
    // Spaces added as tools run on other people's servers with the arguments they are given.
    capabilities: { untrustedInput: 'yes', egress: 'unknown' },
  },
  {
    id: 'terraform',
    label: 'Terraform registry',
    images: ['hashicorp/terraform-mcp-server'],
    // With a Terraform Cloud token it can also read workspaces and start runs.
    capabilities: { untrustedInput: 'yes', privateData: 'unknown', write: 'unknown', exec: 'unknown' },
  },
  // Web search and browsing: outside text comes in, and queries or page requests go to any host.
  {
    id: 'exa',
    label: 'Exa search',
    packages: ['exa-mcp-server'],
    hosts: ['mcp.exa.ai'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'tavily',
    label: 'Tavily search',
    packages: ['tavily-mcp'],
    hosts: ['mcp.tavily.com'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'firecrawl',
    label: 'Firecrawl',
    packages: ['firecrawl-mcp'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'google-maps',
    label: 'Google Maps',
    packages: ['@modelcontextprotocol/server-google-maps'],
    images: ['mcp/google-maps'],
    capabilities: { untrustedInput: 'yes', egress: 'yes' },
  },
  {
    id: 'chrome-devtools',
    label: 'Chrome DevTools browser',
    packages: ['chrome-devtools-mcp'],
    // It drives a Chrome profile, which may hold the user's sign-ins.
    capabilities: { untrustedInput: 'yes', egress: 'yes', privateData: 'unknown' },
  },
  {
    id: 'browsermcp',
    label: 'Browser MCP (your own browser)',
    packages: ['@browsermcp/mcp'],
    capabilities: { untrustedInput: 'yes', egress: 'yes', privateData: 'yes' },
  },
  // Data stores and SaaS accounts: the account's data, and changes to it.
  {
    id: 'redis',
    label: 'Redis',
    packages: ['@modelcontextprotocol/server-redis'],
    images: ['mcp/redis'],
    capabilities: { privateData: 'yes', write: 'yes' },
  },
  {
    id: 'mongodb',
    label: 'MongoDB',
    packages: ['mongodb-mcp-server'],
    capabilities: { privateData: 'yes', write: 'yes' },
  },
  {
    id: 'neon',
    label: 'Neon',
    packages: ['@neondatabase/mcp-server-neon'],
    hosts: ['mcp.neon.tech'],
    capabilities: { privateData: 'yes', write: 'yes' },
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    packages: ['mcp-server-kubernetes'],
    // `kubectl exec` runs commands in pods, which can reach any host the cluster can.
    capabilities: { privateData: 'yes', write: 'yes', exec: 'yes', egress: 'unknown' },
  },
  {
    id: 'mcp-atlassian',
    label: 'Atlassian (community server)',
    packages: ['mcp-atlassian'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'figma',
    label: 'Figma',
    hosts: ['mcp.figma.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes' },
  },
  {
    id: 'vercel',
    label: 'Vercel',
    hosts: ['mcp.vercel.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'unknown' },
  },
  {
    id: 'posthog',
    label: 'PostHog',
    hosts: ['mcp.posthog.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'asana',
    label: 'Asana',
    hosts: ['mcp.asana.com'],
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes' },
  },
  {
    id: 'zapier',
    label: 'Zapier',
    hosts: ['mcp.zapier.com'],
    // Its tools are whatever actions the account set up: anything, including sending and paying.
    capabilities: { privateData: 'yes', untrustedInput: 'yes', write: 'yes', egress: 'yes', spend: 'unknown' },
  },
];

/** Commands that fetch and run a package named in their arguments. */
const RUNNERS = new Set(['npx', 'bunx', 'uvx', 'pipx', 'pnpx']);

/**
 * What each runner's flags mean before the package: which name the package (`npx -p pkg cmd`,
 * `uvx --from pkg cmd`), which add another package to fetch (`uvx --with pkg`), and which take a
 * value that is not a package (`uvx --python 3.12`, `npx --registry URL`). A flag left out of
 * these lists is read as taking no value. Everything after the package belongs to the server.
 */
const RUNNER_FAMILY: Readonly<Record<string, string>> = {
  npx: 'npx',
  'uv tool run': 'uv',
  'npm exec': 'npm',
  pnpx: 'pnpm',
  'pnpm dlx': 'pnpm',
  'yarn dlx': 'yarn',
  bunx: 'bun',
  uvx: 'uv',
  pipx: 'pipx',
};

interface RunnerSpec {
  readonly runner: string;
  readonly spec: string;
  readonly localOnly: boolean;
}

/** `exec` in front of a shell line's command replaces the shell with it: the command is what runs. */
function withoutExec(line: readonly string[]): string[] {
  let at = 0;
  // bash's exec takes -c, -l and -a NAME before the command.
  if (line[0] === 'exec') for (at = 1; line[at]?.startsWith('-'); at += line[at] === '-a' ? 2 : 1);
  return line.slice(at);
}

/** Whether a runner is uv's (`uvx` is `uv tool run`), or reads Python requirements. */
export const isUvRunner = (runner: string) => runner === 'uvx' || runner === 'uv tool run';
export const isPythonRunner = (runner: string) => isUvRunner(runner) || runner === 'pipx';

/**
 * Whether npm exec may only run an installed copy. The last option that says so wins, as npm reads
 * it. npm exec does not know --no-install (npx turns it into --yes=false first), and reads -n as
 * --no-yes (npx drops -n as a removed option).
 */
function installedOnly(options: readonly string[]): boolean {
  let local = false;
  for (const word of options) {
    if (['--no', '--no-yes', '--yes=false', '-n'].includes(word)) local = true;
    else if (['-y', '--yes', '--yes=true'].includes(word)) local = false;
  }
  return local;
}

/**
 * The package a runner command starts and the extra packages it fetches with it, read from the
 * runner's own options only; `unreadable` when an option this check does not know may take the
 * next word as its value; undefined when the command is not a runner.
 */
function runnerParts(
  command: string | undefined,
  args: readonly string[],
):
  | { readonly first: RunnerSpec; readonly extras: readonly string[]; readonly unreadable?: undefined }
  | { readonly unreadable: string }
  | undefined {
  if (!command) return undefined;
  const base = (command.split(/[\\/]/).at(-1) ?? command).replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
  // Launchers that run a command line: `cmd /c npx -y pkg` (the documented Windows form) and `sh -c "npx -y pkg"`.
  if (base === 'cmd' && /^\/[ck]$/i.test(args[0] ?? '') && args[1] !== undefined) {
    const line = withoutExec(args.length === 2 ? splitShell(args[1]) : args.slice(1));
    return runnerParts(line[0], line.slice(1));
  }
  // `-c`, or joined short flags ending in c (`-lc`, `-ic`), takes the script, as in runnerSpecs.
  const script = ['sh', 'bash', 'zsh', 'dash'].includes(base) ? args.findIndex(arg => /^-[a-z]*c$/.test(arg)) : -1;
  if (script >= 0 && args[script + 1] !== undefined) {
    const line = withoutExec(splitShell(args[script + 1]!));
    return runnerParts(line[0], line.slice(1));
  }
  let rest = [...args];
  let runner = base;
  if ((base === 'pnpm' || base === 'yarn') && rest[0] === 'dlx') {
    runner = `${base} dlx`;
    rest = rest.slice(1);
  } else if (base === 'pipx' && rest[0] === 'run') {
    rest = rest.slice(1);
  } else if (base === 'npm' && rest[0] === 'exec') {
    runner = 'npm exec';
    rest = rest.slice(1);
  } else if (base === 'uv' && rest[0] === 'tool' && rest[1] === 'run') {
    runner = 'uv tool run';
    rest = rest.slice(2);
  } else if (!RUNNERS.has(base)) return undefined;
  // npx is npm exec after npx-cli's own pass over the options (npxArgv).
  const npx = RUNNER_FAMILY[runner] === 'npx';
  if (npx) rest = npxArgv(rest);
  const family = npx ? 'npm' : RUNNER_FAMILY[runner]!;
  const table = FLAG_TABLES[family]!;
  const unreadable = (option: string, word: string) => ({
    unreadable: `starts ${runner} with ${option}, an option this check does not know, so it cannot tell whether "${word}" is that option's value or the package to run`,
  });
  // npm exec reads options anywhere before `--` (npm's own parser); every other runner, and npx,
  // which puts `--` before the first plain word, stop at the package. What follows is the server's.
  const mains: string[] = [];
  const extraValues: string[] = [];
  const options: string[] = [];
  const positionals: string[] = [];
  let words = rest;
  for (;;) {
    const read = readArgs(words, table);
    if (read.unknown) return unreadable(read.unknown.option, read.unknown.word);
    mains.push(...read.main);
    extraValues.push(...read.extra);
    const end = read.at < 0 ? words.length : read.at;
    const ended = end > 0 && words[end - 1] === '--' && !options.includes('--');
    options.push(...words.slice(0, end));
    if (read.at < 0) break;
    if (family !== 'npm' || ended) {
      positionals.push(...words.slice(read.at));
      break;
    }
    positionals.push(words[read.at]!);
    words = words.slice(read.at + 1);
  }
  // A flag naming the package makes the first plain word the command; otherwise that word is the package.
  const main = mains[0] ?? positionals[0];
  if (main === undefined) return undefined;
  // Packages listed in a file, or handed to pip, are not in the config: what they pin cannot be read.
  const listed = options.find(word => /^(--with-requirements|--pip-args)(=|$)/.test(word));
  if (listed)
    return {
      unreadable: `starts ${runner} with ${listed.split('=')[0]}, which installs packages this check does not read`,
    };
  const localOnly = family === 'npm' && installedOnly(options);
  const extras = [
    ...mains.slice(1),
    ...extraValues.flatMap(value => (family === 'uv' ? splitUvRequirements(value) : [value])),
  ];
  return { first: { runner, spec: main, localOnly }, extras: extras.filter(spec => spec !== main) };
}

/** The package a runner command starts, with its version marker, or undefined. */
export function runnerPackage(command: string | undefined, args: readonly string[]): RunnerSpec | undefined {
  const parts = runnerParts(command, args);
  return parts && 'first' in parts ? parts.first : undefined;
}

/**
 * Every package a runner command fetches: the one it runs and any extras its runner's options add
 * (`-p`/`--package` for npm runners, `--with` for uvx), each with its runner. `unverifiable` says
 * why what it fetches cannot be read from the config: a shell line that runs more than one
 * command, or an option this check does not know.
 */
export function runnerSpecs(
  command: string | undefined,
  args: readonly string[],
): {
  readonly specs: readonly RunnerSpec[];
  readonly unverifiable: string | undefined;
} {
  const SHELL = 'starts a shell line with more than one command, so what it fetches and runs cannot be checked';
  if (!command) return { specs: [], unverifiable: undefined };
  const base = (command.split(/[\\/]/).at(-1) ?? command).replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
  if (base === 'cmd' && /^\/[ck]$/i.test(args[0] ?? '') && args[1] !== undefined) {
    const words = args.length === 2 ? args[1] : args.slice(1).join(' ');
    if (/[;&|`$<>(){}\n\r^]/.test(words)) return { specs: [], unverifiable: SHELL };
    const line = withoutExec(splitShell(words));
    return runnerSpecs(line[0], line.slice(1));
  }
  // `-c`, or combined short flags ending in c (`-lc`, `-ic`), takes the script.
  const scriptFlag = args.findIndex(arg => /^-[a-z]*c$/.test(arg));
  if (['sh', 'bash', 'zsh', 'dash'].includes(base) && scriptFlag >= 0) {
    const script = args[scriptFlag + 1] ?? '';
    if (/[;&|`$<>(){}\n\r]/.test(script)) return { specs: [], unverifiable: SHELL };
    const line = withoutExec(splitShell(script));
    return runnerSpecs(line[0], line.slice(1));
  }
  const parts = runnerParts(command, args);
  if (!parts) return { specs: [], unverifiable: undefined };
  if (!('first' in parts)) return { specs: [], unverifiable: parts.unreadable };
  const specs = [parts.first, ...[...new Set(parts.extras)].map(spec => ({ ...parts.first, spec }))];
  return { specs, unverifiable: undefined };
}

/** Splits a shell command line into words, honouring quotes. */
function splitShell(text: string): string[] {
  const out: string[] = [];
  const pattern = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text))) out.push(match[1] ?? match[2] ?? match[3] ?? '');
  return out;
}

/**
 * Splits `name@version` (npm, including scoped names) or a Python requirement such as `name==1.0`.
 * `operator` is `@` for npm, and the comparison (`==`, `>=`, `~=`, ...) or `@` for Python.
 */
export function splitSpec(spec: string): {
  readonly name: string;
  readonly version?: string;
  readonly operator?: string;
} {
  // A Python environment marker (`pkg==1.0; python_version<'3.12'`) says when, not what.
  if (/;/.test(spec) && !spec.startsWith('@')) spec = spec.slice(0, spec.indexOf(';')).trim();
  const python = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(===|==|>=|<=|~=|!=|>|<|@)\s*(.+)$/.exec(spec);
  if (python && !spec.startsWith('@')) return { name: python[1]!, version: python[3]!, operator: python[2]! };
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1), operator: '@' };
  return { name: spec };
}

/** Whether a package spec names one exact release: `pkg@1.2.3` (npm) or `pkg==1.2.3` (Python). */
export function isPinnedSpec(runner: string, spec: string): boolean {
  const { version, operator } = splitSpec(spec);
  if (!version) return false;
  if (isPythonRunner(runner)) {
    // A direct source, bare or as PEP 508 `name @ url`, is fixed only by a full git commit
    // (`git+https://host/repo.git@<40 hex>`) or an archive's sha256 (`https://…/x.whl#sha256=<64 hex>`).
    const source = /^(git\+|https?:\/\/)/i.test(spec)
      ? spec
      : operator === '@' && /:\/\//.test(version)
        ? version
        : undefined;
    if (source !== undefined) return /^git\+.*@[0-9a-f]{40}$/i.test(source) || /#sha256=[0-9a-f]{64}$/i.test(source);
    // uvx also takes `pkg@1.2.3` as an exact version (and `pkg@latest` as none).
    if (isUvRunner(runner) && operator === '@')
      return /^\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$/i.test(version);
    // A Python requirement: only == (or ===) with a version that has no wildcard.
    return (
      (operator === '==' || operator === '===') &&
      /^v?\d+(\.\d+)*([a-z0-9.+-]*)$/i.test(version) &&
      !version.includes('*')
    );
  }
  // npm: an exact semantic version. A range, a major alone (@1), or a tag (@latest, @beta) moves.
  return operator === '@' && /^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(version);
}

/**
 * The image a `docker run` or `podman run` command starts; `unreadable` when an option this check
 * does not know may take the next word as its value; undefined when it is not one, or replaces the
 * entrypoint (then it runs something else inside the image, not that image's server).
 */
export function dockerRun(
  command: string | undefined,
  args: readonly string[],
): { readonly image: string; readonly unreadable?: undefined } | { readonly unreadable: string } | undefined {
  if (!command) return undefined;
  const base = baseName(command);
  // The same launchers as runners: `cmd /c docker run …` and `sh -c "docker run …"`, one command only.
  if (base === 'cmd' && /^\/[ck]$/i.test(args[0] ?? '') && args[1] !== undefined) {
    const words = args.length === 2 ? args[1] : args.slice(1).join(' ');
    if (/[;&|`$<>(){}\n\r^]/.test(words)) return undefined;
    const line = withoutExec(splitShell(words));
    return dockerRun(line[0], line.slice(1));
  }
  const script = ['sh', 'bash', 'zsh', 'dash'].includes(base) ? args.findIndex(arg => /^-[a-z]*c$/.test(arg)) : -1;
  if (script >= 0 && args[script + 1] !== undefined) {
    if (/[;&|`$<>(){}\n\r]/.test(args[script + 1]!)) return undefined;
    const line = withoutExec(splitShell(args[script + 1]!));
    return dockerRun(line[0], line.slice(1));
  }
  if (base !== 'docker' && base !== 'podman') return undefined;
  // Global options come first (`docker --context x run`), and `container run` is `run`.
  const global = readArgs(args, FLAG_TABLES['container']!);
  if (global.unknown)
    return {
      unreadable: `starts ${baseName(command)} with ${global.unknown.option}, an option this check does not know, so it cannot tell whether "${global.unknown.word}" is that option's value or the command`,
    };
  let at = global.at;
  if (at >= 0 && args[at] === 'container') at += 1;
  if (at < 0 || args[at] !== 'run') return undefined;
  const runArgs = args.slice(at + 1);
  const read = readArgs(runArgs, FLAG_TABLES['run']!);
  // A replaced entrypoint runs something else; with --rootfs the word is a folder, not an image.
  if (read.seen.has('--entrypoint') || read.seen.has('--rootfs')) return undefined;
  if (read.unknown)
    return {
      unreadable: `runs a container with ${read.unknown.option}, an option this check does not know, so it cannot tell whether "${read.unknown.word}" is that option's value or the image`,
    };
  return read.at >= 0 ? { image: runArgs[read.at]! } : undefined;
}

/** The image a `docker run` command starts, or undefined. */
export function dockerImage(command: string | undefined, args: readonly string[]): string | undefined {
  const run = dockerRun(command, args);
  return run && 'image' in run ? run.image : undefined;
}

/** Runner flags that change neither what is fetched nor what runs. Any other flag ends identification. */
const SAFE_RUNNER_FLAGS = new Set([
  '-y',
  '--yes',
  '-q',
  '--quiet',
  '--silent',
  '--no',
  '--no-install',
  '--offline',
  '--prefer-offline',
  '--isolated',
  '--no-cache',
  '--refresh',
]);
/** Environment variables that change what a runner fetches, or what code an interpreter loads. */
const LOADER_ENV =
  /^(DOCKER_HOST|DOCKER_CONFIG|DOCKER_CONTEXT|DOCKER_CERT_PATH|CONTAINER_HOST|NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|npm_config_.*|YARN_.*|PNPM_.*|BUN_.*|DENO_.*|PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|PYTHONUSERBASE|PIP_.*|PIPX_.*|UV_.*|LD_.*|DYLD_.*|PATH|JAVA_TOOL_OPTIONS|RUBYOPT|PERL5OPT)$/i;
/** Shell syntax that runs more than one command, or substitutes one. */
const SHELL_SYNTAX = /[;&|`$<>(){}\n\r]/;

/**
 * Whether a command is found on the system rather than in the repository: a bare name, or an
 * absolute path in a system folder. `./bin/npx` or `tools\\npx.cmd` is a file the change chose.
 */
function systemCommand(command: string): boolean {
  if (!/[\\/]/.test(command)) return /^[A-Za-z0-9_.-]+$/.test(command);
  return (
    /^\/(usr\/(local\/)?)?s?bin\/[A-Za-z0-9_.-]+$/.test(command) ||
    /^\/opt\/homebrew\/bin\/[A-Za-z0-9_.-]+$/.test(command) ||
    /^[A-Za-z]:\\(Program Files( \(x86\))?|Windows)\\/i.test(command)
  );
}

function baseName(command: string): string {
  return (command.split(/[\\/]/).at(-1) ?? command).replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
}

/**
 * The package a server runs, for the catalog, only when the command has exactly the shape of
 * "runner, harmless flags, package, the package's own arguments". `-p pkg other-command`,
 * `--call`, a registry or other flag, a shell line with a second command, or an environment
 * variable that changes what is loaded all mean the package name says nothing about what runs.
 */
function catalogPackage(
  command: string | undefined,
  args: readonly string[],
  env: Readonly<Record<string, string>>,
): { readonly name: string; readonly ecosystem: 'npm' | 'python' } | undefined {
  if (!command || !systemCommand(command) || Object.keys(env).some(name => LOADER_ENV.test(name))) return undefined;
  const base = baseName(command);
  if (base === 'cmd' && /^\/[ck]$/i.test(args[0] ?? '') && args[1] !== undefined) {
    const words = args.length === 2 ? args[1] : args.slice(1).join(' ');
    if (SHELL_SYNTAX.test(words)) return undefined;
    const line = splitShell(words);
    return catalogPackage(line[0], line.slice(1), {});
  }
  if (['sh', 'bash', 'zsh', 'dash'].includes(base)) {
    if (args.length !== 2 || args[0] !== '-c' || SHELL_SYNTAX.test(args[1]!)) return undefined;
    const line = splitShell(args[1]!);
    return catalogPackage(line[0], line.slice(1), {});
  }
  let rest = [...args];
  if ((base === 'pnpm' || base === 'yarn') && rest[0] === 'dlx') rest = rest.slice(1);
  else if (base === 'pipx' && rest[0] === 'run') rest = rest.slice(1);
  else if (base === 'npm' && rest[0] === 'exec') rest = rest.slice(1);
  else if (!RUNNERS.has(base)) return undefined;
  const ecosystem = base === 'uvx' || base === 'pipx' ? 'python' : 'npm';
  for (const arg of rest) {
    if (arg === '--') continue;
    if (arg.startsWith('-')) {
      if (SAFE_RUNNER_FLAGS.has(arg)) continue;
      return undefined;
    }
    const name = registryName(arg);
    return name === undefined ? undefined : { name, ecosystem };
  }
  return undefined;
}

/**
 * The registry package a spec names, or undefined when the spec fetches from somewhere else: an npm
 * alias (`name@npm:other`), a URL, git or a local path (`name@github:x`, `name@file:./x`), or a
 * Python direct reference (`name @ git+https://...`).
 */
function registryName(spec: string): string | undefined {
  const { name, version, operator } = splitSpec(spec);
  if (!/^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(name)) return undefined;
  if (version !== undefined && (/[:/\\\s]/.test(version) || (operator === '@' && /^[a-z]+\+/.test(version))))
    return undefined;
  return name;
}

/**
 * `docker run` flags that take a value and change neither the image nor what it runs. Mounts and
 * the working folder are not listed: a mount can replace the image's own code.
 */
const DOCKER_VALUED = new Set([
  '-e',
  '--env',
  '--name',
  '--network',
  '--net',
  '-u',
  '--user',
  '--add-host',
  '-m',
  '--memory',
  '--cpus',
  '-l',
  '--label',
  '--platform',
  '--pull',
  '-h',
  '--hostname',
  '--tmpfs',
  '--ulimit',
  '--dns',
  '--expose',
  '-p',
  '--publish',
  '--log-driver',
  '--stop-signal',
  '--restart',
]);
const DOCKER_FLAGS = new Set([
  '-i',
  '--interactive',
  '-t',
  '--tty',
  '-it',
  '-ti',
  '--rm',
  '-d',
  '--detach',
  '--init',
  '--read-only',
  '-q',
  '--quiet',
  '-P',
  '--publish-all',
]);

/**
 * The image a server runs, for the catalog, only when every `docker run` flag before it is known:
 * an unknown flag might take the next word as its value, and `--entrypoint`, `--env-file` or an
 * environment variable that changes what is loaded means the image name says nothing about what runs.
 */
function catalogImage(
  command: string | undefined,
  args: readonly string[],
  env: Readonly<Record<string, string>>,
): string | undefined {
  if (!command || !systemCommand(command) || !['docker', 'podman'].includes(baseName(command)) || args[0] !== 'run')
    return undefined;
  if (Object.keys(env).some(name => LOADER_ENV.test(name))) return undefined;
  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i]!;
    if (!arg.startsWith('-')) return arg.split('@')[0]!.replace(/:[^/:]+$/, '');
    const [flag, inline] = arg.includes('=')
      ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)]
      : [arg, undefined];
    if (DOCKER_FLAGS.has(flag) && inline === undefined) continue;
    if (!DOCKER_VALUED.has(flag)) return undefined;
    const value = inline ?? args[(i += 1)];
    if (value === undefined) return undefined;
    if ((flag === '-e' || flag === '--env') && LOADER_ENV.test(value.split('=')[0]!)) return undefined;
  }
  return undefined;
}

/**
 * A team's own statement of what an MCP server can do, from `.agc.yaml` (`mcp_servers`). `match` is a
 * server's config name, a catalog ID, a package, an image or a remote host. It takes precedence over
 * the built-in catalog.
 */
export interface DeclaredServer {
  readonly match: string;
  readonly capabilities: Readonly<Partial<Record<Capability, 'yes' | 'unknown'>>>;
}

/**
 * What identification needs besides the server itself: the team's declarations, the packages the
 * repository itself depends on (a runner resolves those locally, from whatever the dependency spec
 * says), and whether the repository configures where packages come from (`.npmrc`, `uv.toml`, ...).
 */
export interface CatalogContext {
  readonly declared: readonly DeclaredServer[];
  /** Package names the repository provides or depends on anywhere: a runner may resolve those locally. */
  readonly localPackages: ReadonlySet<string>;
  /**
   * Folders ('' for the root) whose package-source files redirect npm-family or Python runners.
   * A redirect applies to servers configured in that folder or below.
   */
  readonly redirected: { readonly npm: ReadonlySet<string>; readonly python: ReadonlySet<string> };
}

export const NO_CONTEXT: CatalogContext = Object.freeze({
  declared: Object.freeze([]),
  localPackages: new Set<string>(),
  redirected: { npm: new Set<string>(), python: new Set<string>() },
});

/** Whether a folder or one above it is in a set of folders ('' for the root). */
function underAny(folders: ReadonlySet<string>, path: string): boolean {
  const parts = path.split('/').slice(0, -1);
  for (let depth = 0; depth <= parts.length; depth += 1) if (folders.has(parts.slice(0, depth).join('/'))) return true;
  return false;
}

/** What a server runs: its package, image or host, each only for an exact command shape. */
function identityOf(
  command: string | undefined,
  args: readonly string[],
  url: string | undefined,
  env: Readonly<Record<string, string>>,
  context: CatalogContext,
  path: string,
): { package?: string; image?: string; host?: string; installed?: readonly [string, string] } {
  // A server with both a command and a URL is ambiguous: which one runs depends on the client.
  if (command !== undefined && url !== undefined) return {};
  const found = catalogPackage(command, args, env);
  // The repository decides what a dependency, or a registry configured for that runner, resolves to.
  const pkg =
    found !== undefined &&
    !context.localPackages.has(found.name) &&
    !underAny(context.redirected[found.ecosystem], path)
      ? found.name
      : undefined;
  const image = catalogImage(command, args, env);
  // A bare command name (no path, so not a file in the repository) and its first argument.
  const installed: readonly [string, string] | undefined =
    command !== undefined && /^[A-Za-z0-9_-]+$/.test(command) && !Object.keys(env).some(name => LOADER_ENV.test(name))
      ? [command, args[0] ?? '']
      : undefined;
  let host: string | undefined;
  if (url) {
    try {
      host = new URL(url).hostname;
    } catch {
      host = undefined;
    }
  }
  return {
    ...(pkg !== undefined ? { package: pkg } : {}),
    ...(image !== undefined ? { image } : {}),
    ...(host !== undefined ? { host } : {}),
    ...(installed !== undefined ? { installed } : {}),
  };
}

function identify(identity: ReturnType<typeof identityOf>, declared: CatalogContext): CatalogEntry | undefined {
  const { package: pkg, image, host, installed } = identity;
  const known = CATALOG.find(
    entry =>
      (pkg !== undefined && entry.packages?.includes(pkg)) ||
      (image !== undefined && entry.images?.includes(image)) ||
      (host !== undefined && entry.hosts?.includes(host)) ||
      (installed !== undefined &&
        entry.commands?.some(([name, first]) => name === installed[0] && first === installed[1])),
  );
  // A declaration matches what runs (package, image, host, or the catalog entry they identify), never
  // the config name: a change under review chooses names, so a name could claim another server's entry.
  const keys = [pkg, image, host, known?.id].filter((key): key is string => key !== undefined);
  const own = keys.map(key => declared.declared.find(item => item.match === key)).find(item => item !== undefined);
  if (own)
    return {
      id: `declared:${own.match}`,
      label: `declared in .agc.yaml as "${own.match}"`,
      capabilities: own.capabilities,
    };
  return known ? { id: known.id, label: known.label, capabilities: known.capabilities } : undefined;
}

/** Built-in catalog IDs, for validating declarations and for documentation. */
export const CATALOG_IDS: readonly string[] = CATALOG.map(entry => entry.id);

function stringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) if (typeof item === 'string') out[key] = item;
  return out;
}

/**
 * Reads the servers in an MCP config. `.mcp.json` and Cursor use `mcpServers`; VS Code uses `servers`.
 * Throws on invalid JSON so the caller can report it.
 */
export function parseMcpConfig(
  path: string,
  text: string,
  client: McpServer['client'],
  declared: CatalogContext = NO_CONTEXT,
): McpServer[] {
  const parsed = parseJsonc(text);
  return serversFromObject(parsed, path, text, client, 0, declared);
}

export function serversFromObject(
  parsed: unknown,
  path: string,
  text: string,
  client: McpServer['client'],
  lineOffset = 0,
  declared: CatalogContext = NO_CONTEXT,
): McpServer[] {
  if (!isRecord(parsed)) return [];
  const block = isRecord(parsed['mcpServers'])
    ? parsed['mcpServers']
    : isRecord(parsed['servers'])
      ? parsed['servers']
      : {};
  const servers: McpServer[] = [];
  // Server names appear in file order: a moving cursor finds each line without rescanning the file.
  const locate = lineLocator(text);
  for (const [name, raw] of Object.entries(block)) {
    if (!isRecord(raw)) continue;
    const command = asString(raw['command']);
    const args = asStringArray(Array.isArray(raw['args']) ? raw['args'] : []);
    const url = asString(raw['url']) ?? asString(raw['serverUrl']) ?? asString(raw['httpUrl']);
    // `envFile` loads variables the scanner cannot see, and `cwd` changes what resolves locally.
    const env =
      'envFile' in raw || 'cwd' in raw
        ? { ...stringRecord(raw['env']), NODE_OPTIONS: '(envFile or cwd)' }
        : stringRecord(raw['env']);
    const identity = identityOf(command, args, url, env, declared, path);
    const catalog = identify(identity, declared);
    servers.push({
      name,
      client,
      ...(command === undefined ? {} : { command }),
      args,
      ...(url === undefined ? {} : { url }),
      env: stringRecord(raw['env']),
      headers: stringRecord(raw['headers']),
      location: { file: path, line: locate(JSON.stringify(name)) + lineOffset },
      ...(catalog ? { catalog } : {}),
      identity: {
        ...(identity.package !== undefined ? { package: identity.package } : {}),
        ...(identity.image !== undefined ? { image: identity.image } : {}),
        ...(identity.host !== undefined ? { host: identity.host } : {}),
      },
    });
  }
  return servers;
}

/**
 * MCP servers that anthropics/claude-code-action starts itself. They post the action's comments and
 * reviews, read CI results, or commit files, using the action's GitHub token.
 */
export function actionBuiltinServers(location: Location): McpServer[] {
  const builtin = (name: string, label: string, capabilities: CatalogEntry['capabilities']): McpServer => ({
    name,
    client: 'workflow',
    args: [],
    env: {},
    headers: {},
    location,
    catalog: { id: `claude-code-action/${name}`, label, capabilities },
  });
  return [
    builtin('github_comment', 'action comment tool', { egress: 'yes' }),
    builtin('github_inline_comment', 'action review-comment tool', { egress: 'yes' }),
    builtin('github_ci', 'action CI-results tool', { untrustedInput: 'yes' }),
    builtin('github_file_ops', 'action commit tool', { write: 'yes', egress: 'yes' }),
  ];
}
