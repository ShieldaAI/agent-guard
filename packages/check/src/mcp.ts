import type { Capability, Location } from './types.js';
import { asString, asStringArray, isRecord, lineOf, parseJsonc } from './text.js';

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

/** The package a runner command starts, with its version marker, or undefined. */
export function runnerPackage(
  command: string | undefined,
  args: readonly string[],
):
  | {
      readonly runner: string;
      readonly spec: string;
      readonly localOnly: boolean;
    }
  | undefined {
  if (!command) return undefined;
  const base = (command.split(/[\\/]/).at(-1) ?? command).replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
  // Launchers that run a command line: `cmd /c npx -y pkg` (the documented Windows form) and `sh -c "npx -y pkg"`.
  if (base === 'cmd' && /^\/[ck]$/i.test(args[0] ?? '') && args[1] !== undefined) {
    const line = args.length === 2 ? splitShell(args[1]) : args.slice(1);
    return runnerPackage(line[0], line.slice(1));
  }
  if (['sh', 'bash', 'zsh', 'dash'].includes(base) && args[0] === '-c' && args[1] !== undefined) {
    const line = splitShell(args[1]);
    return runnerPackage(line[0], line.slice(1));
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
  } else if (!RUNNERS.has(base)) return undefined;
  // `--no` / `--no-install` / `--offline` forbid downloading: only an installed copy can run.
  const localOnly = rest.some(arg => arg === '--no' || arg === '--no-install' || arg === '--offline');
  const found = (spec: string) => ({ runner, spec, localOnly });
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i]!;
    if (arg === '--') continue;
    if (arg === '-p' || arg === '--package' || arg === '--from') {
      const next = rest[i + 1];
      return next ? found(next) : undefined;
    }
    if (arg.startsWith('--package=') || arg.startsWith('--from=')) return found(arg.split('=', 2)[1]!);
    if (arg.startsWith('-')) continue;
    return found(arg);
  }
  return undefined;
}

/**
 * Every package a runner command fetches: the one it runs and any `-p`/`--package`/`--from`/`--with`
 * extras, each with its runner. `unverifiable` when a shell line runs more than one command, so what
 * it fetches cannot be read from the config.
 */
export function runnerSpecs(
  command: string | undefined,
  args: readonly string[],
): {
  readonly specs: readonly { readonly runner: string; readonly spec: string; readonly localOnly: boolean }[];
  readonly unverifiable: boolean;
} {
  if (!command) return { specs: [], unverifiable: false };
  const base = (command.split(/[\\/]/).at(-1) ?? command).replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
  if (base === 'cmd' && /^\/[ck]$/i.test(args[0] ?? '') && args[1] !== undefined) {
    const words = args.length === 2 ? args[1] : args.slice(1).join(' ');
    if (/[;&|`$<>(){}\n\r^]/.test(words)) return { specs: [], unverifiable: true };
    const line = splitShell(words);
    return runnerSpecs(line[0], line.slice(1));
  }
  if (['sh', 'bash', 'zsh', 'dash'].includes(base) && args.includes('-c')) {
    const script = args[args.indexOf('-c') + 1] ?? '';
    if (/[;&|`$<>(){}\n\r]/.test(script)) return { specs: [], unverifiable: true };
    const line = splitShell(script);
    return runnerSpecs(line[0], line.slice(1));
  }
  const first = runnerPackage(command, args);
  if (!first) return { specs: [], unverifiable: false };
  const specs = [first];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    const value = ['-p', '--package', '--from', '--with'].includes(arg)
      ? args[i + 1]
      : /^--(package|from|with)=/.test(arg)
        ? arg.split('=', 2)[1]
        : undefined;
    if (value !== undefined && value !== first.spec) specs.push({ ...first, spec: value });
  }
  return { specs, unverifiable: false };
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
  if (runner === 'uvx' || runner === 'pipx') {
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

/** The image a `docker run` command starts, or undefined. */
export function dockerImage(command: string | undefined, args: readonly string[]): string | undefined {
  if (!command || !/(^|[\\/])(docker|podman)$/.test(command) || args[0] !== 'run') return undefined;
  // A replaced entrypoint runs something else inside the image: it is not that image's server.
  if (args.some(arg => arg === '--entrypoint' || arg.startsWith('--entrypoint='))) return undefined;
  const valued = new Set(['-e', '--env', '-v', '--volume', '--name', '-p', '--publish', '--network', '-w', '--user']);
  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i]!;
    if (valued.has(arg)) {
      i += 1;
      continue;
    }
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return undefined;
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
  /^(NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|npm_config_.*|YARN_.*|PNPM_.*|BUN_.*|DENO_.*|PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|PYTHONUSERBASE|PIP_.*|PIPX_.*|UV_.*|LD_.*|DYLD_.*|PATH|JAVA_TOOL_OPTIONS|RUBYOPT|PERL5OPT)$/i;
/** Shell syntax that runs more than one command, or substitutes one. */
const SHELL_SYNTAX = /[;&|`$<>(){}\n\r]/;

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
): string | undefined {
  if (!command || Object.keys(env).some(name => LOADER_ENV.test(name))) return undefined;
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
  for (const arg of rest) {
    if (arg === '--') continue;
    if (arg.startsWith('-')) {
      if (SAFE_RUNNER_FLAGS.has(arg)) continue;
      return undefined;
    }
    return registryName(arg);
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
function catalogImage(command: string | undefined, args: readonly string[]): string | undefined {
  if (!command || !['docker', 'podman'].includes(baseName(command)) || args[0] !== 'run') return undefined;
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
  readonly localPackages: ReadonlySet<string>;
  readonly packageSources: boolean;
}

export const NO_CONTEXT: CatalogContext = Object.freeze({
  declared: Object.freeze([]),
  localPackages: new Set<string>(),
  packageSources: false,
});

/** What a server runs: its package, image or host, each only for an exact command shape. */
function identityOf(
  command: string | undefined,
  args: readonly string[],
  url: string | undefined,
  env: Readonly<Record<string, string>>,
  context: CatalogContext,
): { package?: string; image?: string; host?: string; installed?: readonly [string, string] } {
  // A server with both a command and a URL is ambiguous: which one runs depends on the client.
  if (command !== undefined && url !== undefined) return {};
  const found = catalogPackage(command, args, env);
  // The repository decides what a dependency or a configured registry resolves to.
  const pkg = found !== undefined && !context.packageSources && !context.localPackages.has(found) ? found : undefined;
  const image = catalogImage(command, args);
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
  for (const [name, raw] of Object.entries(block)) {
    if (!isRecord(raw)) continue;
    const command = asString(raw['command']);
    const args = asStringArray(Array.isArray(raw['args']) ? raw['args'] : []);
    const url = asString(raw['url']) ?? asString(raw['serverUrl']) ?? asString(raw['httpUrl']);
    // `envFile` loads variables the scanner cannot see, which may change what is loaded.
    const env =
      'envFile' in raw ? { ...stringRecord(raw['env']), NODE_OPTIONS: '(from envFile)' } : stringRecord(raw['env']);
    const identity = identityOf(command, args, url, env, declared);
    const catalog = identify(identity, declared);
    servers.push({
      name,
      client,
      ...(command === undefined ? {} : { command }),
      args,
      ...(url === undefined ? {} : { url }),
      env: stringRecord(raw['env']),
      headers: stringRecord(raw['headers']),
      location: { file: path, line: lineOf(text, JSON.stringify(name)) + lineOffset },
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
