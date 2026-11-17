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
    capabilities: { privateData: 'yes', untrustedInput: 'yes' },
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
    capabilities: { untrustedInput: 'yes' },
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
    capabilities: { privateData: 'yes', write: 'yes', exec: 'yes' },
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
      /** `-p pkg node -e ...`: the package is installed, but something else runs. */
      readonly runsOther?: boolean;
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
      return next ? { ...found(next), ...(runsOther(rest.slice(i + 2)) ? { runsOther: true } : {}) } : undefined;
    }
    if (arg.startsWith('--package=') || arg.startsWith('--from='))
      return { ...found(arg.split('=', 2)[1]!), ...(runsOther(rest.slice(i + 1)) ? { runsOther: true } : {}) };
    if (arg.startsWith('-')) continue;
    return found(arg);
  }
  return undefined;
}

/** Interpreters and shells: after `-p pkg`, running one of these runs code the package did not ship. */
const INTERPRETERS = new Set([
  'node',
  'nodejs',
  'python',
  'python3',
  'sh',
  'bash',
  'zsh',
  'dash',
  'deno',
  'bun',
  'ruby',
  'perl',
  'pwsh',
  'env',
  'npx',
  'npm',
  'uv',
  'pip',
]);

/** Whether the words after `-p pkg` run an interpreter or inline code rather than the package's own command. */
function runsOther(after: readonly string[]): boolean {
  const command = after.find(word => !word.startsWith('-') && word !== '--');
  if (command === undefined) return false;
  const base = (command.split(/[\\/]/).at(-1) ?? command).replace(/\.(cmd|exe)$/i, '').toLowerCase();
  return INTERPRETERS.has(base) || after.some(word => ['-e', '-c', '--eval', '-p', '--print'].includes(word));
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

/**
 * A team's own statement of what an MCP server can do, from `.agc.yaml` (`mcp_servers`). `match` is a
 * server's config name, a catalog ID, a package, an image or a remote host. It takes precedence over
 * the built-in catalog.
 */
export interface DeclaredServer {
  readonly match: string;
  readonly capabilities: Readonly<Partial<Record<Capability, 'yes' | 'unknown'>>>;
}

function identify(
  command: string | undefined,
  args: readonly string[],
  url: string | undefined,
  declared: readonly DeclaredServer[],
): CatalogEntry | undefined {
  const runner = runnerPackage(command, args);
  const pkg = runner && !runner.runsOther ? splitSpec(runner.spec).name : undefined;
  const image = dockerImage(command, args)
    ?.split('@')[0]
    ?.replace(/:[^/:]+$/, '');
  let host: string | undefined;
  if (url) {
    try {
      host = new URL(url).hostname;
    } catch {
      host = undefined;
    }
  }
  const known = CATALOG.find(
    entry =>
      (pkg !== undefined && entry.packages?.includes(pkg)) ||
      (image !== undefined && entry.images?.includes(image)) ||
      (host !== undefined && entry.hosts?.includes(host)),
  );
  // A declaration matches what runs (package, image, host, or the catalog entry they identify), never
  // the config name: a change under review chooses names, so a name could claim another server's entry.
  const keys = [pkg, image, host, known?.id].filter((key): key is string => key !== undefined);
  const own = keys.map(key => declared.find(item => item.match === key)).find(item => item !== undefined);
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
  declared: readonly DeclaredServer[] = [],
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
  declared: readonly DeclaredServer[] = [],
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
    const catalog = identify(command, args, url, declared);
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
