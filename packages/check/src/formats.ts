import { parse as parseToml } from 'smol-toml';
import type { Agent, Approval, Capability, Grant, Location } from './types.js';
import { grantsForRule, parseRule, type PermissionRule } from './claude.js';
import { serversFromObject, type McpServer } from './mcp.js';
import { asString, asStringArray, isRecord, lineOf, parseJsonc } from './text.js';

/**
 * Other agents' configuration: OpenAI Codex (`.codex/config.toml`), Gemini CLI
 * (`.gemini/settings.json`) and Claude Code plugins (marketplaces in settings and
 * `.claude-plugin/marketplace.json`). Each is reduced to the same grants the rules use.
 */

/** A place where an agent runs every action without asking: `--yolo`, `never` + full access, ... */
export interface Bypass {
  readonly agent: string;
  readonly what: string;
  readonly location: Location;
}

export interface ModelChoice {
  readonly agent: string;
  readonly model: string;
  readonly location: Location;
}

export interface OtherAgent {
  readonly agent: Agent;
  readonly servers: readonly McpServer[];
  /** Tools it runs without asking, as Claude Code permission rules (so the same rules judge them). */
  readonly allow: readonly PermissionRule[];
  readonly bypasses: readonly Bypass[];
  readonly models: readonly ModelChoice[];
}

function lineOfKey(text: string, key: string, from = 0): number {
  const lines = text.split('\n');
  const pattern = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=`);
  for (let i = from; i < lines.length; i += 1) if (pattern.test(lines[i]!)) return i + 1;
  return 0;
}

function lineOfTable(text: string, table: string): number {
  const lines = text.split('\n');
  const header = `[${table}]`;
  const index = lines.findIndex(line => line.trim() === header);
  return index + 1;
}

const grant = (
  capability: Capability,
  via: string,
  approval: Approval,
  location: Location,
  certainty: 'yes' | 'unknown' = 'yes',
  tool?: string,
): Grant => ({ capability, via, approval, certainty, location, ...(tool ? { tool } : {}) });

/** `.codex/config.toml`. Throws on invalid TOML so the caller can report it. */
export function parseCodex(path: string, text: string): OtherAgent {
  const data = parseToml(text) as Record<string, unknown>;
  const at = (key: string): Location => ({ file: path, line: lineOfKey(text, key) || 1 });
  const policy = data['approval_policy'];
  const policyName = typeof policy === 'string' ? policy : isRecord(policy) ? 'granular' : 'on-request';
  const sandbox = asString(data['sandbox_mode']) ?? 'workspace-write';
  const workspace = isRecord(data['sandbox_workspace_write']) ? data['sandbox_workspace_write'] : {};
  const network = workspace['network_access'] === true;
  // `untrusted` asks before anything outside a small trusted set; the others run inside the sandbox.
  const approval: Approval = policyName === 'untrusted' ? 'ask' : 'auto';
  const policyAt = policy === undefined ? { file: path, line: 1 } : at('approval_policy');
  const sandboxAt = data['sandbox_mode'] === undefined ? { file: path, line: 1 } : at('sandbox_mode');
  const grants: Grant[] = [];
  const via = (detail: string) => `Codex ${detail}`;
  if (sandbox === 'danger-full-access') {
    for (const capability of ['exec', 'write', 'egress'] as const)
      grants.push(grant(capability, via('sandbox_mode = "danger-full-access"'), approval, sandboxAt, 'yes', 'shell'));
  } else if (sandbox === 'workspace-write') {
    grants.push(grant('write', via('sandbox_mode = "workspace-write"'), approval, sandboxAt, 'yes', 'shell'));
    grants.push(grant('exec', via('sandbox_mode = "workspace-write"'), approval, sandboxAt, 'yes', 'shell'));
    if (network)
      grants.push(
        grant(
          'egress',
          via('sandbox_workspace_write.network_access = true'),
          approval,
          at('network_access'),
          'yes',
          'shell',
        ),
      );
  }
  // Commands the sandbox refuses can be retried outside it after a person approves.
  if (sandbox !== 'danger-full-access' && policyName !== 'never')
    grants.push(
      grant('egress', via(`escalation (approval_policy = "${policyName}")`), 'ask', policyAt, 'yes', 'shell'),
    );
  const search = asString(data['web_search']);
  if (search === 'live' || search === 'cached')
    grants.push(
      grant('untrustedInput', via(`web_search = "${search}"`), 'auto', at('web_search'), 'yes', 'web_search'),
    );
  const servers: McpServer[] = [];
  const mcp = isRecord(data['mcp_servers']) ? data['mcp_servers'] : {};
  for (const [name, raw] of Object.entries(mcp)) {
    if (!isRecord(raw) || raw['enabled'] === false) continue;
    const line = lineOfTable(text, `mcp_servers.${name}`) || lineOfTable(text, `mcp_servers."${name}"`) || 1;
    const [server] = serversFromObject({ mcpServers: { [name]: raw } }, path, '', 'codex');
    if (!server) continue;
    const located: McpServer = { ...server, location: { file: path, line } };
    servers.push(located);
    const mode = asString(raw['default_tools_approval_mode']);
    const serverApproval: Approval = mode === 'prompt' || policyName === 'untrusted' ? 'ask' : 'auto';
    grants.push(...grantsForRule(parseRule(`mcp__${name}`, located.location), serverApproval, [located]));
  }
  const bypasses: Bypass[] = [];
  const name = 'Codex';
  if (policyName === 'never' && sandbox === 'danger-full-access')
    bypasses.push({
      agent: name,
      what: 'approval_policy = "never" with sandbox_mode = "danger-full-access"',
      location: sandboxAt,
    });
  const profiles = isRecord(data['profiles']) ? data['profiles'] : {};
  for (const [profile, raw] of Object.entries(profiles)) {
    if (!isRecord(raw)) continue;
    const p = asString(raw['approval_policy']) ?? policyName;
    const s = asString(raw['sandbox_mode']) ?? sandbox;
    if (p === 'never' && s === 'danger-full-access')
      bypasses.push({
        agent: `${name} profile ${profile}`,
        what: `profile "${profile}" runs with approval_policy = "never" and sandbox_mode = "danger-full-access"`,
        location: { file: path, line: lineOfTable(text, `profiles.${profile}`) || 1 },
      });
  }
  const models: ModelChoice[] = [];
  const model = asString(data['model']);
  if (model) models.push({ agent: name, model, location: at('model') });
  const dir = path.split('/').slice(0, -2).join('/');
  return {
    agent: {
      id: `codex:${dir || '.'}`,
      kind: 'codex',
      name: dir ? `Codex (${dir})` : 'Codex (project)',
      location: { file: path, line: 1 },
      grants,
      mediators: [],
      headless: false,
    },
    servers,
    allow: [],
    bypasses,
    models,
  };
}

/** Gemini CLI tool names, as Claude Code permission rules. Unknown names are left out. */
function geminiRule(name: string): string | undefined {
  const match = /^(\w+)\s*(?:\((.*)\))?$/s.exec(name.trim());
  if (!match) return undefined;
  const [, tool, args] = match;
  const spec = args ? `(${args})` : '';
  switch (tool) {
    case 'run_shell_command':
    case 'ShellTool':
      return `Bash${spec}`;
    case 'web_fetch':
    case 'WebFetchTool':
      return 'WebFetch';
    case 'google_web_search':
    case 'WebSearchTool':
      return 'WebSearch';
    case 'write_file':
    case 'WriteFileTool':
    case 'replace':
    case 'EditTool':
      return `Edit${spec}`;
    default:
      return undefined;
  }
}

/** `.gemini/settings.json` (both the nested v2 layout and the flat v1 one). Throws on invalid JSON. */
export function parseGemini(path: string, text: string): OtherAgent {
  const data = parseJsonc(text);
  if (!isRecord(data)) throw new Error('settings must be an object');
  const tools = isRecord(data['tools']) ? data['tools'] : {};
  const general = isRecord(data['general']) ? data['general'] : {};
  const security = isRecord(data['security']) ? data['security'] : {};
  const at = (key: string): Location => ({ file: path, line: lineOf(text, JSON.stringify(key)) || 1 });
  const list = (v2: unknown, v1: unknown) => asStringArray(Array.isArray(v2) ? v2 : Array.isArray(v1) ? v1 : []);
  const allowed = list(tools['allowed'], data['allowedTools']);
  const core =
    Array.isArray(tools['core']) || Array.isArray(data['coreTools']) ? list(tools['core'], data['coreTools']) : null;
  const excluded = list(tools['exclude'], data['excludeTools']);
  const mode = asString(general['defaultApprovalMode']) ?? asString(data['defaultApprovalMode']);
  const yolo = mode === 'yolo' && security['disableYoloMode'] !== true;
  const servers = serversFromObject(data, path, text, 'gemini');
  const available = (rule: string) => {
    const base = rule.split('(')[0]!;
    if (excluded.some(item => item === rule || geminiRule(item) === rule || geminiRule(item)?.split('(')[0] === base))
      return false;
    return core === null || core.some(item => geminiRule(item)?.split('(')[0] === base);
  };
  const anchor = { file: path, line: 1 };
  const grants: Grant[] = [];
  // Built-in tools are available with confirmation unless excluded or left out of tools.core.
  for (const base of ['Bash', 'Edit', 'WebFetch', 'WebSearch'])
    if (available(base)) grants.push(...grantsForRule(parseRule(base, anchor), yolo ? 'auto' : 'ask', []));
  if (mode === 'auto_edit' && available('Edit'))
    grants.push(...grantsForRule(parseRule('Edit', at('defaultApprovalMode')), 'auto', []));
  const allow: PermissionRule[] = [];
  for (const item of allowed) {
    const rule = geminiRule(item);
    if (!rule || !available(rule)) continue;
    const parsed = parseRule(rule, at(item));
    allow.push(parsed);
    grants.push(...grantsForRule(parsed, 'auto', []));
  }
  const allowedServers =
    isRecord(data['mcp']) && Array.isArray(data['mcp']['allowed']) ? asStringArray(data['mcp']['allowed']) : null;
  const usable = servers.filter(server => allowedServers === null || allowedServers.includes(server.name));
  for (const server of usable) {
    const raw = isRecord(data['mcpServers']) ? data['mcpServers'][server.name] : undefined;
    const trusted = isRecord(raw) && raw['trust'] === true;
    const rule = parseRule(`mcp__${server.name}`, server.location);
    // trust: true skips confirmation for every tool of the server, like allowing mcp__<server>.
    if (trusted) allow.push(rule);
    grants.push(...grantsForRule(rule, trusted || yolo ? 'auto' : 'ask', usable));
  }
  const bypasses: Bypass[] = [];
  if (yolo)
    bypasses.push({
      agent: 'Gemini CLI',
      what: 'general.defaultApprovalMode = "yolo"',
      location: at('defaultApprovalMode'),
    });
  const models: ModelChoice[] = [];
  const model = isRecord(data['model']) ? asString(data['model']['name']) : asString(data['model']);
  if (model) models.push({ agent: 'Gemini CLI', model, location: at(isRecord(data['model']) ? 'name' : 'model') });
  const dir = path.split('/').slice(0, -2).join('/');
  return {
    agent: {
      id: `gemini:${dir || '.'}`,
      kind: 'gemini',
      name: dir ? `Gemini CLI (${dir})` : 'Gemini CLI (project)',
      location: anchor,
      grants,
      mediators: [],
      headless: false,
    },
    servers: usable,
    allow,
    bypasses,
    models,
  };
}

/** One place a plugin or marketplace is fetched from. */
export interface PluginSource {
  readonly kind: 'marketplace' | 'plugin';
  readonly name: string;
  readonly type: string;
  /** Where it comes from: owner/repo, a URL or a package. */
  readonly from: string;
  readonly ref?: string;
  readonly sha?: string;
  readonly version?: string;
  readonly autoUpdate: boolean;
  readonly location: Location;
}

function sourceOf(
  kind: PluginSource['kind'],
  name: string,
  raw: unknown,
  autoUpdate: boolean,
  location: Location,
): PluginSource | undefined {
  if (typeof raw === 'string') return undefined; // a relative path inside the marketplace: pinned with it
  if (!isRecord(raw)) return undefined;
  const type = asString(raw['source']) ?? asString(raw['type']) ?? 'unknown';
  // Local folders and files, and a directory printed by a tool already on the machine, are not fetched.
  if (type === 'directory' || type === 'file' || type === 'settings' || type === 'command') return undefined;
  const from =
    asString(raw['repo']) ?? asString(raw['url']) ?? asString(raw['package']) ?? asString(raw['path']) ?? '?';
  const ref = asString(raw['ref']);
  // A git commit for github, url and git-subdir sources; the archive digest for archive sources.
  const sha = asString(raw['sha']) ?? asString(raw['sha256']);
  const appended = type === 'npm' ? /^(@?[^@]+)@(.+)$/.exec(asString(raw['package']) ?? '')?.[2] : undefined;
  const version = asString(raw['version']) ?? appended;
  return {
    kind,
    name,
    type,
    from,
    ...(ref ? { ref } : {}),
    ...(sha ? { sha } : {}),
    ...(version ? { version } : {}),
    autoUpdate,
    location,
  };
}

/** Marketplaces a `.claude/settings.json` registers. */
export function parsePluginSettings(path: string, text: string): PluginSource[] {
  const data = parseJsonc(text);
  if (!isRecord(data) || !isRecord(data['extraKnownMarketplaces'])) return [];
  const out: PluginSource[] = [];
  for (const [name, entry] of Object.entries(data['extraKnownMarketplaces'])) {
    if (!isRecord(entry)) continue;
    // A `settings` marketplace lists its plugins inline: judge each plugin's own source.
    if (
      isRecord(entry['source']) &&
      entry['source']['source'] === 'settings' &&
      Array.isArray(entry['source']['plugins'])
    )
      for (const plugin of entry['source']['plugins']) {
        if (!isRecord(plugin)) continue;
        const pluginName = asString(plugin['name']) ?? '?';
        const found = sourceOf('plugin', pluginName, plugin['source'], false, {
          file: path,
          line: lineOf(text, JSON.stringify(pluginName)) || 1,
        });
        if (found) out.push(found);
      }
    const found = sourceOf('marketplace', name, entry['source'], entry['autoUpdate'] === true, {
      file: path,
      line: lineOf(text, JSON.stringify(name)) || 1,
    });
    if (found) out.push(found);
  }
  return out;
}

/** Plugins a `.claude-plugin/marketplace.json` lists. */
export function parseMarketplace(path: string, text: string): PluginSource[] {
  const data = parseJsonc(text);
  if (!isRecord(data) || !Array.isArray(data['plugins'])) return [];
  const out: PluginSource[] = [];
  let from = 0;
  for (const plugin of data['plugins']) {
    if (!isRecord(plugin)) continue;
    const name = asString(plugin['name']) ?? '?';
    const index = text.indexOf(JSON.stringify(name), from);
    if (index >= 0) from = index + 1;
    const line = index >= 0 ? text.slice(0, index).split('\n').length : 1;
    const found = sourceOf('plugin', name, plugin['source'], false, { file: path, line });
    if (found) out.push(found);
  }
  return out;
}
