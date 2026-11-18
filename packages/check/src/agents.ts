import type { Approval, Grant, Location, Unrecognized } from './types.js';
import { deniesWholeTool, grantsForRule, parseRule, type PermissionRule } from './claude.js';
import { serversFromObject, type CatalogContext, NO_CONTEXT, type McpServer } from './mcp.js';
import type { Bypass, ModelChoice, OtherAgent } from './formats.js';
import { asString, asStringArray, frontmatter, isRecord, lineOf, parseJsonc } from './text.js';
import { parse as parseYaml } from 'yaml';
import { MODEL_ENDPOINT, endpointSeverity } from './endpoints.js';
import { agentCalls } from './shell.js';
import { isHarnessCredential, MODEL_SECRETS, PUBLISHING_SCOPES, secretNames, UNTRUSTED_TRIGGERS } from './workflows.js';

/**
 * More agents, each reduced to the grants the rules use: OpenCode (`opencode.json`), the Cursor
 * CLI (`.cursor/cli.json`), GitHub Copilot custom agents (`.github/agents/*.md`) and Kiro
 * (`.kiro/settings/mcp.json`). Where a tool's defaults differ between its versions and the file
 * does not say which applies, the capability is reported as unknown, never as absent.
 */

const grantOf = (
  capability: Grant['capability'],
  via: string,
  approval: Approval,
  location: Location,
  certainty: Grant['certainty'],
  tool: string,
): Grant => ({ capability, via, approval, certainty, location, tool });

function withoutDeniedRules(grants: readonly Grant[], deny: readonly PermissionRule[]): Grant[] {
  return grants.filter(grant => {
    if (!grant.tool) return true;
    if (grant.tool.startsWith('mcp__')) return !deniesWholeTool(deny, 'mcp', grant.tool.slice(5));
    return !deniesWholeTool(deny, grant.tool);
  });
}

function dirOf(path: string, levels: number): string {
  return path.split('/').slice(0, -levels).join('/');
}

function empty(agent: OtherAgent['agent'], servers: readonly McpServer[] = []): OtherAgent {
  return { agent, servers, allow: [], bypasses: [], models: [], unrecognized: [] };
}

// ---------------------------------------------------------------------------------------------
// OpenCode

/** OpenCode's tools, with their V1 permission key, their V2 action name and the matching rule. */
const OPENCODE_TOOLS = [
  { v1: 'bash', v2: 'shell', rule: 'Bash', disable: ['bash'] },
  { v1: 'edit', v2: 'edit', rule: 'Edit', disable: ['edit', 'write', 'patch'] },
  { v1: 'webfetch', v2: 'webfetch', rule: 'WebFetch', disable: ['webfetch'] },
  { v1: 'websearch', v2: 'websearch', rule: 'WebSearch', disable: ['websearch'] },
] as const;

const OPENCODE_ACTIONS = new Set(['allow', 'ask', 'deny']);

/** A rule for one OpenCode pattern: `Bash(git push*)`, `Edit(src/**)`, `WebFetch(domain:x)`. */
function openCodeRule(base: string, pattern: string): string {
  if (pattern === '*' || pattern === '') return base;
  if (base === 'WebFetch') {
    const host = /^(?:https?:\/\/)?([^/*]+)/.exec(pattern)?.[1];
    return host ? `WebFetch(domain:${host})` : 'WebFetch';
  }
  return `${base}(${pattern})`;
}

/**
 * `opencode.json` / `opencode.jsonc` (or `.opencode/opencode.json`). OpenCode V1 has a
 * `permission` object whose unset tools are allowed; V2 has a `permissions` list whose unmatched
 * calls ask. Throws on invalid JSON.
 */
export function parseOpenCode(
  path: string,
  text: string,
  declared: CatalogContext = NO_CONTEXT,
  agentFiles: readonly { readonly path: string; readonly text: string }[] = [],
  dirOverride?: string,
): OtherAgent {
  const data = parseJsonc(text);
  if (!isRecord(data)) throw new Error('config must be an object');
  const dir = dirOverride ?? (path.split('/').at(-2) === '.opencode' ? dirOf(path, 2) : dirOf(path, 1));
  const name = dir ? `OpenCode (${dir})` : 'OpenCode (project)';
  const at = (key: string): Location => ({ file: path, line: lineOf(text, JSON.stringify(key)) || 1 });
  const anchor = { file: path, line: 1 };
  const grants: Grant[] = [];
  const allow: PermissionRule[] = [];
  const bypasses: Bypass[] = [];
  const unrecognized: Unrecognized[] = [];
  const disabled = isRecord(data['tools'])
    ? new Set(Object.entries(data['tools']).flatMap(([key, value]) => (value === false ? [key] : [])))
    : new Set<string>();

  // Settings that run code of their own: plugins (npm packages or files loaded into OpenCode) and
  // formatter commands run after every edit, without asking.
  for (const key of ['plugin', 'formatter'])
    if (data[key] !== undefined && data[key] !== false && !(Array.isArray(data[key]) && !data[key].length))
      unrecognized.push({
        agent: name,
        setting: key,
        value: JSON.stringify(data[key]).slice(0, 120),
        assumed: 'it runs code of its own without asking, which may reach the network',
        location: at(key),
        severity: 'high',
      });
  // `share: "auto"` publishes every session (with what the agent read) to a public link.
  if (data['share'] === 'auto')
    unrecognized.push({
      agent: name,
      setting: 'share',
      value: 'auto',
      assumed: 'every session, with what the agent read, is shared at a public link',
      location: at('share'),
      severity: 'medium',
    });
  // MCP servers: local ones give `command` as one array; remote ones a `url`.
  const block: Record<string, unknown> = {};
  if (isRecord(data['mcp']))
    for (const [server, raw] of Object.entries(data['mcp'])) {
      if (!isRecord(raw) || raw['enabled'] === false) continue;
      const command = Array.isArray(raw['command']) ? asStringArray(raw['command']) : [];
      block[server] = {
        ...(command[0] ? { command: command[0], args: command.slice(1) } : {}),
        ...(typeof raw['url'] === 'string' ? { url: raw['url'] } : {}),
        ...(isRecord(raw['environment']) ? { env: raw['environment'] } : {}),
        ...(isRecord(raw['headers']) ? { headers: raw['headers'] } : {}),
      };
    }
  const servers = serversFromObject({ mcpServers: block }, path, text, 'opencode', 0, declared);

  const v1 = data['permission'];
  const v2 = Array.isArray(data['permissions']) ? data['permissions'].filter(isRecord) : undefined;
  const add = (rule: string, approval: Approval, location: Location, certainty: Grant['certainty'] = 'yes') =>
    grants.push(
      ...grantsForRule(parseRule(rule, location), approval, servers).map(item =>
        certainty === 'unknown' ? { ...item, certainty } : item,
      ),
    );
  const action = (value: unknown, where: string, location: Location): string | undefined => {
    if (value === undefined) return undefined;
    if (typeof value === 'string' && OPENCODE_ACTIONS.has(value)) return value;
    unrecognized.push({
      agent: name,
      setting: where,
      value: typeof value === 'string' ? value : JSON.stringify(value),
      assumed: 'the tool runs without asking',
      location,
    });
    return 'unknown';
  };

  /** Grants for one V1 permission object, as one OpenCode agent sees it. */
  const judgeV1 = (permission: Record<string, unknown>, off: ReadonlySet<string>, who: string): void => {
    const fallback = action(permission['*'], 'permission.*', at('permission')) ?? 'allow';
    if (fallback === 'allow' && permission['*'] !== undefined)
      bypasses.push({ agent: `${name}${who}`, what: 'permission "*" = "allow"', location: at('permission') });
    for (const tool of OPENCODE_TOOLS) {
      if (tool.disable.every(key => off.has(key))) continue;
      const value = permission[tool.v1];
      const location = value === undefined ? at('permission') : at(tool.v1);
      if (isRecord(value)) {
        // Patterns, the last match winning; "*" is the default for commands no pattern names.
        const fromPattern = action(value['*'], `permission.${tool.v1}.*`, location) ?? fallback;
        if (fromPattern !== 'deny')
          add(
            tool.rule,
            fromPattern === 'ask' ? 'ask' : 'auto',
            location,
            fromPattern === 'unknown' ? 'unknown' : 'yes',
          );
        for (const [pattern, raw] of Object.entries(value)) {
          if (pattern === '*') continue;
          const verdict = action(raw, `permission.${tool.v1}.${pattern}`, at(pattern));
          if (verdict !== 'allow' && verdict !== 'unknown') continue;
          const rule = parseRule(openCodeRule(tool.rule, pattern), at(pattern));
          if (verdict === 'allow') allow.push(rule);
          add(rule.raw, 'auto', at(pattern), verdict === 'unknown' ? 'unknown' : 'yes');
        }
        continue;
      }
      const verdict = action(value, `permission.${tool.v1}`, location) ?? fallback;
      if (verdict === 'deny') continue;
      if (verdict === 'allow' && value !== undefined) allow.push(parseRule(tool.rule, location));
      add(tool.rule, verdict === 'ask' ? 'ask' : 'auto', location, verdict === 'unknown' ? 'unknown' : 'yes');
    }
    if (permission['external_directory'] === 'allow')
      grants.push(
        grantOf('privateData', 'external_directory = "allow"', 'auto', at('external_directory'), 'yes', 'Read'),
      );
    // MCP tools are named <server>_<tool>: "<server>_*" sets a whole server, "<server>_<tool>" one tool.
    for (const server of servers) {
      const own = action(permission[`${server.name}_*`], `permission.${server.name}_*`, at(`${server.name}_*`));
      const verdict = own ?? (fallback === 'unknown' ? 'allow' : fallback);
      if (verdict !== 'deny')
        grants.push(
          ...grantsForRule(
            parseRule(`mcp__${server.name}`, server.location),
            verdict === 'ask' ? 'ask' : 'auto',
            servers,
          ),
        );
      for (const [key, raw] of Object.entries(permission)) {
        if (!key.startsWith(`${server.name}_`) || key === `${server.name}_*`) continue;
        if (action(raw, `permission.${key}`, at(key)) !== 'allow') continue;
        const rule = parseRule(`mcp__${server.name}__${key.slice(server.name.length + 1)}`, at(key));
        allow.push(rule);
        grants.push(...grantsForRule(rule, 'auto', servers));
      }
    }
  };

  // Agents can override the permissions and tools: in `agent.<name>` or in `.opencode/agent/*.md`.
  // Each one is judged, and the OpenCode agent can do whatever any of them can.
  const overrides: {
    label: string;
    permission?: Record<string, unknown>;
    tools?: Record<string, unknown>;
    at: Location;
  }[] = [];
  if (isRecord(data['agent']))
    for (const [label, raw] of Object.entries(data['agent']))
      if (isRecord(raw))
        overrides.push({
          label,
          ...(isRecord(raw['permission']) ? { permission: raw['permission'] } : {}),
          ...(isRecord(raw['tools']) ? { tools: raw['tools'] } : {}),
          at: at(label),
        });
  const unparsed: { path: string; error: string }[] = [];
  for (const file of agentFiles) {
    const parsed = frontmatter(file.text);
    // An agent file that cannot be parsed may allow anything.
    if (parsed.error) unparsed.push({ path: file.path, error: parsed.error });
    const front: Record<string, unknown> = parsed.error ? { permission: { '*': 'allow' } } : parsed.data;
    overrides.push({
      label: file.path.split('/').at(-1)!.replace(/\.md$/, ''),
      ...(isRecord(front['permission']) ? { permission: front['permission'] } : {}),
      ...(isRecord(front['tools']) ? { tools: front['tools'] } : {}),
      at: { file: file.path, line: 1 },
    });
  }
  const v1Overrides = overrides.some(item => item.permission !== undefined);
  /** The tools an override turns off, starting from the file's own `tools`. */
  const offFor = (item: (typeof overrides)[number]): Set<string> => {
    const off = new Set(disabled);
    for (const [key, value] of Object.entries(item.tools ?? {}))
      if (value === false) off.add(key);
      else if (value === true) off.delete(key);
    return off;
  };

  if (isRecord(v1) || typeof v1 === 'string' || (v1Overrides && !v2)) {
    // V1: a shorthand string applies to every tool; "*" is the default for tools not listed.
    const base: Record<string, unknown> = typeof v1 === 'string' ? { '*': v1 } : isRecord(v1) ? v1 : {};
    judgeV1(base, disabled, '');
    for (const item of overrides)
      judgeV1({ ...base, ...(item.permission ?? {}) }, offFor(item), ` (agent ${item.label})`);
  } else if (v2) {
    // V2: ordered rules of action, resource and effect; a call no rule matches asks.
    const rules = v2.flatMap(item => {
      const act = asString(item['action']);
      const resource = asString(item['resource']);
      const effect = asString(item['effect']);
      if (!act || resource === undefined || !effect) return [];
      const location = at(act);
      return [{ action: act, resource, effect: action(effect, `permissions[${act}].effect`, location), location }];
    });
    for (const tool of OPENCODE_TOOLS) {
      if (tool.disable.every(key => disabled.has(key))) continue;
      const mine = rules.filter(rule => rule.action === tool.v2 || rule.action === '*');
      const allowed = mine.filter(rule => rule.effect === 'allow' || rule.effect === 'unknown');
      const deniedAll = mine.some(rule => rule.effect === 'deny' && rule.resource === '*');
      if (deniedAll && !allowed.length) continue;
      if (!deniedAll) add(tool.rule, 'ask', anchor);
      for (const rule of allowed) {
        const parsed = parseRule(openCodeRule(tool.rule, rule.resource), rule.location);
        if (rule.effect === 'allow') allow.push(parsed);
        add(parsed.raw, 'auto', rule.location, rule.effect === 'unknown' ? 'unknown' : 'yes');
      }
    }
    const everything = rules.some(rule => rule.action === '*' && rule.resource === '*' && rule.effect === 'allow');
    if (everything)
      bypasses.push({ agent: name, what: 'a permissions rule allows every action', location: at('permissions') });
    for (const server of servers)
      grants.push(
        ...grantsForRule(parseRule(`mcp__${server.name}`, server.location), everything ? 'auto' : 'ask', servers),
      );
    // An agent override is written like V1; what it does not set asks, as unmatched V2 calls do.
    for (const item of overrides)
      judgeV1({ '*': 'ask', ...(item.permission ?? {}) }, offFor(item), ` (agent ${item.label})`);
  } else {
    // No permission settings: V1 would run everything without asking, V2 would ask. Say so.
    unrecognized.push({
      agent: name,
      setting: 'permission',
      value: '(not set)',
      assumed: 'tools run without asking, as in OpenCode V1 (V2 asks); set permissions explicitly',
      location: anchor,
    });
    // A tool any agent override turns back on is there too.
    for (const tool of OPENCODE_TOOLS)
      if ([disabled, ...overrides.map(offFor)].some(off => !tool.disable.every(key => off.has(key))))
        add(tool.rule, 'auto', anchor, 'unknown');
    for (const server of servers)
      grants.push(
        ...grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'auto', servers).map(item => ({
          ...item,
          certainty: 'unknown' as const,
        })),
      );
  }

  const models: ModelChoice[] = [];
  const model = asString(data['model']);
  if (model) models.push({ agent: name, model: model.split('/').at(-1)!, location: at('model') });
  return {
    agent: {
      id: `opencode:${dir || '.'}`,
      kind: 'opencode',
      name,
      location: anchor,
      grants,
      mediators: [],
      headless: false,
    },
    servers,
    allow,
    bypasses,
    models,
    unrecognized,
    unparsed,
  };
}

// ---------------------------------------------------------------------------------------------
// Cursor CLI

/** A Cursor CLI permission token as a Claude Code rule, or undefined for a token it does not know. */
function cursorRule(token: string): string | undefined {
  const match = /^(Shell|Read|Write|WebFetch|Mcp)\((.*)\)$/s.exec(token.trim());
  if (!match) return undefined;
  const [, kind, raw] = match;
  const value = raw!.trim();
  switch (kind) {
    case 'Shell':
      return value === '*' || value === '' ? 'Bash' : `Bash(${value})`;
    case 'Read':
      return `Read(${value})`;
    case 'Write':
      return value === '*' || value === '**' ? 'Edit' : `Edit(${value})`;
    case 'WebFetch':
      return value === '*' || value === '' ? 'WebFetch' : `WebFetch(domain:${value})`;
    default: {
      const [server = '', tool = '*'] = value.split(':');
      if (!server) return undefined;
      return tool === '*' ? `mcp__${server}` : `mcp__${server}__${tool}`;
    }
  }
}

/**
 * `.cursor/cli.json`: the Cursor CLI's `permissions.allow` and `permissions.deny`. Other tools ask
 * before they run. `servers` are the MCP servers in the same `.cursor/mcp.json`. Throws on invalid JSON.
 */
export function parseCursorCli(path: string, text: string, servers: readonly McpServer[]): OtherAgent {
  const data = parseJsonc(text);
  if (!isRecord(data)) throw new Error('config must be an object');
  const dir = dirOf(path, 2);
  const name = dir ? `Cursor CLI (${dir})` : 'Cursor CLI (project)';
  const permissions = isRecord(data['permissions']) ? data['permissions'] : {};
  const anchor = { file: path, line: 1 };
  const unrecognized: Unrecognized[] = [];
  const tokens = (key: string): PermissionRule[] =>
    asStringArray(Array.isArray(permissions[key]) ? permissions[key] : []).flatMap(token => {
      const location = { file: path, line: lineOf(text, JSON.stringify(token)) || 1 };
      const rule = cursorRule(token);
      if (rule === undefined) {
        unrecognized.push({
          agent: name,
          setting: `permissions.${key}`,
          value: token,
          assumed: key === 'allow' ? 'it may let any tool run without asking' : 'it denies nothing',
          location,
        });
        return [];
      }
      // `Mcp(*:*)` allows every server's tools.
      if (rule === 'mcp__*') return servers.map(server => parseRule(`mcp__${server.name}`, location));
      return [parseRule(rule, location)];
    });
  const allow = tokens('allow');
  const deny = tokens('deny');
  const grants: Grant[] = [];
  for (const base of ['Bash', 'Edit', 'WebFetch', 'WebSearch'])
    grants.push(...grantsForRule(parseRule(base, anchor), 'ask', servers));
  for (const server of servers)
    grants.push(...grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'ask', servers));
  for (const rule of allow) grants.push(...grantsForRule(rule, 'auto', servers));
  for (const item of unrecognized)
    if (item.setting === 'permissions.allow')
      for (const capability of ['exec', 'egress', 'privateData'] as const)
        grants.push(grantOf(capability, item.value, 'auto', item.location, 'unknown', 'cursor-unknown'));
  return {
    agent: {
      id: `cursor-cli:${dir || '.'}`,
      kind: 'cursor',
      name,
      location: anchor,
      grants: withoutDeniedRules(grants, deny),
      mediators: [],
      headless: false,
    },
    servers: [],
    allow,
    bypasses: [],
    models: [],
    unrecognized,
  };
}

// ---------------------------------------------------------------------------------------------
// GitHub Copilot custom agents

/** What a Copilot tool name (GitHub's aliases and VS Code's tool names, lower-cased) does. */
const COPILOT_TOOLS: Readonly<Record<string, 'execute' | 'edit' | 'web' | 'read' | 'vscode'>> = {
  execute: 'execute',
  shell: 'execute',
  bash: 'execute',
  powershell: 'execute',
  terminal: 'execute',
  runcommands: 'execute',
  runinterminal: 'execute',
  run_in_terminal: 'execute',
  runtasks: 'execute',
  runtests: 'execute',
  runnotebooks: 'execute',
  edit: 'edit',
  write: 'edit',
  multiedit: 'edit',
  notebookedit: 'edit',
  editnotebook: 'edit',
  str_replace: 'edit',
  str_replace_editor: 'edit',
  create: 'edit',
  editfiles: 'edit',
  createfile: 'edit',
  createdirectory: 'edit',
  new: 'edit',
  web: 'web',
  websearch: 'web',
  webfetch: 'web',
  fetch: 'web',
  githubrepo: 'web',
  opensimplebrowser: 'web',
  read: 'read',
  notebookread: 'read',
  view: 'read',
  search: 'read',
  grep: 'read',
  glob: 'read',
  codebase: 'read',
  usages: 'read',
  problems: 'read',
  changes: 'read',
  findtestfiles: 'read',
  testfailure: 'read',
  terminallastcommand: 'read',
  terminalselection: 'read',
  getterminaloutput: 'read',
  vscodeapi: 'read',
  extensions: 'read',
  todo: 'read',
  todos: 'read',
  todowrite: 'read',
  think: 'read',
  agent: 'read',
  'custom-agent': 'read',
  task: 'read',
  runsubagent: 'read',
  vscode: 'vscode',
};

/**
 * `.github/agents/<name>.agent.md` (or `<name>.md`): a Copilot custom agent. On the cloud agent
 * (no `target`, or `target: github-copilot`) nobody approves its calls, and its network is limited
 * by the Copilot firewall, so outbound reach through the shell or the web is unknown rather than
 * yes. It has the GitHub MCP server (read-only for the repository by default) unless `tools`
 * leaves it out. With `target: vscode` it runs in VS Code, which asks before terminal commands,
 * fetches and MCP tools. A tool name it does not know is reported, and counted as unknown reach.
 */
export function parseCopilotAgent(path: string, text: string, declared: CatalogContext = NO_CONTEXT): OtherAgent {
  const parsed = frontmatter(text);
  // Front matter that cannot be parsed: every tool, as when tools is left out.
  const data = parsed.data;
  const file = path.split('/').at(-1)!;
  const label = asString(data['name']) ?? file.replace(/(\.agent)?\.md$/, '');
  const name = `Copilot agent ${label}`;
  const toolsLine = { file: path, line: lineOf(text, 'tools:') || 1 };
  const anchor = { file: path, line: 1 };
  const at = toolsLine.line > 1 ? toolsLine : anchor;
  const ide = asString(data['target'])?.toLowerCase() === 'vscode';
  const prompt: Approval = ide ? 'ask' : 'auto';
  const rawTools = data['tools'];
  // Left out means every tool. A value that is not a list (`tools:` with nothing after it is null)
  // says nothing about which tools: judge it as every tool, and report it.
  const oddTools = rawTools !== undefined && !Array.isArray(rawTools) && typeof rawTools !== 'string';
  const tools = rawTools === undefined || oddTools ? ['*'] : asStringArray(rawTools).map(tool => tool.trim());
  const all = tools.includes('*');
  const ownBlock = isRecord(data['mcp-servers']) ? data['mcp-servers'] : {};
  const servers = serversFromObject({ mcpServers: ownBlock }, path, text, 'copilot', 0, declared);
  const grants: Grant[] = [];
  const unrecognized: Unrecognized[] = [];
  if (oddTools)
    unrecognized.push({
      agent: name,
      setting: 'tools',
      value: JSON.stringify(rawTools) ?? String(rawTools),
      assumed: 'every tool, as when tools is left out',
      location: at,
    });
  const kinds = new Set<string>(all ? ['execute', 'edit', 'web'] : []);
  const serverTools = new Map<string, string[]>();
  for (const tool of tools) {
    if (tool === '*') continue;
    const slash = tool.indexOf('/');
    // `execute/runInTerminal`, `edit/editFiles`: a tool set and one of its tools, not an MCP server.
    const toolSet = slash > 0 ? COPILOT_TOOLS[tool.slice(0, slash).toLowerCase()] : undefined;
    if (toolSet && !servers.some(server => server.name === tool.slice(0, slash))) {
      kinds.add(toolSet);
      continue;
    }
    if (slash > 0) {
      const server = tool.slice(0, slash);
      serverTools.set(server, [...(serverTools.get(server) ?? []), tool.slice(slash + 1)]);
      continue;
    }
    // `shell(git:*)` and `#editFiles` name the same tools as `shell` and `editFiles`.
    const base = tool
      .replace(/^#/, '')
      .replace(/\(.*\)$/s, '')
      .toLowerCase();
    const kind = COPILOT_TOOLS[base];
    if (kind) kinds.add(kind);
    else
      unrecognized.push({
        agent: name,
        setting: 'tools',
        value: tool,
        assumed: 'it may run code, write and reach the network without asking',
        location: at,
      });
  }
  if (kinds.has('execute')) {
    grants.push(grantOf('exec', 'execute', prompt, at, 'yes', 'shell'));
    grants.push(grantOf('write', 'execute', prompt, at, 'yes', 'shell'));
    grants.push(
      ide
        ? grantOf('egress', 'execute', prompt, at, 'yes', 'shell')
        : grantOf('egress', 'execute (behind the Copilot firewall)', prompt, at, 'unknown', 'shell'),
    );
  }
  if (kinds.has('edit')) grants.push(grantOf('write', 'edit', 'auto', at, 'yes', 'edit'));
  if (kinds.has('web')) {
    grants.push(grantOf('untrustedInput', 'web', prompt, at, 'yes', 'web'));
    grants.push(
      ide
        ? grantOf('egress', 'web', prompt, at, 'yes', 'web')
        : grantOf('egress', 'web (behind the Copilot firewall)', prompt, at, 'unknown', 'web'),
    );
  }
  if (kinds.has('vscode')) grants.push(grantOf('exec', 'vscode (editor commands)', prompt, at, 'unknown', 'vscode'));
  for (const item of unrecognized)
    for (const capability of ['exec', 'write', 'egress'] as const)
      grants.push(grantOf(capability, item.value, prompt, item.location, 'unknown', 'copilot-unknown'));
  if (!ide && (all || serverTools.has('github'))) {
    grants.push(grantOf('privateData', 'github MCP server (repository)', 'auto', at, 'yes', 'mcp__github'));
    grants.push(
      grantOf('untrustedInput', 'github MCP server (issues and pull requests)', 'auto', at, 'yes', 'mcp__github'),
    );
  }
  for (const server of servers) {
    const chosen = serverTools.get(server.name) ?? [];
    if (all || chosen.includes('*'))
      grants.push(...grantsForRule(parseRule(`mcp__${server.name}`, server.location), prompt, servers));
    else
      for (const tool of chosen)
        grants.push(...grantsForRule(parseRule(`mcp__${server.name}__${tool}`, server.location), prompt, servers));
  }
  // Servers configured outside this file (repository settings on GitHub, VS Code's mcp.json):
  // what they can do is not in the repository, so it is unknown.
  for (const [server, chosen] of serverTools) {
    // On the cloud agent, github is the read-only GitHub server and playwright is limited to localhost.
    if (servers.some(item => item.name === server) || (!ide && (server === 'github' || server === 'playwright')))
      continue;
    grants.push(
      ...grantsForRule(parseRule(`mcp__${server}${chosen.includes('*') ? '' : `__${chosen[0]}`}`, at), prompt, []),
    );
  }
  const models: ModelChoice[] = [];
  const model = asString(data['model']);
  if (model) models.push({ agent: name, model, location: { file: path, line: lineOf(text, 'model:') || 1 } });
  return {
    ...empty(
      { id: `copilot:${path}`, kind: 'copilot', name, location: anchor, grants, mediators: [], headless: !ide },
      servers,
    ),
    models,
    unrecognized,
    ...(parsed.error ? { unparsed: [{ path, error: parsed.error }] } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Kiro

/**
 * `.kiro/settings/mcp.json`: Kiro's workspace MCP servers. `autoApprove` lists tools that run
 * without a prompt ("*" for all); `disabled: true` turns a server off. Throws on invalid JSON.
 */
export function parseKiroMcp(path: string, text: string, declared: CatalogContext = NO_CONTEXT): OtherAgent {
  const data = parseJsonc(text);
  if (!isRecord(data)) throw new Error('config must be an object');
  const raw = isRecord(data['mcpServers']) ? data['mcpServers'] : {};
  const servers = serversFromObject(data, path, text, 'kiro', 0, declared).filter(server => {
    const entry = raw[server.name];
    return !(isRecord(entry) && entry['disabled'] === true);
  });
  const grants: Grant[] = [];
  const allow: PermissionRule[] = [];
  for (const server of servers) {
    const entry = raw[server.name];
    const approved = isRecord(entry)
      ? asStringArray(Array.isArray(entry['autoApprove']) ? entry['autoApprove'] : [])
      : [];
    if (approved.includes('*')) {
      const rule = parseRule(`mcp__${server.name}`, server.location);
      allow.push(rule);
      grants.push(...grantsForRule(rule, 'auto', servers));
      continue;
    }
    grants.push(...grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'ask', servers));
    for (const tool of approved) {
      const rule = parseRule(`mcp__${server.name}__${tool}`, server.location);
      allow.push(rule);
      grants.push(...grantsForRule(rule, 'auto', servers));
    }
  }
  const dir = dirOf(path, 3);
  return {
    ...empty(
      {
        id: `kiro:${dir || '.'}`,
        kind: 'kiro',
        name: dir ? `Kiro (${dir})` : 'Kiro (project)',
        location: { file: path, line: 1 },
        grants,
        mediators: [],
        headless: false,
      },
      servers,
    ),
    allow,
  };
}

// ---------------------------------------------------------------------------------------------
// GitHub Agentic Workflows (gh-aw)

/** gh-aw keys whose jobs and steps compile into the lock. */
const STEP_KEYS = ['jobs', 'steps', 'pre-steps', 'post-steps', 'pre-agent-steps'] as const;
const AGENT_USES = /^[^/@\s]+\/(claude-code(-base)?-action|codex-action|run-gemini-cli)(\/[^@]*)?@/i;

/** Whether jobs or steps run an agent: an agent action, or an agent CLI call in a script. */
function runsAgent(value: unknown, depth = 0): boolean {
  if (depth > 8) return false;
  if (Array.isArray(value)) return value.some(item => runsAgent(item, depth + 1));
  if (!isRecord(value)) return false;
  if (typeof value['uses'] === 'string' && AGENT_USES.test(value['uses'])) return true;
  if (typeof value['run'] === 'string' && agentCalls(value['run']).length > 0) return true;
  return Object.values(value).some(item => runsAgent(item, depth + 1));
}

/** Triggers that start a gh-aw workflow from text anyone can write. */
const AGENTIC_UNTRUSTED = new Set([...UNTRUSTED_TRIGGERS, 'command', 'slash_command']);
/** Safe-output kinds (`add-comment`, `create-pull-request`, ...), not the keys that configure the job. */
const AGENTIC_OUTPUT =
  /^(create|add|update|push|close|submit|upload|assign|dispatch|link|hide|remove|mark|reply|resolve|unassign|set|merge|autofix)-/;
/** gh-aw's built-in engines, whose tools are the ones `tools` lists. */
const AGENTIC_ENGINES = new Set(['copilot', 'claude', 'codex', 'gemini']);
/** Tools whose reach the scanner models. Any other tool is reported, and counted as unknown reach. */
const AGENTIC_TOOLS = new Set(['github', 'bash', 'edit', 'web-fetch', 'web-search', 'playwright']);
/** Settings imports add to the workflow. */
const AGENTIC_MERGED = ['engine', 'tools', 'safe-outputs', 'mcp-servers', 'env', 'github-token', 'network'] as const;
/** Engine variables that configure the model or telemetry rather than hand data to the agent. */

/** How deep imports of imports are read; anything deeper is unknown reach. */
const MAX_IMPORT_DEPTH = 3;

/**
 * Whether a Markdown file in `.github/workflows/` is a gh-aw workflow. gh-aw needs only `on:` (the
 * engine defaults to Copilot), so any frontmatter with `on:` is one; other notes stay instructions.
 */
export function isAgenticWorkflow(text: string): boolean {
  const parsed = frontmatter(text);
  // Unparseable front matter that looks like a workflow is judged as one, with unknown reach.
  return parsed.data['on'] !== undefined || (parsed.error !== undefined && /^on\s*:/m.test(text));
}

/**
 * Two settings for one tool from a workflow and its imports, merged the way gh-aw widens them: lists
 * are joined, and an enabled tool (true, null or a mapping) is wider than a list of commands.
 */
function widen(a: unknown, b: unknown): unknown {
  if (a === undefined || a === false) return b;
  if (b === undefined || b === false) return a;
  if (Array.isArray(a) && Array.isArray(b)) return [...new Set([...a, ...b])];
  if (isRecord(a) && isRecord(b)) {
    const out: Record<string, unknown> = { ...a };
    for (const [key, value] of Object.entries(b)) out[key] = widen(out[key], value);
    return out;
  }
  if (Array.isArray(a)) return b;
  if (Array.isArray(b)) return a;
  return a === null || a === true ? a : b;
}

/**
 * `.github/workflows/<name>.md`: a GitHub Agentic Workflow. It runs unattended. Its `tools` say what
 * the agent can use; `safe-outputs` are posted for it by a separate job that checks them first (a
 * runtime check, unless `threat-detection` is off); its network sits behind gh-aw's firewall, so
 * fetches are unknown reach. Imports from the repository are read; an import that cannot be read,
 * an engine gh-aw does not build in, or a tool the scanner does not model is unknown reach.
 */
export function parseAgenticWorkflow(
  path: string,
  text: string,
  declared: CatalogContext = NO_CONTEXT,
  readImport: (path: string) => string | undefined = () => undefined,
): OtherAgent {
  const ownParsed = frontmatter(text);
  const own = ownParsed.data;
  const data: Record<string, unknown> = { ...own };
  const unreadImports: { what: string; pinned: boolean }[] = [];
  // Jobs and steps from imports compile into the lock as well: kept to be checked with the workflow's own.
  const importedSteps: { key: string; value: unknown }[] = [];
  const merge = (imported: Record<string, unknown>) => {
    for (const key of STEP_KEYS) if (imported[key] !== undefined) importedSteps.push({ key, value: imported[key] });
    for (const key of AGENTIC_MERGED) {
      if (imported[key] === undefined) continue;
      data[key] = key === 'engine' ? (data[key] ?? imported[key]) : widen(data[key], imported[key]);
    }
  };
  // An import path is relative to the file that names it (the workflow's own folder at the top).
  const resolve = (base: string, target: string): string => {
    const out: string[] = [];
    for (const part of [...base.split('/'), ...target.split('/')]) {
      if (part === '' || part === '.') continue;
      if (part === '..' && out.length && out.at(-1) !== '..') out.pop();
      else out.push(part);
    }
    return out.join('/');
  };
  const visit = (list: unknown, depth: number, base: string) => {
    const items = Array.isArray(list) ? list : list === undefined ? [] : [list];
    for (const item of items) {
      const target =
        typeof item === 'string'
          ? item
          : isRecord(item)
            ? (asString(item['path']) ?? asString(item['uses']))
            : undefined;
      if (target === undefined) {
        unreadImports.push({ what: JSON.stringify(item) ?? String(item), pinned: false });
        continue;
      }
      // An import from another repository (owner/repo/path@ref) is not in this one.
      const local = resolve(base, target.split('#')[0]!);
      const content = /^[\w.-]+\/[\w.-]+\/.+@/.test(target) ? undefined : readImport(local);
      if (content === undefined) {
        // Only an import from another repository pinned to a commit is fixed content; anything
        // else unread (missing, outside the repository, too large, a moving ref) could hide tools.
        unreadImports.push({ what: target, pinned: /^[\w.-]+\/[\w.-]+\/.+@[0-9a-f]{40}$/.test(target) });
        continue;
      }
      const importedParsed = frontmatter(content);
      if (importedParsed.error) {
        unreadImports.push({ what: target, pinned: false });
        continue;
      }
      const imported = importedParsed.data;
      merge(imported);
      const nested = [...asList(imported['imports']), ...bodyImports(importedParsed.body)];
      if (!nested.length) continue;
      if (depth < MAX_IMPORT_DEPTH) visit(nested, depth + 1, local.split('/').slice(0, -1).join('/'));
      else unreadImports.push({ what: `imports of ${target}`, pinned: false });
    }
  };
  // Imports in the front matter, and `{{#import ...}}` / `@include` lines in the body.
  visit([...asList(own['imports']), ...bodyImports(ownParsed.body)], 1, '');
  const file = path.split('/').at(-1)!;
  const name = `Agentic workflow ${asString(data['name']) ?? file}`;
  const anchor = { file: path, line: 1 };
  const at = (key: string): Location => ({ file: path, line: lineOf(text, `${key}:`) || 1 });
  const grants: Grant[] = [];
  const unrecognized: Unrecognized[] = [];
  const add = (
    capability: Grant['capability'],
    via: string,
    location: Location,
    certainty: Grant['certainty'],
    tool: string,
  ) => grants.push(grantOf(capability, via, 'auto', location, certainty, tool));
  const unknownReach = (setting: string, value: string, location: Location) => {
    unrecognized.push({
      agent: name,
      setting,
      value,
      assumed: 'it may run code, write and send data out without asking',
      location,
    });
    for (const capability of ['exec', 'write', 'egress'] as const)
      add(capability, `${setting} ${value}`, location, 'unknown', 'engine');
  };
  for (const trigger of triggerNamesOf(data['on']))
    if (AGENTIC_UNTRUSTED.has(trigger)) add('untrustedInput', `trigger ${trigger}`, at('on'), 'yes', 'trigger');
  const tools = isRecord(data['tools']) ? data['tools'] : {};
  const allow: PermissionRule[] = [];
  // `network: { allowed: ["*"] }` opens gh-aw's firewall to every host; `sandbox: { agent: false }`
  // removes the agent's sandbox, firewall included.
  const network = data['network'];
  const sandbox = own['sandbox'];
  const openNetwork =
    network === '*' ||
    (isRecord(network) && asStringArray(network['allowed'] ?? []).includes('*')) ||
    sandbox === false ||
    (isRecord(sandbox) && sandbox['agent'] === false);
  // The GitHub tool is on unless set to false: issue and pull-request text from anyone. Reading the
  // repository it runs in is not counted as private data, as for other workflow agents. With
  // read-only off it can also write and post.
  const github = tools['github'];
  if (github !== false) {
    add('untrustedInput', 'github tool (issues and pull requests)', at('tools'), 'yes', 'mcp__github');
    if (isRecord(github) && github['read-only'] === false) {
      add('write', 'github tool (read-only: false)', at('read-only'), 'yes', 'mcp__github');
      add('egress', 'github tool (read-only: false)', at('read-only'), 'yes', 'mcp__github');
    }
  }
  const bash = tools['bash'];
  if (bash !== undefined && bash !== false) {
    const commands = Array.isArray(bash) ? asStringArray(bash) : [];
    const rules =
      !Array.isArray(bash) || commands.some(item => item === '*' || item === ':*')
        ? ['Bash']
        : commands.map(item => `Bash(${item})`);
    for (const raw of rules) {
      const rule = parseRule(raw, at('bash'));
      allow.push(rule);
      // Behind the firewall what a command can reach is unknown; with the firewall open, it is yes.
      grants.push(
        ...grantsForRule(rule, 'auto', []).map(item =>
          item.capability === 'egress' && !openNetwork ? { ...item, certainty: 'unknown' as const } : item,
        ),
      );
    }
  }
  if (tools['edit'] !== undefined && tools['edit'] !== false) add('write', 'edit tool', at('edit'), 'yes', 'Edit');
  for (const key of ['web-fetch', 'web-search', 'playwright'])
    if (tools[key] !== undefined && tools[key] !== false) {
      add('untrustedInput', `${key} tool`, at(key), 'yes', key);
      add(
        'egress',
        openNetwork ? `${key} tool (network open to every host)` : `${key} tool (behind the gh-aw firewall)`,
        at(key),
        openNetwork ? 'yes' : 'unknown',
        key,
      );
    }
  for (const [key, value] of Object.entries(tools))
    if (!AGENTIC_TOOLS.has(key) && value !== false) unknownReach('tools', key, at(key));
  // Safe outputs are posted for the agent by a separate job: text sent out, and a change to issues,
  // labels or code. Other keys configure that job; custom `jobs` run steps of their own on the output.
  const safeOutputs = isRecord(data['safe-outputs']) ? data['safe-outputs'] : {};
  const outputs = Object.keys(safeOutputs).filter(
    output => AGENTIC_OUTPUT.test(output) && safeOutputs[output] !== false,
  );
  for (const output of outputs) {
    add('egress', `safe-outputs ${output}`, at('safe-outputs'), 'yes', 'safe-outputs');
    add('write', `safe-outputs ${output}`, at('safe-outputs'), 'yes', 'safe-outputs');
  }
  if (isRecord(safeOutputs['jobs']) && Object.keys(safeOutputs['jobs']).length)
    unknownReach('safe-outputs.jobs', Object.keys(safeOutputs['jobs']).join(', '), at('jobs'));
  // Secrets given to the agent's environment, its MCP servers, its tools or its engine (the agent's
  // shell inherits the engine's environment) are data it holds, except the engine's model keys
  // and telemetry. The safe-output jobs run apart from the agent.
  const engineEnv = isRecord(data['engine']) && isRecord(data['engine']['env']) ? data['engine']['env'] : {};
  const agentEnv = Object.fromEntries(
    Object.entries(engineEnv).filter(([variable, value]) => !isHarnessCredential(variable, value)),
  );
  const agentData = [data['env'], data['mcp-servers'], data['tools'], agentEnv];
  const secrets = new Set<string>();
  for (const secret of secretNames(JSON.stringify(agentData))) if (!MODEL_SECRETS.test(secret)) secrets.add(secret);
  for (const secret of secrets)
    add(
      'privateData',
      `secret ${secret}`,
      { file: path, line: lineOf(text, `secrets.${secret}`) || lineOf(text, 'secrets') || 1 },
      'yes',
      'secret',
    );
  // A token other than the workflow's own: its scopes are not in the repository.
  const token = JSON.stringify([
    data['github-token'],
    isRecord(github) ? github['github-token'] : undefined,
    safeOutputs['github-token'],
  ]);
  for (const secret of secretNames(token))
    if (secret !== 'GITHUB_TOKEN')
      for (const capability of ['write', 'egress'] as const)
        add(
          capability,
          `github-token secrets.${secret}`,
          { file: path, line: lineOf(text, `secrets.${secret}`) || lineOf(text, 'github-token') || 1 },
          'unknown',
          'token',
        );
  // An engine gh-aw does not build in, or an import that cannot be read, brings settings that are
  // not in this file.
  const engine = isRecord(data['engine']) ? asString(data['engine']['id']) : asString(data['engine']);
  if (engine !== undefined && !AGENTIC_ENGINES.has(engine)) unknownReach('engine', engine, at('engine'));
  // Custom jobs and steps compile into the lock that runs: one that starts an agent of its own is
  // not modelled, so it is unknown reach, reported at high.
  for (const { key, value } of [
    ...STEP_KEYS.filter(key => own[key] !== undefined).map(key => ({ key, value: own[key] })),
    ...importedSteps.map(item => ({ key: `${item.key} (imported)`, value: item.value })),
  ])
    if (runsAgent(value)) {
      unknownReach(key, 'runs an agent', at(key.replace(/ \(imported\)$/, '')));
      unrecognized[unrecognized.length - 1] = { ...unrecognized.at(-1)!, severity: 'high' };
    }
  // Secrets the workflow maps for the agent are data it holds.
  if (own['secrets'] !== undefined)
    for (const secret of secretNames(JSON.stringify(own['secrets'])))
      if (!MODEL_SECRETS.test(secret))
        add(
          'privateData',
          `secret ${secret}`,
          { file: path, line: lineOf(text, `secrets.${secret}`) || 1 },
          'yes',
          'secret',
        );
  // Engine settings beyond these (args, command, steps, ...) change how the agent runs.
  if (isRecord(data['engine']))
    for (const key of Object.keys(data['engine']))
      if (!['id', 'version', 'model', 'env', 'concurrency', 'max-turns', 'user-agent'].includes(key)) {
        unknownReach('engine', key, at(key));
        // `command` and `steps` replace or prepare the agent itself; `args` that lift its limits
        // run every tool without asking. Both are high.
        const value = JSON.stringify(data['engine'][key]);
        if (
          key === 'command' ||
          key === 'steps' ||
          (key === 'args' &&
            /dangerously|allow-all|--yolo|bypassPermissions|danger-full-access|approval-mode[= ]yolo/.test(value))
        )
          unrecognized[unrecognized.length - 1] = { ...unrecognized.at(-1)!, severity: 'high' };
      }
  if (unreadImports.length) {
    unknownReach('imports', unreadImports.map(item => item.what).join(', '), at('imports'));
    // Unpinned or local unread imports are high; one pinned to a commit of another repository is
    // fixed but unseen content chosen by its author: medium, so it is visible without failing.
    const last = unrecognized.at(-1)!;
    unrecognized[unrecognized.length - 1] = {
      ...last,
      severity: unreadImports.some(item => !item.pinned) ? 'high' : 'medium',
    };
  }
  if (ownParsed.error) {
    unknownReach('front matter', ownParsed.error, anchor);
    add('untrustedInput', 'front matter not readable', anchor, 'unknown', 'trigger');
  }
  for (const [variable, value] of Object.entries(engineEnv))
    if (MODEL_ENDPOINT.test(variable))
      unrecognized.push({
        agent: name,
        setting: `engine.env.${variable}`,
        value: String(value),
        assumed:
          'model traffic, with everything the agent reads, goes to this endpoint; it is not counted as sending data out',
        location: at(variable),
        severity: endpointSeverity(variable, String(value)),
      });
  const permissions = data['permissions'];
  const writes =
    permissions === 'write-all'
      ? ['*']
      : isRecord(permissions)
        ? Object.entries(permissions).flatMap(([scope, level]) => (level === 'write' ? [scope] : []))
        : [];
  for (const scope of writes)
    if (scope === '*' || PUBLISHING_SCOPES.has(scope)) {
      const via = `GITHUB_TOKEN ${scope === '*' ? 'write-all' : `${scope}: write`}`;
      add('egress', via, at('permissions'), 'yes', 'token');
      add('write', via, at('permissions'), 'yes', 'token');
    }
  // MCP servers: a `container` is a docker image, so the pinning and policy rules judge it.
  const block: Record<string, unknown> = {};
  if (isRecord(data['mcp-servers']))
    for (const [server, raw] of Object.entries(data['mcp-servers'])) {
      if (!isRecord(raw)) continue;
      const container = asString(raw['container']);
      // Keys beyond the image and its environment (entrypoint, mounts, args, ...) change what the
      // container runs: keep them as an unknown docker flag, so the image is never identified.
      const plain = Object.keys(raw).every(key =>
        ['container', 'env', 'allowed', 'version', 'type', 'mode'].includes(key),
      );
      block[server] =
        container && raw['command'] === undefined
          ? {
              ...raw,
              command: 'docker',
              args: ['run', '-i', '--rm', ...(plain ? [] : ['--unmodelled-gh-aw-settings']), container],
            }
          : raw;
    }
  const servers = serversFromObject({ mcpServers: block }, path, text, 'workflow', 0, declared);
  for (const server of servers)
    grants.push(...grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'auto', servers));
  const models: ModelChoice[] = [];
  const model = isRecord(own['engine']) ? asString(own['engine']['model']) : undefined;
  if (model) models.push({ agent: name, model, location: at('model') });
  const checked = outputs.length > 0 && safeOutputs['threat-detection'] !== false;
  return {
    agent: {
      id: `agentic-workflow:${path}`,
      kind: 'workflow',
      name,
      location: anchor,
      grants,
      mediators: checked ? [{ kind: 'safe-outputs', location: at('safe-outputs') }] : [],
      headless: true,
    },
    servers,
    allow,
    bypasses: [],
    models,
    unrecognized,
    ...(ownParsed.error ? { unparsed: [{ path, error: ownParsed.error }] } : {}),
  };
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined || value === null ? [] : [value];
}

/** `{{#import path}}`, `{{#import? path}}` and `@include path` lines in a gh-aw body. */
function bodyImports(body: string): string[] {
  const out: string[] = [];
  for (const match of body.matchAll(/\{\{#import\??\s+([^\s}]+)\s*\}\}|^@include\??\s+(\S+)/gm))
    out.push((match[1] ?? match[2])!);
  return out;
}

function triggerNamesOf(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return asStringArray(value);
  if (isRecord(value)) return Object.keys(value);
  return [];
}

/**
 * A gh-aw lock file (`<name>.lock.yml`) with no `<name>.md` source beside it. Its compiled steps
 * are not modelled, so it is judged as an unattended agent of unknown reach, started by its triggers.
 */
export function parseAgenticLockAlone(path: string, text: string, mismatch?: string): OtherAgent {
  let triggers: string[] = [];
  try {
    const data = parseYaml(text, { maxAliasCount: 50 }) as unknown;
    if (isRecord(data)) triggers = triggerNamesOf(data['on']);
  } catch {
    triggers = [];
  }
  const name = `Compiled agentic workflow ${path.split('/').at(-1)}`;
  const anchor = { file: path, line: 1 };
  const grants: Grant[] = [];
  for (const trigger of triggers)
    if (AGENTIC_UNTRUSTED.has(trigger))
      grants.push(grantOf('untrustedInput', `trigger ${trigger}`, 'auto', anchor, 'yes', 'trigger'));
  for (const capability of ['exec', 'write', 'egress'] as const)
    grants.push(
      grantOf(
        capability,
        mismatch ? 'compiled steps that do not match the source' : 'compiled steps (no source to judge)',
        'auto',
        anchor,
        'unknown',
        'engine',
      ),
    );
  return {
    agent: {
      id: `agentic-lock:${path}`,
      kind: 'workflow',
      name,
      location: anchor,
      grants,
      mediators: [],
      headless: true,
    },
    servers: [],
    allow: [],
    bypasses: [],
    models: [],
    unrecognized: [
      {
        agent: name,
        setting: 'source',
        value: mismatch
          ? `${path.replace(/\.lock\.ya?ml$/, '.md')} (the lock has ${mismatch})`
          : path.replace(/\.lock\.ya?ml$/, '.md'),
        assumed: mismatch
          ? 'the lock was edited by hand, so its source says nothing about it: it may run code, write and send data out'
          : 'the compiled workflow has no source in the repository, so it may run code, write and send data out',
        location: anchor,
        ...(mismatch ? { severity: 'high' as const } : {}),
      },
    ],
  };
}
