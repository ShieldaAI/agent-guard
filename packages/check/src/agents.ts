import type { Approval, Grant, Location, Unrecognized } from './types.js';
import { deniesWholeTool, grantsForRule, parseRule, type PermissionRule } from './claude.js';
import { serversFromObject, type DeclaredServer, type McpServer } from './mcp.js';
import type { Bypass, ModelChoice, OtherAgent } from './formats.js';
import { asString, asStringArray, frontmatter, isRecord, lineOf, parseJsonc } from './text.js';

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
  declared: readonly DeclaredServer[] = [],
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
  for (const file of agentFiles) {
    const { data: front } = frontmatter(file.text);
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
export function parseCopilotAgent(path: string, text: string, declared: readonly DeclaredServer[] = []): OtherAgent {
  const { data } = frontmatter(text);
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
  };
}

// ---------------------------------------------------------------------------------------------
// Kiro

/**
 * `.kiro/settings/mcp.json`: Kiro's workspace MCP servers. `autoApprove` lists tools that run
 * without a prompt ("*" for all); `disabled: true` turns a server off. Throws on invalid JSON.
 */
export function parseKiroMcp(path: string, text: string, declared: readonly DeclaredServer[] = []): OtherAgent {
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
