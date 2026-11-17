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
export function parseOpenCode(path: string, text: string, declared: readonly DeclaredServer[] = []): OtherAgent {
  const data = parseJsonc(text);
  if (!isRecord(data)) throw new Error('config must be an object');
  const dir = path.split('/').at(-2) === '.opencode' ? dirOf(path, 2) : dirOf(path, 1);
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

  if (isRecord(v1) || typeof v1 === 'string') {
    // V1: a shorthand string applies to every tool; "*" is the default for tools not listed.
    const permission: Record<string, unknown> = typeof v1 === 'string' ? { '*': v1 } : v1;
    const fallback = action(permission['*'], 'permission.*', at('permission')) ?? 'allow';
    if (fallback === 'allow' && permission['*'] !== undefined)
      bypasses.push({ agent: name, what: 'permission "*" = "allow"', location: at('permission') });
    for (const tool of OPENCODE_TOOLS) {
      if (tool.disable.some(key => disabled.has(key))) continue;
      const value = permission[tool.v1];
      const location = value === undefined ? at('permission') : at(tool.v1);
      if (isRecord(value)) {
        // Patterns, the last match winning; "*" is the default for commands no pattern names.
        const base = action(value['*'], `permission.${tool.v1}.*`, location) ?? fallback;
        if (base !== 'deny')
          add(tool.rule, base === 'ask' ? 'ask' : 'auto', location, base === 'unknown' ? 'unknown' : 'yes');
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
    const mcpVerdict = fallback === 'unknown' ? 'allow' : fallback;
    if (mcpVerdict !== 'deny')
      for (const server of servers)
        grants.push(
          ...grantsForRule(
            parseRule(`mcp__${server.name}`, server.location),
            mcpVerdict === 'ask' ? 'ask' : 'auto',
            servers,
          ),
        );
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
      if (tool.disable.some(key => disabled.has(key))) continue;
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
  } else {
    // No permission settings: V1 would run everything without asking, V2 would ask. Say so.
    unrecognized.push({
      agent: name,
      setting: 'permission',
      value: '(not set)',
      assumed: 'tools run without asking, as in OpenCode V1 (V2 asks); set permissions explicitly',
      location: anchor,
    });
    for (const tool of OPENCODE_TOOLS)
      if (!tool.disable.some(key => disabled.has(key))) add(tool.rule, 'auto', anchor, 'unknown');
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

const COPILOT_ALIASES: Readonly<Record<string, readonly string[]>> = {
  execute: ['execute', 'shell', 'bash', 'powershell', 'terminal', 'run_in_terminal'],
  edit: ['edit', 'write', 'multiedit', 'str_replace', 'str_replace_editor', 'create'],
  web: ['web', 'websearch', 'webfetch', 'fetch'],
};

/**
 * `.github/agents/<name>.agent.md` (or `<name>.md`): a Copilot custom agent. On the cloud agent
 * nobody approves its calls, so every tool runs without asking; its network is limited by the
 * Copilot firewall, so outbound reach through the shell or the web is unknown rather than yes.
 * The GitHub MCP server (read-only for the repository by default) is on unless `tools` leaves it out.
 */
export function parseCopilotAgent(path: string, text: string, declared: readonly DeclaredServer[] = []): OtherAgent {
  const { data } = frontmatter(text);
  const file = path.split('/').at(-1)!;
  const label = asString(data['name']) ?? file.replace(/(\.agent)?\.md$/, '');
  const name = `Copilot agent ${label}`;
  const toolsLine = { file: path, line: lineOf(text, 'tools:') || 1 };
  const anchor = { file: path, line: 1 };
  const tools = data['tools'] === undefined ? ['*'] : asStringArray(data['tools']).map(tool => tool.trim());
  const lower = tools.map(tool => tool.toLowerCase());
  const all = lower.includes('*');
  const has = (alias: string) => all || COPILOT_ALIASES[alias]!.some(item => lower.includes(item));
  const serverTools = (server: string) => tools.filter(tool => tool.startsWith(`${server}/`));
  const grants: Grant[] = [];
  const at = toolsLine.line > 1 ? toolsLine : anchor;
  if (has('execute')) {
    grants.push(grantOf('exec', 'execute', 'auto', at, 'yes', 'shell'));
    grants.push(grantOf('write', 'execute', 'auto', at, 'yes', 'shell'));
    grants.push(grantOf('egress', 'execute (behind the Copilot firewall)', 'auto', at, 'unknown', 'shell'));
  }
  if (has('edit')) grants.push(grantOf('write', 'edit', 'auto', at, 'yes', 'edit'));
  if (has('web')) {
    grants.push(grantOf('untrustedInput', 'web', 'auto', at, 'yes', 'web'));
    grants.push(grantOf('egress', 'web (behind the Copilot firewall)', 'auto', at, 'unknown', 'web'));
  }
  if (all || serverTools('github').length) {
    grants.push(grantOf('privateData', 'github MCP server (repository)', 'auto', at, 'yes', 'mcp__github'));
    grants.push(
      grantOf('untrustedInput', 'github MCP server (issues and pull requests)', 'auto', at, 'yes', 'mcp__github'),
    );
  }
  const ownBlock = isRecord(data['mcp-servers']) ? data['mcp-servers'] : {};
  const servers = serversFromObject({ mcpServers: ownBlock }, path, text, 'copilot', 0, declared);
  for (const server of servers) {
    const chosen = serverTools(server.name);
    if (all || chosen.includes(`${server.name}/*`))
      grants.push(...grantsForRule(parseRule(`mcp__${server.name}`, server.location), 'auto', servers));
    else
      for (const tool of chosen)
        grants.push(
          ...grantsForRule(
            parseRule(`mcp__${server.name}__${tool.slice(server.name.length + 1)}`, server.location),
            'auto',
            servers,
          ),
        );
  }
  const models: ModelChoice[] = [];
  const model = asString(data['model']);
  if (model) models.push({ agent: name, model, location: { file: path, line: lineOf(text, 'model:') || 1 } });
  return {
    ...empty(
      { id: `copilot:${path}`, kind: 'copilot', name, location: anchor, grants, mediators: [], headless: true },
      servers,
    ),
    models,
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
