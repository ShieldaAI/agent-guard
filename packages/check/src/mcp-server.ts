#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { diffScans, scan } from './scan.js';
import { safeRelative } from './source.js';
import { authority, describeLevel } from './authority.js';
import { RULES } from './rules/index.js';
import { RULES_URI, TOOL_NAME, TOOL_VERSION } from './report.js';
import { CAPABILITIES, CAPABILITY_LABELS, type Finding, type ScanResult } from './types.js';

/**
 * A read-only MCP server (stdio) so an agent can check its own configuration before it changes it.
 * It scans one root fixed at start-up, never leaves it, never runs repository code and makes no
 * network calls. Three tools: scan_agent_config, check_agent_config_change, explain_agent_rule.
 */

const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_LINE = 1024 * 1024;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
interface Request {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const TOOLS = [
  {
    name: 'scan_agent_config',
    title: 'Scan agent configuration',
    description:
      'Shows what each AI agent configured in the repository can do (private data, untrusted input, writes, code execution, sending data out, spending, changing itself) and lists risky findings with fixes. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'A directory inside the server root to scan. Default: the root.' },
        minSeverity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'info'],
          description: 'Leave out findings below this severity. Default: low.',
        },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true },
  },
  {
    name: 'check_agent_config_change',
    title: 'Check a change to agent configuration',
    description:
      'Compares the working tree with a git commit and reports only what the change made worse: agent authority that grew and new findings. Use it before committing changes to settings, MCP configs, subagents or agent workflows.',
    inputSchema: {
      type: 'object',
      properties: {
        base: { type: 'string', description: 'The git ref to compare with, such as HEAD or origin/main.' },
      },
      required: ['base'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true },
  },
  {
    name: 'explain_agent_rule',
    title: 'Explain a rule',
    description: 'Explains one agent-guard-check rule, such as AGC-TRI-001: what it flags, why, and its severity.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'The rule ID, such as AGC-PERM-001.' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true },
  },
];

const ORDER = ['info', 'low', 'medium', 'high', 'critical'];

function findingLines(findings: readonly Finding[]): string[] {
  return findings.map(
    finding =>
      `- [${finding.severity}] ${finding.ruleId} at ${finding.location.file}:${finding.location.line}: ${finding.message}${finding.fix ? ` Fix: ${finding.fix}` : ''}`,
  );
}

function summary(result: ScanResult, min: string): string {
  const out: string[] = [];
  for (const agent of result.agents) {
    const states = authority(agent);
    const caps = CAPABILITIES.filter(capability => states[capability].value !== 'no').map(
      capability => `${CAPABILITY_LABELS[capability]}: ${describeLevel(states[capability])}`,
    );
    out.push(`${agent.name} (${agent.location.file}): ${caps.length ? caps.join('; ') : 'no risky capabilities'}`);
  }
  const shown = result.findings.filter(finding => ORDER.indexOf(finding.severity) >= ORDER.indexOf(min));
  out.push('', shown.length ? `Findings (${shown.length}):` : 'No findings at or above this severity.');
  out.push(...findingLines(shown));
  for (const error of result.errors) out.push(`Could not read ${error.file}: ${error.message}`);
  return out.join('\n');
}

export interface McpServerOptions {
  readonly root: string;
  readonly write: (line: string) => void;
}

/** Handles one JSON-RPC message and returns the response, or undefined for notifications. */
export function handleMessage(message: unknown, options: McpServerOptions): Json | undefined {
  const request = message as Request;
  const isRequest = typeof message === 'object' && message !== null && 'id' in message && request.id !== undefined;
  const reply = (result: Json): Json => ({ jsonrpc: '2.0', id: request.id ?? null, result });
  const error = (code: number, text: string): Json => ({
    jsonrpc: '2.0',
    id: (request?.id as Json) ?? null,
    error: { code, message: text },
  });
  if (typeof message !== 'object' || message === null || typeof request.method !== 'string')
    return error(-32600, 'Invalid request');
  if (!isRequest) return undefined; // notifications (initialized, cancelled) need no answer
  const params = (request.params ?? {}) as Record<string, unknown>;
  switch (request.method) {
    case 'initialize': {
      const asked = typeof params['protocolVersion'] === 'string' ? params['protocolVersion'] : '';
      return reply({
        protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0]!,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: `${TOOL_NAME}-mcp`, version: TOOL_VERSION },
        instructions:
          'Read-only checks of AI agent configuration in this repository. Call check_agent_config_change before committing changes to agent settings, MCP configs, subagents or agent workflows.',
      });
    }
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: TOOLS as unknown as Json });
    case 'tools/call': {
      const name = params['name'];
      const args = (
        typeof params['arguments'] === 'object' && params['arguments'] !== null ? params['arguments'] : {}
      ) as Record<string, unknown>;
      const text = (body: string, isError = false): Json => reply({ content: [{ type: 'text', text: body }], isError });
      try {
        if (name === 'scan_agent_config') {
          const path = args['path'] === undefined ? '' : String(args['path']);
          const clean = path === '' || path === '.' ? '' : safeRelative(path);
          if (clean === undefined) return text('path must be a directory inside the server root.', true);
          if (clean) {
            // A symbolic link must not lead the scan outside the root.
            const real = realpathSync(resolve(options.root, clean));
            const rootReal = realpathSync(options.root);
            if (real !== rootReal && !real.startsWith(`${rootReal}${sep}`))
              return text('path must be a directory inside the server root.', true);
          }
          const min =
            typeof args['minSeverity'] === 'string' && ORDER.includes(args['minSeverity'])
              ? args['minSeverity']
              : 'low';
          return text(summary(scan({ root: clean ? resolve(options.root, clean) : options.root }), min));
        }
        if (name === 'check_agent_config_change') {
          const base = typeof args['base'] === 'string' ? args['base'] : '';
          if (!base) return text('base is required.', true);
          const head = scan({ root: options.root });
          const diff = diffScans(scan({ root: options.root, ref: base }), head);
          const out: string[] = [];
          out.push(
            diff.widened.length
              ? `Authority widened (${diff.widened.length}):`
              : 'No agent gained authority in this change.',
          );
          for (const change of diff.widened)
            out.push(
              `- ${change.agent.name}: ${CAPABILITY_LABELS[change.capability]} ${change.before ? describeLevel(change.before) : 'no'} -> ${describeLevel(change.after)}`,
            );
          out.push('', diff.added.length ? `New findings (${diff.added.length}):` : 'No new findings.');
          out.push(...findingLines(diff.added));
          if (diff.resolved.length) out.push('', `Resolved: ${diff.resolved.length} finding(s).`);
          return text(out.join('\n'));
        }
        if (name === 'explain_agent_rule') {
          const id = String(args['id'] ?? '').toUpperCase();
          const rule = RULES.find(item => item.id === id);
          if (!rule) return text(`Unknown rule ${id}. Rules: ${RULES.map(item => item.id).join(', ')}.`, true);
          return text(
            `${rule.id}: ${rule.title}\nSeverity: ${rule.severity}; evidence: ${rule.mode}; OWASP Agentic: ${rule.owasp.join(', ')}\n\n${rule.help}\n\n${RULES_URI}#${rule.id.toLowerCase()}`,
          );
        }
        return error(-32602, `Unknown tool ${String(name)}`);
      } catch (caught) {
        return text(caught instanceof Error ? caught.message : String(caught), true);
      }
    }
    default:
      return error(-32601, `Method not found: ${request.method}`);
  }
}

/** Serves MCP over stdio: one JSON-RPC message per line. */
export function serveStdio(root: string, input = process.stdin, output = process.stdout): void {
  const lines = createInterface({ input, crlfDelay: Infinity });
  const write = (value: Json) => output.write(`${JSON.stringify(value)}\n`);
  lines.on('line', line => {
    if (!line.trim()) return;
    if (line.length > MAX_LINE) {
      write({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Message too large' } });
      return;
    }
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    const messages = Array.isArray(message) ? message : [message];
    for (const item of messages) {
      const response = handleMessage(item, { root, write: text => output.write(text) });
      if (response !== undefined) write(response);
    }
  });
}

function isEntry(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

/**
 * Starts the server from command-line arguments: `agent-guard-check-mcp [root]`, or
 * `agent-guard-check --mcp [root]` through the package's default bin, which is what MCP registries
 * and `npx @shieldaai/agent-guard-check` run.
 */
export function mcpMain(args: readonly string[]): void {
  if (args.includes('--help')) {
    process.stdout.write(
      `Usage: ${TOOL_NAME}-mcp [root]\n       ${TOOL_NAME} --mcp [root]\n\nA read-only MCP server (stdio) for checking AI agent configuration in one repository.\n`,
    );
  } else if (args.includes('--version')) process.stdout.write(`${TOOL_VERSION}\n`);
  else {
    // The server makes no network calls. In a partial (blobless) clone, git would otherwise fetch
    // a missing object from the remote when a tool compares with a commit; git 2.44 and later
    // honour this and report the object as missing instead.
    process.env.GIT_NO_LAZY_FETCH = '1';
    serveStdio(resolve(process.cwd(), args.find(arg => !arg.startsWith('-')) ?? '.'));
  }
}

if (isEntry()) mcpMain(process.argv.slice(2));
