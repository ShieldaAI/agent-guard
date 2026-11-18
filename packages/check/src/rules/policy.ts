import { ASI, agentServers, rule } from './common.js';
import type { Rule } from './common.js';
import { authority, primaryGrant } from '../authority.js';
import type { McpServer } from '../mcp.js';
import { CAPABILITY_LABELS, type Capability } from '../types.js';

/**
 * Every name a policy may use for a server: its catalog ID, and the package or image it runs when
 * the command has exactly the expected shape. Never the config name, which a change chooses: a
 * server called `github` that runs `node evil.js` is not the GitHub server.
 */
export function serverIdentities(server: McpServer): string[] {
  const names = [server.catalog?.id, server.identity?.package, server.identity?.image];
  return names.filter((name): name is string => typeof name === 'string' && name.length > 0);
}

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

/** `example.com` allows that host and its subdomains; `*.example.com` only subdomains. */
function hostAllowed(host: string, allowed: readonly string[]): boolean {
  return allowed.some(entry => {
    const pattern = entry.toLowerCase();
    if (pattern.startsWith('*.')) return host.endsWith(pattern.slice(1));
    return host === pattern || host.endsWith(`.${pattern}`);
  });
}

/**
 * Policy as code: rules that only run when `.agc.yaml` sets a `policy` section. They encode a
 * team's own decisions (which servers, which hosts, which capability combinations) so a review
 * does not have to re-derive them for each change.
 */
export const POLICY_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-POL-001',
      title: 'MCP server not on the approved list',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'policy.allowed_mcp_servers in .agc.yaml lists the MCP servers agents may use, by catalog ID, npm/PyPI package or container image. A server matches only when its command has exactly the expected shape; the config name never counts.',
    },
    (project, report, context) => {
      const allowed = context.config.policy.allowedMcpServers;
      if (allowed === null) return;
      const set = new Set(allowed.map(name => name.toLowerCase()));
      for (const server of agentServers(project)) {
        // The servers claude-code-action starts itself are part of the action, not a choice in the repo.
        if (server.catalog?.id.startsWith('claude-code-action/')) continue;
        if (serverIdentities(server).some(name => set.has(name.toLowerCase()))) continue;
        report({
          message: `MCP server "${server.name}" (${serverIdentities(server).join(', ') || 'no package or image the scanner can confirm'}) is not on policy.allowed_mcp_servers.`,
          location: server.location,
          subject: `server:${server.client}:${server.name}`,
          fix: `Remove "${server.name}", or add it to policy.allowed_mcp_servers after review.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-POL-002',
      title: 'Remote MCP server on a host not on the approved list',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.supply, ASI.tools],
      help: 'policy.allowed_mcp_hosts in .agc.yaml lists the hosts remote MCP servers may use. `example.com` also allows its subdomains.',
    },
    (project, report, context) => {
      const allowed = context.config.policy.allowedMcpHosts;
      if (allowed === null) return;
      for (const server of agentServers(project)) {
        const host = hostOf(server.url);
        if (host === undefined || hostAllowed(host, allowed)) continue;
        report({
          message: `MCP server "${server.name}" connects to ${host}, which is not on policy.allowed_mcp_hosts.`,
          location: server.location,
          subject: `host:${server.client}:${server.name}:${host}`,
          fix: `Use an approved host, or add ${host} to policy.allowed_mcp_hosts after review.`,
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-POL-003',
      title: 'Agent holds a forbidden capability combination',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.goal],
      help: 'policy.forbid in .agc.yaml names capability combinations no agent may hold. `auto` means the agent holds it without approval; `any` means it holds it at all. Only certain grants count.',
    },
    (project, report, context) => {
      for (const forbidden of context.config.policy.forbid)
        for (const agent of project.agents) {
          if (forbidden.agents && !forbidden.agents.some(name => name === agent.name || name === agent.id)) continue;
          const states = authority(agent);
          const entries = Object.entries(forbidden.when) as [Capability, 'auto' | 'any'][];
          const held = entries.every(([capability, level]) => {
            const state = states[capability];
            return state.value === 'yes' && (level === 'any' || state.approval === 'auto');
          });
          if (!held) continue;
          const parts = entries.map(([capability, level]) => {
            const grant = primaryGrant(states[capability]);
            return `${CAPABILITY_LABELS[capability]}${level === 'auto' ? ' without approval' : ''} (via ${grant?.via ?? 'unknown'})`;
          });
          const anchor = primaryGrant(states[entries[0]![0]])?.location ?? agent.location;
          report({
            message: `${agent.name} holds the combination "${forbidden.name}" that policy forbids: ${parts.join('; ')}.`,
            location: anchor,
            subject: `forbid:${forbidden.name}:${agent.id}`,
            severity: forbidden.severity,
            fix: `Remove one of these capabilities from ${agent.name}, or put it behind approval.`,
          });
        }
    },
  ),
];
