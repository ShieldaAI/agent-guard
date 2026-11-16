import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import type { Grant } from '../types.js';
import { bashScope, parseRule } from '../claude.js';
import { authority } from '../authority.js';

export const GOVERNANCE_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-GOV-001',
      title: 'Agent configuration has no code owner',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'Without a code owner, changes to agent permissions merge with whatever review the rest of the repo gets.',
    },
    (project, report) => {
      const first = project.agents.find(agent => agent.kind !== 'subagent');
      if (!first) return;
      const owned = project.codeowners?.text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .some(line =>
          /^(\*|\/?\*\*|\/?\.claude\b|\/?\.mcp\.json|\/?\.github\b|\/?CLAUDE\.md|\/?AGENTS\.md)/.test(
            line.split(/\s+/)[0]!,
          ),
        );
      if (owned) return;
      report({
        message: project.codeowners
          ? 'CODEOWNERS does not cover agent configuration.'
          : 'No CODEOWNERS file covers agent configuration.',
        location: project.codeowners ? { file: project.codeowners.path, line: 1 } : first.location,
        subject: 'codeowners',
        fix: 'Add CODEOWNERS entries for .claude/, .mcp.json, CLAUDE.md and .github/workflows/.',
      });
    },
  ),
  rule(
    {
      id: 'AGC-GOV-002',
      title: 'Subagent has no stated purpose',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'Claude Code chooses subagents by their description; one without a description is unreviewable and may never be used as intended.',
    },
    (project, report) => {
      for (const sub of project.subagents)
        if (!sub.description)
          report({
            message: `Subagent ${sub.name} has no description.`,
            location: sub.location,
            subject: sub.path,
            fix: 'Add a description to its front matter.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-COV-001',
      title: 'Risky actions with no runtime check',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.tools],
      help: 'Static config is a promise; a runtime check (Agent Guard, a pre-tool hook, an MCP gateway) is what stops a steered agent at call time.',
    },
    (project, report) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent' || agent.mediators.length) continue;
        const a = authority(agent);
        // Only paths that reach an arbitrary host or run arbitrary code count. Running the project's own
        // commands is expected, and posting to the repository through its token is judged by AGC-TRG-001.
        const scopeOf = (grant: Grant) =>
          grant.tool === 'Bash' ? bashScope(parseRule(grant.via, grant.location).specifier) : undefined;
        const arbitrary = (grant: Grant) =>
          grant.approval === 'auto' &&
          grant.certainty === 'yes' &&
          !/^(GITHUB_TOKEN|Claude GitHub App token|default GITHUB_TOKEN)/.test(grant.via) &&
          !(grant.tool ?? '').startsWith('mcp__github_') &&
          (grant.tool !== 'Bash' || ['any', 'network'].includes(scopeOf(grant) ?? ''));
        const egress = a.egress.grants.filter(arbitrary);
        const exec = a.exec.grants.filter(arbitrary);
        const risky = [
          ...(egress.length ? [{ label: 'send data out', grant: egress[0]! }] : []),
          ...(exec.length ? [{ label: 'run code', grant: exec[0]! }] : []),
        ];
        if (!risky.length) continue;
        report({
          message: `${agent.name} can ${risky.map(item => item.label).join(' and ')} without approval (${[...new Set(risky.map(item => item.grant.via))].join(', ')}), and nothing checks those calls at runtime.`,
          location: risky[0]!.grant.location,
          subject: 'coverage',
          agent,
          fix: 'Add a runtime check: Agent Guard, a PreToolUse hook, or an MCP gateway.',
        });
      }
    },
  ),
];
