import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import type { Grant } from '../types.js';
import { bashScope, parseRule } from '../claude.js';
import { authority, isMediated } from '../authority.js';

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
      help: 'Static config is a promise; a runtime check (Agent Guard, a pre-tool hook, an MCP gateway) is what stops a steered agent at call time. A check counts only for the calls it sees: a hook for the tools its matcher names, a guard or gateway for the calls made through it.',
    },
    (project, report) => {
      for (const agent of project.agents) {
        if (agent.kind === 'subagent') continue;
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
          (grant.tool !== 'Bash' || ['any', 'network'].includes(scopeOf(grant) ?? '')) &&
          // A runtime check counts only for the calls it sees: a Bash hook does not see WebFetch.
          !isMediated(agent, grant);
        const egress = a.egress.grants.filter(arbitrary);
        const exec = a.exec.grants.filter(arbitrary);
        const risky = [
          ...(egress.length ? [{ label: 'send data out', grant: egress[0]! }] : []),
          ...(exec.length ? [{ label: 'run code', grant: exec[0]! }] : []),
        ];
        if (!risky.length) continue;
        const vias = [...new Set(risky.map(item => item.grant.via))].join(', ');
        report({
          message: agent.mediators.length
            ? `${agent.name} can ${risky.map(item => item.label).join(' and ')} without approval (${vias}), and its runtime checks do not see those calls.`
            : `${agent.name} can ${risky.map(item => item.label).join(' and ')} without approval (${vias}), and nothing checks those calls at runtime.`,
          location: risky[0]!.grant.location,
          subject: 'coverage',
          agent,
          fix: 'Add a runtime check that sees these calls: a PreToolUse hook whose matcher names these tools, or route them through Agent Guard or an MCP gateway.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-GOV-003',
      title: 'Agent model is a moving alias',
      severity: 'info',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'An alias such as "sonnet" or "-latest" moves to a new model without a change in the repository, which can change how the agent follows its instructions. Pin the full model ID where behavior must stay reviewable.',
    },
    (project, report) => {
      for (const choice of project.models) {
        const model = choice.model.trim().toLowerCase();
        if (!MODEL_ALIAS.test(model)) continue;
        report({
          message: `${choice.agent} uses model "${choice.model}", an alias that can change without a commit.`,
          location: choice.location,
          subject: `model:${choice.agent}`,
          fix: 'Use a full, dated model ID.',
        });
      }
    },
  ),
  rule(
    {
      id: 'AGC-CFG-001',
      title: 'Agent setting the scanner does not model',
      severity: 'info',
      confidence: 'low',
      owasp: [ASI.tools],
      help: 'Agent tools add settings and values faster than any scanner. When this one meets a value it does not know, it assumes the widest reading and says so here, rather than ignoring the setting. Report it so the scanner can learn the value.',
    },
    (project, report) => {
      for (const item of project.unrecognized)
        report({
          message: `${item.agent}: ${item.setting} = "${item.value}" is not modelled; the scan assumed ${item.assumed}.`,
          location: item.location,
          subject: `${item.setting}:${item.value}`,
          fix: 'Check this capability by hand. If the value is valid, report it so the scanner can model it.',
        });
    },
  ),
  rule(
    {
      id: 'AGC-CFG-002',
      title: 'Agent configuration file too large to read',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.supply],
      help: 'Files over 1 MiB are not read, so nothing in them is judged. Agent settings are small; padding a settings file past the limit would otherwise hide what it grants.',
    },
    (project, report) => {
      for (const path of project.skippedFiles) {
        const name = path.split('/').at(-1) ?? path;
        // Instructions and repository metadata hide less than settings that grant tools.
        const severity =
          name === 'package.json' || name === 'CODEOWNERS' ? 'low' : /\.mdc?$/.test(name) ? 'medium' : 'high';
        report({
          message: `${path} is larger than 1 MiB, so it was not read and nothing in it was judged.`,
          location: { file: path, line: 1 },
          subject: path,
          severity,
          fix: 'Keep agent configuration small, or split it; check this file by hand.',
        });
      }
    },
  ),
];

const MODEL_ALIAS = /^(sonnet|opus|haiku|opusplan|default|best|sonnet\[1m\])$|(^|[-_])latest$/;
