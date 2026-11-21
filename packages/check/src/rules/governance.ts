import { ASI, agentServers, allowRules, rule, serverKey } from './common.js';
import type { Rule } from './common.js';
import type { Grant } from '../types.js';
import type { Project } from '../model.js';
import { withoutTrailingSlashes } from '../text.js';
import { bashScope, HARMLESS_TOOLS, parseRule } from '../claude.js';
import { authority, isMediated } from '../authority.js';
import { foldPath, isInstructionPath } from '../source.js';

/** Tools whose allow rules the scanner models. */
const MODELLED_TOOLS = new Set([
  '*',
  'Bash',
  'PowerShell',
  'Monitor',
  'Read',
  'Glob',
  'Grep',
  'LS',
  'Edit',
  'Write',
  'MultiEdit',
  'NotebookEdit',
  'WebFetch',
  'WebSearch',
  'mcp',
]);

/** The first CODEOWNERS line (1-based) whose pattern covers agent configuration, if any. */
function agentOwnerLine(project: Project): number | undefined {
  const lines = project.codeowners?.text.split('\n') ?? [];
  const index = lines.findIndex(raw => {
    const line = raw.trim();
    return (
      line !== '' &&
      !line.startsWith('#') &&
      /^(\*|\/?\*\*|\/?\.claude\b|\/?\.mcp\.json|\/?\.github\b|\/?CLAUDE\.md|\/?AGENTS\.md)/.test(line.split(/\s+/)[0]!)
    );
  });
  return index < 0 ? undefined : index + 1;
}

/** A CODEOWNERS pattern as a matcher for repository paths (gitignore-style, as GitHub reads it). */
function ownerPattern(pattern: string): RegExp | undefined {
  if (pattern.startsWith('!') || pattern.includes('[')) return undefined; // Not supported by GitHub.
  const dir = pattern.endsWith('/');
  let body = withoutTrailingSlashes(pattern);
  const anchored = body.startsWith('/') || body.includes('/');
  body = body.replace(/^\/+/, '');
  if (!body) return undefined;
  const source = body
    .split(/(\*\*\/|\/\*\*$|\*\*|\*|\?)/)
    .map(part =>
      part === '**/'
        ? '(?:.*/)?'
        : part === '/**'
          ? '/.*'
          : part === '**'
            ? '.*'
            : part === '*'
              ? '[^/]*'
              : part === '?'
                ? '[^/]'
                : part.replace(/[.+^${}()|\\]/g, '\\$&'),
    )
    .join('');
  return new RegExp(`^${anchored ? '' : '(?:.*/)?'}${source}${dir ? '/.*' : '(?:/.*)?'}$`);
}

/**
 * The CODEOWNERS line (1-based) that gives an owner to a file defining an agent. The last matching
 * line decides, as on GitHub; a line with a pattern and no owner takes ownership away.
 */
function ownedAgentLine(project: Project): number | undefined {
  const rules = (project.codeowners?.text.split('\n') ?? [])
    .map((raw, index) => {
      const [pattern, ...owners] = raw
        .replace(/(^|\s)#.*$/, '')
        .trim()
        .split(/\s+/);
      const match = pattern ? ownerPattern(pattern) : undefined;
      return match ? { match, owned: owners.length > 0, line: index + 1 } : undefined;
    })
    .filter(rule => rule !== undefined);
  const lines = [...new Set(project.agents.map(agent => agent.location.file))]
    .map(file => rules.filter(rule => rule.match.test(file)).at(-1))
    .filter(rule => rule?.owned)
    .map(rule => rule!.line);
  return lines.length ? Math.min(...lines) : undefined;
}

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
      if (agentOwnerLine(project) !== undefined) return;
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
      id: 'AGC-GOV-004',
      title: 'Code owners are asked to review, not required to approve',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'A CODEOWNERS entry only requests the owner’s review. Unless a ruleset or branch protection rule turns on "Require review from Code Owners", a change that widens an agent’s permissions merges with any approval, or with none on a branch that requires no reviews.',
    },
    (project, report, context) => {
      const github = context.github;
      if (!github || github.codeOwnerReview === 'required' || !project.codeowners) return;
      if (!project.agents.some(agent => agent.kind !== 'subagent')) return; // as AGC-GOV-001
      const line = ownedAgentLine(project);
      if (line === undefined) return; // No owner to require: AGC-GOV-001 covers the missing owner.
      const unknown = github.codeOwnerReview === 'unknown';
      report({
        message: unknown
          ? `CODEOWNERS names owners for agent configuration, and it could not be confirmed that ${github.branch} requires their approval: ${github.why}.`
          : `CODEOWNERS names owners for agent configuration, but ${github.branch} does not require their approval (${github.why}), so a change to an agent can merge without them.`,
        location: { file: project.codeowners.path, line },
        // The branch and repository stay out of the key, so a baseline holds across branches.
        subject: 'code-owner-review',
        severity: unknown ? 'info' : 'low',
        fix: `Turn on "Require review from Code Owners" for ${github.branch} in a ruleset (Settings > Rules) or branch protection rule, and keep the list of who can bypass it short.`,
      });
    },
    'github',
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
          // Both at once, with nothing checking, is an agent that can run anything and send the
          // result anywhere: the gate fails on that reach, whichever setting gave it.
          ...(egress.length && exec.length ? { severity: 'high' as const } : {}),
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
          ...(item.severity ? { severity: item.severity, confidence: 'high' as const } : {}),
          fix: 'Check this capability by hand. If the value is valid, report it so the scanner can model it.',
        });
      // An MCP server the scanner cannot identify, whose tools run without asking: what they do is
      // unknown, so it is reported at high (unknown is never treated as safe).
      const seen = new Set<string>();
      for (const agent of project.agents)
        for (const grant of agent.grants)
          if (
            grant.tool?.startsWith('mcp__') &&
            grant.certainty === 'unknown' &&
            grant.approval === 'auto' &&
            !seen.has(`${agent.id}|${grant.tool}`)
          ) {
            seen.add(`${agent.id}|${grant.tool}`);
            report({
              message: `${agent.name} runs tools of MCP server ${grant.tool.slice(5)} without asking (${grant.via}); the scanner cannot identify the server, so they may run code, write and send data out.`,
              location: grant.location,
              subject: `mcp-unknown:${(() => {
                const server = agentServers(project).find(item => `mcp__${item.name}` === grant.tool);
                return server ? serverKey(server) : grant.tool;
              })()}`,
              agent,
              severity: 'high',
              confidence: 'high',
              fix: 'Keep this server behind approval, or declare what it can do in .agc.yaml (mcp_servers).',
            });
          }
      // An allow rule for a tool the scanner does not know: it may run code, write and send data out.
      for (const allowed of allowRules(project))
        if (!MODELLED_TOOLS.has(allowed.tool) && !HARMLESS_TOOLS.has(allowed.tool))
          report({
            message: `"${allowed.raw}" allows a tool the scanner does not model; the scan assumed it may run code, write and send data out without asking.`,
            location: allowed.location,
            subject: `tool:${allowed.raw}`,
            severity: 'medium',
            confidence: 'high',
            fix: 'Check what this tool can do. If it is a valid tool, report it so the scanner can model it.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-CFG-002',
      title: 'Agent configuration file the scanner could not read',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.supply],
      help: 'A file over 1 MiB, a symbolic link that leaves the repository or cannot be resolved, invalid front matter, or a walk that stopped early leaves configuration unread, so nothing in it is judged. Padding a settings file, or linking it out of the repository, would otherwise hide what it grants.',
    },
    (project, report) => {
      // Instructions and repository metadata hide less than settings that grant tools. Agent
      // definitions written in Markdown (subagents, Copilot, OpenCode and gh-aw agents) grant tools.
      const severityOf = (path: string) => {
        const name = path.split('/').at(-1) ?? path;
        const instructions = isInstructionPath(path);
        // An unread package.json only stops identification (the scan then assumes the worst).
        return name === 'CODEOWNERS' ? 'low' : instructions || name === 'package.json' ? 'medium' : 'high';
      };
      for (const path of project.skippedFiles)
        report({
          message: `${path} is larger than 1 MiB, so it was not read and nothing in it was judged.`,
          location: { file: path, line: 1 },
          subject: path,
          severity: severityOf(path),
          fix: 'Keep agent configuration small, or split it; check this file by hand.',
        });
      for (const path of project.skippedConfig)
        report({
          message: `${path} is agent configuration inside a folder the scan skips (build output or vendored code), so it was not read and nothing in it was judged.`,
          location: { file: path, line: 1 },
          subject: `skipped:${path}`,
          severity: /(^|\/)(\.mcp\.json|\.claude|\.codex|\.gemini|\.cursor|\.claude-plugin|opencode\.json)(\/|$)/.test(
            path,
          )
            ? 'high'
            : 'medium',
          fix: 'Move agent configuration out of build and vendor folders, or check it by hand.',
        });
      for (const path of project.linkedFiles)
        report({
          message: `${path} is a symbolic link that leaves the repository or cannot be resolved, so the scanner did not follow it and nothing it points to was judged.`,
          location: { file: path, line: 1 },
          subject: `link:${path}`,
          severity: severityOf(path),
          fix: 'Commit the configuration as a regular file.',
        });
      for (const item of project.unparsed)
        report({
          message: `${item.path} could not be parsed (${item.error}), so nothing in it was judged.`,
          location: { file: item.path, line: 1 },
          subject: `unparsed:${item.path}`,
          severity: severityOf(item.path),
          fix: 'Fix the file: valid JSON, YAML or TOML, no duplicate keys, no more than 50 YAML aliases.',
        });
      for (const path of project.caseVariants)
        report({
          message: `${path} is agent configuration on macOS and Windows, where letter case is ignored, but the scanner reads only the exact name, so it was not judged.`,
          location: { file: path, line: 1 },
          subject: `case:${path}`,
          severity: severityOf(foldPath(path)),
          fix: 'Rename it to the exact name the agent expects, so every system and this scan read the same file.',
        });
      for (const [first, second] of project.caseCollisions)
        report({
          message: `${first} and ${second} differ only in letter case; on macOS and Windows only one of them exists, and which one is up to the checkout.`,
          location: { file: second, line: 1 },
          subject: `collision:${first.toLowerCase()}`,
          fix: 'Keep one of the two files.',
        });
      if (project.truncated)
        report({
          message:
            'The scan stopped before it looked at every file (more than 200,000 entries, folders more than 32 levels deep, or one folder reached through links more than 4 times), so configuration may be unread.',
          // Configuration folders are walked first, so a large repository reaches the limit only
          // after its agent configuration; still, what was not read was not judged.
          location: { file: '.', line: 1 },
          subject: 'truncated',
          fix: 'Scan the folder that holds the agents, or check the rest by hand.',
        });
    },
  ),
];

const MODEL_ALIAS = /^(sonnet|opus|haiku|opusplan|default|best|sonnet\[1m\])$|(^|[-_])latest$/;
