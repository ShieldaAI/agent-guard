import { ASI, DESTRUCTIVE_COMMAND, DESTRUCTIVE_TOOL, agentServers, allowRules, rule } from './common.js';
import type { Rule } from './common.js';
import { bashScope } from '../claude.js';
import { lineAt } from '../text.js';
import { UNTRUSTED_TRIGGERS } from '../workflows.js';

export const PERMISSIONS_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-PERM-001',
      title: 'Agent runs every tool without asking',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.tools, ASI.trust],
      help: 'Bypass modes remove the approval step for every tool, including shell commands and outbound requests.',
    },
    (project, report) => {
      for (const file of project.settings)
        if (file.defaultMode?.value === 'bypassPermissions')
          report({
            message: 'Claude Code runs every tool without asking (defaultMode: bypassPermissions).',
            location: file.defaultMode.location,
            subject: 'defaultMode',
            agent: project.agents.find(agent => agent.kind === 'claude-code'),
            fix: 'Remove defaultMode or set it to "default", and allow only the tools the agent needs.',
          });
      for (const step of project.workflows)
        if (step.skipPermissions) {
          const untrusted = step.triggers.some(trigger => UNTRUSTED_TRIGGERS.has(trigger));
          report({
            message: `The ${step.job} job runs the agent with approvals and sandbox turned off${untrusted ? ', on events outsiders can trigger' : ''}.`,
            location: step.skipPermissions,
            subject: `${step.job}/${step.step}`,
            agent: project.agents.find(agent => agent.id === `workflow:${step.path}#${step.job}/${step.step}`),
            severity: untrusted ? 'critical' : 'high',
            fix: 'Replace the bypass flag with --allowedTools listing only the tools this job needs.',
          });
        }
      for (const file of project.scripts) {
        const index = file.text.search(/--dangerously-(skip-permissions|bypass-approvals-and-sandbox)/);
        if (index >= 0)
          report({
            message: 'A script starts the agent with approvals turned off.',
            location: { file: file.path, line: lineAt(file.text, index) },
            subject: 'script',
            fix: 'Pass --allowedTools with the specific tools instead.',
          });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PERM-002',
      title: 'Wildcard tool allow',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools],
      help: 'An allow rule for every shell command, or every tool, removes approval for anything the agent decides to run.',
    },
    (project, report) => {
      const servers = agentServers(project);
      for (const allowed of allowRules(project)) {
        if (allowed.tool === '*' || (allowed.tool === 'Bash' && bashScope(allowed.specifier) === 'any')) {
          report({
            message: `"${allowed.raw}" lets the agent run any ${allowed.tool === '*' ? 'tool' : 'shell command'} without asking.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Replace it with the specific commands the agent needs, such as "Bash(npm test:*)".',
          });
        } else if (allowed.tool === 'mcp' && allowed.mcpTool === undefined) {
          const server = servers.find(item => item.name === allowed.server);
          const caps = server?.catalog?.capabilities ?? {};
          if (caps.egress === 'yes' || caps.spend === 'yes' || caps.write === 'yes')
            report({
              message: `"${allowed.raw}" allows every ${server!.catalog!.label} tool without asking, including ones that ${caps.spend === 'yes' ? 'spend money' : caps.egress === 'yes' ? 'send data out' : 'write'}.`,
              location: allowed.location,
              subject: allowed.raw,
              severity: 'medium',
              fix: `List the read-only ${server!.catalog!.label} tools the agent needs, for example "mcp__${allowed.server}__get_…", and leave the rest behind approval.`,
            });
        }
      }
    },
  ),
  rule(
    {
      id: 'AGC-PERM-003',
      title: 'Allowed command can send data out or run any code',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.code],
      help: 'Network tools and interpreters (curl, ssh, python, node, npx) can reach any host, so allowing them is close to allowing everything.',
    },
    (project, report) => {
      for (const allowed of allowRules(project))
        if (allowed.tool === 'Bash' && bashScope(allowed.specifier) === 'network')
          report({
            message: `"${allowed.raw}" runs without asking and can reach the network or run arbitrary code.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: 'Keep this command behind approval, or narrow it to a fixed script that cannot take arbitrary arguments.',
          });
    },
  ),
  rule(
    {
      id: 'AGC-PERM-004',
      title: 'Agent can read files outside the project',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Home directories hold SSH keys, cloud credentials and tokens. An agent that can read them can leak them.',
    },
    (project, report) => {
      for (const file of project.settings) {
        for (const allowed of file.allow)
          if (['Read', 'Glob', 'Grep', 'LS'].includes(allowed.tool) && /^(~|\/\/|\$HOME)/.test(allowed.specifier ?? ''))
            report({
              message: `"${allowed.raw}" lets the agent read outside the project without asking, where keys and tokens live.`,
              location: allowed.location,
              subject: allowed.raw,
              fix: 'Allow only the specific directory the agent needs, and deny ~/.ssh, ~/.aws and .env files.',
            });
        for (const directory of file.additionalDirectories)
          if (/^(~\/?|\/|\$HOME\/?)$/.test(directory.value.trim()))
            report({
              message: `additionalDirectories includes "${directory.value}", which opens the whole ${directory.value.trim() === '/' ? 'disk' : 'home directory'} to the agent.`,
              location: directory.location,
              subject: `dir:${directory.value}`,
              fix: 'List only the project directories the agent needs.',
            });
      }
    },
  ),
  rule(
    {
      id: 'AGC-PERM-005',
      title: 'Destructive action allowed without approval',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.tools, ASI.trust],
      help: 'Deleting, publishing, merging, sending and paying are hard to undo; a person should confirm each one.',
    },
    (project, report) => {
      for (const allowed of allowRules(project)) {
        const destructive =
          (allowed.tool === 'mcp' && allowed.mcpTool !== undefined && DESTRUCTIVE_TOOL.test(allowed.mcpTool)) ||
          (allowed.tool === 'Bash' && DESTRUCTIVE_COMMAND.test((allowed.specifier ?? '').trim()));
        if (destructive)
          report({
            message: `"${allowed.raw}" runs without asking, and it cannot easily be undone.`,
            location: allowed.location,
            subject: allowed.raw,
            fix: `Move "${allowed.raw}" from allow to ask.`,
          });
      }
    },
  ),
];
