import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import { effectiveMode, indexOf, isLive, taskExposure } from '../agent-guard.js';
import type { Location } from '../types.js';

const HOUR = 3_600_000;

/**
 * Mode B: rules over Agent Guard's own records (describe() output, inventory snapshots, manifests).
 * They do nothing when the repository has none.
 */
export const AGENT_GUARD_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-AGX-001',
      title: 'Agent reaches a guarded MCP server directly',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools],
      help: 'Agent Guard mediates this MCP server, but agent configuration in the repository also connects to it directly. Calls on the direct path skip grants, budgets and approvals.',
    },
    (project, report) => {
      const connections = project.agentGuard.mcpConnections;
      if (!connections?.length) return;
      const mediated = new Map(connections.map(connection => [connection.serverId.toLowerCase(), connection.serverId]));
      for (const server of project.servers) {
        const names = [server.name, server.catalog?.id].filter((name): name is string => typeof name === 'string');
        const match = names.map(name => mediated.get(name.toLowerCase())).find(id => id !== undefined);
        if (!match) continue;
        report({
          message: `MCP server "${server.name}" is configured for ${server.client} directly, and Agent Guard also mediates it as "${match}". The direct connection bypasses the guard.`,
          location: server.location,
          subject: `server:${server.client}:${server.name}`,
          fix: `Remove "${server.name}" from ${server.location.file} and reach it only through the guarded MCP connection.`,
        });
      }
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-002',
      title: 'Declared access outside the guard',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.tools, ASI.identity],
      help: 'The host manifest declares access a deployment has without Agent Guard: a shell, a database client, a network client, an SDK or an MCP client. None of it is checked per call.',
    },
    (project, report) => {
      for (const access of project.agentGuard.directAccess)
        report({
          message: `Deployment ${access.deploymentId} has ${access.kind} access outside the guard${access.description ? `: ${access.description}` : ''}.`,
          location: access.location,
          subject: `direct:${access.id}`,
          severity: ['shell', 'database', 'network'].includes(access.kind) ? 'high' : 'medium',
          fix: 'Route this access through a guarded tool, or narrow it and record why it stays outside.',
        });
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-003',
      title: 'Agent Guard task exposed to the dangerous three',
      severity: 'critical',
      confidence: 'high',
      owasp: [ASI.goal, ASI.tools],
      help: 'A live task holds tools that read private data and untrusted content and a tool that sends data out without approval after untrusted content, by Agent Map’s own rules.',
    },
    (project, report) => {
      const evidence = project.agentGuard;
      for (const task of evidence.tasks) {
        if (!isLive(task, evidence)) continue;
        const exposure = taskExposure(task, evidence);
        const legs = exposure.legs;
        if (exposure.status === 'exposed')
          report({
            message: `Task ${task.id} (${task.principalId}) is exposed: ${exposure.evidence.join('; ')}. ${exposure.senders.join(', ')} can send without approval after untrusted content.`,
            location: task.location,
            subject: `task:${task.id}`,
            fix: `Set untrustedContext: 'require_approval' (or 'deny') on ${exposure.senders.join(', ')}, or remove one leg from this task's grants.`,
          });
        else if (exposure.status === 'unknown') {
          const present = Object.values(legs).filter(leg => leg === 'present').length;
          if (present < 2) continue;
          const missing = Object.entries(legs)
            .filter(([, leg]) => leg === 'unknown')
            .map(([name]) => name);
          report({
            message: `Task ${task.id} (${task.principalId}) has ${present} legs of the dangerous three; ${missing.length ? `${missing.join(' and ')} cannot be determined from the declared labels` : 'whether its senders need approval is undeclared'}.`,
            location: task.location,
            subject: `task-unknown:${task.id}`,
            severity: 'medium',
            fix: 'Declare readsUntrusted, sendsExternal and untrustedContext on its tools, and sensitivity on its resource bindings.',
          });
        }
      }
      // Without tasks (describe() only), judge the registry: a task granted both would be exposed.
      if (evidence.tasks.length) return;
      const readers = evidence.tools.filter(tool => tool.registered && tool.readsUntrusted === true);
      const senders = evidence.tools.filter(
        tool => tool.registered && tool.sendsExternal === true && effectiveMode(tool, evidence) === 'allow',
      );
      if (readers.length && senders.length)
        report({
          message: `${senders.map(tool => tool.name).join(', ')} can send data out without approval after ${readers.map(tool => tool.name).join(', ')} read untrusted content. Any task granted both and holding private data would be exposed.`,
          location: senders[0]!.location,
          subject: 'registry',
          severity: 'medium',
          fix: `Set untrustedContext: 'require_approval' on ${senders.map(tool => tool.name).join(', ')}, or set untrustedContextDefault to 'require_approval'.`,
        });
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-004',
      title: 'Agent without an owner, or retired with live work',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'Every agent in the host manifest needs an accountable owner. A retired or inactive agent should have no deployments with live tasks.',
    },
    (project, report) => {
      const evidence = project.agentGuard;
      for (const agent of evidence.agents) {
        const deployments = evidence.deployments.filter(item => item.agentId === agent.id).map(item => item.id);
        const liveTasks = evidence.taskBindings
          .filter(binding => deployments.includes(binding.deploymentId))
          .map(binding => indexOf(evidence).tasks.get(binding.taskId))
          .filter(task => task !== undefined && isLive(task, evidence));
        if ((agent.lifecycleState === 'retired' || agent.lifecycleState === 'inactive') && liveTasks.length)
          report({
            message: `Agent ${agent.name} is ${agent.lifecycleState} but still has ${liveTasks.length} live task(s).`,
            location: agent.location,
            subject: `retired:${agent.id}`,
            severity: 'high',
            fix: 'Revoke its tasks, or correct its lifecycle state.',
          });
        if (agent.ownershipStatus !== 'assigned' || agent.ownerId === null)
          report({
            message: `Agent ${agent.name} has no assigned owner (ownership ${agent.ownershipStatus}).`,
            location: agent.location,
            subject: `owner:${agent.id}`,
            fix: 'Assign an owner in the host manifest.',
          });
      }
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-005',
      title: 'Guarded tool registered but not approved',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.supply],
      help: 'Registering a tool again withdraws its approval. An unapproved tool is new or changed since a person last reviewed its definition; review it with toolChanges() before approving.',
    },
    (project, report) => {
      for (const tool of project.agentGuard.tools)
        if (tool.registered && !tool.approved)
          report({
            message: `Tool ${tool.name} is registered but not approved${tool.fingerprint ? ` (fingerprint ${tool.fingerprint.slice(0, 19)}…)` : ''}: it is new or changed since review.`,
            location: tool.location,
            subject: `tool:${tool.name}:${tool.fingerprint ?? ''}`,
            fix: `Review guard.toolChanges('${tool.name}') and approve the fingerprint, or unregister it.`,
          });
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-006',
      title: 'Task grant broader than its tool warrants',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.tools, ASI.identity],
      help: 'A `*` grant covers every resource of a tool, including ones nobody described. It is risky on tools that send data out or reach sensitive bindings. A grant to an unregistered tool cannot be reviewed.',
    },
    (project, report) => {
      const evidence = project.agentGuard;
      const tools = indexOf(evidence).tools;
      for (const task of evidence.tasks) {
        if (!isLive(task, evidence)) continue;
        for (const grant of task.grants) {
          const tool = tools.get(grant.tool);
          if (!tool || !tool.registered) {
            report({
              message: `Task ${task.id} is granted ${grant.tool}, which is not registered, so its labels cannot be reviewed.`,
              location: task.location,
              subject: `unregistered:${task.id}:${grant.tool}`,
              severity: 'low',
              fix: `Register ${grant.tool} with its labels, or remove the grant.`,
            });
            continue;
          }
          if (!grant.resources.includes('*')) continue;
          const sensitive = (indexOf(evidence).bindingsByTool.get(grant.tool) ?? []).some(
            binding => binding.sensitivity === 'confidential' || binding.sensitivity === 'restricted',
          );
          if (tool.sendsExternal === true || sensitive)
            report({
              message: `Task ${task.id} holds ${grant.tool} on every resource ("*"), and the tool ${tool.sendsExternal === true ? 'sends data out' : 'reaches confidential or restricted bindings'}.`,
              location: task.location,
              subject: `wildcard:${task.id}:${grant.tool}`,
              fix: `List the exact resources ${task.id} needs for ${grant.tool}.`,
            });
        }
      }
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-007',
      title: 'Task budget above the team ceiling',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.cascade],
      help: 'Budgets bound what a steered task can do. Ceilings come from agent_guard in .agc.yaml (defaults: 24-hour deadline, 1,000 calls, no cost ceiling).',
    },
    (project, report, context) => {
      const evidence = project.agentGuard;
      const limits = context.config.agentGuard;
      for (const task of evidence.tasks) {
        if (!isLive(task, evidence)) continue;
        const over: string[] = [];
        if (evidence.observedAt !== null && task.budget.deadline - evidence.observedAt > limits.maxDeadlineHours * HOUR)
          over.push(
            `deadline ${Math.round((task.budget.deadline - evidence.observedAt) / HOUR)} h away (ceiling ${limits.maxDeadlineHours} h)`,
          );
        if (task.budget.maxCalls > limits.maxCalls)
          over.push(`maxCalls ${task.budget.maxCalls} (ceiling ${limits.maxCalls})`);
        if (limits.maxCost !== null && task.budget.maxCost > limits.maxCost)
          over.push(`maxCost ${task.budget.maxCost} (ceiling ${limits.maxCost})`);
        if (over.length)
          report({
            message: `Task ${task.id} has a budget above the ceiling: ${over.join(', ')}.`,
            location: task.location,
            subject: `budget:${task.id}`,
            fix: 'Lower the budget, or raise the ceiling in agent_guard in .agc.yaml with a reason.',
          });
      }
    },
    'agent-guard',
  ),
  rule(
    {
      id: 'AGC-AGX-008',
      title: 'Outbound tool labels leave a gap',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.tools],
      help: 'Agent Guard blocks sensitive data from leaving only through calls marked external, and asks for approval after untrusted content only when untrustedContext says so. An undeclared sendsExternal, or an outbound tool left on allow while other tools read untrusted content, leaves that check open.',
    },
    (project, report) => {
      const evidence = project.agentGuard;
      const readers = evidence.tools.filter(tool => tool.registered && tool.readsUntrusted === true);
      for (const tool of evidence.tools) {
        if (!tool.registered) continue;
        if (tool.sendsExternal === null)
          report({
            message: `Tool ${tool.name} does not declare sendsExternal, so nobody can tell whether it sends data out.`,
            location: tool.location,
            subject: `undeclared:${tool.name}`,
            severity: 'low',
            fix: `Declare sendsExternal: true or false on ${tool.name}.`,
          });
        else if (tool.sendsExternal === true && readers.length && effectiveMode(tool, evidence) === 'allow')
          report({
            message: `Tool ${tool.name} sends data out and stays on untrustedContext 'allow' while ${readers.map(item => item.name).join(', ')} read untrusted content.`,
            location: tool.location,
            subject: `allow-after-untrusted:${tool.name}`,
            fix: `Set untrustedContext: 'require_approval' on ${tool.name}.`,
          });
      }
    },
    'agent-guard',
  ),
];
