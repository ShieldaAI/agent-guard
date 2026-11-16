import { ASI, rule } from './common.js';
import type { Rule } from './common.js';
import type { Location } from '../types.js';

/** Live findings have no line in the repository; they point at the scanner's config file. */
const AT: Location = { file: '.agc.yaml', line: 1 };

/** Mode C: rules over live evidence from a running Agent Map. They do nothing without it. */
export const AGENT_MAP_RULES: readonly Rule[] = [
  rule(
    {
      id: 'AGC-DRF-001',
      title: 'Guarded activity no declared agent accounts for',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.rogue, ASI.identity],
      help: 'Agent Map counts tasks and callers that ran through Agent Guard but belong to no agent in the host manifest: undeclared agents, or declarations that drifted from what runs.',
    },
    (_project, report, context) => {
      for (const source of context.live?.sources ?? []) {
        const activity = source.undeclared;
        if (!activity || !((activity.tasks ?? 0) > 0 || (activity.principals ?? 0) > 0)) continue;
        report({
          message: `Agent Map source ${source.sourceId} saw ${activity.tasks ?? '?'}${activity.minimum ? '+' : ''} task(s) and ${activity.principals ?? '?'} caller(s) that no declared agent accounts for.`,
          location: AT,
          subject: `undeclared:${source.id}`,
          fix: `Review them with list_undeclared_activity (sourceId "${source.id}") and declare the agents in the host manifest.`,
        });
      }
    },
    'agent-map',
  ),
  rule(
    {
      id: 'AGC-DRF-002',
      title: 'Cloud identities no agent claims',
      severity: 'medium',
      confidence: 'high',
      owasp: [ASI.identity],
      help: 'Cloud roles and users that look like agent identities but no declared agent claims. They may belong to agents that bypass the guard.',
    },
    (_project, report, context) => {
      const unclaimed = context.live?.unclaimed;
      if (!unclaimed || !unclaimed.total) return;
      report({
        message: `Agent Map lists ${unclaimed.total} unclaimed cloud identit${unclaimed.total === 1 ? 'y' : 'ies'}${unclaimed.names.length ? `, for example ${unclaimed.names.slice(0, 3).join(', ')}` : ''}.`,
        location: AT,
        subject: 'unclaimed',
        fix: 'Claim each identity with a credential reference or execution binding in the host manifest, or retire it.',
      });
    },
    'agent-map',
  ),
  rule(
    {
      id: 'AGC-DRF-003',
      title: 'Live agent exposed to the dangerous three',
      severity: 'high',
      confidence: 'high',
      owasp: [ASI.goal, ASI.tools],
      help: 'Agent Map computes, from what is deployed now, that one of the agent’s live tasks can read private data and untrusted content and send data out without approval.',
    },
    (_project, report, context) => {
      for (const agent of context.live?.exposedAgents ?? [])
        report({
          message: `Agent Map flags ${agent.name} (${agent.agentId}, source ${agent.sourceId}) as exposed to the dangerous three in production.`,
          location: AT,
          subject: `exposed:${agent.sourceId}:${agent.agentId}`,
          fix: 'Open get_agent_access for this agent to see which task and tools, then require approval on the sender.',
        });
    },
    'agent-map',
  ),
  rule(
    {
      id: 'AGC-DRF-004',
      title: 'Live inventory is stale',
      severity: 'low',
      confidence: 'high',
      owasp: [ASI.rogue],
      help: 'Live findings are only as current as the last snapshot. A stale source may hide new agents or changed grants.',
    },
    (_project, report, context) => {
      for (const source of context.live?.sources ?? [])
        if (source.stale)
          report({
            message: `Agent Map source ${source.sourceId} is stale; live conclusions about it may be out of date.`,
            location: AT,
            subject: `stale:${source.id}`,
            fix: 'Check the collector for this source.',
          });
    },
    'agent-map',
  ),
];
