import { safeProperties } from '../../projection-fields.js';
import { sourceSelection, type Operation } from '../context.js';
import { detailFlags } from '../flags.js';
import { jsonList } from '../json.js';
import { directAccess, identityScope, targetVisibility } from '../outside-guard.js';
import { policyCoverage, policyCoverageOf, selectedPolicy } from '../policy.js';
import {
  agentSummary,
  deployments,
  findAgent,
  findSource,
  focus,
  grantSummary,
  receipt,
  taskSummary,
  type FocusedGraph,
} from '../summaries.js';
import { string } from '../work.js';

/** One agent's neighborhood: evidence lists, boundary flags, outside-guard access and a graph. */
export const getAgentAccess: Operation = {
  // Boundary evidence (ancestors, `*` bindings, identity scope) is read only here, where it is
  // shown. Past the pair limit the policy evidence reads unknown instead of failing the answer.
  request: args => ({
    ...sourceSelection(args),
    agentId: args.agentId as string,
    policy: { optional: true },
    boundary: true,
  }),
  run({ scope, args, work, maxBytes }, view) {
    const source = findSource(view, args.sourceId as string),
      projection = source.current;
    const agent = findAgent(projection, args.agentId as string);
    const focused = focus(projection, agent, work);
    // The response graph carries node properties too: withhold out-of-scope targets there.
    const visibleTarget = targetVisibility(projection, scope, work);
    // Allowlisted properties only, also for a host-provided store.
    const graph: FocusedGraph = {
      ...focused,
      nodes: focused.nodes.map(node => {
        const target = node.label === 'GuardDirectAccess' ? string(node, 'target_ref') : null;
        const allowed = safeProperties(node);
        if (target === null || visibleTarget(target)) return { ...node, properties: allowed };
        const { target_ref: _withheld, ...properties } = allowed;
        return { ...node, properties };
      }),
    };
    const policy = selectedPolicy(projection, work, { nodes: graph.nodes });
    return {
      graph,
      data: {
        agent: agentSummary(source, projection, agent, work),
        deployments: graph.nodes
          .filter(node => node.label === 'GuardDeployment')
          .map(node => ({
            id: node.entityId,
            deploymentId: string(node, 'deployment_id'),
            environment: string(node, 'environment'),
          })),
        tasks: graph.nodes.filter(node => node.label === 'GuardTask').map(taskSummary),
        grants: graph.nodes.filter(node => node.label === 'GuardGrant').map(grantSummary),
        connections: graph.nodes
          .filter(node => node.label === 'GuardMcpConnection')
          .map(node => ({ id: node.entityId, ...safeProperties(node) })),
        bindings: graph.nodes
          .filter(node => ['GuardExecutionBinding', 'GuardResourceBinding'].includes(node.label))
          .map(node => ({ id: node.entityId, kind: node.label, ...safeProperties(node) })),
        policyEvidence: jsonList(policy),
        policyCoverage: policyCoverageOf(projection, policy),
        outsideGuard: {
          directAccess: directAccess(projection, graph, scope, work),
          identityScope: identityScope(projection, graph),
        },
        boundaryFlags: [detailFlags(projection, agent, scope, work.remaining(), maxBytes)],
        receipt: receipt(source),
        assessment: 'unknown',
        graphStatus: 'included',
        limitations: [
          'Declared and observed evidence only; current executor admission is required.',
          'External object and prefix bindings retain their original scope.',
          'Only S3 identity policies and host declarations are checked. Bucket policies, SCPs and permission boundaries are not, so identity-scope buckets are candidates and a deny elsewhere can remove the access. none_declared is the host claim, not a check, and no status means safe.',
        ],
      },
    };
  },
};
