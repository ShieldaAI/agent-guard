import { safeProperties } from '../../projection-fields.js';
import { MapQueryError, type JsonObject } from '../../types.js';
import { sourceSelection, type Operation } from '../context.js';
import { explain } from '../explain.js';
import { jsonList } from '../json.js';
import { policyCoverage, policyCoverageOf, selectedPolicy } from '../policy.js';
import { agentSummary, focus } from '../summaries.js';
import { connected, nodeIds, number, QueryWork, string, strings } from '../work.js';

/** Agents whose declared grants and host bindings map to one resource reference and cloud action. */
export const findAgentsWithAccess: Operation = {
  // A resource most of the fleet uses can match more pairs than one read evaluates: the
  // candidates are then listed with policy coverage unknown instead of failing.
  request: args => ({
    ...sourceSelection(args),
    policy: { resourceRef: args.resourceRef as string, action: args.action as string, optional: true },
  }),
  run({ scope, args, now, work, maxBytes }, view) {
    const candidates: JsonObject[] = [];
    const limit = (args.limit as number | undefined) ?? 50;
    let truncated = false;
    let truncatedReason: string | null = null;
    // The search counts its own work and evidence bytes (leaving room for the envelope), so
    // running out ends the list early instead of failing the answer.
    const search = new QueryWork(Math.max(1, work.remaining() - 25), Math.floor(maxBytes * 0.8));
    try {
      candidateSearch: for (const source of view.sources) {
        // A binding enters an agent's focus only via deployment -> agent <- task -> grant -> resource
        // <- binding. Walking that chain backwards from the matching bindings yields exactly the
        // agents that can have evidence; the full per-agent check below still runs unchanged.
        const projection = source.current;
        const matches = projection.nodes.filter(node => {
          search.step();
          return (
            node.label === 'GuardResourceBinding' &&
            strings(node, 'actions').includes(args.action as string) &&
            (string(node, 'resource_ref') === args.resourceRef ||
              connected(projection, new Set([node.id]), 'G_MAPS_TO', search).some(
                external => string(external, 'arn') === args.resourceRef,
              ))
          );
        });
        if (!matches.length) continue;
        const resources = nodeIds(connected(projection, nodeIds(matches), 'G_BINDS_SELECTOR', search));
        const grants = nodeIds(connected(projection, resources, 'G_TARGETS', search, true));
        const tasks = nodeIds(connected(projection, grants, 'G_HAS_GRANT', search, true));
        const deploymentIds = nodeIds(
          connected(projection, tasks, 'G_ASSIGNED_TO', search).filter(node => node.label === 'GuardDeployment'),
        );
        const reachable = nodeIds(connected(projection, deploymentIds, 'G_INSTANCE_OF', search));
        for (const agent of projection.nodes.filter(node => node.label === 'GuardAgent' && reachable.has(node.id))) {
          search.step();
          const selected = focus(source.current, agent, search),
            selectedProjection = { ...source.current, ...selected };
          const bindings = selected.nodes.filter(
            node => node.label === 'GuardResourceBinding' && strings(node, 'actions').includes(args.action as string),
          );
          const evidence: JsonObject[] = [];
          for (const binding of bindings) {
            search.step();
            const external = connected(selectedProjection, new Set([binding.id]), 'G_MAPS_TO', search)[0];
            if (
              string(binding, 'resource_ref') !== args.resourceRef &&
              (!external || string(external, 'arn') !== args.resourceRef)
            )
              continue;
            const toolName = string(binding, 'tool'),
              resource = string(binding, 'resource_ref');
            if (!toolName || !resource) continue;
            for (const task of selected.nodes.filter(node => node.label === 'GuardTask')) {
              search.step();
              if (
                !connected(selectedProjection, new Set([task.id]), 'G_HAS_GRANT', search).some(
                  grant =>
                    string(grant, 'tool') === toolName &&
                    strings(grant, 'resources').some(item => item === '*' || item === resource),
                )
              )
                continue;
              if (candidates.length >= limit) {
                truncated = true;
                break candidateSearch;
              }
              const deployment = connected(selectedProjection, new Set([task.id]), 'G_ASSIGNED_TO', search);
              const executions = connected(
                selectedProjection,
                nodeIds(deployment),
                'G_EXECUTES_FOR',
                search,
                true,
              ).filter(node => string(node, 'tool') === toolName);
              const policy = selectedPolicy(source.current, search, {
                task,
                executions,
                resources: [binding],
                action: args.action as string,
              });
              evidence.push(
                search.evidence({
                  taskId: string(task, 'task_id'),
                  tool: toolName,
                  resourceRef: resource,
                  action: args.action!,
                  scope: string(binding, 'scope'),
                  externalResource: external ? safeProperties(external) : null,
                  executionBindings: executions.map(node => ({
                    id: node.entityId,
                    ...safeProperties(node),
                    identities: connected(selectedProjection, new Set([node.id]), 'G_USES_IDENTITY', search).map(
                      safeProperties,
                    ),
                  })),
                  policyEvidence: jsonList(policy),
                  policyCoverage: policyCoverageOf(source.current, policy),
                  explanation: explain(source.current, scope, task, toolName, resource, now, search, {
                    action: args.action as string,
                    resourceBindingId: binding.entityId,
                  }),
                }),
              );
            }
          }
          if (evidence.length)
            candidates.push({
              agent: agentSummary(source, source.current, agent, search),
              evidence,
              assessment: 'unknown',
              limitations: [
                'Potential access candidates; no effective permission decision.',
                'Cloud containment is not exact object authorization.',
              ],
            });
        }
      }
    } catch (error) {
      // Out of work or evidence room: the candidates completed so far stand and the result
      // says it is incomplete. With none completed there is nothing honest to return.
      if (!(error instanceof MapQueryError) || error.code !== 'MAP_LIMIT_EXCEEDED' || !candidates.length) throw error;
      truncated = true;
      truncatedReason = 'work_limit';
    }
    return { data: { candidates, truncated, ...(truncatedReason ? { truncatedReason } : {}) } };
  },
};
