import { sourceSelection, type Operation } from '../context.js';
import { inventorySections } from '../inventory.js';
import { jsonList } from '../json.js';
import { page } from '../ordering.js';
import { policyCoverage, policyCoverageOf, selectedPolicy } from '../policy.js';
import type { InventorySection } from '../schemas.js';
import { agentSummary, collection, findAgent, findSource, focus, receipt } from '../summaries.js';
import { string } from '../work.js';

/** One paged section of one agent's inventory, with the size of every section. */
export const getAgentInventory: Operation = {
  // One agent can hold more task/binding/action pairs than one read evaluates: its policy
  // evidence then reads unknown (`limit_exceeded`) and the rest of the answer stands.
  request: args => ({ ...sourceSelection(args), agentId: args.agentId as string, policy: { optional: true } }),
  run({ args, work }, view) {
    const source = findSource(view, args.sourceId as string),
      agent = findAgent(source.current, args.agentId as string);
    const selected = { ...source.current, ...focus(source.current, agent, work) };
    const groups = inventorySections(source, selected, agent, work),
      section = (args.section ?? 'overview') as InventorySection;
    const policy = selectedPolicy(source.current, work, { nodes: selected.nodes });
    groups.policies = [...jsonList(policy)];
    // Policy evidence the store did not load has no size. Its count and the total of its
    // section are null (as for any total that is not known), never zero: an empty list here
    // is "not evaluated", not "none".
    const policyNotLoaded = source.current.policyEvidenceNotLoaded === true;
    return {
      data: {
        agent: agentSummary(source, selected, agent, work),
        section,
        ...page(groups[section], args),
        ...(policyNotLoaded && section === 'policies' ? { total: null } : {}),
        counts: Object.fromEntries(
          Object.entries(groups)
            .filter(([key]) => key !== 'overview')
            .map(([key, value]) => [key, policyNotLoaded && key === 'policies' ? null : value.length]),
        ),
        policyEvidence: section === 'policies' ? page(groups.policies, args).items! : [],
        policyCoverage: policyCoverageOf(source.current, policy),
        receipt: receipt(source),
        assessment: 'unknown',
        graphStatus: 'not_requested',
        collection,
        limitations: ['Read-only host observations and declared grants; current execution still requires admission.'],
      },
    };
  },
};
