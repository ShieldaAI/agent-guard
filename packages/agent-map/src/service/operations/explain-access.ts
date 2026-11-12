import { fail } from '../../common.js';
import { sourceSelection, type Operation } from '../context.js';
import { explain } from '../explain.js';
import { findSource, receipt } from '../summaries.js';
import { matching, string } from '../work.js';

/** Why one task may or may not use one tool on one resource selector, as far as the snapshot says. */
export const explainAccess: Operation = {
  // The policy evidence is narrowed to this task, tool and selector.
  request: args => ({
    ...sourceSelection(args),
    policy: { taskId: args.taskId as string, tool: args.tool as string, resourceRef: args.resourceId as string },
  }),
  run({ scope, args, now, work }, view) {
    const source = findSource(view, args.sourceId as string);
    const task = source.current.nodes.find(
      node => node.label === 'GuardTask' && matching(node, args.taskId as string, 'task_id'),
    );
    if (!task) fail('MAP_NOT_FOUND');
    return {
      data: {
        ...explain(source.current, scope, task, args.tool as string, args.resourceId as string, now, work),
        receipt: receipt(source),
      },
    };
  },
};
