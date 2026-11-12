import { retainedChanges } from '../changes.js';
import { sourceSelection, type Operation } from '../context.js';
import { findSource } from '../summaries.js';
import { string } from '../work.js';

/** What changed between a source's current snapshot and its previous retained one. */
export const getChanges: Operation = {
  request: args => ({ ...sourceSelection(args), history: true }),
  run: ({ scope, args, work }, view) => ({
    data: retainedChanges(findSource(view, args.sourceId as string), args, scope, work),
  }),
};
