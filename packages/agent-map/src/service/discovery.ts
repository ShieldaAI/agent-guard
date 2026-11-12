import type { JsonObject, MapSource, MapUndeclaredActivity } from '../types.js';

// Discovery views list what belongs to no team, so only an all-teams reader sees them. A
// team-scoped reader gets this fixed answer without any read: no names, no counts, and the
// same words whether or not anything would be listed.
export const ALL_TEAMS_NOTE =
  'Shown only to readers with all-teams visibility, because what it lists belongs to no team. This note is the same whether or not anything would be listed.';
export const notVisible = (): JsonObject => ({
  visibility: 'all_teams_required',
  status: 'not_visible',
  note: ALL_TEAMS_NOTE,
});
export function undeclaredCounts(source: MapSource, activity: MapUndeclaredActivity): JsonObject {
  return {
    // Counting stops at 10,000: a minimum is partial, not complete.
    status: activity.tasksCapped || activity.principalsCapped ? 'partial' : 'complete',
    tasks: activity.tasks,
    tasksIsMinimum: activity.tasksCapped,
    principals: activity.principals,
    principalsIsMinimum: activity.principalsCapped,
    // Without a manifest no agent can be declared, so everything the executor saw counts.
    manifest: source.profile === 'core' ? 'not_collected' : 'collected',
  };
}
export const UNDECLARED_LIMITATIONS = [
  'Only activity that ran through an enrolled executor is seen. An agent that does not use the guard leaves nothing here.',
  'A task is undeclared when no manifest task binding assigns it to a deployment of a declared agent. parentDeclared marks a task whose direct parent is assigned: usually a sub-task that only lacks its own binding.',
  'A lead to follow up, not a finding. Listing grants or blocks nothing.',
];
export const UNCLAIMED_LIMITATIONS = [
  'Candidates to review, not findings: most IAM roles and users are not agents, and the map cannot tell which are.',
  'An identity is claimed when a declared execution binding names its exact ARN in a current snapshot you can read. Role assumption, instance profiles and federation are not followed.',
  'Only IAM roles and users of an enrolled AWS account are collected. An account that is missing, stale or inconsistent reads unknown, and its identities are not listed. Listing grants or blocks nothing.',
];
