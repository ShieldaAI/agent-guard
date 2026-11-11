// Wording for the discovery views. Nothing here turns a missing, partial or hidden answer
// into a number: unknown stays unknown, and a hidden view never shows a count.

const ACTIVITY_REASONS = Object.freeze({
  read_unavailable: 'the count could not be read',
  read_timeout: 'the count ran out of time',
  limit_exceeded: 'the count exceeded a read limit',
  publication_changed: 'a new snapshot was published during the read',
  not_reported: 'this service did not report a count',
});
const count = (value, minimum, noun) =>
  Number.isSafeInteger(value) && value >= 0
    ? `${value}${minimum === true ? '+' : ''} ${noun}${value === 1 && minimum !== true ? '' : 's'}`
    : null;

/** True for the fixed answer a team-scoped reader gets: nothing is listed and nothing counted. */
export const discoveryHidden = data => data?.status === 'not_visible';

/** One line for a source's undeclared activity, as `get_inventory_health` reports it. */
export function undeclaredActivityLabel(activity) {
  const value = activity && typeof activity === 'object' ? activity : {};
  if (value.status === 'not_visible') return { tone: 'neutral', text: 'Shown to all-teams readers only' };
  const tasks = count(value.tasks, value.tasksIsMinimum, 'task');
  const callers = count(value.principals, value.principalsIsMinimum, 'caller');
  if (!['complete', 'partial'].includes(value.status) || tasks === null || callers === null)
    return {
      tone: 'amber',
      text: `Unknown: ${ACTIVITY_REASONS[value.reason] ?? 'no count was reported'}`,
    };
  const none = value.tasks === 0 && value.principals === 0 && value.status === 'complete';
  return {
    tone: none ? 'green' : 'amber',
    text: none
      ? 'No task or caller without a declared agent'
      : `${tasks} and ${callers} with no declared agent${value.manifest === 'not_collected' ? ' (this source has no manifest)' : ''}`,
  };
}

const ACCOUNT_REASONS = Object.freeze({
  stale: 'The last AWS collection is older than the enrolled age limit.',
  collection_invalid: 'The AWS collection record is incomplete or malformed.',
  changed: 'The AWS collection changed while it was read, or its members do not match it.',
  limit_exceeded: 'The account holds more identities than one read may judge.',
  claims_limit_exceeded: 'More identities are declared than one read may compare.',
});
/** Why an account's identities are not listed. Never empty for an unknown account. */
export const accountReasonLabel = account =>
  account?.status === 'complete'
    ? 'Collected'
    : (ACCOUNT_REASONS[account?.reason] ?? 'The AWS collection could not be judged.');

/** The headline for `list_unclaimed_identities`: unknown is never shown as "none". */
export function unclaimedSummary(data) {
  const value = data && typeof data === 'object' ? data : {};
  if (value.status === 'complete' && Number.isSafeInteger(value.total))
    return {
      tone: value.total === 0 ? 'green' : 'amber',
      text:
        value.total === 0
          ? 'Every collected IAM role and user is named by a declared agent'
          : `${count(value.total, false, 'candidate')} to review`,
    };
  if (value.status === 'partial' && Number.isSafeInteger(value.total))
    return {
      tone: 'amber',
      text: `${count(value.total, false, 'candidate')} in the accounts that could be judged; the rest are unknown`,
    };
  return {
    tone: 'amber',
    text:
      value.reason === 'cloud_not_collected'
        ? 'Unknown: no AWS account is collected for your tenants'
        : 'Unknown: the AWS collection is stale or could not be judged',
  };
}

/** How one undeclared task relates to what is declared. */
export const taskLineageLabel = task =>
  task?.parentDeclared === true
    ? 'Sub-task of a declared agent (no binding of its own)'
    : task?.delegated === true || task?.derived === true
      ? 'Sub-task of an undeclared task'
      : 'No declared parent';
