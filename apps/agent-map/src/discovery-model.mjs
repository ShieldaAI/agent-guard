// Wording for the discovery views. Nothing here turns a missing, partial or hidden answer
// into a number: unknown stays unknown, and a hidden view never shows a count.
import { LABELS, hasLabel } from './labels.mjs';

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
      text: `Unknown: ${hasLabel('activityReason', value.reason) ? LABELS.activityReason[value.reason] : 'no count was reported'}`,
    };
  const none = value.tasks === 0 && value.principals === 0 && value.status === 'complete';
  return {
    tone: none ? 'green' : 'amber',
    text: none
      ? 'No task or caller without a declared agent'
      : `${tasks} and ${callers} with no declared agent${value.manifest === 'not_collected' ? ' (this source has no manifest)' : ''}`,
  };
}

/** A collected account whose collection the service marks stale: its numbers may be out of date. */
export const accountStale = account => account?.status === 'complete' && account?.stale === true;
/**
 * The collection state of one account: collected (and whether that collection is stale), or why
 * its identities are not listed. Never empty for an unknown account.
 */
export const accountReasonLabel = account =>
  account?.status === 'complete'
    ? accountStale(account)
      ? 'Collected, but stale'
      : 'Collected'
    : hasLabel('accountReason', account?.reason)
      ? LABELS.accountReason[account.reason]
      : 'The AWS collection could not be judged.';

/**
 * The headline for `list_unclaimed_identities`: unknown is never shown as "none", and a stale
 * collection never gets the all-clear wording or colour.
 */
export function unclaimedSummary(data) {
  const value = data && typeof data === 'object' ? data : {};
  const stale = Array.isArray(value.accounts) && value.accounts.some(accountStale);
  const aged = stale ? '; at least one collection is stale, so this may be out of date' : '';
  if (value.status === 'complete' && Number.isSafeInteger(value.total))
    return {
      tone: value.total === 0 && !stale ? 'green' : 'amber',
      text:
        value.total === 0
          ? stale
            ? `No unclaimed IAM role or user in the last collection${aged}`
            : 'Every collected IAM role and user is named by a declared agent'
          : `${count(value.total, false, 'candidate')} to review${aged}`,
    };
  if (value.status === 'partial' && Number.isSafeInteger(value.total))
    return {
      tone: 'amber',
      text: `${count(value.total, false, 'candidate')} in the accounts that could be judged; the rest are unknown${aged}`,
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
