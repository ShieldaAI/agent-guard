// Workspace state and the pure rules that change it. No DOM, no network: unit-tested with node --test.

export const VIEWS = Object.freeze(['requests', 'tickets', 'maintenance', 'setup']);

/** Everything that belongs to one signed-in workspace. Cleared when the session ends. */
export function emptyWorkspace() {
  return {
    requests: [],
    requestsPage: null,
    requestsEtag: null,
    // Rows the service reported while the list was on screen, held until the person asks for them.
    incoming: null,
    // Rows on screen that the service no longer lists.
    goneIds: [],
    tickets: [],
    ticketsPage: null,
    allowedStatuses: [],
    maintenance: null,
    setup: null,
    operational: null,
    activity: null,
    selectedRequestId: '',
    // The selected request disappeared after a refresh; nothing else is selected for the person.
    selectionGone: false,
    selectedTicketId: '',
    targetStatus: '',
    filter: 'all',
    archiveTaskId: '',
    preview: null,
    closeOut: null,
    // The second step of a decision: { kind: 'approve' | 'deny', requestId }.
    decision: null,
    denyReason: '',
    ready: false,
    loading: false,
    error: '',
    notice: '',
  };
}

/** The state a request is shown in: a pending request past its deadline reads as expired. */
export const shownState = (request, now) =>
  request.state === 'pending' && request.expiresAt <= now ? 'expired' : request.state;

export function visibleRequests(requests, filter, now) {
  if (filter === 'review') return requests.filter(request => shownState(request, now) === 'pending');
  if (filter === 'unconfirmed') return requests.filter(request => request.state === 'unconfirmed');
  return requests;
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * A background poll never moves rows. Requests already on screen are updated where they are;
 * new ones are held (`incoming`) for the "new requests" indicator; ones the service no longer
 * lists are marked gone so they cannot be acted on.
 */
export function mergePoll(current, goneIds, rows) {
  const served = new Map(rows.map(row => [row.id, row])),
    known = new Set(current.map(row => row.id));
  const changedIds = [];
  const requests = current.map(row => {
    const next = served.get(row.id);
    if (!next || same(next, row)) return row;
    changedIds.push(row.id);
    return next;
  });
  const gone = current.filter(row => !served.has(row.id)).map(row => row.id);
  const added = rows.filter(row => !known.has(row.id)).length;
  return {
    requests,
    changedIds,
    goneIds: gone,
    newlyGone: gone.filter(id => !goneIds.includes(id)),
    added,
    incoming: added || gone.length ? rows : null,
  };
}

/**
 * After a full reload the selection is kept only if that same request is still listed.
 * Another request is never selected in its place.
 */
export function selectionAfterReload(selectedRequestId, rows) {
  if (!selectedRequestId) return { selectedRequestId: '', selectionGone: false };
  return rows.some(row => row.id === selectedRequestId)
    ? { selectedRequestId, selectionGone: false }
    : { selectedRequestId: '', selectionGone: true };
}

/** Whether Approve may be offered. Self-approval is hidden when the service forbids it. */
export function approval(session, request, now) {
  const operator = session?.operator;
  if (!operator || request.state !== 'pending' || request.expiresAt <= now) return { decide: false, approve: false };
  const reviewer = operator.roles.includes('reviewer'),
    own = request.requesterId === operator.id;
  return {
    decide: reviewer,
    approve: reviewer && !(own && session.policy.forbidSelfApproval),
    selfApprovalForbidden: reviewer && own && session.policy.forbidSelfApproval,
    withdraw: own && operator.roles.includes('requester'),
  };
}

/** Statuses a requester can ask for: what the service allows, minus the one the ticket has. */
export const requestableStatuses = (allowedStatuses, ticket) =>
  ticket ? allowedStatuses.filter(status => status !== ticket.status) : [];

const POLL_MS = 15_000;
const POLL_MAX_MS = 120_000;
/**
 * Time until the next list poll: every 15 seconds while the tab is visible, doubling after each
 * failed or rate-limited poll up to two minutes. A hidden tab does not poll (null).
 */
export function pollDelay({ hidden, failures }) {
  if (hidden) return null;
  return Math.min(POLL_MAX_MS, POLL_MS * 2 ** Math.min(failures, 10));
}

const FRAGMENT = /^#(requests|tickets|maintenance|setup)(?:\/([a-zA-Z0-9-]{1,80}))?$/;
/** `#requests/<id>` names a request; `#tickets`, `#maintenance` and `#setup` name a view. */
export function parseFragment(hash) {
  const match = FRAGMENT.exec(hash ?? '');
  if (!match) return null;
  return { view: match[1], requestId: match[1] === 'requests' ? (match[2] ?? '') : '' };
}
export function fragmentFor(view, selectedRequestId) {
  return view === 'requests' && selectedRequestId ? `#requests/${selectedRequestId}` : `#${view}`;
}
