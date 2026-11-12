// Requests: the list and the review of one request. The list and the detail are separate
// regions, so a background update to one never disturbs focus or scrolling in the other.
import { DENIAL_REASON_MAX } from '../contract.js';
import { badge, button, empty, field, formField, lockable, node, notice } from '../dom.js';
import { approval, shownState, visibleRequests } from '../state.js';
import { countLabel, countdown, date, effectSentence, requester, statusLabel, statusWord } from '../text.js';
import { pagination } from './shared.js';

const STATE_NOTES = {
  unconfirmed: [
    'The change may already have been applied. Do not prepare it again until an operator has checked.',
    'warning',
  ],
  changed: [
    'The ticket changed after this request was prepared, so nothing happened. Prepare a new request.',
    'warning',
  ],
  expired: ['The review time ran out, so nothing happened. Prepare a new request from the current ticket.', 'warning'],
  review_required: [
    'This request can no longer be approved. Prepare a new request from the current ticket.',
    'warning',
  ],
  failed: ['This request was not applied. See the recorded cause under Technical details.', 'error'],
  denied: ['A reviewer denied this request. Nothing was changed.', ''],
  withdrawn: ['The requester withdrew this request. Nothing was changed.', ''],
  completed: ['The confirmation record below shows the completed change.', 'success'],
};

export function requestList(ctx) {
  const { state, actions, now } = ctx;
  const shown = visibleRequests(state.requests, state.filter, now);
  const filter = lockable(
    node(
      'select',
      { id: 'request-filter', onchange: event => actions.setFilter(event.target.value) },
      node('option', { value: 'all' }, 'All requests'),
      node('option', { value: 'review' }, 'Needs review'),
      node('option', { value: 'unconfirmed' }, 'Unconfirmed outcomes'),
    ),
  );
  filter.value = state.filter;
  const added = state.incoming ? state.incoming.filter(row => !state.requests.some(item => item.id === row.id)) : [];
  const rows = shown.map(request => {
    const gone = state.goneIds.includes(request.id);
    return node(
      'li',
      {},
      node(
        'button',
        {
          id: `request-${request.id}`,
          type: 'button',
          class: 'request-item',
          'aria-pressed': String(state.selectedRequestId === request.id),
          onclick: () => actions.selectRequest(request.id),
        },
        node('strong', {}, request.title),
        node(
          'p',
          {},
          `Ticket ${request.ticketId}: ${statusWord(request.beforeStatus)} → ${statusWord(request.afterStatus)} · ${requester(request)}`,
        ),
        node(
          'div',
          { class: 'request-meta' },
          gone ? node('span', { class: 'badge' }, 'No longer available') : badge(shownState(request, now)),
          node('time', {}, date(request.createdAt)),
        ),
      ),
    );
  });
  const contents = rows.length
    ? node('ul', { class: 'request-list', id: 'request-rows', 'data-keep-scroll': true }, rows)
    : state.filter !== 'all'
      ? empty(
          'No matching requests',
          'This filter applies to the current page. Choose another filter or use the page controls.',
        )
      : ctx.allowed('requester')
        ? empty(
            'No requests yet',
            'Prepare a ticket change to create its review request.',
            button('View tickets', () => actions.navigate('tickets')),
          )
        : empty('No requests yet', 'Requests appear here when a requester or an agent proposes a ticket change.');
  return [
    node('div', { class: 'panel-head' }, node('h2', {}, 'Recent requests')),
    node('div', { class: 'list-filter' }, formField('Show on this page', 'request-filter', filter)),
    added.length > 0 &&
      node(
        'div',
        { class: 'new-requests' },
        button(`${countLabel(added.length, 'new request')} · Show`, actions.showIncoming, { id: 'show-new-requests' }),
      ),
    contents,
    pagination(ctx, 'requests'),
  ];
}

function decisionStep(ctx, request, sentence) {
  const { state, actions } = ctx;
  if (state.decision.kind === 'approve')
    return node(
      'section',
      { class: 'decision', 'aria-labelledby': 'decision-heading' },
      node('h3', { id: 'decision-heading', tabindex: '-1' }, 'Confirm approval'),
      node('p', { class: 'effect' }, sentence),
      node(
        'p',
        { class: 'review-note' },
        `Approving submits this change once, for ticket version ${request.resourceVersion}. If the ticket changes first, nothing happens.`,
      ),
      node(
        'div',
        { class: 'actions' },
        button('Cancel', actions.cancelDecision, { id: 'cancel-decision' }),
        button('Approve and submit once', () => actions.approve(request), { id: 'confirm-approve' }),
      ),
    );
  const reason = lockable(
    node('textarea', {
      id: 'deny-reason',
      rows: '3',
      maxlength: String(DENIAL_REASON_MAX),
      'aria-describedby': 'deny-reason-hint',
      oninput: event => actions.setDenyReason(event.target.value),
    }),
  );
  reason.value = state.denyReason;
  return node(
    'section',
    { class: 'decision', 'aria-labelledby': 'decision-heading' },
    node('h3', { id: 'decision-heading', tabindex: '-1' }, 'Deny this request'),
    node(
      'p',
      { class: 'review-note' },
      'Denying changes nothing on the ticket. The request cannot be approved afterwards.',
    ),
    formField(
      'Reason (optional)',
      'deny-reason',
      reason,
      `Up to ${DENIAL_REASON_MAX} characters. Kept with the request for people who sign in here.`,
    ),
    node(
      'div',
      { class: 'actions' },
      button('Cancel', actions.cancelDecision, { id: 'cancel-decision' }),
      button('Deny request', () => actions.deny(request), { id: 'confirm-deny' }),
    ),
  );
}

export function requestDetail(ctx) {
  const { state, actions, now, session } = ctx;
  if (state.selectionGone)
    return [
      empty(
        'This request is no longer available',
        'It is not in the current list any more. Choose another request to continue.',
      ),
    ];
  const request = state.requests.find(item => item.id === state.selectedRequestId);
  if (!request)
    return [empty('Select a request', 'Choose a request from the list to see what it changes and decide on it.')];
  if (state.goneIds.includes(request.id))
    return [
      empty(
        'This request is no longer available',
        'It is not in the current list any more. Choose another request to continue.',
      ),
    ];
  const shown = shownState(request, now),
    sentence = effectSentence(request, shown),
    may = approval(session, request, now),
    receipt = request.receipt,
    operator = ctx.allowed('operator');
  const [note, tone] = STATE_NOTES[shown] ?? [];
  const closing = state.closeOut?.requestId === request.id ? state.closeOut : null;
  const deciding = state.decision?.requestId === request.id && shown === 'pending' ? state.decision : null;

  const controls = [];
  if (shown === 'pending' && !deciding) {
    // Deny comes first in reading and tab order; neither button is styled as the default.
    if (may.decide)
      controls.push(button('Deny…', () => actions.beginDecision(request, 'deny'), { id: 'deny-request' }));
    if (may.approve)
      controls.push(button('Approve…', () => actions.beginDecision(request, 'approve'), { id: 'approve-request' }));
    if (may.withdraw)
      controls.push(button('Withdraw request', () => actions.withdraw(request), { id: 'withdraw-request' }));
  }
  if (shown === 'unconfirmed' && operator)
    controls.push(
      button('Check whether it was applied', () => actions.reconcile(request), { id: 'check-receipt' }),
      closing
        ? button('Close as not applied', () => actions.closeOut(request, closing.digest), { id: 'apply-close-out' })
        : button('No confirmation? Review close-out', () => actions.closeOut(request), { id: 'review-close-out' }),
    );
  let guidance = '';
  if (shown === 'unconfirmed')
    guidance = !operator
      ? 'An operator can check whether this change was applied. Give them the request reference shown above.'
      : closing
        ? closing.ticketChanged
          ? `The stored records hold no confirmation for this change, so it was not applied. Ticket ${closing.ticketId} has changed since this request was reviewed: it was ${statusWord(closing.reviewedStatus)} at version ${closing.reviewedVersion} and is now ${statusWord(closing.ticketStatus)} at version ${closing.ticketVersion}. Check that the ticket is as you expect, then close. Closing marks this request as not applied. It never submits the change.`
          : `The stored records hold no confirmation for this change and ticket ${closing.ticketId} is still ${statusWord(closing.ticketStatus)} at version ${closing.ticketVersion}, as reviewed. Closing marks this request as not applied. It never submits the change.`
        : 'Checking looks up the confirmation record of the original change. It never submits the change again. If no confirmation will ever arrive, review the close-out evidence.';
  else if (shown === 'pending')
    guidance = may.selfApprovalForbidden
      ? 'You created this request, so another reviewer must approve it. You can still deny or withdraw it.'
      : may.approve
        ? 'Approving submits exactly this change once. Check the ticket and its expected version first.'
        : may.withdraw
          ? 'A reviewer must approve or deny this change. You can withdraw it while it waits.'
          : 'A reviewer must approve or deny this change.';

  const cause = request.cause && field('Recorded cause', node('code', {}, request.cause));
  return [
    node(
      'div',
      { class: 'panel-head' },
      node(
        'div',
        {},
        node('h2', { id: 'review-heading', tabindex: '-1' }, request.title),
        node('p', {}, `Request ${request.id}`),
      ),
      badge(shown),
    ),
    node(
      'div',
      { class: 'panel-body' },
      node('p', { class: 'effect', id: 'effect-sentence' }, sentence),
      note && notice(note, tone),
      node(
        'dl',
        { class: 'fields' },
        field('Requested by', requester(request)),
        field('Requested', date(request.createdAt)),
        shown === 'pending' &&
          field(
            'Time left to review',
            node('span', { id: 'review-countdown', class: 'countdown' }, countdown(request.expiresAt, now)),
            { hint: `Until ${date(request.expiresAt)}. After that nothing can be approved.` },
          ),
        request.reviewerId && field(shown === 'denied' ? 'Denied by' : 'Reviewed by', request.reviewerId),
        request.denialReason && field('Reason for denial', request.denialReason, { wide: true }),
        field(
          'Ticket',
          `${request.ticketId} · ${statusLabel(request.beforeStatus)} → ${statusLabel(request.afterStatus)}`,
        ),
        field('Expected version', request.resourceVersion, {
          hint: 'The ticket version this approval is for. If the ticket changes first, nothing happens.',
        }),
        field('Tenant', request.tenantId, { hint: 'The company workspace this request belongs to.' }),
      ),
      request.archived &&
        notice('The working records of this request were archived. The request and its confirmation record stay here.'),
      guidance && node('p', { class: 'review-note', id: 'review-guidance' }, guidance),
      deciding
        ? decisionStep(ctx, request, sentence)
        : controls.length > 0 && node('div', { class: 'actions', id: 'decision-actions' }, controls),
      receipt &&
        node(
          'section',
          { class: 'receipt', 'aria-label': 'Confirmation record' },
          node('h3', {}, 'Confirmation record'),
          node(
            'dl',
            { class: 'fields' },
            field('Confirmed status', statusLabel(receipt.status)),
            field('Ticket version after the change', receipt.version),
            field('Recorded', date(receipt.recordedAt), { wide: true }),
          ),
        ),
      node(
        'details',
        {
          class: 'technical',
          id: 'technical-details',
          open: state.technicalOpen,
          ontoggle: event => actions.setTechnicalOpen(event.target.open),
        },
        node('summary', {}, 'Technical details'),
        node(
          'dl',
          { class: 'fields' },
          request.digest
            ? field(
                'Action fingerprint',
                [
                  node('code', { id: 'action-fingerprint' }, request.digest),
                  button('Copy fingerprint', () => actions.copy(request.digest, 'Action fingerprint'), {
                    id: 'copy-fingerprint',
                  }),
                ],
                {
                  wide: true,
                  hint: 'Identifies exactly this change. A request with a different fingerprint is a different change.',
                },
              )
            : field('Action fingerprint', 'None: the request was never fully prepared.', { wide: true }),
          field('Operation reference', node('code', {}, request.operationId), { wide: true }),
          cause,
        ),
      ),
    ),
  ];
}

export function requestsView(ctx) {
  return node(
    'div',
    { class: 'split' },
    node('section', { class: 'panel', 'aria-label': 'Request list', id: 'request-list-region' }, requestList(ctx)),
    node(
      'section',
      { class: 'panel', 'aria-label': 'Request review', id: 'request-detail-region' },
      requestDetail(ctx),
    ),
  );
}
