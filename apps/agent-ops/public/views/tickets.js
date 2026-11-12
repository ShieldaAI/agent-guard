// Tickets: choose a ticket and prepare a status change for review.
import { button, empty, field, formField, lockable, node, tag } from '../dom.js';
import { requestableStatuses } from '../state.js';
import { statusLabel } from '../text.js';
import { pagination } from './shared.js';

export function ticketsView(ctx) {
  const { state, actions } = ctx,
    operator = ctx.allowed('operator'),
    requester = ctx.allowed('requester');
  if (!state.tickets.length)
    return node(
      'section',
      { class: 'panel' },
      empty(
        'No tickets enrolled yet',
        operator
          ? 'Import your company ticket records with the onboarding commands in Setup, then refresh. Importing records does not approve a change.'
          : 'Ask your deployment owner to import ticket records for this tenant. They appear here after you refresh.',
        operator ? button('Open setup guide', () => actions.navigate('setup')) : null,
      ),
    );
  const ticket = state.tickets.find(item => item.id === state.selectedTicketId);
  const options = requestableStatuses(state.allowedStatuses, ticket);
  // Nothing is preselected: the requester chooses the new status on purpose.
  const status = lockable(
    node(
      'select',
      {
        id: 'target-status',
        required: true,
        onchange: event => actions.setTargetStatus(event.target.value),
      },
      node('option', { value: '' }, 'Choose a status'),
      options.map(value => node('option', { value }, statusLabel(value))),
    ),
    !requester,
  );
  status.value = options.includes(state.targetStatus) ? state.targetStatus : '';
  return node(
    'div',
    { class: 'split' },
    node(
      'section',
      { class: 'panel', 'aria-label': 'Available tickets' },
      node('div', { class: 'panel-head' }, node('h2', {}, 'Available tickets')),
      node(
        'ul',
        { class: 'request-list', id: 'ticket-rows', 'data-keep-scroll': true },
        state.tickets.map(item =>
          node(
            'li',
            {},
            node(
              'button',
              {
                type: 'button',
                id: `ticket-${item.id}`,
                class: 'request-item',
                'aria-pressed': String(ticket?.id === item.id),
                onclick: () => actions.selectTicket(item.id),
              },
              node('strong', {}, item.title),
              node('p', {}, `Ticket ${item.id}`),
              node('div', { class: 'ticket-summary' }, tag(statusLabel(item.status)), `Version ${item.version}`),
            ),
          ),
        ),
      ),
      pagination(ctx, 'tickets'),
    ),
    node(
      'section',
      { class: 'panel', 'aria-labelledby': 'prepare-heading' },
      node('div', { class: 'panel-head' }, node('h2', { id: 'prepare-heading', tabindex: '-1' }, 'Prepare a change')),
      ticket
        ? node(
            'div',
            { class: 'panel-body' },
            node(
              'dl',
              { class: 'fields' },
              field('Ticket', `${ticket.id} · ${ticket.title}`, { wide: true }),
              field('Current status', statusLabel(ticket.status)),
              field('Current version', ticket.version),
            ),
            node(
              'p',
              { class: 'review-note' },
              'Preparing changes nothing yet. A reviewer sees exactly this change and approves or denies it.',
            ),
            requester
              ? node(
                  'form',
                  { class: 'form-stack', onsubmit: actions.prepare },
                  formField('New status', 'target-status', status),
                  lockable(
                    node('button', { class: 'button', type: 'submit', id: 'prepare-review' }, 'Prepare for review'),
                    !state.targetStatus || !options.includes(state.targetStatus),
                  ),
                )
              : node('p', { class: 'subtle' }, 'Only requesters can prepare ticket changes.'),
          )
        : empty('Select a ticket', 'Choose a ticket from the list to prepare a status change.'),
    ),
  );
}
