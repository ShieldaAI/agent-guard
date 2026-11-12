// Pieces used by more than one view.
import { button, node, notice } from '../dom.js';
import { quantity } from '../text.js';

export function pagination(ctx, kind) {
  const { state, actions } = ctx,
    page = state[`${kind}Page`];
  if (!page) return null;
  const rows = state[kind],
    start = rows.length ? page.offset + 1 : 0;
  return node(
    'div',
    { class: 'pagination' },
    node('p', {}, `${start}–${page.offset + rows.length} of ${page.total} ${kind}`),
    page.total > page.limit && [
      node(
        'div',
        { class: 'actions' },
        button(`Previous ${kind}`, () => actions.loadPage(kind, Math.max(0, page.offset - page.limit)), {
          disabled: page.offset === 0,
          id: `previous-${kind}`,
        }),
        button(`Next ${kind}`, () => actions.loadPage(kind, page.nextOffset), {
          disabled: page.nextOffset === null,
          id: `next-${kind}`,
        }),
      ),
      node('p', { class: 'subtle' }, 'New activity can move rows between pages. Refresh starts from the first page.'),
    ],
  );
}

function historyCapacityNote(capacity) {
  const ratio = capacity.total / capacity.limit;
  return node(
    'div',
    {},
    node(
      'p',
      { class: 'review-note' },
      `Deployment-wide history: ${quantity(capacity.committed)} committed + ${quantity(capacity.reserved)} reserved = ${quantity(capacity.total)} segments. Pending compaction reserves its slot before creating history.`,
    ),
    node(
      'p',
      { class: 'subtle' },
      'This fixed recovery limit includes every tenant. The configure-limits command cannot raise it.',
    ),
    ratio >= 0.95
      ? notice(
          `History recovery capacity is ${ratio >= 1 ? 'exhausted' : 'nearly exhausted'}. Pause new compaction. The deployment owner must arrange a separately reviewed compatible recovery adapter or migration before more history can be kept. Preserve all records, history, witnesses and keys.`,
          'error',
        )
      : ratio >= 0.8
        ? notice(
            'History has reached 80% of the fixed recovery limit. Arrange a capacity review with the deployment owner before it fills.',
            'warning',
          )
        : null,
  );
}

/** Deployment-wide usage against limits. Every value comes from one validated service response. */
export function capacityTable({ usage, limits, statistics, keyring, historyCapacity }) {
  const rows = [
    ['Tickets', quantity(usage.tickets), quantity(limits.maxTickets)],
    ['Requests', quantity(usage.requests), quantity(limits.maxRequests)],
    ['Confirmation records', quantity(usage.receipts), quantity(limits.maxRequests)],
    ['Ticket data', quantity(usage.backendBytes, true), quantity(limits.maxBackendBytes, true)],
    ['Executor ledger', quantity(statistics.ledgerBytes, true), quantity(limits.maxLedgerBytes, true)],
    ['Retained keys', quantity(keyring?.keyCount), quantity(keyring?.maxKeys ?? limits.maxRetainedKeys)],
    [
      'History segments (committed + reserved)',
      quantity(historyCapacity.total),
      `${quantity(historyCapacity.limit)} · fixed`,
    ],
  ];
  return node(
    'div',
    {},
    node(
      'table',
      { class: 'capacity-table' },
      node('caption', {}, 'Deployment-wide usage and capacity limits'),
      node(
        'thead',
        {},
        node(
          'tr',
          {},
          ['Resource', 'Current', 'Limit'].map(label => node('th', { scope: 'col' }, label)),
        ),
      ),
      node(
        'tbody',
        {},
        rows.map(([label, current, limit]) =>
          node('tr', {}, node('th', { scope: 'row' }, label), node('td', {}, current), node('td', {}, limit)),
        ),
      ),
    ),
    historyCapacityNote(historyCapacity),
  );
}
