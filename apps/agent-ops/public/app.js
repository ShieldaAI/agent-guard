// Entry point: session, actions and which region of the page is redrawn when.
// The page is drawn in regions (top bar, navigation, heading, notices, view, and inside the
// requests view the list and the review). An update redraws only the regions it changes, so
// focus, scroll position and half-typed text elsewhere are left alone.
import { ApiError, SessionEnded, createApi, failure } from './api.js';
import { DEFINITIVE_REFUSALS, HARMLESS_REFUSALS } from './contract.js';
import {
  announce,
  button,
  clearAnnouncements,
  copyText,
  empty,
  focusOn,
  isBusy,
  mount,
  node,
  notice,
  setBusy,
} from './dom.js';
import {
  VIEWS,
  emptyWorkspace,
  fragmentFor,
  mergePoll,
  parseFragment,
  pollDelay,
  selectionAfterReload,
  shownState,
} from './state.js';
import { countLabel, countdown, date } from './text.js';
import * as check from './validate.js';
import { loginView } from './views/login.js';
import { maintenanceView } from './views/maintenance.js';
import { requestDetail, requestList, requestsView } from './views/requests.js';
import { setupView } from './views/setup.js';
import { ticketsView } from './views/tickets.js';

const app = document.getElementById('app');
const RETURN_KEY = 'agent-ops:return';
const state = { session: null, phase: 'checking', view: 'requests', technicalOpen: false, ...emptyWorkspace() };
// Changes whenever the signed-in session ends; answers to older requests are dropped.
let epoch = 0;
let refreshRun = 0;
let expiryTimer;
let pollTimer;
let pollFailures = 0;
let announcedIncoming = 0;
let lastExpiry = '';

const allowed = role => state.session?.operator?.roles.includes(role) === true;
const tenant = () => state.session.operator.tenantId;
const selectedRequest = () => state.requests.find(request => request.id === state.selectedRequestId);
const context = () => ({ state, session: state.session, now: Date.now(), allowed, actions });

const api = createApi({
  epoch: () => epoch,
  csrfToken: () => state.session?.csrfToken,
  signedIn: () => state.session?.authenticated === true,
  onUnauthorized: message => endSession(message),
});

// ---- Regions ----------------------------------------------------------------------------

const TITLES = {
  requests: ['Requests', 'Review proposed ticket changes and follow them until they are confirmed.'],
  tickets: ['Tickets', 'Prepare a ticket change for a reviewer.'],
  maintenance: ['Maintenance', 'Check service status and capacity, and archive finished requests.'],
  setup: ['Setup', 'See what this installation is connected to and how to bring in company data.'],
};

function topbar() {
  const operator = state.session?.authenticated ? state.session.operator : null;
  return [
    node(
      'div',
      { class: 'brand' },
      node('span', { class: 'brand-mark', 'aria-hidden': 'true' }, 'G'),
      node(
        'div',
        {},
        node('span', { class: 'brand-name' }, 'AGENT GUARD'),
        node('span', { class: 'brand-product' }, 'Operations'),
      ),
    ),
    operator &&
      node(
        'div',
        { class: 'identity' },
        node(
          'div',
          { class: 'identity-copy' },
          node('strong', { class: 'identity-name' }, operator.name || operator.id),
          node(
            'span',
            { class: 'identity-roles' },
            operator.roles.map(role => role[0].toUpperCase() + role.slice(1)).join(' · '),
          ),
        ),
        button('Sign out', actions.signOut, { id: 'sign-out' }),
      ),
  ];
}

function navigation() {
  const tabs = [
    ['requests', 'Requests', state.requestsPage?.total],
    ['tickets', 'Tickets', state.ticketsPage?.total],
  ];
  if (allowed('operator')) tabs.push(['maintenance', 'Maintenance'], ['setup', 'Setup']);
  return [
    node('div', { class: 'scope' }, 'Tenant', node('strong', {}, tenant())),
    node(
      'nav',
      { class: 'nav', 'aria-label': 'Views' },
      tabs.map(([view, label, total]) =>
        node(
          'button',
          {
            id: `nav-${view}`,
            type: 'button',
            'aria-current': state.view === view ? 'page' : null,
            onclick: () => actions.navigate(view),
          },
          label,
          total !== undefined && state.ready && node('span', { class: 'nav-count' }, total),
        ),
      ),
    ),
  ];
}

function heading() {
  const [title, subtitle] = TITLES[state.view];
  return [
    node(
      'div',
      {},
      node('span', { class: 'eyebrow' }, 'Review workspace'),
      node('h1', { id: 'page-heading', tabindex: '-1' }, title),
      node('p', {}, subtitle),
    ),
    button('Refresh', actions.refresh, { id: 'refresh-workspace' }),
  ];
}

function notices() {
  return [
    state.error && notice(state.error, 'error', 'error-notice'),
    state.notice && notice(state.notice, '', 'notice'),
  ];
}

function view() {
  if (!state.ready)
    return state.loading
      ? node('div', { class: 'panel loading' }, 'Loading the workspace…')
      : node(
          'section',
          { class: 'panel' },
          empty(
            'Refresh to load the current state',
            'What was on screen may be out of date. Refresh before preparing or deciding anything.',
          ),
        );
  const draw = { requests: requestsView, tickets: ticketsView, maintenance: maintenanceView, setup: setupView };
  return draw[state.view](context());
}

function footer() {
  return `Signed in until ${date(state.session.expiresAt)}. The service checks your role on every action.`;
}

const REGIONS = {
  topbar: ['topbar', topbar],
  nav: ['sidebar', navigation],
  heading: ['heading-region', heading],
  notices: ['notice-region', notices],
  view: ['view-region', view],
  list: ['request-list-region', () => requestList(context())],
  detail: ['request-detail-region', () => requestDetail(context())],
  footer: ['footer-region', footer],
};

/** Redraws the named regions. Focus that a redraw removed moves to the nearest heading. */
function paint(...names) {
  const focused = document.activeElement && document.activeElement !== document.body;
  for (const name of names) {
    const [id, draw] = REGIONS[name];
    mount(document.getElementById(id), draw());
  }
  lastExpiry = expirySnapshot(Date.now());
  if (focused && (!document.activeElement || document.activeElement === document.body))
    focusOn(state.view === 'requests' ? 'review-heading' : null, 'page-heading', 'login-heading');
}

/** Builds the page frame for the current phase: the sign-in page or the workspace. */
function shell() {
  if (!state.session?.authenticated) {
    app.replaceChildren(
      node('header', { class: 'topbar', id: 'topbar' }),
      loginView({ phase: state.phase, error: state.error, actions }),
    );
    paint('topbar');
    return;
  }
  app.replaceChildren(
    node('header', { class: 'topbar', id: 'topbar' }),
    node(
      'div',
      { class: 'shell' },
      node('aside', { class: 'sidebar', id: 'sidebar' }),
      node(
        'main',
        { id: 'main', class: 'workspace', tabindex: '-1' },
        node('div', { class: 'page-heading', id: 'heading-region' }),
        node('div', { id: 'notice-region' }),
        node('div', { id: 'view-region' }),
        node('p', { class: 'session-footnote', id: 'footer-region' }),
      ),
    ),
  );
  paint('topbar', 'nav', 'heading', 'notices', 'view', 'footer');
}

/** After an action: redraw what it may have changed, speak the outcome and place focus on it. */
function settle(focusId) {
  if (!state.session?.authenticated) shell();
  else {
    paint('nav', 'heading', 'notices', 'view', 'footer');
    syncFragment();
  }
  if (state.error) {
    announce(state.error, true);
    focusOn('error-notice');
  } else {
    if (state.notice) announce(state.notice);
    focusOn(focusId, 'notice');
  }
}

function expirySnapshot(now) {
  if (!state.ready) return '';
  if (state.view === 'requests')
    return JSON.stringify(
      state.requests
        .filter(request => request.state === 'pending')
        .map(request => [request.id, request.expiresAt <= now]),
    );
  if (state.view === 'maintenance' && state.preview)
    return JSON.stringify([state.preview.id, state.preview.expiresAt <= now]);
  return '';
}

// ---- Session ----------------------------------------------------------------------------

function resetWorkspace() {
  epoch++;
  refreshRun++;
  clearTimeout(expiryTimer);
  clearTimeout(pollTimer);
  api.abortAll();
  if (state.activity?.url) URL.revokeObjectURL(state.activity.url);
  Object.assign(state, emptyWorkspace());
  pollFailures = 0;
  announcedIncoming = 0;
  setBusy(false);
  clearAnnouncements();
}

/** The session really ended: clear what was shown and offer one click to sign in again. */
function endSession(message) {
  resetWorkspace();
  state.session = null;
  state.phase = 'ended';
  state.error = message;
  shell();
  announce(message, true);
  focusOn('sign-in');
}

function scheduleExpiry() {
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(
    () => endSession('Your session expired. Sign in again to continue.'),
    Math.min(state.session.expiresAt - Date.now(), 2_147_483_647),
  );
}

/** Opens the workspace for a signed-in session, at the request or view named in the address. */
async function enter() {
  let stored = null;
  try {
    stored = sessionStorage.getItem(RETURN_KEY);
    sessionStorage.removeItem(RETURN_KEY);
  } catch {
    /* Storage is optional: the workspace simply opens on the request list. */
  }
  if (!parseFragment(location.hash) && parseFragment(stored)) history.replaceState(null, '', stored);
  applyFragment(parseFragment(location.hash));
  scheduleExpiry();
  shell();
  await refresh();
  schedulePoll();
}

function applyFragment(target) {
  if (!target) return;
  state.view = ['maintenance', 'setup'].includes(target.view) && !allowed('operator') ? 'requests' : target.view;
  state.selectedRequestId = target.requestId;
  state.selectionGone = false;
}

function syncFragment() {
  const target = fragmentFor(state.view, state.selectedRequestId);
  if (location.hash !== target) history.replaceState(null, '', target);
}

async function start() {
  resetWorkspace();
  state.session = null;
  state.phase = 'checking';
  shell();
  const current = epoch;
  try {
    const value = check.sessionValue((await api.request('/api/session')) ?? null);
    if (current !== epoch) return;
    state.session = value;
    state.phase = 'ready';
    if (!value.authenticated) return shell();
    await enter();
    if (current === epoch) settle();
  } catch (error) {
    if (current !== epoch || error instanceof SessionEnded) return;
    state.phase = 'unavailable';
    state.error = error.message;
    shell();
    announce(error.message, true);
  }
}

async function signIn() {
  await run(async () => {
    if (!state.session || state.session.authenticated) {
      // This page holds no pre-login session yet (the last one ended). Get one first.
      const session = check.sessionValue(await api.request('/api/session'));
      state.session = session;
      state.phase = 'ready';
      if (session.authenticated) return void (await enter());
    }
    let result;
    try {
      result = await api.request('/auth/login', { method: 'POST', body: {} });
    } catch (error) {
      if (error?.code !== 'CSRF_INVALID') throw error;
      // The short-lived pre-login cookie expired while this page was open. Renew it and try once more.
      state.session = check.sessionValue(await api.request('/api/session'));
      if (state.session.authenticated) return void (await enter());
      result = await api.request('/auth/login', { method: 'POST', body: {} });
    }
    const destination = check.authorizationUrl(result, state.session);
    try {
      // Sign-in returns to the same request or view this page was showing.
      if (parseFragment(location.hash)) sessionStorage.setItem(RETURN_KEY, location.hash);
    } catch {
      /* Without storage, sign-in returns to the request list. */
    }
    window.location.assign(destination);
  });
}

async function signOut() {
  const retry = state.phase === 'logout-unconfirmed';
  let token = state.session?.csrfToken;
  resetWorkspace();
  state.session = null;
  state.phase = 'signing-out';
  history.replaceState(null, '', location.pathname);
  shell();
  try {
    if (retry) token = check.sessionValue(await api.request('/api/session')).csrfToken;
    await api.request('/auth/logout', { method: 'POST', body: {}, token });
    const value = check.sessionValue(await api.request('/api/session'));
    if (value.authenticated) throw new Error();
    state.session = value;
    state.phase = 'ready';
    state.error = '';
  } catch {
    state.session = null;
    state.phase = 'logout-unconfirmed';
    state.error = 'This page was cleared, but the service did not confirm the sign-out. Retry sign out.';
  }
  shell();
  if (state.error) announce(state.error, true);
  else announce('You are signed out.');
  focusOn('sign-in', 'retry-sign-out', 'login-heading');
}

/** On returning to the tab: keep everything on screen and only check that the session still stands. */
async function revalidate() {
  if (!state.session?.authenticated) return;
  const current = epoch;
  try {
    const value = check.sessionValue(await api.request('/api/session'));
    if (current !== epoch) return;
    const operator = state.session.operator;
    if (!value.authenticated || value.operator.id !== operator.id || value.operator.tenantId !== operator.tenantId)
      return endSession('Your session ended. Sign in again to continue.');
    state.session = value;
    scheduleExpiry();
    if (['maintenance', 'setup'].includes(state.view) && !allowed('operator')) {
      state.view = 'requests';
      paint('heading', 'view');
    }
    paint('topbar', 'nav', 'footer');
    pollFailures = 0;
    clearTimeout(pollTimer);
    void poll();
  } catch (error) {
    if (current === epoch && !(error instanceof SessionEnded)) schedulePoll();
  }
}

// ---- Loading and background updates -------------------------------------------------------

function clearLoaded() {
  const { selectedRequestId, filter } = state;
  if (state.activity?.url) URL.revokeObjectURL(state.activity.url);
  Object.assign(state, emptyWorkspace(), { selectedRequestId, filter });
}

/** Loads everything the signed-in person may see. What is on screen stays until the answer arrives. */
async function refresh() {
  if (!state.session?.authenticated) return;
  const current = epoch,
    run = ++refreshRun,
    stale = () => current !== epoch || run !== refreshRun;
  state.loading = true;
  state.error = '';
  state.preview = null;
  state.closeOut = null;
  state.decision = null;
  if (!state.ready) paint('view');
  document.getElementById('view-region')?.setAttribute('aria-busy', 'true');
  try {
    const operator = allowed('operator');
    const [requests, tickets, maintenance, setup, operational] = await Promise.all([
      api.conditional('/api/requests?offset=0&limit=500', null),
      api.request('/api/tickets?offset=0&limit=500'),
      operator ? api.request('/api/maintenance') : null,
      operator ? api.request('/api/setup') : null,
      operator ? api.request('/api/status') : null,
    ]);
    if (stale()) return;
    const requestPage = check.pageValue(requests.body, 'requests', 0, tenant()),
      ticketPage = check.pageValue(tickets, 'tickets', 0, tenant());
    const next = {
      requests: requestPage.rows,
      requestsPage: requestPage.page,
      requestsEtag: requests.etag,
      incoming: null,
      goneIds: [],
      tickets: ticketPage.rows,
      ticketsPage: ticketPage.page,
      allowedStatuses: ticketPage.allowedStatuses,
      maintenance: operator ? check.maintenanceValue(maintenance) : null,
      setup: operator ? check.setupValue(setup) : null,
      operational: operator ? check.operationalValue(operational, tenant()) : null,
      ...selectionAfterReload(state.selectedRequestId, requestPage.rows),
    };
    Object.assign(state, next);
    if (!state.tickets.some(ticket => ticket.id === state.selectedTicketId)) {
      state.selectedTicketId = state.tickets[0]?.id ?? '';
      state.targetStatus = '';
    }
    if (!state.maintenance?.archiveCandidates.some(item => item.taskId === state.archiveTaskId))
      state.archiveTaskId = '';
    announcedIncoming = 0;
    state.ready = true;
  } catch (error) {
    if (stale() || error instanceof SessionEnded) return;
    clearLoaded();
    state.error = error.message;
  } finally {
    if (!stale()) {
      state.loading = false;
      document.getElementById('view-region')?.removeAttribute('aria-busy');
    }
  }
}

function schedulePoll() {
  clearTimeout(pollTimer);
  if (!state.session?.authenticated) return;
  const delay = pollDelay({ hidden: document.visibilityState === 'hidden', failures: pollFailures });
  if (delay !== null) pollTimer = setTimeout(poll, delay);
}

/** Asks whether the request list changed. An unchanged list costs one small conditional request. */
async function poll() {
  const current = epoch,
    offset = state.requestsPage?.offset;
  const idle = () =>
    current === epoch && state.ready && !state.loading && !isBusy() && state.requestsPage?.offset === offset;
  try {
    if (!idle()) return;
    const result = await api.conditional(`/api/requests?offset=${offset}&limit=500`, state.requestsEtag);
    if (!idle()) return;
    pollFailures = 0;
    if (result.notModified) return;
    const page = check.pageValue(result.body, 'requests', offset, tenant());
    const merged = mergePoll(state.requests, state.goneIds, page.rows);
    state.requests = merged.requests;
    state.goneIds = merged.goneIds;
    state.incoming = merged.incoming;
    state.requestsEtag = result.etag;
    if (!merged.incoming) state.requestsPage = page.page;
    if (state.view === 'requests') {
      const selected = state.selectedRequestId;
      if (merged.changedIds.length || merged.added || merged.newlyGone.length) paint('list');
      if (merged.changedIds.includes(selected) || merged.newlyGone.includes(selected)) {
        paint('detail');
        announce('The request you are viewing changed.');
      }
    }
    if (merged.added && merged.added !== announcedIncoming) announce(`${countLabel(merged.added, 'new request')}.`);
    announcedIncoming = merged.added;
    paint('nav');
  } catch (error) {
    // A failed or rate-limited poll is retried later and less often; the page stays as it is.
    if (!(error instanceof SessionEnded)) pollFailures++;
  } finally {
    if (current === epoch) schedulePoll();
  }
}

/**
 * Runs one operation at a time. A refusal made before anything was done reloads the current
 * state; an outcome that cannot be known (a lost response) clears what is shown until a reload.
 */
async function run(work, { clearOnUnknown = false, focus } = {}) {
  if (isBusy()) return;
  const current = epoch;
  setBusy(true);
  state.error = '';
  state.notice = '';
  paint('notices');
  let focusId = focus;
  try {
    focusId = (await work()) ?? focus;
  } catch (error) {
    if (current !== epoch || error instanceof SessionEnded) return;
    if (DEFINITIVE_REFUSALS.includes(error.code)) {
      await refresh();
      if (current === epoch) state.error ||= error.message;
    } else {
      if (clearOnUnknown && !HARMLESS_REFUSALS.includes(error.code)) clearLoaded();
      state.error = error.message;
    }
  } finally {
    setBusy(false);
    if (current === epoch) settle(focusId);
  }
}

// ---- Actions ----------------------------------------------------------------------------

function showRequest(value) {
  const index = state.requests.findIndex(request => request.id === value.id);
  if (index === -1) state.requests.unshift(value);
  else state.requests[index] = value;
  state.selectedRequestId = value.id;
  state.selectionGone = false;
  if (value.state === 'completed') {
    const ticket = state.tickets.find(item => item.id === value.ticketId);
    if (ticket) Object.assign(ticket, { status: value.receipt.status, version: value.receipt.version });
  }
}

function decided(request, path, body, noticeFor) {
  return run(
    async () => {
      const result = check.requestResult(
        await api.request(`/api/requests/${encodeURIComponent(request.id)}/${path}`, { method: 'POST', body }),
        tenant(),
        request.id,
      );
      state.decision = null;
      state.denyReason = '';
      showRequest(result);
      state.notice = noticeFor(result);
    },
    { clearOnUnknown: true },
  );
}

const actions = {
  signIn,
  signOut,
  refresh: () =>
    run(async () => {
      await refresh();
      if (state.ready && !state.error) state.notice = 'Showing the current state.';
    }),
  navigate(target) {
    if (!VIEWS.includes(target)) return;
    state.view = target;
    state.error = '';
    state.notice = '';
    paint('nav', 'heading', 'notices', 'view');
    syncFragment();
    focusOn('page-heading');
  },
  selectRequest(id) {
    state.selectedRequestId = id;
    state.selectionGone = false;
    state.decision = null;
    state.closeOut = null;
    state.denyReason = '';
    paint('list', 'detail');
    syncFragment();
    focusOn('review-heading');
  },
  setFilter(value) {
    state.filter = ['all', 'review', 'unconfirmed'].includes(value) ? value : 'all';
    paint('list');
  },
  showIncoming() {
    if (!state.incoming) return;
    const known = new Set(state.requests.map(request => request.id));
    const first = state.incoming.find(request => !known.has(request.id));
    state.requests = state.incoming;
    state.incoming = null;
    state.goneIds = [];
    announcedIncoming = 0;
    state.filter = 'all';
    Object.assign(state, selectionAfterReload(state.selectedRequestId, state.requests));
    paint('nav', 'list', 'detail');
    syncFragment();
    focusOn(first && `request-${first.id}`, 'request-filter');
  },
  loadPage(kind, offset) {
    if (!['tickets', 'requests'].includes(kind) || !Number.isSafeInteger(offset) || offset < 0) return;
    return run(
      async () => {
        const result = await api.conditional(`/api/${kind}?offset=${offset}&limit=500`, null);
        const page = check.pageValue(result.body, kind, offset, tenant());
        state[kind] = page.rows;
        state[`${kind}Page`] = page.page;
        if (kind === 'requests') {
          Object.assign(state, {
            requestsEtag: result.etag,
            incoming: null,
            goneIds: [],
            selectedRequestId: '',
            selectionGone: false,
            decision: null,
            closeOut: null,
            filter: 'all',
          });
          announcedIncoming = 0;
        } else {
          state.allowedStatuses = page.allowedStatuses;
          state.selectedTicketId = page.rows[0]?.id ?? '';
          state.targetStatus = '';
        }
        state.notice = `Showing ${kind} ${page.page.offset + 1} to ${page.page.offset + page.rows.length} of ${page.page.total}.`;
      },
      { clearOnUnknown: true },
    );
  },

  /** Step one of a decision. Approval first reads back what the stored action will run. */
  beginDecision(request, kind) {
    if (kind === 'deny') {
      state.decision = { kind, requestId: request.id };
      state.denyReason = '';
      paint('detail');
      focusOn('decision-heading');
      return;
    }
    return run(async () => {
      const detail = check.detailValue(
        await api.request(`/api/requests/${encodeURIComponent(request.id)}`),
        tenant(),
        request.id,
      );
      showRequest(detail.request);
      if (shownState(detail.request, Date.now()) !== 'pending') throw failure({ error: { code: 'REVIEW_STALE' } });
      if (!detail.action?.matchesRequest)
        throw new ApiError(
          'The stored action does not match this request, so it cannot be approved. Prepare a new request.',
        );
      state.decision = { kind, requestId: request.id };
      return 'decision-heading';
    });
  },
  cancelDecision() {
    const kind = state.decision?.kind;
    state.decision = null;
    state.denyReason = '';
    paint('detail');
    focusOn(kind === 'approve' ? 'approve-request' : 'deny-request', 'review-heading');
  },
  setDenyReason(value) {
    state.denyReason = value;
  },
  setTechnicalOpen(open) {
    state.technicalOpen = open;
  },
  approve: request =>
    decided(request, 'approve', { digest: request.digest }, result =>
      result.state === 'completed'
        ? 'Approved. The change was applied and confirmed.'
        : result.state === 'unconfirmed'
          ? 'Approved, but the outcome is not confirmed. Do not prepare the change again; an operator must check it.'
          : 'Approved, but the change was not applied. Prepare a new request from the current ticket.',
    ),
  deny(request) {
    const reason = state.denyReason.trim();
    return decided(
      request,
      'deny',
      { digest: request.digest, ...(reason ? { reason } : {}) },
      () => 'Denied. Nothing was changed.',
    );
  },
  withdraw: request =>
    decided(request, 'withdraw', { digest: request.digest }, () => 'Withdrawn. Nothing was changed.'),
  reconcile: request =>
    decided(request, 'reconcile', {}, result =>
      result.state === 'completed' ? 'Confirmed: the change was applied.' : 'The outcome is still unconfirmed.',
    ),
  /** Without a digest this only loads the evidence; with the reviewed digest it closes the request. */
  closeOut(request, digest) {
    if (digest)
      return decided(request, 'close-out', { digest }, () => 'Closed as not applied. No change was submitted.');
    return run(
      async () => {
        state.closeOut = check.closeOutValue(
          await api.request(`/api/requests/${encodeURIComponent(request.id)}/close-out`, { method: 'POST', body: {} }),
          request,
        );
        state.notice = 'Close-out evidence is shown. Nothing was closed yet.';
        return 'apply-close-out';
      },
      { clearOnUnknown: true },
    );
  },
  async copy(value, label) {
    announce(
      (await copyText(value)) ? `${label} copied.` : `${label} could not be copied. Select it and copy it by hand.`,
    );
  },

  selectTicket(id) {
    state.selectedTicketId = id;
    state.targetStatus = '';
    paint('view');
    focusOn('prepare-heading');
  },
  setTargetStatus(value) {
    state.targetStatus = value;
    paint('view');
  },
  prepare(event) {
    event.preventDefault();
    const ticketId = state.selectedTicketId,
      status = state.targetStatus;
    if (!ticketId || !status) return;
    return run(
      async () => {
        const prepared = check.requestResult(
          await api.request('/api/requests', { method: 'POST', body: { ticketId, status } }),
          tenant(),
        );
        await refresh();
        if (!state.ready) return;
        showRequest(prepared);
        state.view = 'requests';
        state.filter = 'all';
        state.targetStatus = '';
        state.notice = 'The change is ready for review.';
        return 'review-heading';
      },
      { clearOnUnknown: true },
    );
  },

  setArchiveTask(taskId) {
    state.archiveTaskId = taskId;
    state.preview = null;
    paint('view');
  },
  previewArchive(event) {
    event.preventDefault();
    const taskId = state.archiveTaskId;
    if (!state.maintenance?.archiveCandidates.some(candidate => candidate.taskId === taskId)) return;
    return run(async () => {
      state.preview = null;
      state.preview = check.archivePreviewValue(
        await api.request('/api/maintenance/archive/preview', { method: 'POST', body: { taskId } }),
        taskId,
      );
      state.notice = 'The archive preview is ready. Nothing was archived yet.';
      return 'archive-preview-heading';
    });
  },
  applyArchive() {
    const preview = state.preview;
    if (!preview || preview.expiresAt <= Date.now() || preview.blockers.length) return;
    return run(
      async () => {
        const archived = check.archiveResultValue(
          await api.request('/api/maintenance/archive/apply', {
            method: 'POST',
            body: { id: preview.id, digest: preview.digest },
          }),
        );
        state.preview = null;
        state.archiveTaskId = '';
        await refresh();
        if (state.ready) state.notice = `${countLabel(archived, 'request')} archived.`;
      },
      { clearOnUnknown: true },
    );
  },
  prepareActivity() {
    const current = epoch;
    return run(async () => {
      const result = await api.request('/api/audit/export', { method: 'POST', body: {} });
      const parsed = check.activityValue(result, tenant());
      const bytes = new TextEncoder().encode(result.content);
      if (bytes.byteLength !== result.bytes) throw new ApiError('The activity snapshot could not be verified.');
      const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
      if (digest !== result.digest) throw new ApiError('The activity snapshot fingerprint could not be verified.');
      if (current !== epoch) return;
      if (state.activity?.url) URL.revokeObjectURL(state.activity.url);
      state.activity = {
        digest,
        count: parsed.events.length,
        capturedAt: parsed.capturedAt,
        omitted: parsed.coverage.omittedRetainedEvents,
        url: URL.createObjectURL(new Blob([bytes], { type: 'application/json' })),
      };
      state.notice = 'The activity snapshot is ready to download. It is a recent selection, not a complete history.';
      return 'download-activity';
    });
  },
};

// ---- Clock, tab and address ---------------------------------------------------------------

// Once a second: count down the selected review and, the moment any review deadline passes,
// redraw the list and the review so an expired request can no longer be approved.
setInterval(() => {
  if (!state.session?.authenticated || !state.ready) return;
  const now = Date.now();
  if (expirySnapshot(now) !== lastExpiry) {
    const selected = selectedRequest();
    if (state.view === 'requests') {
      paint('list', 'detail');
      if (selected?.state === 'pending' && selected.expiresAt <= now)
        announce('The review time for this request ran out. Nothing can be approved.');
    } else paint('view');
    return;
  }
  const label = document.getElementById('review-countdown'),
    request = selectedRequest();
  if (label && request) label.textContent = countdown(request.expiresAt, now);
}, 1000);

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') clearTimeout(pollTimer);
  else void revalidate();
});
window.addEventListener('pageshow', event => {
  if (event.persisted) void revalidate();
});
window.addEventListener('hashchange', () => {
  const target = parseFragment(location.hash);
  if (!target || !state.session?.authenticated || !state.ready || isBusy()) return;
  applyFragment(target);
  Object.assign(state, selectionAfterReload(state.selectedRequestId, state.requests));
  state.decision = null;
  state.closeOut = null;
  paint('nav', 'heading', 'view');
});

await start();
