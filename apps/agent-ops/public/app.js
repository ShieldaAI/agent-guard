const app = document.getElementById('app');
const announcement = document.getElementById('announcement');
const roles = new Set(['requester', 'reviewer', 'operator']);
const stateLabels = {
  pending: 'Awaiting review', completed: 'Completed', denied: 'Denied', expired: 'Expired',
  changed: 'Target changed', unconfirmed: 'Outcome unconfirmed', failed: 'Failed', review_required: 'Review required',
};
const state = {
  session: null, phase: 'checking', view: 'requests', requests: [], tickets: [], maintenance: null, setup: null, operational: null, activity: null,
  selectedRequestId: '', selectedTicketId: '', targetStatus: 'resolved', filter: 'all',
  archiveTaskId: '', preview: null, busy: false, loading: false, ready: false,
  error: '', notice: '', requestsPage: null, ticketsPage: null,
};
let generation = 0;
let workspaceGeneration = 0;
let expiryTimer;
let lastReviewExpired;
const pending = new Set();

function node(tag, attributes = {}, ...children) {
  const item = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key.startsWith('on')) item.addEventListener(key.slice(2), value);
    else if (key === 'class') item.className = value;
    else if (key === 'value') item.value = value;
    else if (value === true) item.setAttribute(key, '');
    else if (value !== false && value !== null && value !== undefined) item.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false) item.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return item;
}

function text(value, fallback = 'Unavailable') {
  return typeof value === 'string' && value.length ? value.slice(0, 4096) : fallback;
}

function date(value) {
  return Number.isFinite(value) ? new Intl.DateTimeFormat(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  }).format(new Date(value)) : 'Unavailable';
}

function expired(value) { return !Number.isFinite(value) || value <= Date.now(); }
function allowed(role) { return state.session?.operator?.roles?.includes(role) === true; }
function requestState(request) {
  return request.state === 'pending' && expired(request.expiresAt) ? 'expired' : request.state;
}
function badge(value) { return node('span', { class: `badge ${Object.hasOwn(stateLabels, value) ? value : ''}` }, stateLabels[value] ?? text(value)); }
function button(label, action, { primary = false, danger = false, disabled = false, id } = {}) {
  return node('button', { type: 'button', id, class: `button${primary ? ' primary' : ''}${danger ? ' danger' : ''}`,
    disabled: disabled || state.busy, onclick: action }, label);
}
function notice(message, tone = '') { return node('div', { class: `notice ${tone}`, role: tone === 'error' ? 'alert' : 'status' }, message); }
function field(label, value, wide = false) { return node('div', { class: wide ? 'wide' : '' }, node('dt', {}, label), node('dd', {}, value)); }
function countLabel(count, noun) { return `${count} ${noun}${count === 1 ? '' : 's'}`; }
function quantity(value, bytes = false) {
  if (!Number.isSafeInteger(value) || value < 0) return 'Not reported';
  if (!bytes) return new Intl.NumberFormat().format(value);
  const divisor = value >= 1_048_576 ? 1_048_576 : value >= 1024 ? 1024 : 1;
  const unit = divisor === 1_048_576 ? 'MiB' : divisor === 1024 ? 'KiB' : 'B';
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value / divisor)} ${unit}`;
}
function formField(label, id, input) { return node('div', { class: 'field-control' }, node('label', { for: id }, label), input); }
function empty(title, message, action) {
  return node('div', { class: 'empty' }, node('h2', {}, title), node('p', {}, message), action);
}
function announce(message) { announcement.textContent = message; }

function clearWorkspace(message = '') {
  announcement.textContent = '';
  generation++;
  workspaceGeneration++;
  clearTimeout(expiryTimer);
  for (const controller of pending) controller.abort();
  pending.clear();
  if (state.activity?.url) URL.revokeObjectURL(state.activity.url);
  Object.assign(state, { session: null, requests: [], tickets: [], maintenance: null, setup: null, operational: null, activity: null, preview: null,
    selectedRequestId: '', selectedTicketId: '', archiveTaskId: '', busy: false, loading: false,
    ready: false, error: message, notice: '', requestsPage: null, ticketsPage: null, filter: 'all', targetStatus: 'resolved' });
}

function endSession(message) {
  clearWorkspace(message);
  state.phase = 'unavailable';
  render();
}

async function responseJson(response) {
  if (response.status === 204) return {};
  if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) throw new Error('Invalid service response. Check the connection and refresh.');
  const limit = 1_048_576;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) throw new Error('The service response exceeded the workspace limit.');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('The service returned an empty response.');
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('The service response exceeded the workspace limit.');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new Error('The service response could not be read. Refresh to check current state.'); }
}

const errors = {
  REVIEW_EXPIRED: 'This review expired. Prepare a new request from the current ticket.',
  REQUEST_EXPIRED: 'This review expired. Prepare a new request from the current ticket.',
  RESOURCE_CHANGED: 'The ticket changed after preparation. Refresh and prepare a new review.',
  REQUEST_CHANGED: 'The ticket changed after preparation. Refresh and prepare a new review.',
  TICKET_CHANGED: 'The ticket changed after preparation. Refresh and prepare a new review.',
  REVIEW_STALE: 'This review changed or was already used. Refresh the request before continuing.',
  NO_CHANGE: 'The ticket already has this status. Choose a different status to prepare a change.',
  RECEIPT_UNAVAILABLE: 'A backend receipt is still unavailable. Keep this request unresolved and contact its operator.',
  RECEIPT_NOT_FOUND: 'A backend receipt is still unavailable. Keep this request unresolved and contact its operator.',
  OUTCOME_UNCONFIRMED: 'The outcome is unconfirmed. Check the existing backend receipt before making another change.',
  ARCHIVE_BLOCKED: 'This task has records that must be retained. Review the preview blockers.',
  PREVIEW_EXPIRED: 'The archive preview expired. Generate a new preview before applying it.',
  ARCHIVE_PREVIEW_STALE: 'The archive preview expired or its records changed. Generate a new preview before applying it.',
  ARCHIVE_UNAVAILABLE: 'This task is currently unavailable for archival. Refresh maintenance to check its state.',
  RECORD_CAPACITY_REACHED: 'The durable record limit was reached. Contact the deployment owner to follow the capacity runbook.',
  LIMITS_BELOW_USAGE: 'A configured storage limit was reached. Refresh to check the request outcome. The deployment owner must review and adjust limits offline.',
  HISTORY_SEGMENT_CAPACITY: 'History recovery capacity is exhausted. Stop new compaction and ask the deployment owner for a reviewed migration plan. Preserve all records, history, witnesses and keys.',
  HISTORY_MIGRATION_REQUIRED: 'History exceeds this recovery profile. Stop maintenance changes and ask the deployment owner for a reviewed compatible recovery or migration plan. Preserve all records, history, witnesses and keys.',
  RATE_LIMITED: 'Too many requests. Wait briefly, then refresh current state.',
};

async function api(path, { method = 'GET', body, csrfToken = state.session?.csrfToken } = {}) {
  const current = generation;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  pending.add(controller);
  try {
    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
      if (typeof csrfToken !== 'string' || !csrfToken) throw new Error('Check your session before submitting a decision.');
      headers['Content-Type'] = 'application/json';
      headers['X-CSRF-Token'] = csrfToken;
    }
    const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal });
    if (current !== generation) throw new Error('SESSION_ENDED');
    if (response.status === 401 || response.status === 403) {
      const message = response.status === 403
        ? 'Your account cannot perform this operation. Check your assigned role and sign in again.'
        : 'Your session ended. Sign in again to load current requests.';
      endSession(message);
      throw new Error('SESSION_ENDED');
    }
    const result = await responseJson(response);
    if (current !== generation || controller.signal.aborted) throw new Error('SESSION_ENDED');
    if (!response.ok) throw new Error(errors[result?.error?.code] ?? 'The operation could not be confirmed. Refresh current state before continuing.');
    return result;
  } catch (error) {
    if (current !== generation || error?.message === 'SESSION_ENDED') throw new Error('SESSION_ENDED');
    if (error?.name === 'AbortError') throw new Error('The request timed out. Refresh current state before deciding what to do next.');
    if (error instanceof TypeError) throw new Error('The service is unavailable. Refresh to check the current state.');
    throw error;
  } finally { clearTimeout(timer); pending.delete(controller); }
}

function sessionValue(value) {
  if (typeof value?.authenticated !== 'boolean' || typeof value.csrfToken !== 'string' || !value.csrfToken || value.csrfToken.length > 512) throw new Error('Sign-in settings could not be verified.');
  if (value.authenticated && (typeof value.operator?.id !== 'string' || !value.operator.id ||
      typeof value.operator.tenantId !== 'string' || !value.operator.tenantId ||
      !Array.isArray(value.operator.roles) || value.operator.roles.some(role => !roles.has(role)) || expired(value.expiresAt))) throw new Error('Your session is unavailable or expired. Sign in again.');
  return value;
}

async function bootstrap() {
  clearWorkspace();
  state.phase = 'checking';
  render();
  const current = generation;
  try {
    const value = sessionValue(await api('/api/session'));
    if (current !== generation) return;
    state.session = value;
    state.phase = 'ready';
    if (value.authenticated) {
      expiryTimer = setTimeout(() => endSession('Your session expired. Sign in again to load current requests.'), Math.min(value.expiresAt - Date.now(), 2_147_483_647));
      if (['maintenance', 'setup'].includes(state.view) && !allowed('operator')) state.view = 'requests';
      await refresh();
    } else render();
  } catch (error) {
    if (current !== generation) return;
    state.phase = 'unavailable';
    state.error = error.message;
    render();
  }
}

async function signIn() {
  await action(async () => {
    const settings = state.session;
    const result = await api('/auth/login', { method: 'POST', body: {} });
    let destination;
    try {
      destination = new URL(result.authorizationUrl);
      const origins = (settings.authorizationOrigins ?? [new URL(settings.publicAuthIssuer).origin]).map(origin => {
        const url = new URL(origin);
        if (url.protocol !== 'https:' || url.origin !== origin) throw new Error();
        return url.origin;
      });
      if (destination.protocol !== 'https:' || destination.username || destination.password || destination.hash ||
          destination.href.length > 8192 || !origins.includes(destination.origin) ||
          ['access_token', 'id_token', 'refresh_token', 'client_secret'].some(key => destination.searchParams.has(key))) throw new Error();
    } catch { throw new Error('The company sign-in destination could not be verified. Contact the service owner.'); }
    window.location.assign(destination.href);
  });
}

async function signOut() {
  const retry = state.phase === 'logout-unconfirmed';
  let csrfToken = state.session?.csrfToken;
  clearWorkspace();
  state.phase = 'signing-out';
  render();
  try {
    if (retry) csrfToken = sessionValue(await api('/api/session')).csrfToken;
    await api('/auth/logout', { method: 'POST', body: {}, csrfToken });
    const value = sessionValue(await api('/api/session'));
    if (value.authenticated) throw new Error();
    state.session = value;
    state.phase = 'ready';
  } catch {
    state.phase = 'logout-unconfirmed';
    state.error = 'Local workspace data was cleared. Server sign-out could not be confirmed. Retry sign-out before reconnecting.';
  }
  render();
}

function list(value, name) {
  if (!Array.isArray(value?.[name]) || value[name].length > 500) throw new Error('The workspace response could not be verified.');
  const ids = new Set();
  for (const item of value[name]) {
    if (!item || typeof item.id !== 'string' || !item.id || ids.has(item.id)) throw new Error('The workspace response could not be verified.');
    ids.add(item.id);
    if (name === 'requests') validateRequest(item);
    else if (typeof item.title !== 'string' || !['open', 'resolved'].includes(item.status) || !Number.isSafeInteger(item.version)) throw new Error('The ticket response could not be verified.');
  }
  return value[name];
}

function pageValue(value, name, requestedOffset = 0) {
  const rows = list(value, name);
  const { offset, limit, total, nextOffset } = value;
  if (offset !== requestedOffset || !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 500 ||
      !Number.isSafeInteger(total) || total < 0 || rows.length > limit || rows.length > total ||
      nextOffset !== null && (!Number.isSafeInteger(nextOffset) || nextOffset !== offset + rows.length || nextOffset >= total || !rows.length) ||
      nextOffset === null && offset + rows.length < total) throw new Error('The page could not be verified. Refresh to load the current list.');
  return { rows, page: { offset, limit, total, nextOffset } };
}

async function loadPage(kind, offset) {
  if (state.loading || !['tickets', 'requests'].includes(kind) || !Number.isSafeInteger(offset) || offset < 0) return;
  await action(async () => {
    state.loading = true;
    state.ready = false;
    render();
    try {
      const result = pageValue(await api(`/api/${kind}?offset=${offset}&limit=500`), kind, offset);
      state[kind] = result.rows;
      state[`${kind}Page`] = result.page;
      if (kind === 'requests') { state.selectedRequestId = result.rows[0]?.id ?? ''; state.filter = 'all'; }
      else state.selectedTicketId = result.rows[0]?.id ?? '';
      state.ready = true;
      announce(`Loaded ${kind} ${result.page.offset + 1} through ${result.page.offset + result.rows.length} of ${result.page.total}.`);
    } finally { state.loading = false; }
  }, { refreshOnFailure: true });
}

function pagination(kind) {
  const page = state[`${kind}Page`];
  if (!page) return null;
  const start = state[kind].length ? page.offset + 1 : 0;
  return node('div', { class: 'pagination', 'aria-label': `${kind} pages` },
    node('p', {}, `${start}–${page.offset + state[kind].length} of ${page.total} ${kind}`),
    node('div', { class: 'actions' },
      button(`Previous ${kind}`, () => loadPage(kind, Math.max(0, page.offset - page.limit)), { disabled: page.offset === 0, id: `previous-${kind}` }),
      button(`Next ${kind}`, () => loadPage(kind, page.nextOffset), { disabled: page.nextOffset === null, id: `next-${kind}` })),
    page.total > page.limit && node('p', { class: 'subtle' }, 'This is a live list. New activity can move rows between pages. Refresh starts from the first page.'));
}

function validateRequest(value) {
  if (!value || typeof value.id !== 'string' || !value.id || !Object.hasOwn(stateLabels, value.state) ||
      value.tenantId !== state.session?.operator?.tenantId || typeof value.ticketId !== 'string' ||
      !['open', 'resolved'].includes(value.beforeStatus) || !['open', 'resolved'].includes(value.afterStatus) ||
      !Number.isFinite(value.expiresAt) || !Number.isFinite(value.createdAt) ||
      !(typeof value.resourceVersion === 'string' || Number.isSafeInteger(value.resourceVersion))) throw new Error('The request status could not be verified. Refresh before taking another action.');
  const digestValid = typeof value.digest === 'string' && /^[a-f0-9]{64}$/.test(value.digest);
  if (!digestValid && !(['failed', 'review_required'].includes(value.state) && value.digest == null)) throw new Error('The prepared action fingerprint could not be verified. Refresh before taking another action.');
  if (value.receipt && (typeof value.receipt.operationId !== 'string' || !value.receipt.operationId ||
      !['open', 'resolved'].includes(value.receipt.status) || !Number.isSafeInteger(value.receipt.version) ||
      !Number.isFinite(value.receipt.recordedAt) ||
      value.receipt.ticketId !== undefined && value.receipt.ticketId !== value.ticketId ||
      value.receipt.requestId !== undefined && value.receipt.requestId !== value.id ||
      value.receipt.tenantId !== undefined && value.receipt.tenantId !== value.tenantId ||
      value.receipt.digest !== undefined && value.receipt.digest !== value.digest ||
      value.receipt.version !== Number(value.resourceVersion) + 1 ||
      value.state === 'completed' && value.receipt.status !== value.afterStatus)) throw new Error('The backend receipt could not be verified. Keep this request for reconciliation.');
}

function maintenanceValue(value) {
  if (value === null) { state.archiveTaskId = ''; return null; }
  if (!value || !Array.isArray(value.archiveCandidates) || value.archiveCandidates.length > 500) throw new Error('The maintenance response could not be verified. Refresh before continuing.');
  const ids = new Set();
  for (const candidate of value.archiveCandidates) {
    if (!candidate || typeof candidate.taskId !== 'string' || !candidate.taskId || ids.has(candidate.taskId)) throw new Error('The maintenance response could not be verified. Refresh before continuing.');
    ids.add(candidate.taskId);
  }
  if (!ids.has(state.archiveTaskId)) { state.archiveTaskId = ''; state.preview = null; }
  return value;
}

function validateLimits(value) {
  for (const key of ['maxTickets', 'maxRequests', 'maxBackendBytes', 'maxLedgerBytes', 'maxRetainedKeys']) {
    if (!Number.isSafeInteger(value?.[key]) || value[key] < 1) throw new Error('Configured limits could not be verified. Refresh or run the host preflight command.');
  }
}

function setupValue(value) {
  if (value === null) return null;
  const fail = () => { throw new Error('Setup information could not be verified. Refresh or run the host preflight command.'); };
  if (!value || value.deployment !== 'self-hosted' || value.data?.kind !== 'local-tickets' ||
      !Array.isArray(value.checks) || value.checks.length > 30 || !Array.isArray(value.commands) || value.commands.length > 12) fail();
  for (const url of [value.identity?.issuer, value.identity?.callbackUrl]) {
    try { const parsed = new URL(url); if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) fail(); }
    catch { fail(); }
  }
  for (const check of value.checks) {
    if (!check || typeof check.id !== 'string' || typeof check.label !== 'string' || typeof check.status !== 'string' || typeof check.message !== 'string') fail();
  }
  for (const command of value.commands) {
    if (!command || typeof command.label !== 'string' || typeof command.command !== 'string' || command.command.length > 4096) fail();
  }
  for (const count of [value.data.tickets, value.data.requests, value.data.receipts,
    ...(value.keyring ? [value.keyring.keyCount, value.keyring.maxKeys] : [])]) {
    if (!Number.isSafeInteger(count) || count < 0) fail();
  }
  validateLimits(value.limits);
  return value;
}

function operationalValue(value) {
  if (value === null) return null;
  if (value?.schemaVersion !== 1 || value.scope?.tenantId !== state.session.operator.tenantId || value.scope.capacity !== 'deployment' ||
      value.scope.workflow !== 'tenant' || value.scope.http !== 'deployment' || !Number.isFinite(value.capturedAt) ||
      value.service?.ready !== true || !Array.isArray(value.alerts) || value.alerts.length > 30 ||
      value.alerts.some(alert => !['warning', 'critical'].includes(alert.severity) || typeof alert.message !== 'string') ||
      !['requests', 'pending', 'unconfirmed', 'oldestUnconfirmedMs'].every(key => Number.isSafeInteger(value.workflow?.[key]) && value.workflow[key] >= 0)) throw new Error('Operational status could not be verified. Refresh before continuing.');
  return value;
}

async function refresh() {
  if (!state.session?.authenticated) return;
  const current = generation;
  const run = ++workspaceGeneration;
  state.loading = true;
  state.ready = false;
  state.error = '';
  state.preview = null;
  render();
  try {
    const [requests, tickets, maintenance, setup, operational] = await Promise.all([
      api('/api/requests?offset=0&limit=500'), api('/api/tickets?offset=0&limit=500'), allowed('operator') ? api('/api/maintenance') : Promise.resolve(null),
      allowed('operator') ? api('/api/setup') : Promise.resolve(null),
      allowed('operator') ? api('/api/status') : Promise.resolve(null),
    ]);
    if (current !== generation || run !== workspaceGeneration) return;
    const requestResult = pageValue(requests, 'requests'), ticketResult = pageValue(tickets, 'tickets');
    state.requests = requestResult.rows;
    state.requestsPage = requestResult.page;
    state.tickets = ticketResult.rows;
    state.ticketsPage = ticketResult.page;
    state.maintenance = maintenanceValue(maintenance);
    state.setup = setupValue(setup);
    state.operational = operationalValue(operational);
    if (!state.requests.some(request => request.id === state.selectedRequestId)) state.selectedRequestId = state.requests[0]?.id ?? '';
    if (!state.tickets.some(ticket => ticket.id === state.selectedTicketId)) state.selectedTicketId = state.tickets[0]?.id ?? '';
    state.ready = true;
  } catch (error) {
    if (current !== generation || run !== workspaceGeneration) return;
    state.requests = [];
    state.tickets = [];
    state.maintenance = null;
    state.setup = null;
    state.operational = null;
    state.requestsPage = null;
    state.ticketsPage = null;
    state.error = error.message;
  } finally {
    if (current === generation && run === workspaceGeneration) { state.loading = false; render(); }
  }
}

async function action(work, { refreshOnFailure = false } = {}) {
  if (state.busy) return;
  const current = generation;
  state.busy = true;
  state.error = '';
  state.notice = '';
  render();
  try { await work(); }
  catch (error) {
    if (current === generation) {
      state.error = error.message;
      // A lost response may follow a committed effect. Require a fresh read before offering another action.
      if (refreshOnFailure) { state.ready = false; state.preview = null; }
    }
  }
  finally { if (current === generation) { state.busy = false; render(); } }
}

function updateRequest(value) {
  validateRequest(value);
  const index = state.requests.findIndex(request => request.id === value.id);
  if (index === -1) state.requests.unshift(value);
  else state.requests[index] = value;
  state.selectedRequestId = value.id;
  if (value.state === 'completed' && value.receipt) {
    const ticket = state.tickets.find(ticket => ticket.id === value.ticketId);
    if (ticket) { ticket.status = value.receipt.status; ticket.version = value.receipt.version; }
  }
}

async function decide(request, decision) {
  await action(async () => {
    const result = await api(`/api/requests/${encodeURIComponent(request.id)}/${decision}`, {
      method: 'POST', body: decision === 'reconcile' ? {} : { digest: request.digest },
    });
    updateRequest(result.request);
    state.notice = result.request.state === 'completed' && result.request.receipt
      ? 'The backend receipt confirms this change.'
      : result.request.state === 'denied' ? 'The request was denied.'
        : result.request.state === 'unconfirmed' ? 'The outcome remains unconfirmed. Keep this request for reconciliation.'
          : `Request updated. ${stateLabels[result.request.state]}.`;
  }, { refreshOnFailure: true });
}

async function prepare(event) {
  event.preventDefault();
  const ticketId = state.selectedTicketId;
  const status = state.targetStatus;
  await action(async () => {
    const result = await api('/api/requests', { method: 'POST', body: { ticketId, status } });
    await refresh();
    updateRequest(result.request);
    state.view = 'requests';
    state.filter = 'all';
    state.notice = 'The change is prepared for review.';
    queueMicrotask(() => document.getElementById('review-heading')?.focus());
  }, { refreshOnFailure: true });
}

function navigate(view) {
  state.view = view;
  state.error = '';
  state.notice = '';
  render('page-heading');
}

function header() {
  const operator = state.session?.authenticated ? state.session.operator : null;
  return node('header', { class: 'topbar' },
    node('div', { class: 'brand' }, node('span', { class: 'brand-mark', 'aria-hidden': 'true' }, 'G'),
      node('div', {}, node('span', { class: 'brand-name' }, 'AGENT GUARD'), node('span', { class: 'brand-product' }, 'Operations'))),
    operator && node('div', { class: 'identity' }, node('div', { class: 'identity-copy' },
      node('strong', { class: 'identity-name' }, text(operator.name, operator.id)),
      node('span', { class: 'identity-roles' }, operator.roles.map(role => role[0].toUpperCase() + role.slice(1)).join(' · '))),
    button('Sign out', signOut, { id: 'sign-out' })));
}

function login() {
  let control;
  if (state.phase === 'checking' || state.phase === 'signing-out') control = node('p', { class: 'subtle', role: 'status' }, state.phase === 'checking' ? 'Checking your session…' : 'Signing out…');
  else if (state.phase === 'logout-unconfirmed') control = button('Retry sign out', signOut, { primary: true });
  else if (state.session && state.phase === 'ready') control = button(state.busy ? 'Opening sign-in…' : 'Sign in with company account', signIn, { primary: true, id: 'sign-in' });
  else control = button('Check session', bootstrap, { primary: true });
  return node('main', { id: 'main', class: 'login', tabindex: '-1' },
    node('section', { class: 'login-intro' }, node('span', { class: 'eyebrow' }, 'Operator workspace'),
      node('h1', {}, 'Review the change.', node('br'), 'Know the outcome.'),
      node('p', {}, 'Prepare scoped requests, review their exact effect and follow the backend receipt through completion.')),
    node('section', { class: 'panel login-card' }, node('h2', {}, 'Connect to your workspace'),
      node('p', {}, 'Use your company account. The host assigns your tenant and operator permissions.'),
      state.error && notice(state.error, 'error'), control,
      node('p', { class: 'session-footnote' }, 'Your identity provider handles sign-in. Administrative credentials stay with the host.')));
}

function sidebar() {
  const tabs = [['requests', 'Requests', state.requestsPage?.total ?? state.requests.length], ['tickets', 'Tickets', state.ticketsPage?.total ?? state.tickets.length]];
  if (allowed('operator')) tabs.push(['maintenance', 'Maintenance', null], ['setup', 'Setup', null]);
  return node('aside', { class: 'sidebar' },
    node('div', { class: 'scope' }, 'Tenant', node('strong', {}, state.session.operator.tenantId)),
    node('nav', { class: 'nav', 'aria-label': 'Operator views' }, tabs.map(([view, label, count]) =>
      node('button', { id: `nav-${view}`, type: 'button', 'aria-current': state.view === view ? 'page' : null, onclick: () => navigate(view) },
        label, count !== null && state.ready && node('span', { class: 'nav-count' }, count)))));
}

function requestDetail(request) {
  if (!request) return node('section', { class: 'panel' }, empty('Select a request', 'Choose a request to inspect its exact change and current outcome.'));
  const isExpired = expired(request.expiresAt);
  const reviewable = request.state === 'pending';
  const receipt = request.receipt;
  let statusMessage;
  if (request.state === 'unconfirmed') statusMessage = notice('The submission may already have taken effect. Check its backend receipt before preparing another change.', 'warning');
  else if (request.state === 'changed') statusMessage = notice('The ticket changed after preparation. Refresh the ticket and prepare a new review.', 'warning');
  else if (request.state === 'expired' || reviewable && isExpired) statusMessage = notice('This review expired. Prepare a new request using the current ticket.', 'warning');
  else if (request.state === 'review_required') statusMessage = notice('This preparation can no longer be approved. Prepare a new request using the current ticket.', 'warning');
  else if (request.state === 'failed') statusMessage = notice('This request failed. Check its recorded outcome before preparing another change.', 'error');
  else if (request.state === 'denied') statusMessage = notice('The reviewer denied this prepared change.');
  else if (request.state === 'completed' && receipt) statusMessage = notice('The backend receipt confirms the completed change.', 'success');
  else if (request.state === 'completed') statusMessage = notice('The request is marked completed. Refresh to retrieve its backend receipt.', 'warning');
  const controls = [];
  if (reviewable && !isExpired && allowed('reviewer')) {
    controls.push(button('Approve and submit once', () => decide(request, 'approve'), { primary: true, id: 'approve-request' }));
    controls.push(button('Deny request', () => decide(request, 'deny'), { danger: true, id: 'deny-request' }));
  }
  if (request.state === 'unconfirmed' && allowed('operator')) controls.push(button('Check backend receipt', () => decide(request, 'reconcile'), { primary: true, id: 'check-receipt' }));
  const guidance = request.state === 'unconfirmed'
    ? allowed('operator') ? 'Receipt lookup reconciles the original request. It never submits the change again.' : 'An operator can inspect the receipt and reconcile this request. Keep the request reference below.'
    : reviewable && !isExpired ? allowed('reviewer') ? 'Approval submits this exact prepared change once. Review the tenant, target and version before continuing.' : 'An assigned reviewer must approve or deny this change.' : '';
  return node('section', { class: 'panel', 'aria-labelledby': 'review-heading' },
    node('div', { class: 'panel-head' }, node('div', {}, node('h2', { id: 'review-heading', tabindex: '-1' }, text(request.title, `Ticket ${request.ticketId}`)),
      node('p', {}, `Request ${request.id}`)), badge(reviewable && isExpired ? 'expired' : request.state)),
    node('div', { class: 'panel-body' }, statusMessage,
      node('div', { class: 'change' }, node('h3', {}, 'Prepared status change'),
        node('div', { class: 'change-values' }, text(request.beforeStatus), node('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'), node('span', { class: 'visually-hidden' }, 'to'), text(request.afterStatus))),
      node('dl', { class: 'fields' }, field('Tenant', text(request.tenantId)), field('Ticket', text(request.ticketId)),
        field('Expected version', request.resourceVersion ?? 'Unavailable'), field('Review valid until', date(request.expiresAt)),
        request.requesterId && field('Requested by', text(request.requesterId)),
        request.reviewerId && field('Reviewed by', text(request.reviewerId)),
        field('Action fingerprint', node('code', {}, text(request.digest)), true)),
      request.archived === true && notice('Execution records were archived. This retained request and its backend receipt remain available.'),
      guidance && node('p', { class: 'review-note' }, guidance),
      controls.length > 0 && node('div', { class: 'actions' }, controls),
      receipt && node('section', { class: 'receipt', 'aria-label': 'Backend receipt' }, node('h3', {}, 'Backend receipt'),
        node('dl', { class: 'fields' }, field('Operation', node('code', {}, text(receipt.operationId)), true),
          field('Confirmed status', text(receipt.status)), field('Version', receipt.version ?? 'Unavailable'),
          field('Recorded', date(receipt.recordedAt), true)))));
}

function requestsView() {
  const filtered = state.requests.filter(request => state.filter === 'all' || (state.filter === 'review' ? ['pending', 'review_required'].includes(request.state) : request.state === 'unconfirmed'));
  const selection = filtered.find(request => request.id === state.selectedRequestId);
  const select = node('select', { id: 'request-filter', onchange: event => { state.filter = event.target.value; render(); } },
    node('option', { value: 'all' }, 'All requests'), node('option', { value: 'review' }, 'Needs review'), node('option', { value: 'unconfirmed' }, 'Unconfirmed outcomes'));
  select.value = state.filter;
  const rows = filtered.map(request => {
    const selectRequest = node('button', {
      id: `request-${request.id}`, type: 'button', class: 'request-item', 'aria-pressed': selection?.id === request.id,
      onclick: () => { state.selectedRequestId = request.id; render('review-heading'); },
    }, node('strong', {}, text(request.title, `Ticket ${request.ticketId}`)),
    node('p', {}, `${text(request.beforeStatus)} → ${text(request.afterStatus)}`),
    node('div', { class: 'request-meta' }, badge(requestState(request)), node('time', {}, date(request.createdAt))));
    return node('li', {}, selectRequest);
  });
  const contents = rows.length ? node('ul', { class: 'request-list' }, rows)
    : empty(state.filter === 'all' ? 'No requests yet' : 'No matching requests',
      state.filter === 'all' ? 'Prepare a ticket change to create its review request.' : 'This filter applies to the current page. Choose another filter or use the page controls.',
      state.filter === 'all' && allowed('requester') ? button('View tickets', () => navigate('tickets')) : null);
  return node('div', { class: 'split' }, node('section', { class: 'panel', 'aria-label': 'Request list' },
    node('div', { class: 'panel-head' }, node('h2', {}, 'Recent requests')),
    node('div', { class: 'list-filter' }, formField('Show on this page', 'request-filter', select)), contents, pagination('requests')), requestDetail(selection));
}

function ticketsView() {
  if (!state.tickets.length) return node('section', { class: 'panel' }, empty('No tickets enrolled yet',
    allowed('operator') ? 'Import your company ticket records using the host onboarding tools, then refresh this workspace. Importing records does not approve a change.'
      : 'Ask your deployment owner to import ticket records for this tenant. Imported tickets will appear here after you refresh.',
    allowed('operator') ? button('Open setup guide', () => navigate('setup'), { primary: true }) : null));
  const ticket = state.tickets.find(item => item.id === state.selectedTicketId) ?? state.tickets[0];
  const statuses = node('select', { id: 'target-status', required: true, disabled: !allowed('requester') || state.busy,
    onchange: event => { state.targetStatus = event.target.value; } }, node('option', { value: 'open' }, 'Open'), node('option', { value: 'resolved' }, 'Resolved'));
  statuses.value = state.targetStatus;
  return node('div', { class: 'split' }, node('section', { class: 'panel', 'aria-label': 'Available tickets' },
    node('div', { class: 'panel-head' }, node('h2', {}, 'Available tickets')),
    node('ul', { class: 'request-list' }, state.tickets.map(item => node('li', {}, node('button', {
      type: 'button', id: `ticket-${item.id}`, class: 'request-item', 'aria-pressed': ticket.id === item.id,
      onclick: () => { state.selectedTicketId = item.id; render('prepare-heading'); },
    }, node('strong', {}, text(item.title, `Ticket ${item.id}`)), node('p', {}, `Ticket ${item.id}`),
    node('div', { class: 'ticket-summary' }, badge(item.status), `Version ${item.version}`))))), pagination('tickets')),
    node('section', { class: 'panel' }, node('div', { class: 'panel-head' }, node('h2', { id: 'prepare-heading', tabindex: '-1' }, 'Prepare a change')),
      node('div', { class: 'panel-body' }, node('dl', { class: 'fields' }, field('Ticket', text(ticket.title, ticket.id), true),
        field('Current status', text(ticket.status)), field('Current version', ticket.version)),
      node('p', { class: 'review-note' }, 'The host will prepare the exact change for a reviewer to approve or deny.'),
      node('form', { class: 'form-stack', onsubmit: prepare }, formField('Requested status', 'target-status', statuses),
        node('button', { class: 'button primary', type: 'submit', disabled: !allowed('requester') || state.busy }, state.busy ? 'Preparing…' : 'Prepare review')),
      !allowed('requester') && node('p', { class: 'subtle' }, 'The requester role is required to prepare ticket changes.'))));
}

async function previewArchive(event) {
  event.preventDefault();
  const taskId = state.archiveTaskId;
  if (!state.maintenance?.archiveCandidates.some(candidate => candidate.taskId === taskId)) return;
  await action(async () => {
    state.preview = null;
    const result = await api('/api/maintenance/archive/preview', { method: 'POST', body: { taskId } });
    if (!result.preview || result.preview.taskId !== taskId || typeof result.preview.id !== 'string' || !result.preview.id ||
        typeof result.preview.digest !== 'string' || !/^[a-f0-9]{64}$/.test(result.preview.digest) || !Number.isFinite(result.preview.expiresAt) ||
        !Number.isSafeInteger(result.preview.eligibleCount) || result.preview.eligibleCount < 0 ||
        !Number.isSafeInteger(result.preview.retainedCount) || result.preview.retainedCount < 0 ||
        !Array.isArray(result.preview.blockers) || result.preview.blockers.some(reason => typeof reason !== 'string')) throw new Error('The archive preview could not be verified. Generate a new preview.');
    state.preview = result.preview;
    announce('Archive preview is ready for review.');
  });
}

async function applyArchive() {
  const preview = state.preview;
  if (!preview || expired(preview.expiresAt) || preview.blockers.length) return;
  await action(async () => {
    const result = await api('/api/maintenance/archive/apply', { method: 'POST', body: { id: preview.id, digest: preview.digest } });
    state.preview = null;
    if (!Number.isSafeInteger(result.archivedCount) || result.archivedCount < 0) throw new Error('Archival result is unconfirmed. Refresh before taking another maintenance action.');
    state.notice = `${countLabel(result.archivedCount, 'task')} archived.`;
    state.maintenance = maintenanceValue(await api('/api/maintenance'));
  }, { refreshOnFailure: true });
}

async function prepareActivity() {
  const current = generation;
  await action(async () => {
    const result = await api('/api/audit/export', { method: 'POST', body: {} });
    if (typeof result.content !== 'string' || !/^[a-f0-9]{64}$/.test(result.digest) || result.completeHistory !== false) throw new Error('The activity snapshot could not be verified.');
    const bytes = new TextEncoder().encode(result.content);
    if (bytes.byteLength !== result.bytes || bytes.byteLength > 524_288) throw new Error('The activity snapshot exceeded its download limit.');
    const parsed = JSON.parse(result.content);
    const keysAllowed = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
    if (!keysAllowed(parsed, ['schemaVersion', 'kind', 'tenantId', 'capturedAt', 'coverage', 'events']) || parsed.schemaVersion !== 1 ||
        parsed.kind !== 'agent-ops-activity-snapshot' || parsed.tenantId !== state.session.operator.tenantId || !Number.isFinite(parsed.capturedAt) ||
        parsed.coverage?.kind !== 'bounded_activity_only' || parsed.coverage.completeHistory !== false ||
        !Array.isArray(parsed.events) || parsed.events.length > 1000 || parsed.events.length !== result.eventCount ||
        parsed.events.some(event => !keysAllowed(event, ['at', 'event', 'requestId', 'operatorId']))) throw new Error('The activity snapshot scope could not be verified.');
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    if (digest !== result.digest) throw new Error('The activity snapshot fingerprint could not be verified.');
    if (current !== generation) return;
    if (state.activity?.url) URL.revokeObjectURL(state.activity.url);
    state.activity = { digest, count: parsed.events.length, capturedAt: parsed.capturedAt,
      omitted: parsed.coverage.omittedRetainedEvents, url: URL.createObjectURL(new Blob([bytes], { type: 'application/json' })) };
    announce('Activity snapshot is ready to download. It contains a bounded selection, not a complete history.');
  });
}

function operationalPanel() {
  const status = state.operational;
  if (!status) return notice('Operational status is unavailable. Refresh to check it.', 'warning');
  const recent = status.http?.recent ?? {}, activity = state.activity;
  const latency = recent.p95AboveMaxBucket ? 'Over 10 seconds' : Number.isFinite(recent.p95UpperBoundMs) ? `Up to ${recent.p95UpperBoundMs} ms` : 'No measured requests';
  return node('section', { class: 'panel setup-wide', 'aria-label': 'Operational status' },
    node('div', { class: 'panel-head' }, node('div', {}, node('h2', {}, 'Operational status'), node('p', {}, `Observed ${date(status.capturedAt)}. Refresh to update.`)), badge('Stores readable')),
    node('div', { class: 'panel-body' },
      status.alerts.length ? node('div', {}, status.alerts.map(alert => notice(`${alert.severity === 'critical' ? 'Action required' : 'Needs attention'}: ${alert.message}`, alert.severity === 'critical' ? 'error' : 'warning')))
        : notice('No configured alert thresholds are currently exceeded. This is not a complete deployment health assessment.'),
      node('dl', { class: 'fields' }, field('Pending reviews in this tenant', status.workflow.pending),
        field('Unconfirmed outcomes in this tenant', status.workflow.unconfirmed),
        field('Oldest unresolved request age', `${Math.floor(status.workflow.oldestUnconfirmedMs / 60_000)} minutes`),
        field('Deployment HTTP requests · recent window', quantity(recent.requests)),
        field('Deployment HTTP server errors · recent window', quantity(recent.serverErrors)), field('95th-percentile latency bucket', latency)),
      node('p', { class: 'subtle' }, 'HTTP counters cover this process and include health/monitoring requests. The recent window uses five one-minute buckets. Host disk space and external dependencies need separate monitoring.'),
      node('section', { class: 'receipt', 'aria-label': 'Activity snapshot' }, node('h3', {}, 'Activity snapshot'),
        node('p', { class: 'subtle' }, 'Download up to 1,000 retained events for this tenant. Older events may be absent. This minimized snapshot does not replace authoritative receipts, archived evidence or a complete audit history.'),
        node('div', { class: 'actions' }, button('Prepare activity snapshot', prepareActivity, { id: 'prepare-activity' })),
        activity && node('div', { class: 'preview' },
          node('dl', { class: 'fields' }, field('Exported events', activity.count), field('Omitted retained events', activity.omitted),
            field('Snapshot captured', date(activity.capturedAt), true), field('SHA-256 fingerprint', node('code', {}, activity.digest), true)),
          node('div', { class: 'actions' }, node('a', { class: 'button primary', href: activity.url, download: 'agent-ops-activity.json' }, 'Download activity JSON'))))));
}

function maintenanceView() {
  const maintenance = state.maintenance;
  if (!maintenance) return node('section', { class: 'panel' }, empty('Maintenance unavailable', 'Refresh the workspace to check current maintenance permissions and state.'));
  const candidates = Array.isArray(maintenance.archiveCandidates) ? maintenance.archiveCandidates : [];
  const selected = node('select', { id: 'archive-task', required: true, disabled: state.busy || !candidates.length,
    onchange: event => { state.archiveTaskId = event.target.value; state.preview = null; render(); } },
    node('option', { value: '' }, 'Choose a task'), candidates.map(item => node('option', { value: item.taskId }, text(item.label, item.taskId))));
  selected.value = state.archiveTaskId;
  const preview = state.preview;
  const rotation = maintenance.keyRotation ?? {};
  return node('div', { class: 'maintenance-grid' },
    operationalPanel(),
    node('section', { class: 'panel setup-wide' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Deployment capacity')),
      node('div', { class: 'panel-body' },
        maintenance.capacityWarning === true && notice('The deployment is nearing a capacity limit. Review usage with the deployment owner before accepting more work.', 'warning'),
        capacityTable(maintenance.usage, maintenance.limits, maintenance.keyring ?? state.setup?.keyring, maintenance.historyCapacity),
        node('p', { class: 'subtle' }, 'Usage is a snapshot from the last refresh. Backend bytes measure the decoded ledger, not database disk usage. Archival preserves business requests and receipts.'),
        node('p', { class: 'review-note' }, 'Configurable record, byte and key limits require reviewed offline host changes and restart. The history segment limit belongs to the fixed recovery profile and has no configuration override. Preserve existing evidence.'))),
    maintenance.history && node('section', { class: 'panel setup-wide' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Business history retention')),
      node('div', { class: 'panel-body' },
        node('dl', { class: 'fields' }, field('Archived requests in this tenant', text(maintenance.history.archivedRequests, 'Not reported')),
          field('Committed local segments', Number.isSafeInteger(maintenance.history.segments) ? String(maintenance.history.segments) : 'Not reported'),
          field('Last local history commit', maintenance.history.lastCommittedAt === null ? 'No history committed yet' : date(maintenance.history.lastCommittedAt)),
          field('Maintenance state', maintenance.history.pending === true ? 'Pending offline recovery' : 'No pending history operation'),
          typeof maintenance.history.commitment === 'string' && /^[a-f0-9]{64}$/.test(maintenance.history.commitment) &&
            field('Local history head fingerprint', node('code', {}, maintenance.history.commitment), true)),
        node('p', { class: 'review-note' }, 'These observations describe committed local history. Business retention uses a reviewed offline export and compaction; its authenticated encrypted history is separate from the minimized activity snapshot. Preserve the history artifact, keys and custody evidence. This screen does not verify off-host custody, restore tests or alert delivery.'),
        maintenance.history.pending === true && notice('The deployment owner must finish or recover the existing history operation. Do not recreate authority or discard the pending artifact.', 'warning'))),
    node('section', { class: 'panel' }, node('div', { class: 'panel-head' }, node('div', {}, node('h2', {}, 'Archive settled records'), node('p', {}, 'Review eligibility before changing retention.'))),
      node('div', { class: 'panel-body' },
        Number.isSafeInteger(maintenance.records) && Number.isSafeInteger(maintenance.recordLimit) &&
          node('p', { class: 'subtle' }, `${maintenance.records} retained requests in this tenant.`),
        Number.isSafeInteger(maintenance.unresolvedCount) && maintenance.unresolvedCount > 0 &&
          notice(`${countLabel(maintenance.unresolvedCount, 'outcome')} ${maintenance.unresolvedCount === 1 ? 'remains' : 'remain'} unconfirmed. Resolve their backend receipts before archival.`, 'warning'),
        maintenance.archiveCandidatesTruncated === true && notice('The task selector shows a bounded selection of 500 archival candidates. Refresh after archival to load remaining candidates.'),
        candidates.length ? node('form', { class: 'form-stack', onsubmit: previewArchive },
          formField('Task', 'archive-task', selected), node('button', { type: 'submit', class: 'button', disabled: state.busy || !state.archiveTaskId }, 'Preview archive'))
          : node('p', { class: 'subtle' }, 'No tasks are available for archival. Active and unresolved work must remain available for recovery.'),
        preview && node('section', { class: 'preview', 'aria-label': 'Archive preview' }, node('h3', {}, 'Archive preview'),
          node('dl', { class: 'fields' }, field('Task', node('code', {}, preview.taskId), true),
            field('Eligible tasks', preview.eligibleCount), field('Retained request records', preview.retainedCount),
            field('Valid until', date(preview.expiresAt), true), field('Preview fingerprint', node('code', {}, preview.digest), true)),
          preview.blockers.length ? node('div', {}, node('p', { class: 'review-note' }, 'Resolve these blockers before archival.'), node('ul', {}, preview.blockers.map(reason => node('li', {}, text(reason))))) : null,
          expired(preview.expiresAt) && notice('This preview expired. Generate a new preview.', 'warning'),
          node('div', { class: 'actions' }, button(`Archive ${preview.eligibleCount} eligible task${preview.eligibleCount === 1 ? '' : 's'}`, applyArchive, {
            primary: true, disabled: expired(preview.expiresAt) || preview.blockers.length > 0 || preview.eligibleCount === 0,
          }))))),
    node('section', { class: 'panel' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Ledger key rotation')),
      node('div', { class: 'panel-body' }, badge('Host CLI required'),
        node('p', { class: 'review-note' }, text(rotation.message, 'Perform key rotation from the authenticated host CLI with the executor stopped. Follow the deployment runbook and preserve recovery material until verification completes.')),
        rotation.keyId && node('dl', { class: 'fields receipt' }, field('Current key identifier', node('code', {}, text(rotation.keyId)), true)),
        node('p', { class: 'subtle' }, 'Secret keys stay in the host secret store. This workspace displays maintenance guidance.'))));
}

function historyCapacityNote(capacity) {
  if (!capacity || !['committed', 'reserved', 'total', 'limit'].every(key => Number.isSafeInteger(capacity[key]) && capacity[key] >= 0) ||
      capacity.limit === 0 || capacity.committed + capacity.reserved !== capacity.total)
    return notice('History recovery capacity is not reported. Ask the deployment owner to verify usage before further compaction.', 'warning');
  const ratio = capacity.total / capacity.limit;
  return node('div', {},
    node('p', { class: 'review-note' }, `Deployment-wide history: ${quantity(capacity.committed)} committed + ${quantity(capacity.reserved)} reserved = ${quantity(capacity.total)} segments. Pending compaction reserves its slot before creating history.`),
    node('p', { class: 'subtle' }, 'This fixed recovery limit includes every tenant. The configure-limits command cannot raise it.'),
    ratio >= .95 ? notice(`History recovery capacity is ${ratio >= 1 ? 'exhausted' : 'nearly exhausted'}. Pause new compaction. The deployment owner must arrange a separately reviewed compatible recovery adapter or migration before more history can be retained. Preserve all records, history, witnesses and keys.`, 'error')
      : ratio >= .8 ? notice('History has reached 80% of the fixed recovery limit. Arrange a capacity review with the deployment owner before it fills.', 'warning') : null);
}

function capacityTable(usage = {}, limits = {}, keyring, historyCapacity) {
  const rows = [
    ['Tickets', quantity(usage.tickets), quantity(limits.maxTickets)],
    ['Requests', quantity(usage.requests), quantity(limits.maxRequests)],
    ['Receipts', quantity(usage.receipts), quantity(limits.maxRequests)],
    ['Backend data', quantity(usage.backendBytes, true), quantity(limits.maxBackendBytes, true)],
    ['Executor ledger', quantity(usage.ledgerBytes ?? state.maintenance?.statistics?.ledgerBytes, true), quantity(limits.maxLedgerBytes, true)],
    ['Retained keys', quantity(keyring?.keyCount), quantity(keyring?.maxKeys ?? limits.maxRetainedKeys)],
    ['History segments (committed + reserved)', quantity(historyCapacity?.total), `${quantity(historyCapacity?.limit)} · fixed`],
  ];
  return node('div', {}, node('table', { class: 'capacity-table' }, node('caption', {}, 'Deployment-wide usage and capacity limits'),
    node('thead', {}, node('tr', {}, ['Resource', 'Current', 'Limit'].map(label => node('th', { scope: 'col' }, label)))),
    node('tbody', {}, rows.map(([label, current, limit]) => node('tr', {}, node('th', { scope: 'row' }, label), node('td', {}, current), node('td', {}, limit))))),
    historyCapacityNote(historyCapacity));
}

function setupView() {
  const setup = state.setup;
  if (!allowed('operator') || !setup) return node('section', { class: 'panel' }, empty('Setup unavailable', 'The operator role is required to inspect host setup. Check your session and assigned role.'));
  const checkLabels = { ok: 'Ready', pass: 'Ready', passed: 'Ready', warning: 'Needs attention', error: 'Action required', failed: 'Action required', missing: 'Missing', pending: 'Not verified', not_checked: 'Not verified' };
  const recovery = setup.recovery;
  const mirrored = recovery?.mode === 'current-state-mirror' && recovery.executorMirror === true && recovery.backendMirror === true && recovery.historyMirror === true;
  const recoveryLabel = mirrored ? 'Current-state recovery enrolled' : recovery?.mode === 'not-enrolled' ? 'Current-state recovery not enrolled' : 'Recovery enrollment not verified here';
  return node('div', { class: 'setup-grid' },
    node('section', { class: 'panel' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Your company workspace')),
      node('div', { class: 'panel-body' }, badge('Self-hosted'),
        node('p', { class: 'review-note' }, 'Your deployment owns the ticket records and encrypted evidence on its host. Company sign-in establishes identity; the host assigns tenant permissions.'),
        node('dl', { class: 'fields receipt' }, field('Current tenant', text(state.session.operator.tenantId), true),
          setup.company?.name && field('Company', text(setup.company.name), true),
          setup.company?.id && field('Company identifier', text(setup.company.id), true),
          field('OIDC issuer', node('code', {}, setup.identity.issuer), true), field('Sign-in callback', node('code', {}, setup.identity.callbackUrl), true)),
        node('p', { class: 'subtle' }, 'This local ticket service does not synchronize with Jira, Linear or another external ticket system.'))),
    node('section', { class: 'panel' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Runtime configuration checks')),
      node('div', { class: 'panel-body' },
        node('p', { class: 'subtle' }, 'These checks establish local readability and current sign-in only. They do not establish backup custody, external alert delivery or complete production acceptance.'),
        setup.checks.length ? node('ul', { class: 'setup-checks' }, setup.checks.map(check => node('li', {},
          node('div', { class: 'check-title' }, node('strong', {}, text(check.label)), badge(checkLabels[check.status] ?? 'Not verified')),
          node('p', {}, text(check.message))))) : notice('No configuration checks were reported. Run host preflight before continuing.'))),
    node('section', { class: 'panel setup-wide' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Recovery protection')),
      node('div', { class: 'panel-body' }, notice(recoveryLabel, mirrored ? 'info' : 'warning'),
        node('p', { class: 'review-note' }, mirrored
          ? 'When this service started, both encrypted stores had current-state mirrors and the bound history mirror was verified. Repair requires the surviving independent witnesses, mirrors and runtime keys.'
          : recovery?.mode === 'not-enrolled'
            ? 'This installation has not enrolled the complete current-state recovery profile. A cold checkpoint becomes stale after a later authoritative write, including service startup. The deployment owner must stop the service and complete reviewed mirror enrollment before relying on primary-volume-loss repair.'
            : 'This service did not report verified recovery enrollment. The deployment owner must check the local recovery profile before relying on primary-volume-loss repair.'),
        recovery?.verifiedAt && node('dl', { class: 'fields receipt' }, field('Enrollment checked at service startup', date(recovery.verifiedAt), true)),
        node('p', { class: 'subtle' }, 'Enrollment does not prove independent storage durability, available recovery keys or a successful restore drill. Keep those records with the company acceptance checks below.'))),
    node('section', { class: 'panel setup-wide' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Company acceptance checks')),
      node('div', { class: 'panel-body' }, notice('Not verified by this interface. The deployment owner must retain acceptance evidence before unattended company use.', 'warning'),
        node('ul', { class: 'setup-checks' }, [
          ['Backup and restore', 'Independent current-mirror and witness custody, a tested primary-volume-loss repair, archival backups and recovery-key access.'],
          ['History and key retention', 'Authoritative history artifacts, retained backup dependencies and reviewed key retirement.'],
          ['Alerts and operating owner', 'Delivered test alerts, named recipients, collector retention and an incident response owner.'],
          ['Company environment', 'Trusted HTTPS and actual company IdP enrollment, host sizing and the supported deployment profile.'],
        ].map(([label, message]) => node('li', {}, node('div', { class: 'check-title' }, node('strong', {}, label), badge('Not verified here')), node('p', {}, message)))),
        node('p', { class: 'review-note' }, 'Keep the resulting receipts and acknowledgements in the installation acceptance record. Runtime green checks do not substitute for these records.'))),
    node('section', { class: 'panel setup-wide' }, node('div', { class: 'panel-head' }, node('h2', {}, 'Capacity limits')),
      node('div', { class: 'panel-body' }, capacityTable(setup.usage, setup.limits, setup.keyring, setup.historyCapacity),
        node('p', { class: 'subtle' }, 'Usage is a snapshot from the last refresh. Limits remain finite and changes must stay within supported ceilings. These host configuration values are read-only; changes require the offline host workflow and restart.'))),
    node('section', { class: 'panel setup-wide' }, node('div', { class: 'panel-head' }, node('div', {}, node('h2', {}, 'Host onboarding steps'),
      node('p', {}, 'Run these commands on the deployment host using the private configuration.'))),
      node('div', { class: 'panel-body' },
        setup.data.tickets === 0 && notice('No company tickets are enrolled in this tenant. Start with an empty workspace or import reviewed ticket data before preparing changes.', 'warning'),
        node('p', { class: 'subtle' }, 'Stop the service before host preflight, import or limit changes: durable-state checks require exclusive access. Replace generic paths on the host. Review previews before apply. No command runs from this page.'),
        node('ol', { class: 'setup-commands' }, setup.commands.map(command => node('li', {}, node('h3', {}, text(command.label)), node('pre', {}, node('code', {}, command.command))))),
        node('p', { class: 'review-note' }, 'Keep TLS private keys, OIDC client secrets, proposal tokens and ledger keys in host-owned files. This page does not accept or reveal those secrets.'),
        button('View tickets', () => navigate('tickets')))));
}

function workspace() {
  const titles = {
    requests: ['Requests', 'Review proposed changes and reconcile their backend receipts.'],
    tickets: ['Tickets', 'Prepare a scoped change for an authorized reviewer.'],
    maintenance: ['Maintenance', 'Inspect retention and plan host key maintenance.'],
    setup: ['Setup', 'Check company scope, deployment health and host onboarding steps.'],
  };
  const [title, subtitle] = titles[state.view];
  let content;
  if (state.loading) content = node('div', { class: 'panel loading', role: 'status' }, 'Loading current workspace…');
  else if (!state.ready) content = node('section', { class: 'panel' }, empty('Refresh to load current state', 'Check the service connection and refresh before preparing or reviewing a change.'));
  else content = state.view === 'requests' ? requestsView() : state.view === 'tickets' ? ticketsView() : state.view === 'setup' ? setupView() : maintenanceView();
  return node('div', { class: 'shell' }, sidebar(), node('main', { id: 'main', class: 'workspace', tabindex: '-1' },
    node('div', { class: 'page-heading' }, node('div', {}, node('span', { class: 'eyebrow' }, 'Operator workspace'),
      node('h1', { id: 'page-heading', tabindex: '-1' }, title), node('p', {}, subtitle)),
      button('Refresh', refresh, { disabled: state.loading, id: 'refresh-workspace' })),
    state.error && notice(state.error, 'error'), state.notice && notice(state.notice),
    content, node('p', { class: 'session-footnote' }, `Session valid until ${date(state.session.expiresAt)}. Permissions are checked by the host for every operation.`)));
}

function visibleExpirySnapshot() {
  if (state.view === 'requests') return JSON.stringify(state.requests.filter(request => request.state === 'pending')
    .map(request => [request.id, expired(request.expiresAt)]));
  if (state.view === 'maintenance' && state.preview) return JSON.stringify([state.preview.id, expired(state.preview.expiresAt)]);
  return '';
}

function render(focusId, { expiryOnly = false } = {}) {
  const focused = document.activeElement?.id;
  // A normal render already reflects current expiry; its next timer tick must not replace it again.
  lastReviewExpired = visibleExpirySnapshot();
  const main = expiryOnly && state.session?.authenticated ? document.getElementById('main') : null;
  // Expired decisions disappear immediately without detaching a navigation button during its click.
  if (main) main.replaceWith(workspace().querySelector('#main'));
  else app.replaceChildren(header(), state.session?.authenticated ? workspace() : login());
  const target = document.getElementById(focusId || focused);
  if (target && !target.disabled) target.focus({ preventScroll: !focusId });
}

setInterval(() => {
  if (!state.session?.authenticated) return;
  if (visibleExpirySnapshot() !== lastReviewExpired) render(undefined, { expiryOnly: true });
}, 1000);

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && state.session?.authenticated) endSession('The workspace was paused. Check your session to load current state.');
});
window.addEventListener('pageshow', event => {
  if (event.persisted) endSession('Check your session to load current requests.');
});

await bootstrap();
