// Checks every service response before the client shows or acts on it. Pure: no DOM, no network.
import { DENIAL_REASON_MAX, REQUESTER_KINDS, REQUEST_STATES, TICKET_STATUSES, receiptMatches } from './contract.js';

const ROLES = ['requester', 'reviewer', 'operator'];
const DIGEST = /^[a-f0-9]{64}$/;
const CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const text = (value, max = 4096) => typeof value === 'string' && value.length > 0 && value.length <= max;
const count = value => Number.isSafeInteger(value) && value >= 0;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function reject(message) {
  throw new Error(message);
}

export function sessionValue(value, now = Date.now()) {
  if (!record(value) || typeof value.authenticated !== 'boolean' || !text(value.csrfToken, 512))
    reject('Sign-in settings could not be verified.');
  if (
    !Array.isArray(value.authorizationOrigins) ||
    !value.authorizationOrigins.length ||
    value.authorizationOrigins.some(origin => !text(origin, 2048))
  )
    reject('Sign-in settings could not be verified.');
  if (
    value.authenticated &&
    (!text(value.operator?.id) ||
      !text(value.operator.tenantId) ||
      !Array.isArray(value.operator.roles) ||
      !value.operator.roles.length ||
      value.operator.roles.some(role => !ROLES.includes(role)) ||
      !Number.isFinite(value.expiresAt) ||
      value.expiresAt <= now ||
      typeof value.policy?.forbidSelfApproval !== 'boolean')
  )
    reject('Your session is unavailable or expired. Sign in again.');
  return value;
}

/** The sign-in destination must be one of the HTTPS origins the service announced. */
export function authorizationUrl(result, session) {
  try {
    const destination = new URL(result.authorizationUrl);
    const origins = session.authorizationOrigins.map(origin => {
      const url = new URL(origin);
      if (url.protocol !== 'https:' || url.origin !== origin) throw new Error();
      return url.origin;
    });
    if (
      destination.protocol !== 'https:' ||
      destination.username ||
      destination.password ||
      destination.hash ||
      destination.href.length > 8192 ||
      !origins.includes(destination.origin) ||
      ['access_token', 'id_token', 'refresh_token', 'client_secret'].some(key => destination.searchParams.has(key))
    )
      throw new Error();
    return destination.href;
  } catch {
    return reject('The company sign-in destination could not be verified. Contact the service owner.');
  }
}

export function requestValue(value, tenantId) {
  if (
    !record(value) ||
    !text(value.id, 160) ||
    !REQUEST_STATES.includes(value.state) ||
    value.tenantId !== tenantId ||
    !text(value.ticketId, 160) ||
    !text(value.title, 240) ||
    !text(value.operationId, 200) ||
    !text(value.requesterId, 160) ||
    (value.requesterKind !== undefined && !REQUESTER_KINDS.includes(value.requesterKind)) ||
    (value.reviewerId !== undefined && !text(value.reviewerId, 160)) ||
    (value.denialReason !== undefined && !text(value.denialReason, DENIAL_REASON_MAX)) ||
    (value.cause !== undefined && !(typeof value.cause === 'string' && CODE.test(value.cause))) ||
    typeof value.archived !== 'boolean' ||
    !TICKET_STATUSES.includes(value.beforeStatus) ||
    !TICKET_STATUSES.includes(value.afterStatus) ||
    !count(value.expiresAt) ||
    !count(value.createdAt) ||
    typeof value.resourceVersion !== 'string' ||
    !/^[1-9][0-9]{0,15}$/.test(value.resourceVersion)
  )
    reject('The request could not be verified. Refresh before taking another action.');
  const fingerprint = typeof value.digest === 'string' && DIGEST.test(value.digest);
  // Only a request whose preparation never finished has no fingerprint.
  if (!fingerprint && !(['failed', 'review_required'].includes(value.state) && value.digest === undefined))
    reject('The action fingerprint could not be verified. Refresh before taking another action.');
  if (value.receipt !== undefined) {
    // The service attaches the record only when it completes the request.
    if (value.state !== 'completed' || !receiptMatches(value, value.receipt) || !count(value.receipt.recordedAt))
      reject('The confirmation record could not be verified. Keep this request and ask an operator to check it.');
  } else if (value.state === 'completed')
    reject('The confirmation record could not be verified. Keep this request and ask an operator to check it.');
  return value;
}

export function ticketValue(value) {
  if (
    !record(value) ||
    !text(value.id, 160) ||
    !text(value.title, 240) ||
    !TICKET_STATUSES.includes(value.status) ||
    !Number.isSafeInteger(value.version) ||
    value.version < 1
  )
    reject('The ticket list could not be verified. Refresh to load it again.');
  return value;
}

/** One page of tickets or requests, with totals that must agree with the rows. */
export function pageValue(value, name, requestedOffset, tenantId) {
  const failed = 'The list could not be verified. Refresh to load it again.';
  if (!record(value) || !Array.isArray(value[name]) || value[name].length > 500) reject(failed);
  const rows = value[name],
    ids = new Set();
  for (const item of rows) {
    if (name === 'requests') requestValue(item, tenantId);
    else ticketValue(item);
    if (ids.has(item.id)) reject(failed);
    ids.add(item.id);
  }
  const { offset, limit, total, nextOffset } = value;
  if (
    offset !== requestedOffset ||
    !count(offset) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 500 ||
    !count(total) ||
    rows.length > limit ||
    offset + rows.length > total ||
    (nextOffset !== null && (nextOffset !== offset + rows.length || nextOffset >= total || !rows.length)) ||
    (nextOffset === null && offset + rows.length !== total) ||
    value.truncated !== (nextOffset !== null)
  )
    reject(failed);
  const result = { rows, page: { offset, limit, total, nextOffset } };
  if (name === 'tickets') {
    if (
      !Array.isArray(value.allowedStatuses) ||
      !value.allowedStatuses.length ||
      value.allowedStatuses.some(status => !TICKET_STATUSES.includes(status)) ||
      new Set(value.allowedStatuses).size !== value.allowedStatuses.length
    )
      reject(failed);
    result.allowedStatuses = value.allowedStatuses;
  }
  return result;
}

/** A decision or preparation answers with the one request it touched. */
export function requestResult(value, tenantId, expectedId) {
  const request = requestValue(value?.request, tenantId);
  if (expectedId !== undefined && request.id !== expectedId)
    reject('The request could not be verified. Refresh before taking another action.');
  return request;
}

/** A request with what its stored action will run. Approval is offered only when they agree. */
export function detailValue(value, tenantId, expectedId) {
  const request = requestResult(value, tenantId, expectedId),
    action = value.action;
  if (action === undefined) return { request, action: null };
  if (
    !record(action) ||
    !text(action.tool, 200) ||
    !text(action.resourceId, 160) ||
    !text(action.resourceVersion, 32) ||
    !text(action.status, 32) ||
    typeof action.matchesRequest !== 'boolean'
  )
    reject('The stored action could not be verified. Refresh before taking another action.');
  return { request, action };
}

export function closeOutValue(value, request) {
  const evidence = value?.closeOut;
  if (
    !record(evidence) ||
    evidence.requestId !== request.id ||
    evidence.operationId !== request.operationId ||
    typeof evidence.digest !== 'string' ||
    !DIGEST.test(evidence.digest) ||
    evidence.receipt !== 'absent' ||
    evidence.ticketId !== request.ticketId ||
    // The ticket as this request was reviewed, beside the ticket as it is now.
    String(evidence.reviewedVersion) !== request.resourceVersion ||
    evidence.reviewedStatus !== request.beforeStatus ||
    !Number.isSafeInteger(evidence.ticketVersion) ||
    evidence.ticketVersion < 1 ||
    !TICKET_STATUSES.includes(evidence.ticketStatus) ||
    evidence.ticketChanged !==
      (String(evidence.ticketVersion) !== request.resourceVersion || evidence.ticketStatus !== request.beforeStatus) ||
    !text(evidence.execution, 32)
  )
    reject('The close-out evidence could not be verified. Refresh before continuing.');
  return evidence;
}

function limitsValue(value, message) {
  for (const key of ['maxTickets', 'maxRequests', 'maxBackendBytes', 'maxLedgerBytes', 'maxRetainedKeys'])
    if (!Number.isSafeInteger(value?.[key]) || value[key] < 1) reject(message);
}
function usageValue(value, message) {
  for (const key of ['tickets', 'requests', 'receipts', 'backendBytes']) if (!count(value?.[key])) reject(message);
}
function historyCapacityValue(value, message) {
  if (
    !record(value) ||
    !['committed', 'reserved', 'total', 'limit'].every(key => count(value[key])) ||
    value.limit === 0 ||
    value.committed + value.reserved !== value.total
  )
    reject(message);
}

export function maintenanceValue(value) {
  const failed = 'Maintenance information could not be verified. Refresh before continuing.';
  if (
    !record(value) ||
    !Array.isArray(value.archiveCandidates) ||
    value.archiveCandidates.length > 500 ||
    typeof value.archiveCandidatesTruncated !== 'boolean' ||
    !count(value.unresolvedCount) ||
    !count(value.records) ||
    typeof value.capacityWarning !== 'boolean' ||
    !count(value.statistics?.ledgerBytes) ||
    !record(value.history) ||
    typeof value.history.archivedRequests !== 'string' ||
    !/^[0-9]{1,20}$/.test(value.history.archivedRequests) ||
    !count(value.history.segments) ||
    !(value.history.lastCommittedAt === null || count(value.history.lastCommittedAt)) ||
    !(value.history.commitment === null || DIGEST.test(value.history.commitment)) ||
    typeof value.history.pending !== 'boolean' ||
    value.keyRotation?.state !== 'offline' ||
    !text(value.keyRotation.message, 600) ||
    (value.keyring !== undefined && (!count(value.keyring.keyCount) || !count(value.keyring.maxKeys)))
  )
    reject(failed);
  limitsValue(value.limits, failed);
  usageValue(value.usage, failed);
  historyCapacityValue(value.historyCapacity, failed);
  const ids = new Set();
  for (const candidate of value.archiveCandidates) {
    if (
      !record(candidate) ||
      !text(candidate.taskId, 200) ||
      ids.has(candidate.taskId) ||
      !text(candidate.requestId, 160) ||
      !text(candidate.ticketId, 160) ||
      !REQUEST_STATES.includes(candidate.state) ||
      !text(candidate.requesterId, 160) ||
      !count(candidate.createdAt)
    )
      reject(failed);
    ids.add(candidate.taskId);
  }
  return value;
}

export function archivePreviewValue(value, taskId) {
  const preview = value?.preview;
  if (
    !record(preview) ||
    preview.taskId !== taskId ||
    !text(preview.id, 200) ||
    !text(preview.requestId, 160) ||
    typeof preview.digest !== 'string' ||
    !DIGEST.test(preview.digest) ||
    !count(preview.expiresAt) ||
    !count(preview.eligibleCount) ||
    !Array.isArray(preview.blockers) ||
    preview.blockers.length > 16 ||
    preview.blockers.some(code => typeof code !== 'string' || !CODE.test(code))
  )
    reject('The archive preview could not be verified. Preview again.');
  return preview;
}

export function archiveResultValue(value) {
  if (!count(value?.archivedCount))
    reject('The archive result could not be confirmed. Refresh before another maintenance action.');
  return value.archivedCount;
}

export function setupValue(value) {
  const failed = 'Setup information could not be verified. Refresh to load it again.';
  if (
    !record(value) ||
    value.deployment !== 'self-hosted' ||
    value.data?.kind !== 'local-tickets' ||
    !Array.isArray(value.checks) ||
    value.checks.length > 30 ||
    !Array.isArray(value.commands) ||
    value.commands.length > 12 ||
    !count(value.statistics?.ledgerBytes) ||
    (value.company !== undefined &&
      (!text(value.company.id, 160) || !(value.company.name === undefined || text(value.company.name, 120)))) ||
    !['current-state-mirror', 'not-enrolled', 'unverified'].includes(value.recovery?.mode) ||
    !(value.recovery.verifiedAt === null || count(value.recovery.verifiedAt))
  )
    reject(failed);
  for (const url of [value.identity?.issuer, value.identity?.callbackUrl]) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash)
        reject(failed);
    } catch {
      reject(failed);
    }
  }
  for (const check of value.checks)
    if (
      !record(check) ||
      !text(check.id, 64) ||
      !text(check.label, 120) ||
      !['passed', 'attention'].includes(check.status) ||
      !text(check.message, 600)
    )
      reject(failed);
  for (const command of value.commands)
    if (!record(command) || !text(command.label, 200) || !text(command.command)) reject(failed);
  for (const number of [
    value.data.tickets,
    value.data.requests,
    value.data.receipts,
    ...(value.keyring ? [value.keyring.keyCount, value.keyring.maxKeys] : []),
  ])
    if (!count(number)) reject(failed);
  limitsValue(value.limits, failed);
  usageValue(value.usage, failed);
  historyCapacityValue(value.historyCapacity, failed);
  return value;
}

export function operationalValue(value, tenantId) {
  if (
    value?.schemaVersion !== 1 ||
    value.scope?.tenantId !== tenantId ||
    value.scope.capacity !== 'deployment' ||
    value.scope.workflow !== 'tenant' ||
    value.scope.http !== 'deployment' ||
    !count(value.capturedAt) ||
    value.service?.ready !== true ||
    !Array.isArray(value.alerts) ||
    value.alerts.length > 30 ||
    value.alerts.some(alert => !['warning', 'critical'].includes(alert?.severity) || !text(alert.message, 600)) ||
    !['requests', 'pending', 'unconfirmed', 'oldestUnconfirmedMs'].every(key => count(value.workflow?.[key])) ||
    !record(value.http?.recent) ||
    !count(value.http.recent.requests) ||
    !count(value.http.recent.serverErrors) ||
    typeof value.http.recent.p95AboveMaxBucket !== 'boolean' ||
    !(value.http.recent.p95UpperBoundMs === null || count(value.http.recent.p95UpperBoundMs))
  )
    reject('Operational status could not be verified. Refresh before continuing.');
  return value;
}

/** The activity export envelope and its parsed, tenant-scoped content. The caller checks the digest. */
export function activityValue(result, tenantId) {
  if (
    !record(result) ||
    typeof result.content !== 'string' ||
    typeof result.digest !== 'string' ||
    !DIGEST.test(result.digest) ||
    result.completeHistory !== false ||
    !count(result.bytes) ||
    result.bytes > 524_288 ||
    !count(result.eventCount)
  )
    reject('The activity snapshot could not be verified.');
  let parsed;
  try {
    parsed = JSON.parse(result.content);
  } catch {
    reject('The activity snapshot could not be verified.');
  }
  const only = (value, keys) => record(value) && Object.keys(value).every(key => keys.includes(key));
  if (
    !only(parsed, ['schemaVersion', 'kind', 'tenantId', 'capturedAt', 'coverage', 'events']) ||
    parsed.schemaVersion !== 1 ||
    parsed.kind !== 'agent-ops-activity-snapshot' ||
    parsed.tenantId !== tenantId ||
    !count(parsed.capturedAt) ||
    parsed.coverage?.kind !== 'bounded_activity_only' ||
    parsed.coverage.completeHistory !== false ||
    !count(parsed.coverage.omittedRetainedEvents) ||
    !Array.isArray(parsed.events) ||
    parsed.events.length > 1000 ||
    parsed.events.length !== result.eventCount ||
    parsed.events.some(
      event =>
        !only(event, ['at', 'event', 'requestId', 'operatorId', 'code']) ||
        (event.code !== undefined && !(typeof event.code === 'string' && CODE.test(event.code))),
    )
  )
    reject('The activity snapshot scope could not be verified.');
  return parsed;
}
