// Every JSON body the service sends to a signed-in person or an agent is shaped here, from
// stored rows and measured values. The synthetic browser check builds its replies with the
// same functions, so it cannot feed the client a shape the service never returns.
import { TICKET_STATUSES, errorMessage } from './public/contract.js';

const count = value => Number.isSafeInteger(value) && value >= 0;

/** The state a person sees: internal steps and a lapsed review deadline are folded in. */
export function publicState(request, now) {
  if (request.state === 'pending' && request.expiresAt <= now) return 'expired';
  if (request.state === 'dispatching') return 'unconfirmed';
  if (request.state === 'preparing') return 'review_required';
  return request.state;
}

/** One request row. A denial reason leaves only when `includeDenialReason` allows it. */
export function publicRequest(request, now, { includeDenialReason = true } = {}) {
  return {
    id: request.id,
    ticketId: request.ticketId,
    title: request.title,
    tenantId: request.tenantId,
    beforeStatus: request.beforeStatus,
    afterStatus: request.afterStatus,
    resourceVersion: request.resourceVersion,
    operationId: request.operationId,
    digest: request.digest,
    expiresAt: request.expiresAt,
    createdAt: request.createdAt,
    state: publicState(request, now),
    ...(request.receipt ? { receipt: request.receipt } : {}),
    ...(request.reviewerId ? { reviewerId: request.reviewerId } : {}),
    requesterId: request.requesterId,
    ...(request.requesterKind ? { requesterKind: request.requesterKind } : {}),
    ...(includeDenialReason && request.denialReason ? { denialReason: request.denialReason } : {}),
    archived: !!request.archived,
    ...(request.cause ? { cause: request.cause } : {}),
  };
}

export function publicTicket({ tenantId: _tenant, ...ticket }) {
  return ticket;
}

/** A page of rows with the totals the client checks before showing it. */
export function pageBody(name, rows, total, { offset, limit }, extra = {}) {
  const nextOffset = offset + limit < total ? offset + limit : null;
  return { [name]: rows, ...extra, total, offset, limit, nextOffset, truncated: nextOffset !== null };
}
export const ticketsBody = (tickets, total, page) =>
  pageBody('tickets', tickets.map(publicTicket), total, page, { allowedStatuses: TICKET_STATUSES });
export const requestsBody = (requests, total, page, now) =>
  pageBody(
    'requests',
    requests.map(request => publicRequest(request, now)),
    total,
    page,
  );

/** What the stored action of a pending request will run, read back from the executor. */
export function actionBody(request, stored) {
  const action = stored.action ?? {};
  return {
    tool: action.tool,
    resourceId: action.resourceId,
    resourceVersion: action.resourceVersion,
    status: stored.status,
    // The executor's record and the request row must describe the same change.
    matchesRequest:
      stored.id === request.actionId &&
      stored.taskId === request.taskId &&
      stored.digest === request.actionDigest &&
      stored.requiresApproval === true &&
      stored.status === 'PREPARED' &&
      action.tool === 'ticket.update' &&
      action.args?.requestId === request.id &&
      action.resourceId === request.ticketId &&
      action.tenantId === request.tenantId &&
      String(action.resourceVersion) === request.resourceVersion,
  };
}

export function errorBody(code) {
  return { error: { code, message: errorMessage(code) } };
}

export function sessionBody({ session, authorizationOrigins, issuer, policy }) {
  return {
    authenticated: !!session.operator,
    csrfToken: session.csrfToken,
    authorizationOrigins,
    publicAuthIssuer: issuer,
    ...(session.operator
      ? {
          operator: session.operator,
          expiresAt: session.expiresAt,
          policy: { forbidSelfApproval: policy.forbidSelfApproval === true },
        }
      : {}),
  };
}

/**
 * What an operator reviews before closing an unconfirmed request as not applied: no receipt, the
 * ticket as it was reviewed beside the ticket as it is now, and the executor's record of the call.
 */
export function closeOutEvidence(request, ticket, execution) {
  return {
    requestId: request.id,
    operationId: request.operationId,
    receipt: 'absent',
    ticketId: ticket.id,
    reviewedVersion: Number(request.resourceVersion),
    reviewedStatus: request.beforeStatus,
    ticketVersion: ticket.version,
    ticketStatus: ticket.status,
    ticketChanged: String(ticket.version) !== request.resourceVersion || ticket.status !== request.beforeStatus,
    execution,
  };
}

export function closeOutBody(evidence, digest) {
  return { closeOut: { ...evidence, digest } };
}

/** Enough to tell two finished requests for the same ticket apart. */
export function archiveCandidate(request, now) {
  return {
    taskId: request.taskId,
    requestId: request.id,
    ticketId: request.ticketId,
    state: publicState(request, now),
    requesterId: request.requesterId,
    createdAt: request.createdAt,
  };
}

export function archivePreviewBody({ id, taskId, requestId, digest, eligibleCount, expiresAt, blockers }) {
  return { preview: { id, taskId, requestId, digest, eligibleCount, expiresAt, blockers } };
}

export const KEY_ROTATION = Object.freeze({
  state: 'offline',
  message:
    'Stop the service, rotate keys with the reviewed offline custody commands for every enrolled store, verify each store, then restart. Keys never enter this browser.',
});

/**
 * Maintenance view of one tenant. `requests` are that tenant's stored rows, `eligible` the ones
 * the single archive rule admits, `company` the tenant's committed history state (or undefined).
 */
export function maintenanceBody({
  requests,
  eligible,
  now,
  limits,
  usage,
  historyCapacity,
  company,
  historyPending,
  statistics,
}) {
  return {
    archiveCandidates: eligible.slice(0, 500).map(request => archiveCandidate(request, now)),
    archiveCandidatesTruncated: eligible.length > 500,
    unresolvedCount: requests.filter(request => request.state === 'unconfirmed' || request.state === 'dispatching')
      .length,
    records: requests.length,
    recordLimit: limits.maxRequests,
    limits,
    usage,
    historyCapacity,
    history: {
      archivedRequests: company?.archivedRequests ?? '0',
      segments: company?.head?.index ?? 0,
      lastCommittedAt: company?.lastCommittedAt ?? null,
      commitment: company?.head?.hash ?? null,
      pending: !!historyPending,
      mode: 'reviewed-offline',
    },
    capacityWarning:
      usage.requests >= limits.maxRequests * 0.8 ||
      usage.tickets >= limits.maxTickets * 0.8 ||
      usage.backendBytes >= limits.maxBackendBytes * 0.8 ||
      historyCapacity.total >= historyCapacity.limit * 0.8,
    statistics,
    keyRotation: KEY_ROTATION,
  };
}

/** Recovery enrollment as the runtime observed it at startup, or `unverified` without one. */
export function recoveryBody(observed) {
  const verified =
    observed &&
    ['current-state-mirror', 'not-enrolled'].includes(observed.mode) &&
    count(observed.verifiedAt) &&
    observed.verifiedAt > 0 &&
    ['executorMirror', 'backendMirror', 'historyMirror'].every(key => typeof observed[key] === 'boolean');
  if (!verified) return { mode: 'unverified', verifiedAt: null };
  return {
    mode:
      observed.executorMirror && observed.backendMirror && observed.historyMirror
        ? 'current-state-mirror'
        : 'not-enrolled',
    executorMirror: observed.executorMirror,
    backendMirror: observed.backendMirror,
    historyMirror: observed.historyMirror,
    verifiedAt: observed.verifiedAt,
  };
}

/**
 * Checks measured while answering this request. Each is `passed` or `attention`; none is a
 * constant. The stores check is only reached after both stores were read and verified.
 */
export function setupChecks({ securityLog, tlsExpiresAt, recovery, capacityWarning, now }) {
  const tlsDays = count(tlsExpiresAt) ? Math.floor((tlsExpiresAt - now) / 86_400_000) : null;
  const check = (id, label, passed, message) => ({ id, label, status: passed ? 'passed' : 'attention', message });
  return [
    check(
      'stores',
      'Encrypted stores',
      true,
      'Both encrypted stores and their independent witnesses were read and verified for this page.',
    ),
    check(
      'security_log',
      'Security event log',
      securityLog.configured && securityLog.failures === 0,
      !securityLog.configured
        ? 'No security-event logger is configured for this service.'
        : securityLog.failures
          ? 'Some security events could not be written to the configured logger since the service started.'
          : 'Security events are written to the configured logger.',
    ),
    check(
      'tls',
      'TLS certificate',
      tlsDays !== null && tlsDays >= 14,
      tlsDays === null
        ? 'The certificate expiry could not be read.'
        : tlsDays >= 14
          ? `The served certificate is valid for ${tlsDays} more days.`
          : `The served certificate expires in ${Math.max(0, tlsDays)} days. Renew it and reload the service.`,
    ),
    check(
      'recovery',
      'Current-state recovery',
      recovery.mode === 'current-state-mirror',
      recovery.mode === 'current-state-mirror'
        ? 'Both stores and the history directory had verified mirrors when the service started.'
        : recovery.mode === 'not-enrolled'
          ? 'This installation has not enrolled current-state mirrors.'
          : 'Recovery enrollment was not reported by this service.',
    ),
    check(
      'capacity',
      'Capacity',
      capacityWarning !== true,
      capacityWarning === true
        ? 'At least one capacity limit is above 80%. See Maintenance.'
        : 'Every measured resource is below 80% of its limit.',
    ),
  ];
}

const CONFIG = '"${AGENT_OPS_CONFIG_FILE:-/run/agent-ops/config.json}"';
export const SETUP_COMMANDS = Object.freeze([
  {
    label: 'Check configuration and OIDC discovery',
    command: `docker compose -f deployment/production/compose.yaml run --rm onboarding preflight --config ${CONFIG}`,
  },
  {
    label: 'Preview a company ticket import (stop the service first)',
    command: `docker compose -f deployment/production/compose.yaml run --rm onboarding import-tickets --config ${CONFIG} --tickets /run/company/additional-tickets.json`,
  },
  {
    label: 'Preview changed capacity limits (stop the service first)',
    command: `docker compose -f deployment/production/compose.yaml run --rm --entrypoint node maintenance apps/agent-ops/cli.mjs configure-limits --config ${CONFIG}`,
  },
]);

export function setupBody({ company, issuer, callbackUrl, counts, maintenance, recovery, keyring, checks }) {
  return {
    deployment: 'self-hosted',
    ...(company ? { company: { id: company.id, ...(company.name ? { name: company.name } : {}) } } : {}),
    identity: { issuer, callbackUrl },
    data: { kind: 'local-tickets', tickets: counts.tickets, requests: counts.requests, receipts: counts.receipts },
    limits: maintenance.limits,
    usage: maintenance.usage,
    historyCapacity: maintenance.historyCapacity,
    statistics: maintenance.statistics,
    recovery,
    ...(keyring ? { keyring } : {}),
    checks,
    commands: SETUP_COMMANDS,
  };
}
