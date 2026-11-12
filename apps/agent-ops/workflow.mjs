import { numberedTaskId } from '@shieldaai/agent-guard-executor';
import { randomUUID, createHash } from 'node:crypto';
import { normalizeLimits, assertCapacity, LIMIT_BOUNDS } from './limits.mjs';
import { allocateRequestIdentity, assertHistoryIdle, historyState, historySegmentUsage } from './history-state.mjs';
import { DENIAL_REASON_MAX, TICKET_STATUSES, isSettled, isTerminalState, receiptMatches } from './public/contract.js';
import {
  actionBody,
  archivePreviewBody,
  closeOutBody,
  closeOutEvidence,
  maintenanceBody,
  publicRequest,
  requestsBody,
  ticketsBody,
} from './responses.mjs';

export class OpsError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
export const fail = (code, status) => {
  throw new OpsError(code, status);
};
export function fields(value, names) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).some(key => !names.includes(key))
  )
    fail('INVALID_INPUT');
  return value;
}
export function identifier(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,159}$/.test(value)) fail('INVALID_INPUT');
  return value;
}
const statuses = TICKET_STATUSES;
/** Actor ids with this prefix are written by the service itself. Enrollment refuses them. */
export const SYSTEM_ACTOR_PREFIX = 'system:';
const RETENTION_ACTOR = `${SYSTEM_ACTOR_PREFIX}retention`;
/** Review and admission policy. Defaults keep existing installations' behaviour. */
const DEFAULT_REQUEST_POLICY = Object.freeze({
  reviewExpiryMs: 5 * 60_000,
  forbidSelfApproval: false,
  maxPendingPerRequester: 50,
  maxPendingPerTenant: 1000,
  // A reviewer's denial reason stays with signed-in people unless this is set.
  shareDenialReason: false,
});
export function normalizeRequestPolicy(value = {}) {
  const known = [...Object.keys(DEFAULT_REQUEST_POLICY), 'autoArchiveAfterDays'];
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).some(key => !known.includes(key))
  )
    fail('REQUEST_POLICY_INVALID');
  const policy = {
    ...DEFAULT_REQUEST_POLICY,
    ...Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)),
  };
  const integer = (item, min, max) => Number.isSafeInteger(item) && item >= min && item <= max;
  if (
    !integer(policy.reviewExpiryMs, 60_000, 24 * 60 * 60_000) ||
    typeof policy.forbidSelfApproval !== 'boolean' ||
    !integer(policy.maxPendingPerRequester, 1, 20_000) ||
    !integer(policy.maxPendingPerTenant, 1, 20_000) ||
    typeof policy.shareDenialReason !== 'boolean' ||
    (policy.autoArchiveAfterDays !== undefined && !integer(policy.autoArchiveAfterDays, 1, 3650))
  )
    fail('REQUEST_POLICY_INVALID');
  return Object.freeze(policy);
}
const own = (object, key) => (Object.hasOwn(object, key) ? object[key] : undefined);
/** A stable uppercase identifier taken from an error; never its message, a path or request data. */
export const safeCode = (error, fallback) =>
  typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : fallback;
// Errors raised inside a backend transaction body. The store rolls such a transaction back,
// so nothing it attempted was committed.
const refusedBeforeCommit = new WeakSet();
const unresolved = state => state === 'unconfirmed' || state === 'dispatching';
// Executor statuses of an admitted action whose outcome the executor has not recorded.
const UNSETTLED = Object.freeze(['UNKNOWN', 'RUNNING', 'ADMITTED']);
/**
 * The fingerprint a reviewer approves: the stored action and every field of the row that decides
 * what the approval does. Recomputed from the row wherever the fingerprint is relied on.
 */
const reviewDigest = request =>
  hash([
    request.id,
    request.actionDigest,
    request.ticketId,
    request.beforeStatus,
    request.afterStatus,
    request.resourceVersion,
    request.expiresAt,
  ]);
const clone = value => structuredClone(value);
function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return value;
}
/** An optional short note from the reviewer who denies a request. Plain text on one line. */
function denialReason(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') fail('INVALID_INPUT');
  const reason = value.trim();
  if (reason.length > DENIAL_REASON_MAX || /[\u0000-\u001f\u007f\u2028\u2029]/.test(reason)) fail('INVALID_INPUT');
  return reason || undefined;
}
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const committedBytes = state => Buffer.byteLength(JSON.stringify({ ...state, revision: state.revision + 1 }));
function page(options = {}) {
  fields(options, ['offset', 'limit']);
  const { offset = 0, limit = 500 } = options;
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset > LIMIT_BOUNDS.maxRequests.max ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 500
  )
    fail('PAGINATION_INVALID');
  return { offset, limit };
}

/** Safe to call before creating keys, ledgers or witnesses. Empty enrollment is valid. */
export function validateTicketSeed(tickets, limits) {
  const policy = normalizeLimits(limits);
  if (!Array.isArray(tickets) || tickets.length > policy.maxTickets) fail('INVALID_SEED');
  const ids = new Set();
  return Array.from(tickets, item => {
    fields(item, ['id', 'tenantId', 'title', 'status']);
    identifier(item.id);
    identifier(item.tenantId);
    if (
      ids.has(item.id) ||
      typeof item.title !== 'string' ||
      !item.title.trim() ||
      item.title.length > 240 ||
      !statuses.includes(item.status)
    )
      fail('INVALID_SEED');
    ids.add(item.id);
    return { id: item.id, tenantId: item.tenantId, title: item.title, status: item.status };
  });
}

/** A separate encrypted, witnessed business store. A ticket CAS and its operation receipt commit together. */
export function initializeTickets(store, { guardInstanceId, tickets, limits }) {
  identifier(guardInstanceId);
  const policy = normalizeLimits(limits),
    seed = validateTicketSeed(tickets, policy);
  const rows = Object.create(null);
  for (const item of seed) rows[item.id] = { ...item, version: 1 };
  store.transaction(state => {
    if (state.ticketService) fail('ALREADY_INITIALIZED');
    state.ticketService = {
      version: 1,
      guardInstanceId,
      limits: policy,
      tickets: rows,
      requests: Object.create(null),
      receipts: Object.create(null),
      audit: [],
      lastClock: 0,
    };
    assertCapacity(state.ticketService, policy);
    if (committedBytes(state) > policy.maxBackendBytes) fail('LIMITS_BELOW_USAGE', 409);
  });
}

export class TicketWorkflow {
  #view;
  #limitsKey;
  constructor({
    executor,
    store,
    guardInstanceId,
    limits,
    requestPolicy,
    clock = Date.now,
    afterCommit,
    acceptClockSkewMs,
  }) {
    this.executor = executor;
    this.store = store;
    this.clock = clock;
    this.afterCommit = afterCommit;
    this.limits = normalizeLimits(limits);
    this.#limitsKey = JSON.stringify(this.limits);
    this.requestPolicy = normalizeRequestPolicy(requestPolicy);
    this.busy = new Set();
    this.previews = new Map();
    this.dispatchAuthorization = new Map();
    this.dispatchRefusals = new Map();
    if (acceptClockSkewMs !== undefined) {
      // Operator override for a backward clock step, at startup only (see the executor option).
      this.store.transaction(state => {
        const data = state.ticketService,
          now = this.clock();
        if (Number.isSafeInteger(now) && now < data.lastClock && data.lastClock - now <= acceptClockSkewMs)
          data.lastClock = now;
      });
    }
    const state = this.data();
    assertHistoryIdle(state);
    if (state.guardInstanceId !== guardInstanceId) fail('AUTHORITY_STORE_MISMATCH', 503);
    // Process changes invalidate preparations. Never silently create fresh approval authority.
    this.write(data => {
      data.limits ??= this.limits; // Existing default-policy installations migrate without changing limits.
      for (const request of Object.values(data.requests)) {
        if (request.state === 'pending' || request.state === 'preparing') request.state = 'review_required';
        if (request.state === 'dispatching') {
          request.state = 'unconfirmed';
          request.cause ??= 'RESTARTED_DURING_DISPATCH';
        }
        if (request.archiveIntent && !request.archived) {
          const archive = executor.findTaskFamilyArchive({ tenantId: request.tenantId, taskId: request.taskId });
          if (archive) {
            request.archived = archive.archiveId;
            delete request.archiveIntent;
          }
        }
      }
    });
    const fingerprint = executor.registerTool({
      name: 'ticket.update',
      description: 'Change an enrolled ticket status once after exact human review',
      maxCost: 1,
      requiresApproval: true,
      parse: args => {
        fields(args, ['requestId']);
        return { requestId: identifier(args.requestId) };
      },
      resolve: args => {
        const request = this.request(args.requestId),
          ticket = this.ticket(request.ticketId, request.tenantId);
        return { resourceId: ticket.id, tenantId: ticket.tenantId, resourceVersion: String(ticket.version) };
      },
      execute: args => ({ value: this.commit(args.requestId), actualCost: 1 }),
    });
    executor.approveTool('ticket.update', fingerprint);
  }
  /**
   * The current business state, decoded and checked once per committed revision. Every call
   * still reads the authenticated ciphertext and compares it with the witness; only decoding,
   * validation and measuring are reused while that ciphertext is unchanged. The result is
   * frozen: all changes go through write().
   */
  #load() {
    let commitment;
    try {
      commitment = this.store.snapshotCommitment?.();
    } catch {
      commitment = undefined; // The full read below reports the store's own error.
    }
    if (commitment !== undefined && this.#view?.commitment === commitment) return this.#view;
    const state = this.store.read(),
      data = state.ticketService;
    if (!data || data.version !== 1 || !data.tickets || !data.requests || !data.receipts || !Array.isArray(data.audit))
      fail('BACKEND_STATE_INVALID', 503);
    if (JSON.stringify(normalizeLimits(data.limits)) !== this.#limitsKey) fail('LIMITS_CHANGE_REQUIRES_OFFLINE', 409);
    const serialized = JSON.stringify(state);
    const usage = Object.freeze({
      ...assertCapacity(data, this.limits),
      backendBytes: Buffer.byteLength(serialized),
    });
    historyState(data);
    const view = {
      commitment: commitment ?? createHash('sha256').update(serialized).digest('hex'),
      data: deepFreeze(data),
      usage,
    };
    this.#view = commitment === undefined ? undefined : view;
    return view;
  }
  data() {
    return this.#load().data;
  }
  assertPolicy(data) {
    if (JSON.stringify(normalizeLimits(data.limits)) !== this.#limitsKey) fail('LIMITS_CHANGE_REQUIRES_OFFLINE', 409);
    assertCapacity(data, this.limits);
  }
  /** A full verified read of both stores, never the reused view. */
  health() {
    this.#view = undefined;
    this.#load();
    this.executor.audit();
  }
  /** Changes whenever the request list of this tenant would read differently. */
  requestsRevision(tenantId) {
    identifier(tenantId);
    const { commitment, data } = this.#load(),
      now = this.clock();
    let lapsed = 0;
    for (const request of Object.values(data.requests))
      if (request.tenantId === tenantId && request.state === 'pending' && request.expiresAt <= now) lapsed++;
    return `${commitment}.${lapsed}`;
  }
  write(callback) {
    return this.store.transaction(state => {
      try {
        const data = state.ticketService,
          now = this.clock();
        this.assertPolicy(data);
        if (!Number.isSafeInteger(now) || now < data.lastClock) fail('CLOCK_INVALID', 503);
        data.lastClock = now;
        const result = callback(data, now);
        if (data.history !== undefined && state.schema === 1) state.schema = 2;
        this.assertPolicy(data);
        if (committedBytes(state) > this.limits.maxBackendBytes) fail('LIMITS_BELOW_USAGE', 409);
        return result;
      } catch (error) {
        if (error !== null && typeof error === 'object') refusedBeforeCommit.add(error);
        throw error;
      }
    });
  }
  event(data, now, event, request, operatorId, code) {
    data.audit.push({
      at: now,
      event,
      requestId: request.id,
      tenantId: request.tenantId,
      ...(operatorId ? { operatorId } : {}),
      ...(code ? { code } : {}),
    });
    // No authority is reconstructed from this bounded activity log; receipts and review identities are retained.
    if (data.audit.length > 4000) data.audit.splice(0, data.audit.length - 4000);
  }
  ticket(id, tenantId) {
    const ticket = own(this.data().tickets, id);
    if (!ticket || ticket.tenantId !== tenantId) fail('NOT_FOUND', 404);
    return ticket;
  }
  request(id, tenantId) {
    const request = own(this.data().requests, id);
    if (!request || (tenantId !== undefined && request.tenantId !== tenantId)) fail('NOT_FOUND', 404);
    return request;
  }
  /** `forAgent` applies the denial-reason policy; signed-in people always see the reason. */
  public(request, { forAgent = false } = {}) {
    return publicRequest(request, this.clock(), {
      includeDenialReason: !forAgent || this.requestPolicy.shareDenialReason,
    });
  }
  /** One request with what its stored action will run, read back from the executor's ledger. */
  detail(id, tenantId) {
    const request = this.request(id, tenantId),
      result = { request: this.public(request) };
    if (result.request.state !== 'pending' || !request.actionId) return result;
    try {
      result.action = actionBody(request, this.executor.preparedAction(request.actionId));
    } catch (error) {
      if (error?.code !== 'INVALID_PREPARED') throw error; // No stored action: nothing to approve.
    }
    return result;
  }
  tickets(tenantId, options) {
    identifier(tenantId);
    const selected = page(options);
    const all = Object.values(this.data().tickets)
      .filter(t => t.tenantId === tenantId)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return ticketsBody(all.slice(selected.offset, selected.offset + selected.limit), all.length, selected);
  }
  requests(tenantId, options) {
    identifier(tenantId);
    const selected = page(options);
    const all = Object.values(this.data().requests)
      .filter(r => r.tenantId === tenantId)
      .sort(
        (a, b) =>
          Number(isTerminalState(a.state)) - Number(isTerminalState(b.state)) ||
          b.createdAt - a.createdAt ||
          (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
      );
    return requestsBody(
      all.slice(selected.offset, selected.offset + selected.limit),
      all.length,
      selected,
      this.clock(),
    );
  }
  async propose(operator, input, assertAuthorized = () => {}) {
    fields(input, ['ticketId', 'status']);
    identifier(input.ticketId);
    if (!statuses.includes(input.status)) fail('INVALID_STATUS');
    assertAuthorized();
    // Decided before any lookup: a ticket outside the allowlist gets one answer whether or not it exists.
    if (operator.allowedTicketIds && !operator.allowedTicketIds.includes(input.ticketId)) fail('FORBIDDEN', 403);
    const ticket = this.ticket(input.ticketId, operator.tenantId);
    if (ticket.status === input.status) fail('NO_CHANGE', 409);
    const now = this.clock();
    let request;
    this.write(data => {
      if (Object.keys(data.requests).length >= this.limits.maxRequests) fail('RECORD_CAPACITY_REACHED', 503);
      // A looping requester or agent fills only its own share of open reviews.
      let mine = 0,
        tenant = 0;
      for (const open of Object.values(data.requests)) {
        if (
          open.tenantId !== operator.tenantId ||
          !(open.state === 'preparing' || (open.state === 'pending' && open.expiresAt > now))
        )
          continue;
        tenant++;
        if (open.requesterId === operator.id) mine++;
      }
      if (mine >= this.requestPolicy.maxPendingPerRequester || tenant >= this.requestPolicy.maxPendingPerTenant)
        fail('PENDING_LIMIT_REACHED', 429);
      const identity = allocateRequestIdentity(data, operator.tenantId),
        id = identity.id;
      if (Object.hasOwn(data.requests, id)) fail('HISTORY_ID_COLLISION', 503);
      request = {
        id,
        sequence: identity.sequence,
        taskId: numberedTaskId(identity.namespace, identity.sequence),
        operationId: `operation-${id}`,
        tenantId: operator.tenantId,
        requesterId: operator.id,
        requesterKind: operator.kind === 'agent' ? 'agent' : 'person',
        ticketId: ticket.id,
        title: ticket.title,
        beforeStatus: ticket.status,
        afterStatus: input.status,
        resourceVersion: String(ticket.version),
        createdAt: now,
        expiresAt: now + this.requestPolicy.reviewExpiryMs,
        state: 'preparing',
      };
      data.requests[id] = request;
    });
    const { id, taskId } = request;
    try {
      this.executor.createTask({
        id: taskId,
        principalId: operator.id,
        tenantId: operator.tenantId,
        grants: [{ tool: 'ticket.update', resources: [ticket.id] }],
        budget: { maxCalls: 1, maxConcurrent: 1, maxCost: 1, deadline: request.expiresAt },
      });
      const prepared = await this.executor.prepare(taskId, { tool: 'ticket.update', args: { requestId: id } });
      assertAuthorized();
      this.write((data, at) => {
        Object.assign(data.requests[id], {
          actionId: prepared.id,
          actionDigest: prepared.digest,
          digest: reviewDigest({ ...request, actionDigest: prepared.digest }),
          state: 'pending',
        });
        this.event(data, at, 'REQUESTED', request, operator.id);
      });
    } catch (error) {
      try {
        this.executor.revokeTask(taskId);
      } catch {
        /* A failed task creation never granted authority. */
      }
      let noTask = false;
      try {
        this.executor.snapshot(taskId);
      } catch (readError) {
        noTask = readError?.code === 'INVALID_TASK';
      }
      this.write((data, at) => {
        data.requests[id].state = 'failed';
        data.requests[id].cause = safeCode(error, 'PREPARATION_FAILED');
        if (noTask) data.requests[id].noTask = true;
        this.event(data, at, 'PREPARATION_FAILED', request, operator.id, data.requests[id].cause);
      });
      throw error;
    }
    return { request: this.public(this.request(id, operator.tenantId), { forAgent: operator.kind === 'agent' }) };
  }
  async decide(operator, id, input, approve, assertAuthorized = () => {}) {
    fields(input, approve ? ['digest'] : ['digest', 'reason']);
    const reason = approve ? undefined : denialReason(input.reason);
    assertAuthorized();
    const request = this.request(id, operator.tenantId);
    if (
      this.busy.has(id) ||
      request.state !== 'pending' ||
      request.digest !== input.digest ||
      // The stored fingerprint must still be the fingerprint of this row.
      reviewDigest(request) !== request.digest
    )
      fail('REVIEW_STALE', 409);
    if (approve && this.requestPolicy.forbidSelfApproval && request.requesterId === operator.id)
      // 409, not 403: the reviewer keeps their role; only this request needs someone else.
      fail('SELF_APPROVAL_FORBIDDEN', 409);
    if (request.expiresAt <= this.clock()) {
      this.write(data => {
        data.requests[id].state = 'expired';
      });
      fail('REVIEW_EXPIRED', 409);
    }
    const ticket = this.ticket(request.ticketId, operator.tenantId);
    if (String(ticket.version) !== request.resourceVersion) {
      this.write(data => {
        data.requests[id].state = 'changed';
      });
      fail('TICKET_CHANGED', 409);
    }
    this.busy.add(id);
    try {
      if (!approve) {
        this.executor.revokeTask(request.taskId);
        this.write((data, now) => {
          data.requests[id].state = 'denied';
          data.requests[id].reviewerId = operator.id;
          if (reason) data.requests[id].denialReason = reason;
          this.event(data, now, 'DENIED', request, operator.id);
        });
      } else {
        assertAuthorized();
        // The executor's stored action must be the change this row describes. A stored action
        // that is gone (its task expired or was revoked) is the same answer: nothing to approve.
        let stored;
        try {
          stored = this.executor.preparedAction(request.actionId);
        } catch (error) {
          if (error?.code !== 'INVALID_PREPARED') throw error;
        }
        if (!stored || !actionBody(request, stored).matchesRequest) fail('REVIEW_STALE', 409);
        const approvalId = this.executor.approve(request.actionId, {
          approverId: operator.id,
          expiresAt: request.expiresAt,
        });
        this.write((data, now) => {
          data.requests[id].state = 'dispatching';
          data.requests[id].reviewerId = operator.id;
          this.event(data, now, 'APPROVED', request, operator.id);
        });
        // Synchronous backend commit checks the live authorization again immediately before its effect.
        this.dispatchAuthorization.set(id, assertAuthorized);
        try {
          await this.executor.execute(request.taskId, request.actionId, { approvalId });
          this.write(data => {
            data.requests[id].state = 'completed';
            data.requests[id].receipt = data.receipts[request.operationId];
          });
        } catch (error) {
          const refusal = this.dispatchRefusals.get(id);
          let { status } = this.#execution(request),
            cause = refusal ?? safeCode(error, 'DISPATCH_FAILED');
          const applied = !!own(this.data().receipts, request.operationId);
          // The backend refused inside this process before its transaction committed, and the
          // durable store holds no receipt for this operation: the change provably did not
          // happen. Settle the reservation at zero cost. Anything else stays unconfirmed.
          if (refusal && UNSETTLED.includes(status) && !applied) {
            try {
              this.executor.reconcile(request.actionId, {
                outcome: 'FAILED',
                actualCost: 0,
                reference: JSON.stringify({ operationId: request.operationId, requestId: id, refused: refusal }),
              });
              status = 'FAILED';
            } catch (settleError) {
              cause = safeCode(settleError, 'SETTLEMENT_FAILED'); // Left for the operator's reviewed close-out.
            }
          }
          // Definitive only when the executor settled the call as failed and no receipt exists, or
          // when the action never left PREPARED. Every other answer, including one this service
          // does not recognise, stays unconfirmed for an operator.
          const next = applied
            ? 'unconfirmed'
            : status === 'FAILED'
              ? refusal === 'TICKET_CHANGED'
                ? 'changed'
                : 'failed'
              : status === 'PREPARED'
                ? 'review_required'
                : 'unconfirmed';
          this.write((data, now) => {
            data.requests[id].state = next;
            data.requests[id].cause = cause;
            this.event(
              data,
              now,
              next === 'unconfirmed' ? 'OUTCOME_UNCONFIRMED' : refusal ? 'DISPATCH_REFUSED' : 'DISPATCH_FAILED',
              request,
              operator.id,
              cause,
            );
          });
        } finally {
          this.dispatchAuthorization.delete(id);
          this.dispatchRefusals.delete(id);
        }
      }
    } finally {
      this.busy.delete(id);
    }
    return { request: this.public(this.request(id, operator.tenantId)) };
  }
  /** The requester takes back their own request before anyone decides it. Nothing is applied. */
  withdraw(operator, id, input, assertAuthorized = () => {}) {
    fields(input, ['digest']);
    assertAuthorized();
    const request = this.request(id, operator.tenantId);
    // 409, not 403: the person keeps their role; this request is simply not theirs.
    if (request.requesterId !== operator.id) fail('WITHDRAW_FORBIDDEN', 409);
    if (this.busy.has(id) || request.state !== 'pending' || request.digest !== input.digest) fail('REVIEW_STALE', 409);
    this.busy.add(id);
    try {
      this.executor.revokeTask(request.taskId);
      this.write((data, now) => {
        data.requests[id].state = 'withdrawn';
        this.event(data, now, 'WITHDRAWN', request, operator.id);
      });
    } finally {
      this.busy.delete(id);
    }
    return { request: this.public(this.request(id, operator.tenantId)) };
  }
  commit(id) {
    const assertAuthorized = this.dispatchAuthorization.get(id);
    if (!assertAuthorized) fail('DISPATCH_AUTHORITY_MISSING', 403);
    let authorized = false;
    try {
      assertAuthorized();
      authorized = true;
      return this.#commit(id);
    } catch (error) {
      // Only a refusal raised before the store began committing is recorded as definitive.
      if (!authorized) this.dispatchRefusals.set(id, safeCode(error, 'AUTHORIZATION_REVOKED'));
      else if (refusedBeforeCommit.has(error)) this.dispatchRefusals.set(id, safeCode(error, 'DISPATCH_REFUSED'));
      throw error;
    }
  }
  #commit(id) {
    const receipt = this.write((data, now) => {
      const request = data.requests[id],
        ticket = data.tickets[request.ticketId];
      if (request.state !== 'dispatching' || !request.reviewerId || reviewDigest(request) !== request.digest)
        fail('DISPATCH_AUTHORITY_MISSING', 403);
      const prior = own(data.receipts, request.operationId);
      if (prior) return prior;
      if (
        request.expiresAt <= now ||
        ticket.tenantId !== request.tenantId ||
        String(ticket.version) !== request.resourceVersion ||
        ticket.status !== request.beforeStatus
      )
        fail('TICKET_CHANGED', 409);
      if (Object.keys(data.receipts).length >= this.limits.maxRequests) fail('RECORD_CAPACITY_REACHED', 503);
      ticket.status = request.afterStatus;
      ticket.version++;
      const receipt = {
        operationId: request.operationId,
        requestId: id,
        digest: request.digest,
        ticketId: ticket.id,
        tenantId: ticket.tenantId,
        status: ticket.status,
        version: ticket.version,
        recordedAt: now,
      };
      data.receipts[request.operationId] = receipt;
      this.event(data, now, 'TICKET_COMMITTED', request, request.reviewerId);
      return clone(receipt);
    });
    this.afterCommit?.(receipt); // Test-only fault injection after the durable transaction; no runtime configuration exposes this.
    return receipt;
  }
  /**
   * What the executor's ledger holds for a request's action: the executor's own status, or the
   * outcome a pruned receipt kept. `ABSENT` means the action is gone, or is only known to have
   * settled (a pruned receipt without its outcome); the task's accounting then decides.
   */
  #execution(request) {
    let receipt;
    try {
      receipt = this.executor.execution(request.taskId, request.actionId);
    } catch (error) {
      if (error?.code !== 'INVALID_PREPARED') throw error;
      return { status: 'ABSENT' };
    }
    if (receipt.status !== 'PRUNED') return receipt;
    return receipt.outcome === 'SUCCEEDED' || receipt.outcome === 'FAILED'
      ? { ...receipt, status: receipt.outcome }
      : { status: 'ABSENT' };
  }
  /** The task's call and cost counters, or undefined when the executor no longer has the task. */
  #accounting(request) {
    try {
      return this.executor.snapshot(request.taskId);
    } catch {
      return undefined;
    }
  }
  reconcile(operator, id) {
    const request = this.request(id, operator.tenantId);
    if (this.busy.has(id) || !unresolved(request.state)) fail('RECONCILIATION_UNAVAILABLE', 409);
    const receipt = own(this.data().receipts, request.operationId);
    // Absence never means permission to retry; closing it as failed is a separate reviewed step (closeOut).
    if (!receipt) fail('RECEIPT_NOT_FOUND', 409);
    if (!receiptMatches(request, receipt)) fail('RECEIPT_MISMATCH', 503);
    let { status } = this.#execution(request);
    if (status === 'ABSENT') {
      // The SDK may prune a terminal action before this business marker is saved.
      // This host gives each nondelegated task exactly one call/cost unit. A missing
      // action plus settled one-unit accounting and its exact backend receipt can
      // finish the marker; it cannot release an unsettled reservation or reexecute.
      const task = this.#accounting(request);
      if (!task || task.calls !== 1 || task.spent !== 1 || task.reserved !== 0 || task.concurrent !== 0)
        fail('RECONCILIATION_UNAVAILABLE', 409);
      status = 'SUCCEEDED';
    }
    if (UNSETTLED.includes(status))
      this.executor.reconcile(request.actionId, {
        outcome: 'SUCCEEDED',
        actualCost: 1,
        reference: JSON.stringify(receipt),
      });
    else if (status !== 'SUCCEEDED') fail('RECONCILIATION_UNAVAILABLE', 409);
    this.write((data, now) => {
      data.requests[id].state = 'completed';
      data.requests[id].receipt = receipt;
      this.event(data, now, 'RECONCILED', request, operator.id);
    });
    return { request: this.public(this.request(id, operator.tenantId)) };
  }
  /** What the durable stores prove about an unresolved request that has no receipt. */
  #closeOutEvidence(operator, id) {
    const request = this.request(id, operator.tenantId);
    if (this.busy.has(id) || !unresolved(request.state)) fail('RECONCILIATION_UNAVAILABLE', 409);
    const data = this.data();
    if (own(data.receipts, request.operationId)) fail('RECEIPT_FOUND', 409); // Reconcile it instead.
    // The ticket write and its receipt commit in one transaction of this single-owner store, so
    // the missing receipt alone proves this request's change was never applied. The ticket may
    // have been changed since by another request: the operator sees its reviewed and its current
    // version and status side by side, and the digest binds exactly what was shown.
    const ticket = own(data.tickets, request.ticketId);
    if (!ticket || ticket.tenantId !== request.tenantId) fail('CLOSE_OUT_UNPROVEN', 409);
    const execution = this.#execution(request);
    let status = execution.status;
    if (status === 'ABSENT') {
      // The executor no longer holds the action. This host gives each task one call that costs
      // one unit when it succeeds: a task that never admitted a call never ran its handler, and
      // one settled call with nothing spent was settled as failed.
      const task = this.#accounting(request);
      if (!task || task.spent !== 0 || task.reserved !== 0 || task.concurrent !== 0 || task.calls > 1)
        fail('CLOSE_OUT_UNPROVEN', 409);
      status = task.calls === 0 ? 'NEVER_ADMITTED' : 'SETTLED_NO_CHARGE';
    } else if (
      // An unsettled call is settled at zero cost on close; PREPARED never reached the backend;
      // FAILED was settled at zero cost.
      !UNSETTLED.includes(status) &&
      status !== 'PREPARED' &&
      !(status === 'FAILED' && execution.charged === 0)
    )
      fail('CLOSE_OUT_UNPROVEN', 409);
    const evidence = closeOutEvidence(request, ticket, status);
    return { request, status, evidence, digest: hash(['close-out-v2', request.digest ?? null, evidence]) };
  }
  /** Read-only: the evidence and digest an operator reviews before closing an unconfirmed request as failed. */
  previewCloseOut(operator, id) {
    const { evidence, digest } = this.#closeOutEvidence(operator, id);
    return closeOutBody(evidence, digest);
  }
  /**
   * Explicit reviewed way out of an unconfirmed request that will never get a receipt (for example
   * a crash between approval and the backend commit). It never retries or submits the change.
   */
  closeOut(operator, id, input) {
    fields(input, ['digest']);
    const { request, status, evidence, digest } = this.#closeOutEvidence(operator, id);
    if (typeof input.digest !== 'string' || input.digest !== digest) fail('CLOSE_OUT_STALE', 409);
    if (UNSETTLED.includes(status))
      this.executor.reconcile(request.actionId, {
        outcome: 'FAILED',
        actualCost: 0,
        reference: JSON.stringify({ operationId: request.operationId, requestId: id, closeOut: digest }),
      });
    else if (status === 'PREPARED' || status === 'NEVER_ADMITTED') this.executor.revokeTask(request.taskId); // The approved action can never run.
    this.write((data, now) => {
      const item = data.requests[id],
        ticket = own(data.tickets, item.ticketId);
      if (
        !unresolved(item.state) ||
        own(data.receipts, item.operationId) ||
        !ticket ||
        // The ticket is still exactly as the reviewed evidence showed it.
        ticket.version !== evidence.ticketVersion ||
        ticket.status !== evidence.ticketStatus
      )
        fail('CLOSE_OUT_STALE', 409);
      item.state = 'failed';
      item.cause = 'CLOSED_WITHOUT_RECEIPT';
      this.event(data, now, 'CLOSED_OUT', item, operator.id, item.cause);
    });
    return { request: this.public(this.request(id, operator.tenantId)) };
  }
  /**
   * The one archive rule: a finished request (or a pending one past its deadline) that still
   * has an executor task, is not already archived and is not being decided right now. A request
   * that is still being prepared is never eligible.
   */
  #archivable(request, now) {
    return !request.archived && !request.noTask && !this.busy.has(request.id) && isSettled(request, now);
  }
  maintenance(operator) {
    const { data, usage } = this.#load(),
      now = this.clock(),
      history = historyState(data);
    const requests = Object.values(data.requests).filter(r => r.tenantId === operator.tenantId);
    return maintenanceBody({
      requests,
      eligible: requests.filter(r => this.#archivable(r, now)),
      now,
      limits: this.limits,
      usage,
      historyCapacity: historySegmentUsage(data),
      company: history?.companies?.[operator.tenantId],
      historyPending: history?.pending,
      statistics: this.executor.maintenanceStatistics({ tenantId: operator.tenantId }),
    });
  }
  previewArchive(operator, input) {
    fields(input, ['taskId']);
    identifier(input.taskId);
    const request = Object.values(this.data().requests).find(
      r => r.taskId === input.taskId && r.tenantId === operator.tenantId,
    );
    if (!request || !this.#archivable(request, this.clock())) fail('ARCHIVE_UNAVAILABLE', 409);
    const plan = this.executor.previewTaskFamilyRetirement({ tenantId: operator.tenantId, taskId: input.taskId });
    for (const [id, preview] of this.previews) if (preview.expiresAt <= this.clock()) this.previews.delete(id);
    if (this.previews.size >= 256) fail('PREVIEW_CAPACITY_REACHED', 503);
    const preview = {
      id: randomUUID(),
      taskId: input.taskId,
      digest: plan.reviewDigest,
      requestId: request.id,
      eligibleCount: plan.counts.tasks,
      expiresAt: this.clock() + 60_000,
      blockers: [...new Set([...plan.retirementBlockers, ...plan.archiveBlockers])].filter(
        x => x !== 'FAMILY_NOT_RETIRED',
      ),
    };
    this.previews.set(preview.id, {
      ...preview,
      retired: plan.retired,
      operatorId: operator.id,
      tenantId: operator.tenantId,
    });
    return archivePreviewBody(preview);
  }
  archive(operator, input) {
    fields(input, ['id', 'digest']);
    const preview = this.previews.get(input.id);
    if (
      !preview ||
      preview.operatorId !== operator.id ||
      preview.tenantId !== operator.tenantId ||
      preview.digest !== input.digest ||
      preview.expiresAt <= this.clock() ||
      preview.blockers.length
    )
      fail('ARCHIVE_PREVIEW_STALE', 409);
    this.previews.delete(input.id);
    const receipt = this.#archiveFamily(
      { tenantId: operator.tenantId, taskId: preview.taskId },
      preview.requestId,
      preview.retired,
      preview.digest,
      'ARCHIVED',
      operator.id,
    );
    return { archivedCount: receipt.counts.tasks };
  }
  /** Retire (if needed) and archive one request's task family, recording the intent first. */
  #archiveFamily(scope, requestId, retired, digest, event, actorId) {
    if (!retired) this.executor.retireTaskFamily({ ...scope, expectedDigest: digest });
    const archiveDigest = retired ? digest : this.executor.previewTaskFamilyRetirement(scope).reviewDigest;
    this.write(data => {
      data.requests[requestId].archiveIntent = true;
    });
    const receipt = this.executor.archiveTaskFamily({ ...scope, expectedDigest: archiveDigest });
    this.write((data, now) => {
      const request = data.requests[requestId];
      request.archived = receipt.archiveId;
      delete request.archiveIntent;
      this.event(data, now, event, request, actorId);
    });
    return receipt;
  }
  /**
   * Online retention: archive the executor task families of finished requests older than
   * `requests.autoArchiveAfterDays`, oldest first, at most `limit` per run, through the same
   * retire-then-archive path an operator uses. A request with any blocker is skipped and left
   * for review. Moving request records into company history files stays an offline job.
   */
  autoArchive({ limit = 10 } = {}) {
    const days = this.requestPolicy.autoArchiveAfterDays;
    if (days === undefined) return { archived: 0, skipped: 0 };
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) fail('INVALID_INPUT');
    const now = this.clock(),
      cutoff = now - days * 24 * 60 * 60_000;
    // An interrupted archive (archiveIntent) is left for an operator to finish.
    const due = Object.values(this.data().requests)
      .filter(r => this.#archivable(r, now) && !r.archiveIntent && r.createdAt <= cutoff)
      .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))
      .slice(0, limit);
    let archived = 0,
      skipped = 0;
    const causes = new Set();
    for (const request of due) {
      try {
        const scope = { tenantId: request.tenantId, taskId: request.taskId };
        const plan = this.executor.previewTaskFamilyRetirement(scope);
        const blockers = [...plan.retirementBlockers, ...plan.archiveBlockers].filter(
          code => code !== 'FAMILY_NOT_RETIRED',
        );
        if (blockers.length) {
          skipped++;
          for (const code of blockers) causes.add(safeCode({ code }, 'ARCHIVE_BLOCKED'));
          continue;
        }
        this.#archiveFamily(scope, request.id, plan.retired, plan.reviewDigest, 'AUTO_ARCHIVED', RETENTION_ACTOR);
        archived++;
      } catch (error) {
        skipped++; // Left for an operator; the codes say why without naming a request.
        causes.add(safeCode(error, 'ARCHIVE_FAILED'));
      }
    }
    return { archived, skipped, ...(causes.size ? { causes: [...causes].sort() } : {}) };
  }
}
