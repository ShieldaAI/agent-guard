import { randomUUID, createHash } from 'node:crypto';
import { normalizeLimits, assertCapacity, LIMIT_BOUNDS } from './limits.mjs';
import { allocateRequestIdentity, assertHistoryIdle, historyState, historySegmentUsage } from './history-state.mjs';

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
const statuses = ['open', 'resolved'];
const terminal = new Set(['completed', 'denied', 'expired', 'changed', 'failed', 'review_required']);
/** Review and admission policy. Defaults keep existing installations' behaviour. */
export const DEFAULT_REQUEST_POLICY = Object.freeze({
  reviewExpiryMs: 5 * 60_000,
  forbidSelfApproval: false,
  maxPendingPerRequester: 50,
  maxPendingPerTenant: 1000,
});
export function normalizeRequestPolicy(value = {}) {
  fields(value, Object.keys(DEFAULT_REQUEST_POLICY));
  const policy = {
    ...DEFAULT_REQUEST_POLICY,
    ...Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)),
  };
  const integer = (item, min, max) => Number.isSafeInteger(item) && item >= min && item <= max;
  if (
    !integer(policy.reviewExpiryMs, 60_000, 24 * 60 * 60_000) ||
    typeof policy.forbidSelfApproval !== 'boolean' ||
    !integer(policy.maxPendingPerRequester, 1, 20_000) ||
    !integer(policy.maxPendingPerTenant, 1, 20_000)
  )
    fail('REQUEST_POLICY_INVALID');
  return Object.freeze(policy);
}
const own = (object, key) => (Object.hasOwn(object, key) ? object[key] : undefined);
// A receipt pruned by executor retention keeps its settled outcome.
const settledStatus = receipt => (receipt.status === 'PRUNED' ? receipt.outcome : receipt.status);
const clone = value => structuredClone(value);
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
function pagination(total, { offset, limit }) {
  const nextOffset = offset + limit < total ? offset + limit : null;
  return { total, offset, limit, nextOffset, truncated: nextOffset !== null };
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
  constructor({ executor, store, guardInstanceId, limits, requestPolicy, clock = Date.now, afterCommit }) {
    this.executor = executor;
    this.store = store;
    this.clock = clock;
    this.afterCommit = afterCommit;
    this.limits = normalizeLimits(limits);
    this.requestPolicy = normalizeRequestPolicy(requestPolicy);
    this.busy = new Set();
    this.previews = new Map();
    this.dispatchAuthorization = new Map();
    const state = this.data();
    assertHistoryIdle(state);
    if (state.guardInstanceId !== guardInstanceId) fail('AUTHORITY_STORE_MISMATCH', 503);
    // Process changes invalidate preparations. Never silently create fresh approval authority.
    this.write(data => {
      data.limits ??= this.limits; // Existing default-policy installations migrate without changing limits.
      for (const request of Object.values(data.requests)) {
        if (request.state === 'pending' || request.state === 'preparing') request.state = 'review_required';
        if (request.state === 'dispatching') request.state = 'unconfirmed';
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
  data() {
    const data = this.store.read().ticketService;
    if (!data || data.version !== 1 || !data.tickets || !data.requests || !data.receipts || !Array.isArray(data.audit))
      fail('BACKEND_STATE_INVALID', 503);
    this.assertPolicy(data);
    historyState(data);
    return data;
  }
  assertPolicy(data) {
    if (JSON.stringify(normalizeLimits(data.limits)) !== JSON.stringify(this.limits))
      fail('LIMITS_CHANGE_REQUIRES_OFFLINE', 409);
    assertCapacity(data, this.limits);
  }
  health() {
    this.data();
    this.executor.audit();
  }
  write(callback) {
    return this.store.transaction(state => {
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
    });
  }
  event(data, now, event, request, operatorId) {
    data.audit.push({
      at: now,
      event,
      requestId: request.id,
      tenantId: request.tenantId,
      ...(operatorId ? { operatorId } : {}),
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
  public(request) {
    const {
      id,
      ticketId,
      title,
      tenantId,
      beforeStatus,
      afterStatus,
      resourceVersion,
      digest,
      expiresAt,
      createdAt,
      state,
      receipt,
      reviewerId,
      requesterId,
      archived,
    } = request;
    return {
      id,
      ticketId,
      title,
      tenantId,
      beforeStatus,
      afterStatus,
      resourceVersion,
      digest,
      expiresAt,
      createdAt,
      state:
        state === 'pending' && expiresAt <= this.clock()
          ? 'expired'
          : state === 'dispatching'
            ? 'unconfirmed'
            : state === 'preparing'
              ? 'review_required'
              : state,
      ...(receipt ? { receipt } : {}),
      ...(reviewerId ? { reviewerId } : {}),
      requesterId,
      archived: !!archived,
    };
  }
  tickets(tenantId, options) {
    identifier(tenantId);
    const selected = page(options);
    const all = Object.values(this.data().tickets)
      .filter(t => t.tenantId === tenantId)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return {
      tickets: all.slice(selected.offset, selected.offset + selected.limit).map(({ tenantId: _, ...ticket }) => ticket),
      allowedStatuses: statuses,
      ...pagination(all.length, selected),
    };
  }
  requests(tenantId, options) {
    identifier(tenantId);
    const selected = page(options);
    const all = Object.values(this.data().requests)
      .filter(r => r.tenantId === tenantId)
      .sort(
        (a, b) =>
          Number(terminal.has(a.state)) - Number(terminal.has(b.state)) ||
          b.createdAt - a.createdAt ||
          (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
      );
    return {
      requests: all.slice(selected.offset, selected.offset + selected.limit).map(r => this.public(r)),
      ...pagination(all.length, selected),
    };
  }
  async propose(operator, input, assertAuthorized = () => {}) {
    fields(input, ['ticketId', 'status']);
    identifier(input.ticketId);
    if (!statuses.includes(input.status)) fail('INVALID_STATUS');
    assertAuthorized();
    const ticket = this.ticket(input.ticketId, operator.tenantId);
    if (operator.allowedTicketIds && !operator.allowedTicketIds.includes(ticket.id)) fail('FORBIDDEN', 403);
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
        taskId: `ticket:${id}`,
        operationId: `operation-${id}`,
        tenantId: operator.tenantId,
        requesterId: operator.id,
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
          digest: hash([
            id,
            prepared.digest,
            request.ticketId,
            request.beforeStatus,
            request.afterStatus,
            request.resourceVersion,
            request.expiresAt,
          ]),
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
      this.write(data => {
        data.requests[id].state = 'failed';
        if (noTask) data.requests[id].noTask = true;
      });
      throw error;
    }
    return { request: this.public(this.request(id, operator.tenantId)) };
  }
  async decide(operator, id, input, approve, assertAuthorized = () => {}) {
    fields(input, ['digest']);
    assertAuthorized();
    let request = this.request(id, operator.tenantId);
    if (this.busy.has(id) || request.state !== 'pending' || request.digest !== input.digest) fail('REVIEW_STALE', 409);
    if (approve && this.requestPolicy.forbidSelfApproval && request.requesterId === operator.id)
      fail('SELF_APPROVAL_FORBIDDEN', 403);
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
          this.event(data, now, 'DENIED', request, operator.id);
        });
      } else {
        assertAuthorized();
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
          const status = settledStatus(this.executor.execution(request.taskId, request.actionId));
          this.write(data => {
            data.requests[id].state = ['UNKNOWN', 'ADMITTED', 'RUNNING', 'SUCCEEDED'].includes(status)
              ? 'unconfirmed'
              : status === 'PREPARED'
                ? 'review_required'
                : 'failed';
          });
        } finally {
          this.dispatchAuthorization.delete(id);
        }
      }
    } finally {
      this.busy.delete(id);
    }
    return { request: this.public(this.request(id, operator.tenantId)) };
  }
  commit(id) {
    const assertAuthorized = this.dispatchAuthorization.get(id);
    if (!assertAuthorized) fail('DISPATCH_AUTHORITY_MISSING', 403);
    assertAuthorized();
    const receipt = this.write((data, now) => {
      const request = data.requests[id],
        ticket = data.tickets[request.ticketId];
      if (request.state !== 'dispatching' || !request.reviewerId) fail('DISPATCH_AUTHORITY_MISSING', 403);
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
  reconcile(operator, id) {
    const request = this.request(id, operator.tenantId);
    if (this.busy.has(id) || request.state !== 'unconfirmed') fail('RECONCILIATION_UNAVAILABLE', 409);
    const receipt = own(this.data().receipts, request.operationId);
    if (!receipt) fail('RECEIPT_NOT_FOUND', 409); // Absence never means failure or permission to retry.
    if (
      receipt.operationId !== request.operationId ||
      receipt.requestId !== id ||
      receipt.digest !== request.digest ||
      receipt.tenantId !== request.tenantId ||
      receipt.ticketId !== request.ticketId ||
      receipt.status !== request.afterStatus ||
      receipt.version !== Number(request.resourceVersion) + 1
    )
      fail('RECEIPT_MISMATCH', 503);
    let status;
    try {
      status = settledStatus(this.executor.execution(request.taskId, request.actionId));
    } catch (error) {
      if (error?.code !== 'INVALID_PREPARED') throw error;
      // The SDK may prune a terminal action before this business marker is saved.
      // This host gives each nondelegated task exactly one call/cost unit. A missing
      // action plus settled one-unit accounting and its exact backend receipt can
      // finish the marker; it cannot release an UNKNOWN reservation or reexecute.
      const task = this.executor.snapshot(request.taskId);
      if (task.calls !== 1 || task.spent !== 1 || task.reserved !== 0 || task.concurrent !== 0)
        fail('RECONCILIATION_UNAVAILABLE', 409);
      status = 'SUCCEEDED';
    }
    if (status === 'UNKNOWN')
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
  maintenance(operator) {
    const data = this.data(),
      usage = {
        ...assertCapacity(data, this.limits),
        backendBytes: Buffer.byteLength(JSON.stringify(this.store.read())),
      };
    const historyCapacity = historySegmentUsage(data);
    const requests = Object.values(data.requests).filter(r => r.tenantId === operator.tenantId);
    return {
      archiveCandidates: requests
        .filter(
          r =>
            !r.archived &&
            !r.noTask &&
            !this.busy.has(r.id) &&
            (terminal.has(r.state) || (r.state === 'pending' && r.expiresAt <= this.clock())),
        )
        .slice(0, 500)
        .map(r => ({ taskId: r.taskId, label: `${r.ticketId} · ${this.public(r).state}` })),
      archiveCandidatesTruncated:
        requests.filter(r => !r.archived && !r.noTask && terminal.has(this.public(r).state)).length > 500,
      unresolvedCount: requests.filter(r => r.state === 'unconfirmed' || r.state === 'dispatching').length,
      records: requests.length,
      recordLimit: this.limits.maxRequests,
      limits: this.limits,
      usage,
      historyCapacity,
      history: {
        archivedRequests: historyState(data)?.companies?.[operator.tenantId]?.archivedRequests ?? '0',
        segments: historyState(data)?.companies?.[operator.tenantId]?.head?.index ?? 0,
        lastCommittedAt: historyState(data)?.companies?.[operator.tenantId]?.lastCommittedAt ?? null,
        commitment: historyState(data)?.companies?.[operator.tenantId]?.head?.hash ?? null,
        pending: !!historyState(data)?.pending,
        mode: 'reviewed-offline',
      },
      capacityWarning:
        usage.requests >= this.limits.maxRequests * 0.8 ||
        usage.tickets >= this.limits.maxTickets * 0.8 ||
        usage.backendBytes >= this.limits.maxBackendBytes * 0.8 ||
        historyCapacity.total >= historyCapacity.limit * 0.8,
      statistics: this.executor.maintenanceStatistics({ tenantId: operator.tenantId }),
      keyRotation: {
        state: 'offline',
        message:
          'Stop the service; use reviewed offline custody rotation for the enrolled store group, verify every store, then restart. Keys never enter this browser.',
      },
    };
  }
  previewArchive(operator, input) {
    fields(input, ['taskId']);
    identifier(input.taskId);
    const request = Object.values(this.data().requests).find(
      r => r.taskId === input.taskId && r.tenantId === operator.tenantId,
    );
    if (
      !request ||
      request.archived ||
      request.noTask ||
      !terminal.has(this.public(request).state) ||
      this.busy.has(request.id)
    )
      fail('ARCHIVE_UNAVAILABLE', 409);
    const plan = this.executor.previewTaskFamilyRetirement({ tenantId: operator.tenantId, taskId: input.taskId });
    for (const [id, preview] of this.previews) if (preview.expiresAt <= this.clock()) this.previews.delete(id);
    if (this.previews.size >= 256) fail('PREVIEW_CAPACITY_REACHED', 503);
    const preview = {
      id: randomUUID(),
      taskId: input.taskId,
      digest: plan.reviewDigest,
      eligibleCount: plan.counts.tasks,
      retainedCount: 1,
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
      requestId: request.id,
    });
    return { preview };
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
    const scope = { tenantId: operator.tenantId, taskId: preview.taskId };
    if (!preview.retired) this.executor.retireTaskFamily({ ...scope, expectedDigest: preview.digest });
    const archiveDigest = preview.retired
      ? preview.digest
      : this.executor.previewTaskFamilyRetirement(scope).reviewDigest;
    this.write(data => {
      data.requests[preview.requestId].archiveIntent = true;
    });
    const receipt = this.executor.archiveTaskFamily({ ...scope, expectedDigest: archiveDigest });
    this.write((data, now) => {
      const request = data.requests[preview.requestId];
      request.archived = receipt.archiveId;
      delete request.archiveIntent;
      this.event(data, now, 'ARCHIVED', request, operator.id);
    });
    return { archivedCount: receipt.counts.tasks };
  }
}
