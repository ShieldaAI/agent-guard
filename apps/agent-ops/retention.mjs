import { randomBytes, randomUUID } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { join, basename } from 'node:path';
import {
  TaskFamilyLifecycle,
  readTaskFamilyArchiveTransfer,
  verifyTransferredTaskFamilyArchive,
  compactExportedTaskFamilies,
  externalTaskHistoryHead,
} from '../../packages/executor/dist/lifecycle.js';
import {
  companyHistory,
  historyState,
  historyFailure as fail,
  namespaceValid,
  validHistoryHead,
  assertHistorySegmentCapacity,
  HISTORY_SEGMENT_LIMIT,
} from './history-state.mjs';
import {
  privateHistoryDirectory,
  privateHistoryMirrorDirectory,
  historyFilename,
  historyHash,
  historyJson,
  encryptHistorySegment,
  decryptHistorySegment,
  readHistoryFile,
  publishHistoryFile,
} from './history-files.mjs';

const terminal = new Set(['completed', 'denied', 'expired', 'changed', 'failed', 'review_required']);
const own = (value, key) => (Object.hasOwn(value, key) ? value[key] : undefined);
const sha = value => historyHash(historyJson(value));
function text(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,159}$/.test(value)) fail('HISTORY_SCOPE_INVALID');
  return value;
}
function current(stores) {
  const backend = stores.backend.read(),
    guard = stores.guard.read();
  if (backend.ticketService?.guardInstanceId !== guard.inventoryInstanceId) fail('AUTHORITY_STORE_MISMATCH');
  historyState(backend.ticketService);
  return { backend, guard, data: backend.ticketService };
}
function receiptMatches(request, receipt) {
  return (
    receipt &&
    receipt.operationId === request.operationId &&
    receipt.requestId === request.id &&
    receipt.digest === request.digest &&
    receipt.tenantId === request.tenantId &&
    receipt.ticketId === request.ticketId &&
    receipt.status === request.afterStatus &&
    receipt.version === Number(request.resourceVersion) + 1
  );
}
function reviewedRequestDigest(request, now) {
  const { archived: _archive, archiveIntent: _intent, noTask: _missing, ...reviewed } = request;
  if (reviewed.state === 'pending' && reviewed.expiresAt <= now) reviewed.state = 'expired';
  return sha(reviewed);
}
function inspectRequest(request, data, guard, now) {
  if (!terminal.has(request.state) && !(request.state === 'pending' && request.expiresAt <= now))
    fail('HISTORY_UNRESOLVED_WORK');
  const receipt = own(data.receipts, request.operationId);
  if (request.state === 'completed' ? !receiptMatches(request, receipt) : receipt !== undefined)
    fail('HISTORY_RECEIPT_MISMATCH');
  const task = own(guard.tasks, request.taskId);
  if (
    task &&
    (task.options.tenantId !== request.tenantId ||
      task.options.id !== request.taskId ||
      task.parent !== null ||
      task.sourceTaskId !== undefined ||
      task.family !== request.taskId ||
      task.concurrent !== 0 ||
      task.reserved !== 0 ||
      (request.state === 'completed' ? task.calls !== 1 || task.spent !== 1 : task.spent !== 0))
  )
    fail('HISTORY_TASK_UNRESOLVED');
}
function lifecycle(stores) {
  return new TaskFamilyLifecycle(stores.guard, {
    activeTaskIds: () => new Set(), // Both stores' exclusive owners are held by this offline operation.
    now(state) {
      const now = Date.now();
      if (!Number.isSafeInteger(now) || now < (state?.lastClock ?? 0)) fail('CLOCK_INVALID');
      if (state) state.lastClock = now;
      return now;
    },
    quarantine(_state, _tenant, ids) {
      if (ids.size) fail('HISTORY_TASK_REFERENCED');
    },
    retired() {},
  });
}
export function historyDirectoryEnrollment(config) {
  const path = privateHistoryDirectory(config),
    stat = lstatSync(path);
  return { path, device: String(stat.dev), inode: String(stat.ino) };
}
export function historyMirrorEnrollment(config) {
  const path = privateHistoryMirrorDirectory(config),
    stat = lstatSync(path);
  return { path, device: String(stat.dev), inode: String(stat.ino) };
}
function previewDigest(stores, config, tenantId, ids, pending) {
  const { backend, guard, data } = current(stores);
  return sha({
    kind: pending ? 'history-recovery-v1' : 'history-review-v1',
    backendInstance: backend.inventoryInstanceId,
    guardInstance: guard.inventoryInstanceId,
    backendRevision: backend.revision,
    guardRevision: guard.revision,
    directory: historyDirectoryEnrollment(config),
    mirror: config.historyMirrorDirectory ? historyMirrorEnrollment(config) : null,
    tenantId,
    ids,
    pending: pending?.operationId ?? null,
    requests: ids.map(id => own(data.requests, id)),
    head: companyHistory(data, tenantId)?.head?.hash ?? null,
  });
}
function selectedRequests(data, tenantId, limit, now) {
  const all = Object.values(data.requests).filter(request => request.tenantId === tenantId);
  const eligible = all.filter(
    request => terminal.has(request.state) || (request.state === 'pending' && request.expiresAt <= now),
  );
  const archived = eligible.filter(request => request.archived);
  // Empty existing archive slots first: even a full 4096-row SDK archive pool can recover.
  const candidates = archived.length ? archived : eligible;
  candidates.sort(
    (a, b) => (a.sequence ?? 0) - (b.sequence ?? 0) || a.createdAt - b.createdAt || a.id.localeCompare(b.id),
  );
  return {
    rows: candidates.slice(0, limit),
    excludedUnresolved: all.length - eligible.length,
    eligible: eligible.length,
  };
}
function pendingState(data) {
  const pending = historyState(data)?.pending;
  if (!pending) return null;
  if (
    !namespaceValid(pending.operationId) ||
    !namespaceValid(pending.namespace) ||
    typeof pending.tenantId !== 'string' ||
    !Array.isArray(pending.requestIds) ||
    !pending.requestIds.length ||
    pending.requestIds.length > 100 ||
    new Set(pending.requestIds).size !== pending.requestIds.length ||
    !validHistoryHead(pending.previous) ||
    !Number.isSafeInteger(pending.index) ||
    pending.index !== (pending.previous?.index ?? 0) + 1 ||
    !Number.isSafeInteger(pending.createdAt) ||
    !/^[A-Za-z0-9+/]{43}=$/.test(pending.keyBase64) ||
    !/^[A-Za-z0-9+/]{16}$/.test(pending.ivBase64) ||
    !pending.sourceDigests ||
    pending.requestIds.some(id => !/^[a-f0-9]{64}$/.test(pending.sourceDigests[id] ?? '')) ||
    (pending.plaintextSha !== undefined && !/^[a-f0-9]{64}$/.test(pending.plaintextSha)) ||
    (pending.targetHash !== undefined && !/^[a-f0-9]{64}$/.test(pending.targetHash))
  )
    fail('HISTORY_STATE_INVALID');
  return pending;
}
export function previewBusinessHistory(stores, config, { tenantId, limit = 100 }) {
  text(tenantId);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) fail('HISTORY_SCOPE_INVALID');
  privateHistoryDirectory(config);
  const { data, guard } = current(stores),
    pending = pendingState(data);
  if (pending) {
    if (pending.tenantId !== tenantId) fail('HISTORY_RECOVERY_REQUIRED');
    assertHistorySegmentCapacity(data);
    return {
      status: 'recovery-required',
      tenantId,
      count: pending.requestIds.length,
      operationId: pending.operationId,
      digest: previewDigest(stores, config, tenantId, pending.requestIds, pending),
      blockers: [],
    };
  }
  const selected = selectedRequests(data, tenantId, limit, Date.now());
  assertHistorySegmentCapacity(data, selected.rows.length ? 1 : 0);
  verifyHistoryStorage(stores, config);
  const blockers = new Set(),
    life = lifecycle(stores);
  try {
    for (const request of selected.rows) {
      try {
        inspectRequest(request, data, guard, Date.now());
        const existing = life.findArchive({ tenantId, taskId: request.taskId });
        if (existing) continue;
        if (!own(guard.tasks, request.taskId)) {
          if (!request.noTask && request.actionId) fail('HISTORY_TASK_BINDING_MISSING');
          continue;
        }
        const plan = life.preview({ tenantId, taskId: request.taskId });
        if (plan.counts.tasks !== 1 || plan.counts.memoryEntries !== 0) fail('HISTORY_TASK_REFERENCED');
        for (const code of [...plan.retirementBlockers, ...plan.archiveBlockers])
          if (code !== 'FAMILY_NOT_RETIRED') blockers.add(code);
      } catch (error) {
        blockers.add(error.code ?? 'HISTORY_TASK_INVALID');
      }
    }
  } finally {
    life.close();
  }
  return {
    status: 'preview',
    tenantId,
    count: selected.rows.length,
    eligible: selected.eligible,
    excludedUnresolved: selected.excludedUnresolved,
    digest: previewDigest(
      stores,
      config,
      tenantId,
      selected.rows.map(request => request.id),
      null,
    ),
    blockers: [...blockers].sort(),
    effects: [
      'Preserve exact requests, receipts and SDK evidence in encrypted company history.',
      'Remove only exported live records and SDK archive rows; retain permanent identity fences.',
    ],
  };
}
function ensureArchives(stores, pending, checkpoint) {
  const life = lifecycle(stores);
  try {
    for (const id of pending.requestIds) {
      let { data, guard } = current(stores);
      const request = own(data.requests, id);
      if (!request || request.tenantId !== pending.tenantId) fail('HISTORY_STATE_INVALID');
      if (reviewedRequestDigest(request, pending.createdAt) !== pending.sourceDigests[id])
        fail('HISTORY_SOURCE_CHANGED');
      inspectRequest(request, data, guard, pending.createdAt);
      let receipt = life.findArchive({ tenantId: pending.tenantId, taskId: request.taskId });
      if (!receipt && own(guard.tasks, request.taskId)) {
        const plan = life.preview({ tenantId: pending.tenantId, taskId: request.taskId });
        if (plan.counts.tasks !== 1 || plan.counts.memoryEntries !== 0) fail('HISTORY_TASK_REFERENCED');
        if (!plan.retired)
          life.retire({ tenantId: pending.tenantId, taskId: request.taskId, expectedDigest: plan.reviewDigest });
        const retired = life.preview({ tenantId: pending.tenantId, taskId: request.taskId });
        receipt = life.archive({
          tenantId: pending.tenantId,
          taskId: request.taskId,
          expectedDigest: retired.reviewDigest,
        });
      }
      if (!receipt && !request.noTask && request.actionId) fail('HISTORY_TASK_BINDING_MISSING');
      stores.backend.transaction(state => {
        const retained = own(state.ticketService.requests, id);
        if (receipt) retained.archived = receipt.archiveId;
        else retained.noTask = true;
        if (retained.state === 'pending') retained.state = 'expired';
        delete retained.archiveIntent;
      });
      checkpoint?.('task-archived');
    }
  } finally {
    life.close();
  }
}
function makePayload(stores, pending) {
  const { backend, guard, data } = current(stores),
    requests = pending.requestIds.map(id => own(data.requests, id));
  if (requests.some(request => !request || request.tenantId !== pending.tenantId)) fail('HISTORY_STATE_INVALID');
  if (requests.some(request => reviewedRequestDigest(request, pending.createdAt) !== pending.sourceDigests[request.id]))
    fail('HISTORY_SOURCE_CHANGED');
  const archives = requests
    .filter(request => request.archived)
    .map(request =>
      readTaskFamilyArchiveTransfer(stores.guard, { tenantId: pending.tenantId, archiveId: request.archived }),
    );
  return {
    version: 1,
    backendInstanceId: backend.inventoryInstanceId,
    guardInstanceId: guard.inventoryInstanceId,
    tenantId: pending.tenantId,
    namespace: pending.namespace,
    operationId: pending.operationId,
    index: pending.index,
    createdAt: pending.createdAt,
    previous: pending.previous,
    requests,
    audit: data.audit.filter(event => pending.requestIds.includes(event.requestId)),
    receipts: Object.fromEntries(
      requests.flatMap(request => {
        const receipt = own(data.receipts, request.operationId);
        return receipt ? [[request.operationId, receipt]] : [];
      }),
    ),
    archives,
  };
}
function validatePayload(payload, guardInstanceId, company) {
  if (
    payload.guardInstanceId !== guardInstanceId ||
    payload.namespace !== company.namespace ||
    !Array.isArray(payload.requests) ||
    !payload.requests.length ||
    payload.requests.length > 100 ||
    !Array.isArray(payload.archives) ||
    payload.archives.length > payload.requests.length ||
    !Array.isArray(payload.audit) ||
    payload.audit.length > 4000 ||
    new Set(payload.requests.map(request => request.id)).size !== payload.requests.length ||
    !payload.receipts ||
    typeof payload.receipts !== 'object'
  )
    fail('HISTORY_EVIDENCE_INVALID');
  const transfers = new Map(payload.archives.map(transfer => [transfer.archiveId, transfer]));
  if (transfers.size !== payload.archives.length) fail('HISTORY_EVIDENCE_INVALID');
  const usedReceipts = new Set(),
    usedArchives = new Set();
  for (const request of payload.requests) {
    if (
      request.tenantId !== payload.tenantId ||
      !terminal.has(request.state) ||
      request.taskId !== `ticket:${request.id}`
    )
      fail('HISTORY_EVIDENCE_INVALID');
    if (
      request.sequence !== undefined &&
      (!Number.isSafeInteger(request.sequence) ||
        request.sequence < 1 ||
        request.sequence >= company.nextSequence ||
        request.id !== `${company.namespace}-${request.sequence}`)
    )
      fail('HISTORY_EVIDENCE_INVALID');
    const receipt = own(payload.receipts, request.operationId);
    if (request.state === 'completed' ? !receiptMatches(request, receipt) : receipt !== undefined)
      fail('HISTORY_EVIDENCE_INVALID');
    if (request.receipt !== undefined && sha(request.receipt) !== sha(receipt ?? null))
      fail('HISTORY_EVIDENCE_INVALID');
    if (receipt) usedReceipts.add(request.operationId);
    if (request.archived) {
      const transfer = transfers.get(request.archived);
      if (!transfer || transfer.tenantId !== payload.tenantId) fail('HISTORY_EVIDENCE_INVALID');
      const decoded = verifyTransferredTaskFamilyArchive(guardInstanceId, transfer);
      if (
        Object.keys(decoded.tasks).length !== 1 ||
        !own(decoded.tasks, request.taskId) ||
        decoded.familyId !== request.taskId ||
        Object.keys(decoded.memory).length
      )
        fail('HISTORY_EVIDENCE_INVALID');
      usedArchives.add(request.archived);
    } else if (!request.noTask) fail('HISTORY_EVIDENCE_INVALID');
  }
  if (usedArchives.size !== transfers.size || usedReceipts.size !== Object.keys(payload.receipts).length)
    fail('HISTORY_EVIDENCE_INVALID');
}
/** Verifies the entire backward chain with bounded memory; I/O is proportional to retained history. */
export function verifyHistoryStorage(
  stores,
  config,
  {
    allowPending = false,
    includeFiles = false,
    ignoreEnrollment = false,
    verifyMirror = true,
    source = 'primary',
    ignoreMirrorEnrollment = false,
  } = {},
) {
  const { backend, guard, data } = current(stores),
    history = historyState(data),
    pending = pendingState(data);
  assertHistorySegmentCapacity(data);
  if (pending && !allowPending) fail('HISTORY_RECOVERY_REQUIRED');
  const companies = Object.entries(history?.companies ?? {});
  // Check the complete SDK commitment set, including a head absent from the
  // business store. Independently valid stores cannot silently lose a binding.
  externalTaskHistoryHead(stores.guard, backend.inventoryInstanceId);
  const expectedHeads = new Map(
    companies.map(([tenantId, company]) => [
      historyHash(`agent-guard-archive-tenant-v1\0${tenantId}`),
      { tenantId, company },
    ]),
  );
  for (const [digest, head] of Object.entries(guard.lifecycle?.externalHeads ?? {})) {
    const expected = expectedHeads.get(digest);
    if (
      !expected ||
      head.namespace !== expected.company.namespace ||
      (head.hash !== expected.company.head?.hash &&
        !(allowPending && pending?.tenantId === expected.tenantId && head.hash === pending.targetHash))
    )
      fail('HISTORY_COMMITMENT_MISMATCH');
  }
  if (
    !companies.some(([, company]) => company.head) &&
    !pending &&
    !config.historyDirectory &&
    !history?.mirrorEnrollment &&
    !config.historyMirrorDirectory
  )
    return { status: 'verified', companies: 0, segments: 0, bytes: 0, files: [] };
  if (!['primary', 'mirror'].includes(source)) fail('HISTORY_SCOPE_INVALID');
  let mirrorDirectory;
  if (source === 'mirror' || (verifyMirror && (history?.mirrorEnrollment || config.historyMirrorDirectory))) {
    if (!config.historyMirrorDirectory) fail('HISTORY_MIRROR_REQUIRED');
    mirrorDirectory = privateHistoryMirrorDirectory(config);
    if (
      !ignoreMirrorEnrollment &&
      (!history?.mirrorEnrollment || sha(history.mirrorEnrollment) !== sha(historyMirrorEnrollment(config)))
    )
      fail('HISTORY_MIRROR_NOT_ENROLLED');
  }
  const directory = source === 'mirror' ? mirrorDirectory : privateHistoryDirectory(config);
  const result = { status: 'verified', companies: 0, segments: 0, bytes: 0, files: [] };
  if (
    source === 'primary' &&
    !ignoreEnrollment &&
    (!history?.enrollment || sha(history.enrollment) !== sha(historyDirectoryEnrollment(config)))
  )
    fail('HISTORY_DIRECTORY_NOT_ENROLLED');
  const read = (tenantId, head) => {
    const filename = historyFilename(backend.inventoryInstanceId, tenantId, head),
      bytes = readHistoryFile(directory, filename);
    if (source === 'primary' && mirrorDirectory && !readHistoryFile(mirrorDirectory, filename).equals(bytes))
      fail('HISTORY_MIRROR_MISMATCH');
    const payload = decryptHistorySegment(bytes, backend.inventoryInstanceId, tenantId, head);
    result.segments++;
    result.bytes += bytes.length;
    if (!Number.isSafeInteger(result.segments) || !Number.isSafeInteger(result.bytes)) fail('HISTORY_COUNTER_CAPACITY');
    if (includeFiles) {
      if (result.files.length >= HISTORY_SEGMENT_LIMIT) fail('HISTORY_BACKUP_FILE_LIMIT');
      result.files.push({ path: join(directory, filename), sha256: head.hash, bytes: bytes.length });
    }
    return payload;
  };
  for (const [tenantId, company] of companies) {
    let head = company.head,
      count = 0n;
    const sdkHead = externalTaskHistoryHead(stores.guard, tenantId),
      expectedHash = company.head?.hash ?? null;
    if (
      (sdkHead?.hash ?? null) !== expectedHash &&
      !(allowPending && pending?.tenantId === tenantId && sdkHead?.hash === pending.targetHash)
    )
      fail('HISTORY_COMMITMENT_MISMATCH');
    if (head) result.companies++;
    while (head) {
      const payload = read(tenantId, head);
      validatePayload(payload, guard.inventoryInstanceId, company);
      count += BigInt(payload.requests.length);
      head = payload.previous;
    }
    if (count.toString() !== company.archivedRequests) fail('HISTORY_EVIDENCE_INVALID');
  }
  // A crash after SDK compaction makes the staged segment necessary authority
  // evidence even though the business head has not advanced yet.
  if (
    allowPending &&
    pending?.targetHash &&
    externalTaskHistoryHead(stores.guard, pending.tenantId)?.hash === pending.targetHash
  ) {
    const head = { index: pending.index, hash: pending.targetHash, keyBase64: pending.keyBase64 };
    const payload = read(pending.tenantId, head);
    validatePayload(payload, guard.inventoryInstanceId, companyHistory(data, pending.tenantId));
    if (
      sha(payload) !== pending.plaintextSha ||
      payload.operationId !== pending.operationId ||
      sha(payload.previous) !== sha(pending.previous) ||
      sha(payload.requests.map(request => request.id)) !== sha(pending.requestIds)
    )
      fail('HISTORY_EVIDENCE_INVALID');
  }
  return result;
}
/** Trusted two-store custody adapter; staged copies verify against their authenticated snapshot heads. */
export function businessHistoryBackupAdapter(config, { guardName = 'authority', backendName = 'tickets' } = {}) {
  return {
    directory: config.historyDirectory,
    ...(config.historyMirrorDirectory ? { recoveryDirectory: config.historyMirrorDirectory } : {}),
    verify(readers, directory) {
      if (readers.size !== 2 || !readers.has(guardName) || !readers.has(backendName) || guardName === backendName)
        fail('HISTORY_BACKUP_SCOPE_INVALID');
      const stores = { guard: readers.get(guardName), backend: readers.get(backendName) };
      const mirror = directory === config.historyMirrorDirectory;
      const verified = mirror
        ? verifyHistoryStorage(stores, config, { source: 'mirror', allowPending: true, includeFiles: true })
        : verifyHistoryStorage(
            stores,
            { ...config, historyDirectory: directory },
            {
              includeFiles: true,
              ignoreEnrollment: directory !== config.historyDirectory,
              verifyMirror: directory === config.historyDirectory,
            },
          );
      return verified.files.map(file => ({ name: basename(file.path), sha256: file.sha256 }));
    },
  };
}
/** Full backfill precedes enrollment; retries copy only exact immutable ciphertext. */
export function enrollBusinessHistoryMirror(stores, config, { apply = false, digest, checkpoint } = {}) {
  const verified = verifyHistoryStorage(stores, config, {
    verifyMirror: false,
    allowPending: true,
    includeFiles: true,
  });
  const { backend, guard, data } = current(stores),
    desired = historyMirrorEnrollment(config);
  // Reserve the complete post-enrollment snapshot before any native schema
  // migration. Otherwise an almost-full backend could strand a partial upgrade
  // that cannot record its mirror enrollment under the existing byte policy.
  const prospective = structuredClone(backend);
  prospective.schema = 3;
  prospective.recoveryMirror = 1;
  prospective.revision += 2;
  historyState(prospective.ticketService, true).mirrorEnrollment = desired;
  const prospectiveGuard = { ...guard, schema: 3, recoveryMirror: 1, revision: guard.revision + 1 };
  if (
    Buffer.byteLength(JSON.stringify(prospective)) > stores.backend.maxBytes ||
    Buffer.byteLength(JSON.stringify(prospectiveGuard)) > stores.guard.maxBytes
  )
    fail('STORE_CAPACITY_EXCEEDED');
  const expected = sha({
    kind: 'history-mirror-enrollment-v1',
    backendInstance: backend.inventoryInstanceId,
    guardInstance: guard.inventoryInstanceId,
    backendRevision: backend.revision,
    guardRevision: guard.revision,
    current: historyState(data)?.mirrorEnrollment ?? null,
    desired,
    files: verified.files.map(file => [basename(file.path), file.sha256]),
  });
  if (!apply)
    return {
      status: 'preview',
      digest: expected,
      segments: verified.segments,
      bytes: verified.bytes,
      effects: [
        'Copy and verify the complete exact encrypted history under independent witness custody before enrolling it.',
      ],
    };
  if (digest !== expected) fail('HISTORY_PREVIEW_STALE');
  const operationId = randomUUID();
  for (const file of verified.files) {
    publishHistoryFile(
      desired.path,
      basename(file.path),
      operationId,
      readHistoryFile(config.historyDirectory, basename(file.path)),
    );
    checkpoint?.('mirror-backfill-file');
  }
  verifyHistoryStorage(stores, config, { source: 'mirror', allowPending: true, ignoreMirrorEnrollment: true });
  checkpoint?.('mirror-backfill-verified');
  // Publish no mirror marker until both native stores enforce schema 3 and
  // atomically mirror subsequent authority changes under independent custody.
  stores.guard.enableRecoveryMirror();
  checkpoint?.('guard-mirror-enabled');
  stores.backend.enableRecoveryMirror();
  checkpoint?.('backend-mirror-enabled');
  stores.backend.transaction(state => {
    if (state.schema === 1) state.schema = 2;
    historyState(state.ticketService, true).mirrorEnrollment = desired;
  });
  return { status: 'enrolled', segments: verified.segments, bytes: verified.bytes };
}
/** Legacy enrollment or relocation requires exact reviewed custody and complete chain verification. */
export function enrollBusinessHistory(stores, config, { apply = false, digest } = {}) {
  verifyHistoryStorage(stores, config, { ignoreEnrollment: true, allowPending: true });
  const { backend, guard, data } = current(stores),
    desired = historyDirectoryEnrollment(config);
  const pending = pendingState(data);
  if (pending?.targetHash && externalTaskHistoryHead(stores.guard, pending.tenantId)?.hash === pending.targetHash) {
    const head = { index: pending.index, hash: pending.targetHash, keyBase64: pending.keyBase64 };
    const payload = decryptHistorySegment(
      readHistoryFile(desired.path, historyFilename(backend.inventoryInstanceId, pending.tenantId, head)),
      backend.inventoryInstanceId,
      pending.tenantId,
      head,
    );
    validatePayload(payload, guard.inventoryInstanceId, companyHistory(data, pending.tenantId));
    if (sha(payload) !== pending.plaintextSha || payload.operationId !== pending.operationId)
      fail('HISTORY_EVIDENCE_INVALID');
  }
  const expected = sha({
    kind: 'history-enrollment-v1',
    backendInstance: backend.inventoryInstanceId,
    guardInstance: guard.inventoryInstanceId,
    backendRevision: backend.revision,
    guardRevision: guard.revision,
    current: historyState(data)?.enrollment ?? null,
    pending: pending?.operationId ?? null,
    desired,
  });
  if (!apply)
    return {
      status: 'preview',
      digest: expected,
      directory: desired.path,
      effects: ['Enroll this private directory only after every existing encrypted history segment verifies.'],
    };
  if (digest !== expected) fail('HISTORY_PREVIEW_STALE');
  stores.backend.transaction(state => {
    if (state.schema === 1) state.schema = 2;
    historyState(state.ticketService, true).enrollment = desired;
  });
  return { status: 'enrolled', directory: desired.path };
}
/** Offline review/apply, including explicit reviewed resumption of an interrupted transition. */
export function applyBusinessHistory(stores, config, { tenantId, limit = 100, digest, checkpoint } = {}) {
  const review = previewBusinessHistory(stores, config, { tenantId, limit });
  if (typeof digest !== 'string' || digest !== review.digest) fail('HISTORY_PREVIEW_STALE');
  if (!review.count || review.blockers.length) fail(review.blockers[0] ?? 'HISTORY_EMPTY');
  let { data } = current(stores),
    pending = pendingState(data);
  if (!pending) {
    const selected = selectedRequests(data, tenantId, limit, Date.now());
    stores.backend.transaction(state => {
      assertHistorySegmentCapacity(state.ticketService, 1);
      if (state.schema === 1) state.schema = 2;
      const history = historyState(state.ticketService, true),
        company = companyHistory(state.ticketService, tenantId, true);
      if (history.pending) fail('HISTORY_RECOVERY_REQUIRED');
      if ((company.head?.index ?? 0) >= Number.MAX_SAFE_INTEGER) fail('HISTORY_SEQUENCE_CAPACITY');
      const createdAt = Date.now();
      history.pending = {
        operationId: randomUUID(),
        tenantId,
        namespace: company.namespace,
        requestIds: selected.rows.map(request => request.id),
        previous: company.head,
        index: (company.head?.index ?? 0) + 1,
        keyBase64: randomBytes(32).toString('base64'),
        ivBase64: randomBytes(12).toString('base64'),
        createdAt,
        sourceDigests: Object.fromEntries(
          selected.rows.map(request => [request.id, reviewedRequestDigest(request, createdAt)]),
        ),
      };
    });
    checkpoint?.('intent-committed');
    pending = pendingState(current(stores).data);
  }
  verifyHistoryStorage(stores, config, { allowPending: true });
  const directory = privateHistoryDirectory(config),
    { backend } = current(stores);
  let payload, bytes, head;
  const compacted = pending.targetHash && externalTaskHistoryHead(stores.guard, tenantId)?.hash === pending.targetHash;
  if (compacted) {
    head = { index: pending.index, hash: pending.targetHash, keyBase64: pending.keyBase64 };
    bytes = readHistoryFile(directory, historyFilename(backend.inventoryInstanceId, tenantId, head));
    payload = decryptHistorySegment(bytes, backend.inventoryInstanceId, tenantId, head);
  } else {
    ensureArchives(stores, pending, checkpoint);
    payload = makePayload(stores, pending);
    validatePayload(payload, stores.guard.read().inventoryInstanceId, companyHistory(current(stores).data, tenantId));
    const plaintextSha = sha(payload);
    if (pending.plaintextSha && pending.plaintextSha !== plaintextSha) fail('HISTORY_SOURCE_CHANGED');
    if (!pending.plaintextSha) {
      stores.backend.transaction(state => {
        pendingState(state.ticketService).plaintextSha = plaintextSha;
      });
      pending = pendingState(current(stores).data);
      checkpoint?.('plaintext-bound');
    }
    // The exact canonical plaintext is committed before this key/IV is ever used.
    checkpoint?.('encrypting');
    bytes = encryptHistorySegment(backend.inventoryInstanceId, tenantId, pending, payload);
    head = { index: pending.index, hash: historyHash(bytes), keyBase64: pending.keyBase64 };
    if (pending.targetHash && pending.targetHash !== head.hash) fail('HISTORY_EVIDENCE_INVALID');
    if (!pending.targetHash) {
      stores.backend.transaction(state => {
        pendingState(state.ticketService).targetHash = head.hash;
      });
      pending = pendingState(current(stores).data);
      checkpoint?.('export-planned');
    }
    if (config.historyMirrorDirectory) {
      publishHistoryFile(
        privateHistoryMirrorDirectory(config),
        historyFilename(backend.inventoryInstanceId, tenantId, head),
        pending.operationId,
        bytes,
      );
      checkpoint?.('mirror-durable');
    }
    publishHistoryFile(
      directory,
      historyFilename(backend.inventoryInstanceId, tenantId, head),
      pending.operationId,
      bytes,
    );
    checkpoint?.('export-durable');
  }
  const company = companyHistory(current(stores).data, tenantId);
  validatePayload(payload, stores.guard.read().inventoryInstanceId, company);
  if (sha(payload) !== pending.plaintextSha) fail('HISTORY_SOURCE_CHANGED');
  if (
    payload.operationId !== pending.operationId ||
    payload.namespace !== pending.namespace ||
    sha(payload.requests.map(request => request.id)) !== sha(pending.requestIds) ||
    sha(payload.previous) !== sha(pending.previous)
  )
    fail('HISTORY_EVIDENCE_INVALID');
  compactExportedTaskFamilies(stores.guard, {
    tenantId,
    namespace: pending.namespace,
    archiveIds: payload.archives.map(archive => archive.archiveId),
    segmentHash: head.hash,
    previousHash: pending.previous?.hash ?? null,
  });
  checkpoint?.('sdk-compacted');
  stores.backend.transaction(state => {
    const data = state.ticketService,
      currentPending = pendingState(data),
      retained = companyHistory(data, tenantId);
    if (currentPending?.operationId !== pending.operationId || currentPending.targetHash !== head.hash)
      fail('HISTORY_STATE_INVALID');
    for (const request of payload.requests) {
      if (sha(own(data.requests, request.id)) !== sha(request)) fail('HISTORY_STATE_INVALID');
      const receipt = own(data.receipts, request.operationId);
      if (sha(receipt ?? null) !== sha(own(payload.receipts, request.operationId) ?? null))
        fail('HISTORY_STATE_INVALID');
      delete data.requests[request.id];
      delete data.receipts[request.operationId];
      retained.highestExportedSequence = Math.max(retained.highestExportedSequence, request.sequence ?? 0);
    }
    if (sha(data.audit.filter(event => pending.requestIds.includes(event.requestId))) !== sha(payload.audit))
      fail('HISTORY_SOURCE_CHANGED');
    data.audit = data.audit.filter(event => !pending.requestIds.includes(event.requestId));
    retained.head = head;
    retained.lastCommittedAt = Date.now();
    retained.archivedRequests = (BigInt(retained.archivedRequests) + BigInt(payload.requests.length)).toString();
    data.history.pending = null;
  });
  checkpoint?.('business-compacted');
  return {
    status: 'compacted',
    tenantId,
    requests: payload.requests.length,
    archives: payload.archives.length,
    segment: head.index,
    commitment: head.hash,
    archivedRequests: companyHistory(current(stores).data, tenantId).archivedRequests,
  };
}
/** Host-only evidence lookup. The caller controls disclosure; no HTTP endpoint exposes this payload. */
export function lookupBusinessHistory(stores, config, { tenantId, requestId }) {
  text(tenantId);
  text(requestId);
  verifyHistoryStorage(stores, config);
  const { backend, data } = current(stores),
    company = companyHistory(data, tenantId);
  if (!company?.head) return null;
  const directory = privateHistoryDirectory(config);
  let head = company.head;
  while (head) {
    const payload = decryptHistorySegment(
      readHistoryFile(directory, historyFilename(backend.inventoryInstanceId, tenantId, head)),
      backend.inventoryInstanceId,
      tenantId,
      head,
    );
    const request = payload.requests.find(request => request.id === requestId);
    if (request)
      return {
        request,
        receipt: own(payload.receipts, request.operationId) ?? null,
        segment: head.index,
        commitment: head.hash,
      };
    head = payload.previous;
  }
  return null;
}
