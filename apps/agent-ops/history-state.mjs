import { randomUUID } from 'node:crypto';

const own = (value, key) => Object.hasOwn(value, key) ? value[key] : undefined;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
// Shared by compaction, backup and exact-current repair. Never admit history
// that the supported recovery manifest cannot enumerate completely.
export const HISTORY_SEGMENT_LIMIT = 10_000;
export const historyFailure = code => { throw Object.assign(new Error(code), { code, status: 409 }); };
export const namespaceValid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
export function validHistoryHead(head) {
  return head === null || plain(head) && integer(head.index) && head.index > 0 && /^[a-f0-9]{64}$/.test(head.hash) &&
    typeof head.keyBase64 === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(head.keyBase64) &&
    Buffer.from(head.keyBase64, 'base64').toString('base64') === head.keyBase64;
}
/** Constant metadata per enrolled company; individual historical IDs are not kept here. */
export function historyState(data, create = false) {
  if (data.history === undefined) {
    if (!create) return null;
    data.history = { version: 1, companies: Object.create(null), pending: null };
  }
  const value = data.history;
  if (!plain(value) || value.version !== 1 || !plain(value.companies) || Object.keys(value.companies).length > 10_000 ||
      !(value.pending === null || plain(value.pending))) historyFailure('HISTORY_STATE_INVALID');
  for (const enrollment of [value.enrollment, value.mirrorEnrollment]) {
    if (enrollment !== undefined && (!plain(enrollment) || typeof enrollment.path !== 'string' ||
        !/^[0-9]+$/.test(enrollment.device) || !/^[0-9]+$/.test(enrollment.inode))) historyFailure('HISTORY_STATE_INVALID');
  }
  const namespaces = new Set();
  for (const company of Object.values(value.companies)) {
    if (!plain(company) || !namespaceValid(company.namespace) || namespaces.has(company.namespace) ||
        !integer(company.nextSequence) || company.nextSequence < 1 || !integer(company.highestExportedSequence) ||
        company.highestExportedSequence >= company.nextSequence || !validHistoryHead(company.head) ||
        (company.lastCommittedAt !== undefined && !integer(company.lastCommittedAt)) ||
        typeof company.archivedRequests !== 'string' || !/^(?:0|[1-9][0-9]{0,23})$/.test(company.archivedRequests)) historyFailure('HISTORY_STATE_INVALID');
    namespaces.add(company.namespace);
  }
  return value;
}
/** Deployment-wide authenticated heads plus one slot for the durable intent. */
export function historySegmentUsage(data) {
  const history = historyState(data);
  let committed = 0;
  for (const company of Object.values(history?.companies ?? {})) {
    committed += company.head?.index ?? 0;
    if (!Number.isSafeInteger(committed)) historyFailure('HISTORY_COUNTER_CAPACITY');
  }
  const reserved = history?.pending ? 1 : 0, total = committed + reserved;
  if (!Number.isSafeInteger(total)) historyFailure('HISTORY_COUNTER_CAPACITY');
  return { committed, reserved, total, limit: HISTORY_SEGMENT_LIMIT };
}
export function assertHistorySegmentCapacity(data, additional = 0) {
  if (!integer(additional)) historyFailure('HISTORY_SCOPE_INVALID');
  const usage = historySegmentUsage(data);
  if (usage.total > usage.limit) historyFailure('HISTORY_MIGRATION_REQUIRED');
  if (additional > usage.limit - usage.total) historyFailure('HISTORY_SEGMENT_CAPACITY');
  return usage;
}
export function companyHistory(data, tenantId, create = false) {
  const state = historyState(data, create);
  if (!state) return null;
  let company = own(state.companies, tenantId);
  if (!company && create) {
    if (Object.keys(state.companies).length >= 10_000) historyFailure('HISTORY_COMPANY_CAPACITY');
    const namespace = randomUUID();
    if (Object.values(state.companies).some(item => item.namespace === namespace)) historyFailure('HISTORY_ID_COLLISION');
    company = state.companies[tenantId] = { namespace, nextSequence: 1, highestExportedSequence: 0, head: null, archivedRequests: '0' };
  }
  return company ?? null;
}
export function allocateRequestIdentity(data, tenantId) {
  const history = historyState(data, true);
  if (history.pending) historyFailure('HISTORY_RECOVERY_REQUIRED');
  const company = companyHistory(data, tenantId, true);
  if (company.nextSequence >= Number.MAX_SAFE_INTEGER) historyFailure('HISTORY_SEQUENCE_CAPACITY');
  const sequence = company.nextSequence++;
  return { id: `${company.namespace}-${sequence}`, sequence };
}
export function assertHistoryIdle(data) {
  if (historyState(data)?.pending) historyFailure('HISTORY_RECOVERY_REQUIRED');
}
