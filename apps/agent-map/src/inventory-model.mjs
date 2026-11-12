import { LABELS, displayValue, hasLabel, label } from './labels.mjs';

/** The owner's name when one is assigned; otherwise the ownership state in words. */
export function ownershipLabel(item = {}) {
  const state = item.ownershipStatus;
  if (state === 'assigned') return item.ownerName ?? item.ownerId ?? LABELS.ownership.assigned;
  return hasLabel('ownership', state) ? LABELS.ownership[state] : LABELS.ownership.unknown;
}
/** Display text for any value; see `displayValue` in labels.mjs. */
export const shownValue = displayValue;
/** Keep native select labels short; full authorized identifiers remain in text details. */
export function sourceOptionLabel(source, index) {
  const value = Array.from(String(source.tenantId ?? source.sourceId ?? source.id));
  return `${value.slice(0, 16).join('')}${value.length > 16 ? '…' : ''} · ${index + 1}`;
}
/**
 * The source a view starts on: the one it already started on while the service still lists it,
 * otherwise the first one listed, or none while the list is empty.
 */
export function defaultSource(current, sources) {
  const list = Array.isArray(sources) ? sources : [];
  return current && list.some(source => source?.id === current) ? current : (list[0]?.id ?? '');
}
export function pageInfo(data, count = 0) {
  const offset = Number.isSafeInteger(data?.offset) && data.offset >= 0 ? data.offset : 0;
  const limit = Number.isSafeInteger(data?.limit) && data.limit > 0 ? data.limit : Math.max(1, count);
  const total = Number.isSafeInteger(data?.total) && data.total >= 0 ? data.total : null;
  return {
    offset,
    limit,
    total,
    previous: offset > 0 ? Math.max(0, offset - limit) : null,
    next: total !== null && offset + count < total && count > 0 ? offset + limit : null,
    label: count
      ? `${offset + 1}–${offset + count}${total === null ? '' : ` of ${total}`}`
      : total === null
        ? 'No visible results'
        : `0 of ${total}`,
    incomplete: total === null && data?.truncated === true,
  };
}
/** Search boxes wait this long after the last key before querying. */
export const SEARCH_DEBOUNCE_MS = 300;
/** Runs `run` with the last value once calls have paused for `delay` ms; `cancel` drops a pending run. */
export function debounced(run, delay = SEARCH_DEBOUNCE_MS, timers = globalThis) {
  let timer = null;
  const call = value => {
    if (timer !== null) timers.clearTimeout(timer);
    timer = timers.setTimeout(() => {
      timer = null;
      run(value);
    }, delay);
  };
  call.cancel = () => {
    if (timer !== null) timers.clearTimeout(timer);
    timer = null;
  };
  return call;
}
export const relationshipLabel = kind =>
  hasLabel('relation', kind)
    ? LABELS.relation[kind]
    : label(
        'relation',
        typeof kind === 'string' ? kind.replace(/^G_/, '') : kind,
        'Unknown relationship',
      ).toLowerCase();
/** The cloud actions the service maps to policy evidence; any other declared action can still be typed. */
export const KNOWN_ACTIONS = Object.freeze(['s3:GetObject', 's3:PutObject', 's3:ListBucket']);
/** Resource references the lookup can offer: each loaded binding's selector and the ARNs it maps to. */
export function resourceReferences(resources) {
  const values = new Set();
  for (const resource of resources ?? []) {
    if (typeof resource?.resourceRef === 'string') values.add(resource.resourceRef);
    for (const target of resource?.targets ?? []) if (typeof target?.arn === 'string') values.add(target.arn);
  }
  return [...values].sort();
}
