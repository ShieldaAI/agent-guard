const OWNERSHIP = Object.freeze({
  assigned: 'Assigned owner',
  unassigned: 'Unassigned owner',
  unknown: 'Ownership unknown',
});
export function ownershipLabel(item = {}) {
  const state = item.ownershipStatus ?? item.ownership_status;
  if (state === 'assigned')
    return item.ownerName ?? item.owner_name ?? item.ownerId ?? item.owner_id ?? 'Assigned owner';
  return OWNERSHIP[state] ?? OWNERSHIP.unknown;
}
export function shownValue(value) {
  if (value === undefined || value === null) return 'Unknown';
  if (value === '') return 'Empty';
  if (Array.isArray(value)) return value.length ? value.map(shownValue).join(', ') : 'None recorded';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
/** Keep native select labels short; full authorized identifiers remain in text details. */
export function sourceOptionLabel(source, index) {
  const value = Array.from(String(source.tenantId ?? source.sourceId ?? source.id));
  return `${value.slice(0, 16).join('')}${value.length > 16 ? '…' : ''} · ${index + 1}`;
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
const RELATIONS = Object.freeze({
  G_OWNED_BY: 'is owned by',
  G_RESOURCE_OWNED_BY: 'resource is owned by',
  G_USES_CREDENTIAL: 'uses credential reference',
  G_DEPENDS_ON: 'depends on',
  G_INSTANCE_OF: 'is a deployment of',
  G_ASSIGNED_TO: 'is assigned to',
  G_ACTS_AS: 'acts as',
  G_DELEGATED_FROM: 'is delegated from',
  G_DERIVED_FROM: 'is derived from',
  G_HAS_GRANT: 'has declared grant',
  G_FOR_TOOL: 'declares tool',
  G_TARGETS: 'targets selector',
  G_BINDS_SELECTOR: 'binds selector',
  G_MAPS_TO: 'maps to collected resource',
  G_EXECUTES_FOR: 'executes for',
  G_EXECUTES_TOOL: 'executes tool',
  G_USES_IDENTITY: 'uses identity',
  G_VIA_CONNECTION: 'uses connection',
  G_EXPOSES_OPERATION: 'exposes operation',
  G_OPERATION_TOOL: 'maps operation to tool',
});
export const relationshipLabel = kind =>
  RELATIONS[kind] ??
  String(kind ?? 'Unknown relationship')
    .replace(/^G_/, '')
    .replaceAll('_', ' ')
    .toLowerCase();
