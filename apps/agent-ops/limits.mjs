const MiB = 1024 * 1024;

/** Installation-wide retention limits. Raising them does not change per-action authority. */
export const DEFAULT_LIMITS = Object.freeze({
  maxTickets: 500,
  maxRequests: 4000,
  maxBackendBytes: 16 * MiB,
  maxLedgerBytes: 16 * MiB,
  maxRetainedKeys: 4,
});
export const LIMIT_BOUNDS = Object.freeze({
  maxTickets: Object.freeze({ min: 1, max: 10_000 }),
  maxRequests: Object.freeze({ min: 1, max: 20_000 }),
  maxBackendBytes: Object.freeze({ min: MiB, max: 64 * MiB }),
  maxLedgerBytes: Object.freeze({ min: MiB, max: 64 * MiB }),
  maxRetainedKeys: Object.freeze({ min: 1, max: 64 }),
});
function fail(code, status = 400) {
  throw Object.assign(new Error(code), { code, status });
}
function record(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

/** Partial configuration is normalized once; unknown properties and coercion are rejected. */
export function normalizeLimits(value = {}) {
  if (!record(value)) fail('LIMITS_INVALID');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).some(
      key =>
        typeof key !== 'string' || !Object.hasOwn(DEFAULT_LIMITS, key) || !Object.hasOwn(descriptors[key], 'value'),
    )
  )
    fail('LIMITS_INVALID');
  return Object.freeze(
    Object.fromEntries(
      Object.entries(DEFAULT_LIMITS).map(([key, fallback]) => {
        const selected = Object.hasOwn(descriptors, key) ? descriptors[key].value : fallback;
        const { min, max } = LIMIT_BOUNDS[key];
        if (!Number.isSafeInteger(selected) || selected < min || selected > max) fail('LIMITS_INVALID');
        return [key, selected];
      }),
    ),
  );
}

/** Counts cover every tenant. No row is evicted to make a smaller policy fit. */
export function assertCapacity(data, limits) {
  const policy = normalizeLimits(limits);
  if (!record(data) || !record(data.tickets) || !record(data.requests) || !record(data.receipts))
    fail('BACKEND_STATE_INVALID', 503);
  const usage = {
    tickets: Object.keys(data.tickets).length,
    requests: Object.keys(data.requests).length,
    receipts: Object.keys(data.receipts).length,
    backendBytes: Buffer.byteLength(JSON.stringify(data)),
  };
  if (
    usage.tickets > policy.maxTickets ||
    usage.requests > policy.maxRequests ||
    usage.receipts > policy.maxRequests ||
    usage.backendBytes > policy.maxBackendBytes
  )
    fail('LIMITS_BELOW_USAGE', 409);
  return Object.freeze(usage);
}
