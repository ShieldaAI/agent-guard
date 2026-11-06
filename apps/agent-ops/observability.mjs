import { createHash } from 'node:crypto';
import { fail } from './workflow.mjs';

const WINDOW_MS = 300_000;
const LATENCY_MS = [50, 100, 250, 500, 1000, 2000, 5000, 10_000];
const classes = ['1xx', '2xx', '3xx', '4xx', '5xx'];
const increment = (value, addition = 1) => Math.min(Number.MAX_SAFE_INTEGER, value + addition);
const empty = () => ({ requests: 0, serverErrors: 0, denied: 0, rateLimited: 0, latencySumMs: 0,
  statusClasses: Object.fromEntries(classes.map(key => [key, 0])), latencyBuckets: LATENCY_MS.map(() => 0) });
const count = value => Number.isSafeInteger(value) && value >= 0;

/** Fixed-size process-local aggregates. Never records URLs, IDs, cookies, bodies or credentials. */
export function createOpsTelemetry({ clock = Date.now, securityLoggingEnabled = false } = {}) {
  const startedAt = clock(), total = empty();
  if (!count(startedAt)) fail('METRICS_CLOCK_INVALID', 503);
  const windows = new Map();
  let lastTime = startedAt;
  let securityLogFailures = 0;
  function instant() {
    const now = clock();
    if (!count(now) || now < lastTime) { windows.clear(); return lastTime; }
    lastTime = now; return now;
  }
  function prune(now) {
    for (const key of windows.keys()) if (key < Math.floor(now / 60_000) - 4) windows.delete(key);
  }
  function record({ statusCode, durationMs }) {
    if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599 || !Number.isFinite(durationMs) || durationMs < 0) return;
    const now = instant(), minute = Math.floor(now / 60_000);
    prune(now);
    if (!windows.has(minute)) windows.set(minute, empty());
    for (const target of [total, windows.get(minute)]) {
      target.requests = increment(target.requests);
      target.statusClasses[`${Math.floor(statusCode / 100)}xx`] = increment(target.statusClasses[`${Math.floor(statusCode / 100)}xx`]);
      if (statusCode >= 500) target.serverErrors = increment(target.serverErrors);
      if ([401, 403].includes(statusCode)) target.denied = increment(target.denied);
      if (statusCode === 429) target.rateLimited = increment(target.rateLimited);
      target.latencySumMs = increment(target.latencySumMs, Math.min(durationMs, 86_400_000));
      LATENCY_MS.forEach((bound, index) => { if (durationMs <= bound) target.latencyBuckets[index] = increment(target.latencyBuckets[index]); });
    }
  }
  function snapshot() {
    const now = instant(); prune(now);
    const recent = empty();
    for (const value of windows.values()) {
      for (const key of ['requests', 'serverErrors', 'denied', 'rateLimited', 'latencySumMs']) recent[key] = increment(recent[key], value[key]);
      for (const key of classes) recent.statusClasses[key] = increment(recent.statusClasses[key], value.statusClasses[key]);
      value.latencyBuckets.forEach((value, index) => { recent.latencyBuckets[index] = increment(recent.latencyBuckets[index], value); });
    }
    const bucket = recent.latencyBuckets.findIndex(value => recent.requests && value >= recent.requests * .95);
    return structuredClone({ startedAt, uptimeSeconds: Math.max(0, Math.floor((now - startedAt) / 1000)), securityLog: { configured: securityLoggingEnabled, failures: securityLogFailures },
      lifetime: total, recent: { ...recent, windowSeconds: WINDOW_MS / 1000, bucketSeconds: 60,
        p95UpperBoundMs: recent.requests && bucket >= 0 ? LATENCY_MS[bucket] : null,
        p95AboveMaxBucket: recent.requests > 0 && bucket < 0 }, latencyBoundsMs: LATENCY_MS });
  }
  return Object.freeze({ record, snapshot, securityLogFailed() { securityLogFailures = increment(securityLogFailures); } });
}

function operatorScope(operator) {
  if (!operator || !Array.isArray(operator.roles) || !operator.roles.includes('operator') || typeof operator.tenantId !== 'string' || !operator.tenantId) fail('FORBIDDEN', 403);
  return operator.tenantId;
}

function capacity(maintenance, keyring) {
  const usage = maintenance.usage ?? {}, limits = maintenance.limits ?? {}, statistics = maintenance.statistics ?? {};
  return [
    ['tickets', usage.tickets, limits.maxTickets], ['requests', usage.requests, limits.maxRequests],
    ['receipts', usage.receipts, limits.maxRequests], ['backend_bytes', usage.backendBytes, limits.maxBackendBytes],
    ['ledger_bytes', usage.ledgerBytes ?? statistics.ledgerBytes, limits.maxLedgerBytes ?? statistics.ledgerByteLimit],
    ['retained_keys', keyring?.keyCount, keyring?.maxKeys ?? limits.maxRetainedKeys],
  ].map(([id, used, limit]) => {
    const measured = count(used) && count(limit) && limit > 0, ratio = measured ? used / limit : null;
    return { id, used: count(used) ? used : null, limit: count(limit) ? limit : null, ratio,
      state: !measured ? 'unknown' : ratio >= .95 ? 'critical' : ratio >= .8 ? 'warning' : 'ok' };
  });
}

/** For the trusted host's stdout collector: deployment aggregates only, no tenant/actor references. */
export function monitoringSummary({ workflow, telemetry, keyring, tenantIdForStatistics, tlsExpiresAt, now = Date.now() }) {
  workflow.health();
  const requests = Object.values(workflow.data().requests), unconfirmed = requests.filter(request => ['dispatching', 'unconfirmed'].includes(request.state));
  const capacities = capacity(workflow.maintenance({ tenantId: tenantIdForStatistics }), keyring), http = telemetry.snapshot();
  return { schemaVersion: 1, capturedAt: now, scope: 'deployment', uptimeSeconds: http.uptimeSeconds,
    requests: requests.length, unconfirmed: unconfirmed.length,
    oldestUnconfirmedMs: unconfirmed.reduce((age, request) => Math.max(age, count(request.createdAt) ? Math.max(0, now - request.createdAt) : 0), 0),
    securityLog: http.securityLog, http: { windowSeconds: http.recent.windowSeconds, requests: http.recent.requests, serverErrors: http.recent.serverErrors,
      rateLimited: http.recent.rateLimited, p95UpperBoundMs: http.recent.p95UpperBoundMs, p95AboveMaxBucket: http.recent.p95AboveMaxBucket },
    capacity: capacities, capacityWarning: capacities.some(item => item.state !== 'ok'),
    ...(count(tlsExpiresAt) ? { tlsExpiresAt } : {}) };
}

/** Aggregates are scoped explicitly: workflow/activity to the tenant, HTTP/capacity to the deployment. */
export function operationalStatus({ workflow, operator, telemetry, keyring, tlsExpiresAt, now = Date.now() }) {
  const tenantId = operatorScope(operator);
  if (!count(now)) fail('STATUS_UNAVAILABLE', 503);
  if (count(tlsExpiresAt) && now >= tlsExpiresAt) fail('TLS_CERTIFICATE_EXPIRED', 503);
  workflow.health();
  const data = workflow.data(), maintenance = workflow.maintenance(operator);
  const requests = Object.values(data.requests).filter(request => request.tenantId === tenantId);
  const pending = requests.filter(request => request.state === 'pending' && request.expiresAt > now);
  const unconfirmed = requests.filter(request => ['dispatching', 'unconfirmed'].includes(request.state));
  const oldest = unconfirmed.reduce((age, request) => Math.max(age, count(request.createdAt) ? Math.max(0, now - request.createdAt) : 0), 0);
  const http = telemetry.snapshot(), capacities = capacity(maintenance, keyring), alerts = [];
  if (!http.securityLog.configured || http.securityLog.failures) alerts.push({ id: 'security_log', severity: http.securityLog.failures ? 'critical' : 'warning',
    message: http.securityLog.failures ? 'A security event could not reach the configured host logger. Investigate collector health and preserve local evidence.' : 'No host security-event logger is configured. Enroll the deployment collector before production use.' });
  if (count(tlsExpiresAt) && tlsExpiresAt - now < 14 * 86_400_000) alerts.push({ id: 'tls_expiry', severity: tlsExpiresAt - now < 7 * 86_400_000 ? 'critical' : 'warning', message: 'Renew the served TLS certificate and restart before it expires.' });
  if (unconfirmed.length) alerts.push({ id: 'unconfirmed_outcome', severity: oldest >= 300_000 ? 'critical' : 'warning',
    message: 'An original submission needs receipt reconciliation. Do not resubmit it.', count: unconfirmed.length });
  for (const item of capacities) if (item.state !== 'ok') alerts.push({ id: `capacity_${item.id}`, severity: item.state === 'critical' ? 'critical' : 'warning',
    message: item.state === 'unknown' ? 'Capacity usage is unavailable. Verify host instrumentation.' : 'Review retained usage and the offline maintenance plan before accepting more work.' });
  if (http.recent.serverErrors >= 5 && http.recent.serverErrors / http.recent.requests >= .05) alerts.push({ id: 'http_errors', severity: 'critical', message: 'Service failures exceeded the five-minute warning threshold. Check readiness and preserve state.' });
  if (http.recent.rateLimited >= 10) alerts.push({ id: 'rate_limited', severity: 'warning', message: 'Repeated requests are being rate limited. Inspect workload volume and client retry behavior.' });
  if (http.recent.requests >= 20 && (http.recent.p95AboveMaxBucket || http.recent.p95UpperBoundMs > 2000)) alerts.push({ id: 'http_latency', severity: 'warning', message: 'Request latency exceeded the two-second operating target. Inspect host load and storage.' });
  return { schemaVersion: 1, capturedAt: now, scope: { tenantId, workflow: 'tenant', capacity: 'deployment', http: 'deployment' },
    service: { ready: true, startedAt: http.startedAt, uptimeSeconds: http.uptimeSeconds, ...(count(tlsExpiresAt) ? { tlsExpiresAt } : {}) },
    workflow: { requests: requests.length, pending: pending.length, unconfirmed: unconfirmed.length, oldestUnconfirmedMs: oldest },
    capacity: capacities, http, alerts, audit: { retainedEvents: data.audit.filter(event => event.tenantId === tenantId).length,
      coverage: 'bounded_activity_only', completeHistory: false } };
}

/** Fixed metric names and numeric values only: no user-controlled Prometheus labels. */
export function prometheusStatus(status) {
  const lines = ['# HELP agent_ops_ready Store readiness at the authenticated observation.', '# TYPE agent_ops_ready gauge', 'agent_ops_ready 1',
    '# TYPE agent_ops_uptime_seconds gauge', `agent_ops_uptime_seconds ${status.service.uptimeSeconds}`,
    '# TYPE agent_ops_http_requests_total counter'];
  for (const key of classes) lines.push(`agent_ops_http_requests_total{class="${key}"} ${status.http.lifetime.statusClasses[key]}`);
  lines.push('# TYPE agent_ops_http_duration_seconds histogram');
  status.http.latencyBoundsMs.forEach((bound, index) => lines.push(`agent_ops_http_duration_seconds_bucket{le="${bound / 1000}"} ${status.http.lifetime.latencyBuckets[index]}`));
  lines.push(`agent_ops_http_duration_seconds_bucket{le="+Inf"} ${status.http.lifetime.requests}`,
    `agent_ops_http_duration_seconds_sum ${status.http.lifetime.latencySumMs / 1000}`, `agent_ops_http_duration_seconds_count ${status.http.lifetime.requests}`);
  for (const item of status.capacity) {
    if (item.used !== null) lines.push(`agent_ops_capacity_used{resource="${item.id}"} ${item.used}`);
    if (item.limit !== null) lines.push(`agent_ops_capacity_limit{resource="${item.id}"} ${item.limit}`);
  }
  lines.push(`agent_ops_tenant_unconfirmed ${status.workflow.unconfirmed}`, `agent_ops_tenant_oldest_unconfirmed_seconds ${status.workflow.oldestUnconfirmedMs / 1000}`);
  lines.push(`agent_ops_security_log_failures_total ${status.http.securityLog.failures}`, `agent_ops_security_log_configured ${status.http.securityLog.configured ? 1 : 0}`);
  return lines.join('\n') + '\n';
}

/** A minimized operational snapshot, never a replacement for authoritative retained receipts. */
export function exportActivity({ workflow, operator, now = Date.now() }) {
  const tenantId = operatorScope(operator), data = workflow.data();
  if (!count(now) || !Array.isArray(data.audit) || data.audit.length > 4000) fail('AUDIT_EXPORT_UNAVAILABLE', 503);
  const retained = data.audit.filter(event => event.tenantId === tenantId);
  const events = retained.slice(-1000).map(event => {
    if (!count(event.at) || typeof event.event !== 'string' || !/^[A-Z_]{1,64}$/.test(event.event) ||
        typeof event.requestId !== 'string' || !/^[A-Za-z0-9_.:@/-]{1,160}$/.test(event.requestId) ||
        event.operatorId !== undefined && (typeof event.operatorId !== 'string' || !/^[A-Za-z0-9_.:@/-]{1,160}$/.test(event.operatorId))) fail('AUDIT_EXPORT_UNAVAILABLE', 503);
    return { at: event.at, event: event.event, requestId: event.requestId, ...(event.operatorId ? { operatorId: event.operatorId } : {}) };
  });
  const payload = { schemaVersion: 1, kind: 'agent-ops-activity-snapshot', tenantId, capturedAt: now,
    coverage: { kind: 'bounded_activity_only', completeHistory: false, retainedEventCount: retained.length, exportedEventCount: events.length,
      omittedRetainedEvents: retained.length - events.length, historicalDropCount: 'unknown',
      earliestExportedAt: events.length ? Math.min(...events.map(event => event.at)) : null,
      latestExportedAt: events.length ? Math.max(...events.map(event => event.at)) : null,
      note: 'Older events may have been dropped. This snapshot does not include authoritative receipts, archived payloads or a complete decision history.' }, events };
  const content = JSON.stringify(payload) + '\n';
  if (Buffer.byteLength(content) > 512 * 1024) fail('AUDIT_EXPORT_LIMIT', 503);
  return { filename: 'agent-ops-activity.json', content, bytes: Buffer.byteLength(content),
    digest: createHash('sha256').update(content).digest('hex'), eventCount: events.length,
    coverage: 'bounded_activity_only', completeHistory: false, omittedRetainedEvents: retained.length - events.length };
}
