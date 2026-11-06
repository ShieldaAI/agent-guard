// Optional synthetic-benchmark instrumentation. Never imported by production packages.
import { performance, PerformanceObserver } from 'node:perf_hooks';
import { threadId } from 'node:worker_threads';
import { isPromise, isProxy } from 'node:util/types';
import { AsyncLocalStorage } from 'node:async_hooks';
import { channel } from 'node:diagnostics_channel';
import { openSync, readSync, closeSync } from 'node:fs';

const STREAMS = ['polls', 'ticks', 'exports', 'observations', 'requests', 'heartbeats', 'gc', 'prepare', 'execute', 'ledgerRead', 'ledgerTransaction',
  'fetches', 'httpMilestones', 'workerMilestones', 'threadCounters'];
export const DIAGNOSTIC_ROLES = Object.freeze({ owner: 0, poll: 1, workload: 2, inventory: 3 });
export const HTTP_MILESTONES = Object.freeze({ create: 1, beforeConnect: 2, connected: 3, sendHeaders: 4, headers: 5, error: 6, connectError: 7 });
export const WORKER_MILESTONES = Object.freeze({ constructStart: 1, constructReturn: 2, online: 3, ready: 4, roleEntered: 5,
  firstRequest: 6, postStart: 7, postReturn: 8, resultReceived: 9, errorReceived: 10 });
const RESOURCE_COUNTERS = ['minorPageFault', 'majorPageFault', 'fsRead', 'fsWrite',
  'voluntaryContextSwitches', 'involuntaryContextSwitches'];
const FIELDS = {
  polls: ['poll', 'startedNs', 'headersNs', 'bodyNs', 'parseStartedNs', 'parsedNs', 'completedNs', 'status', 'bytes', 'ok'],
  ticks: ['atNs', 'scheduled', 'skippedBusy', 'poll'],
  exports: ['startedNs', 'endedNs', 'durationMs', 'ok'],
  requests: ['id', 'startedNs', 'endedNs', 'durationMs', 'finished', 'status'],
  heartbeats: ['startedNs', 'endedNs', 'intervalElapsedMs', 'requestedIntervalMs', 'eventLoopActiveMs', 'eventLoopIdleMs',
    'eventLoopUtilization', 'processCpuUserUs', 'processCpuSystemUs', ...RESOURCE_COUNTERS],
  gc: ['startedNs', 'endedNs', 'deliveredNs', 'durationMs', 'kind', 'flags'],
  fetches: ['id', 'role', 'startedNs', 'returnedNs', 'ok', 'promise'],
  httpMilestones: ['atNs', 'event', 'role', 'fetch', 'request', 'connection', 'socket'],
  workerMilestones: ['atNs', 'event', 'role', 'worker', 'job', 'ok'],
  threadCounters: ['atNs', 'role', 'event', 'ref', 'threadCpuAvailable', 'threadCpuUserUs', 'threadCpuSystemUs',
    'schedstatAvailable', 'schedRunNs', 'schedWaitNs', 'schedSlices'],
};
for (const name of ['observations', 'prepare', 'execute', 'ledgerRead', 'ledgerTransaction'])
  FIELDS[name] = ['id', 'startedNs', 'returnedNs', 'endedNs', 'durationMs', 'ok', 'asynchronous'];
const elapsed = (start, end) => Number(end - start) / 1e6;
const finite = value => Number.isFinite(value) ? value : null;

export function createAdmissionDiagnostics({ processMetrics = false, limit = 4096, intervalMs = 100 } = {}) {
  if (typeof processMetrics !== 'boolean' || !Number.isInteger(limit) || limit < 1 || limit > 4096 ||
      !Number.isInteger(intervalMs) || intervalMs < 10 || intervalMs > 1000)
    throw new Error('ADMISSION_DIAGNOSTICS_CONFIG_INVALID');
  const streams = Object.fromEntries(STREAMS.map(name => [name, { observed: 0, dropped: 0, samples: [] }]));
  let errors = 0, closed = false, timer, observer, final, previous;
  const fail = () => { errors++; };
  const add = (name, sample) => {
    if (closed) return;
    try {
      if (!Object.hasOwn(streams, name)) { fail(); return; }
      const stream = streams[name];
      stream.observed++;
      if (stream.samples.length >= limit) { stream.dropped++; return; }
      const keys = Object.getOwnPropertyNames(sample), allowed = FIELDS[name], copy = Object.create(null);
      if (Object.getOwnPropertySymbols(sample).length || keys.length > allowed.length) { fail(); return; }
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(sample, key);
        if (!allowed.includes(key) || !descriptor.enumerable || !('value' in descriptor)) { fail(); return; }
        const value = descriptor.value;
        if (!(value === null || typeof value === 'boolean' ||
            (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER) ||
            (key.endsWith('Ns') && typeof value === 'string' && /^\d{1,30}$/.test(value)))) { fail(); return; }
        copy[key] = value;
      }
      stream.samples.push(copy);
    } catch { fail(); }
  };
  const startedNs = process.hrtime.bigint();
  const calibrationBefore = process.hrtime.bigint(), performanceNow = performance.now(), calibrationAfter = process.hrtime.bigint();
  const anchor = (calibrationBefore + calibrationAfter) / 2n;
  const gcSupported = PerformanceObserver.supportedEntryTypes.includes('gc');
  const read = () => ({ atNs: process.hrtime.bigint(), elu: performance.eventLoopUtilization(),
    ...(processMetrics ? { cpu: process.cpuUsage(), resources: process.resourceUsage() } : {}) });
  const initial = read(); previous = initial;
  const gc = entries => {
    for (const entry of entries) {
      try {
        if (!Number.isFinite(entry.startTime) || !Number.isFinite(entry.duration) || entry.duration < 0) { fail(); continue; }
        const begin = anchor + BigInt(Math.round((entry.startTime - performanceNow) * 1e6));
        add('gc', { startedNs: begin.toString(), endedNs: (begin + BigInt(Math.round(entry.duration * 1e6))).toString(),
          deliveredNs: process.hrtime.bigint().toString(), durationMs: entry.duration,
          kind: finite(entry.detail?.kind), flags: finite(entry.detail?.flags) });
      } catch { fail(); }
    }
  };
  const heartbeat = () => {
    try {
      const current = read(), utilization = performance.eventLoopUtilization(current.elu, previous.elu);
      const sample = { startedNs: previous.atNs.toString(), endedNs: current.atNs.toString(),
        intervalElapsedMs: elapsed(previous.atNs, current.atNs), requestedIntervalMs: intervalMs,
        eventLoopActiveMs: finite(utilization.active), eventLoopIdleMs: finite(utilization.idle),
        eventLoopUtilization: finite(utilization.utilization) };
      if (processMetrics) {
        sample.processCpuUserUs = current.cpu.user - previous.cpu.user;
        sample.processCpuSystemUs = current.cpu.system - previous.cpu.system;
        for (const name of RESOURCE_COUNTERS) sample[name] = current.resources[name] - previous.resources[name];
      }
      previous = current; add('heartbeats', sample);
    } catch { fail(); }
  };
  try {
    if (gcSupported) { observer = new PerformanceObserver(list => gc(list.getEntries())); observer.observe({ entryTypes: ['gc'] }); }
    timer = setInterval(heartbeat, intervalMs); timer.unref();
  } catch { fail(); }
  return {
    add, fail,
    stop() {
      if (final) return final;
      clearInterval(timer);
      try { if (observer) gc(observer.takeRecords()); } catch { fail(); }
      finally { try { observer?.disconnect(); } catch { fail(); } }
      heartbeat(); closed = true;
      let totals = null;
      try {
        const current = read(), utilization = performance.eventLoopUtilization(current.elu, initial.elu);
        totals = { endedNs: current.atNs.toString(), elapsedMs: elapsed(initial.atNs, current.atNs),
          eventLoopActiveMs: finite(utilization.active), eventLoopIdleMs: finite(utilization.idle),
          eventLoopUtilization: finite(utilization.utilization) };
        if (processMetrics) {
          totals.processCpuUserUs = current.cpu.user - initial.cpu.user;
          totals.processCpuSystemUs = current.cpu.system - initial.cpu.system;
          totals.processMaxRssKiB = current.resources.maxRSS;
          for (const name of RESOURCE_COUNTERS) totals[name] = current.resources[name] - initial.resources[name];
        }
      } catch { fail(); }
      final = { threadId, startedNs: startedNs.toString(), closed, errors, gcSupported, processMetrics,
        definitions: { roles: DIAGNOSTIC_ROLES, httpMilestones: HTTP_MILESTONES, workerMilestones: WORKER_MILESTONES },
        complete: errors === 0 && gcSupported && Object.values(streams).every(stream => stream.dropped === 0),
        limitPerStream: limit, clockCalibrationUncertaintyNs: (calibrationAfter - calibrationBefore).toString(), totals, streams };
      return final;
    },
  };
}

/** Preserve dynamic this, argument identity, exact return and thrown value. Retain none of those values. */
export function instrumentInventorySnapshot(executor, diagnostics) {
  const own = Object.getOwnPropertyDescriptor(executor, 'inventorySnapshot');
  const original = executor.inventorySnapshot;
  Object.defineProperty(executor, 'inventorySnapshot', { configurable: true, writable: true,
    value: function (...args) {
      const startedNs = process.hrtime.bigint(); let ok = false;
      try { const value = Reflect.apply(original, this, args); ok = true; return value; }
      finally {
        // A diagnostic failure must never replace the original result or exception.
        try {
          const endedNs = process.hrtime.bigint();
          diagnostics.add('exports', { startedNs: startedNs.toString(), endedNs: endedNs.toString(),
            durationMs: elapsed(startedNs, endedNs), ok });
        } catch { try { diagnostics.fail(); } catch { /* no authority behavior change */ } }
      }
    } });
  let restored = false;
  return () => {
    if (restored) return;
    if (own) Object.defineProperty(executor, 'inventorySnapshot', own); else delete executor.inventorySnapshot;
    restored = true;
  };
}

/** Timestamps only: never inspect or retain request headers, URLs, bodies or response payloads. */
export function instrumentObserverRequests(server, diagnostics) {
  let sequence = 0;
  const pending = new Set();
  const request = (_request, response) => {
    const startedNs = process.hrtime.bigint(), id = ++sequence;
    const detach = () => { response.off('finish', finish); response.off('close', close); pending.delete(detach); };
    const ended = finished => {
      detach();
      try {
        const endedNs = process.hrtime.bigint();
        diagnostics.add('requests', { id, startedNs: startedNs.toString(), endedNs: endedNs.toString(),
          durationMs: elapsed(startedNs, endedNs), finished, status: response.statusCode });
      } catch { try { diagnostics.fail(); } catch { /* diagnostics only */ } }
    };
    const finish = () => ended(true), close = () => ended(false);
    // The real observer caps concurrent sockets at32; also bound retained diagnostic listeners.
    if (pending.size >= 4096) { diagnostics.fail(); return; }
    pending.add(detach); response.once('finish', finish); response.once('close', close);
  };
  server.prependListener('request', request);
  return () => {
    server.off('request', request);
    // An unfinished span is evidence loss, not a fabricated completed request.
    if (pending.size) diagnostics.fail();
    for (const detach of pending) detach();
  };
}

/**
 * Fixed hooks in the disposable benchmark process only. Ledger transaction spans
 * include nested reads and commit work; overlapping durations must not be summed.
 * Async spans end in a Promise reaction, not an invented synchronous completion.
 */
function instrumentMethods(hooks, diagnostics) {
  const restores = []; let pending = 0, restored = false;
  const fail = () => { try { diagnostics.fail(); } catch { /* never affect the original call */ } };
  const install = (target, method, stream, asynchronous) => {
    const own = Object.getOwnPropertyDescriptor(target, method), original = target[method];
    if (typeof original !== 'function') throw new Error('ADMISSION_DIAGNOSTICS_HOOK_INVALID');
    let sequence = 0;
    Object.defineProperty(target, method, { configurable: true, writable: true,
      value: function (...args) {
        const startedNs = process.hrtime.bigint(), id = ++sequence;
        let returnedNs = null, observing = false, finished = false;
        const finish = ok => {
          if (finished) return;
          finished = true; if (observing) pending--;
          try {
            const endedNs = process.hrtime.bigint();
            diagnostics.add(stream, { id, startedNs: startedNs.toString(), returnedNs: returnedNs?.toString() ?? null,
              endedNs: endedNs.toString(), durationMs: elapsed(startedNs, endedNs), ok, asynchronous: observing });
          } catch { fail(); }
        };
        let result;
        try { result = Reflect.apply(original, this, args); }
        catch (error) { finish(false); throw error; }
        returnedNs = process.hrtime.bigint();
        if (asynchronous) {
          if (isPromise(result)) {
            observing = true; pending++;
            // Return the exact original Promise. These extra reactions perturb
            // scheduling/handledness, which is why profiling is never acceptance.
            try { Promise.prototype.then.call(result, () => finish(true), () => finish(false)); }
            catch { fail(); finish(false); }
          } else { fail(); finish(true); }
        } else finish(true);
        return result;
      } });
    restores.push(() => { if (own) Object.defineProperty(target, method, own); else delete target[method]; });
  };
  const restore = () => {
    if (restored) return;
    restored = true;
    if (pending) fail();
    for (const release of restores.reverse()) { try { release(); } catch { fail(); } }
  };
  try {
    for (const hook of hooks) install(...hook);
  } catch (error) { restore(); throw error; }
  return restore;
}

/** Async HTTP observation includes its bounded queue, trusted worker and serialization. */
export function instrumentInventoryObservation(ObservationSession, diagnostics) {
  return instrumentMethods([[ObservationSession.prototype, 'snapshot', 'observations', true]], diagnostics);
}

export function instrumentAdmissionMethods(executor, LedgerStore, diagnostics) {
  return instrumentMethods([
    [executor, 'prepare', 'prepare', true], [executor, 'execute', 'execute', true],
    [LedgerStore.prototype, 'read', 'ledgerRead', false],
    [LedgerStore.prototype, 'transaction', 'ledgerTransaction', false],
  ], diagnostics);
}

const diagnosticFailure = diagnostics => { try { diagnostics.fail(); } catch { /* never replace original behavior */ } };
const record = (diagnostics, stream, sample) => {
  try { diagnostics.add(stream, sample); } catch { diagnosticFailure(diagnostics); }
};
const objectKey = value => value !== null && (typeof value === 'object' || typeof value === 'function') && !isProxy(value);
// Read only this named data property. Never invoke getters or enumerate payloads.
function ownValue(value, name) {
  if (!objectKey(value)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
function readSchedstat() {
  if (process.platform !== 'linux') return null;
  const fd = openSync('/proc/thread-self/schedstat', 'r');
  try {
    const buffer = Buffer.alloc(129), count = readSync(fd, buffer, 0, buffer.length, 0);
    if (count === buffer.length) return null;
    const match = /^(\d{1,30}) (\d{1,30}) (\d{1,15})\n?$/.exec(buffer.subarray(0, count).toString('ascii'));
    return match ? { run: match[1], wait: match[2], slices: Number(match[3]) } : null;
  } finally { closeSync(fd); }
}

/** Absolute thread counters at a few cold-path boundaries; missing facilities are explicit, not zero. */
export function recordAdmissionThreadCounters(diagnostics, role, event, ref = 0,
  { cpu = () => typeof process.threadCpuUsage === 'function' ? process.threadCpuUsage() : null, schedstat = readSchedstat } = {}) {
  let usage = null, scheduler = null;
  try { const value = cpu(); if (value && Number.isSafeInteger(value.user) && value.user >= 0 &&
    Number.isSafeInteger(value.system) && value.system >= 0) usage = value; } catch { /* unsupported */ }
  try { const value = schedstat(); if (value && typeof value.run === 'string' && typeof value.wait === 'string' && /^\d{1,30}$/.test(value.run) && /^\d{1,30}$/.test(value.wait) &&
    Number.isSafeInteger(value.slices) && value.slices >= 0) scheduler = value; } catch { /* unsupported */ }
  record(diagnostics, 'threadCounters', { atNs: process.hrtime.bigint().toString(), role, event, ref,
    threadCpuAvailable: usage !== null, threadCpuUserUs: usage?.user ?? null, threadCpuSystemUs: usage?.system ?? null,
    schedstatAvailable: scheduler !== null, schedRunNs: scheduler?.run ?? null, schedWaitNs: scheduler?.wait ?? null,
    schedSlices: scheduler?.slices ?? null });
}

/** No async wrapper, Promise reaction or fetch-argument inspection. All subscriptions are opt-in and disposable. */
export function instrumentAdmissionFetch(diagnostics, role, target = globalThis) {
  const descriptor = Object.getOwnPropertyDescriptor(target, 'fetch'), original = target.fetch;
  if (typeof original !== 'function') throw new Error('ADMISSION_DIAGNOSTICS_HOOK_INVALID');
  const context = new AsyncLocalStorage(), requests = new WeakMap(), connections = new WeakMap(), sockets = new WeakMap();
  let calls = 0, expectedRequests = 0, requestCount = 0, connectionCount = 0, socketCount = 0, closed = false, overflow = false;
  const subscriptions = [], pending = new Set(), observedFetches = new Set();
  const limited = count => {
    if (count <= 4096) return true;
    if (!overflow) { overflow = true; diagnosticFailure(diagnostics); }
    return false;
  };
  const identity = (map, object, next) => {
    if (!objectKey(object)) return null;
    let id = map.get(object);
    if (!id) { id = next(); if (!limited(id)) return null; map.set(object, id); }
    return id;
  };
  const observe = (name, event) => {
    const selected = channel('undici:' + name);
    const listener = message => {
      if (closed || overflow) return;
      try {
        let request = null, fetch = null, connection = null, socket = null;
        const rawRequest = ownValue(message, 'request');
        if (event === HTTP_MILESTONES.create) {
          const active = context.getStore();
          if (!Number.isSafeInteger(active) || !objectKey(rawRequest) || requests.has(rawRequest)) { diagnosticFailure(diagnostics); return; }
          request = ++requestCount; fetch = active;
          if (!limited(request)) return;
          requests.set(rawRequest, { request, fetch }); pending.add(request); observedFetches.add(fetch);
        } else if (name.startsWith('request:') || event === HTTP_MILESTONES.sendHeaders) {
          const known = objectKey(rawRequest) ? requests.get(rawRequest) : undefined;
          if (!known || typeof known !== 'object') { diagnosticFailure(diagnostics); return; }
          ({ request, fetch } = known);
          if (event === HTTP_MILESTONES.headers || event === HTTP_MILESTONES.error) pending.delete(request);
        }
        // Connection creation is pooled; never attribute it to a request via async context.
        if (event === HTTP_MILESTONES.beforeConnect || event === HTTP_MILESTONES.connected || event === HTTP_MILESTONES.connectError)
          connection = identity(connections, ownValue(message, 'connectParams'), () => ++connectionCount);
        if (event === HTTP_MILESTONES.connected || event === HTTP_MILESTONES.sendHeaders)
          socket = identity(sockets, ownValue(message, 'socket'), () => ++socketCount);
        record(diagnostics, 'httpMilestones', { atNs: process.hrtime.bigint().toString(), event, role, fetch, request, connection, socket });
      } catch { diagnosticFailure(diagnostics); }
    };
    selected.subscribe(listener); subscriptions.push(() => selected.unsubscribe(listener));
  };
  try {
    for (const [name, event] of [['request:create', 1], ['client:beforeConnect', 2], ['client:connected', 3],
      ['client:sendHeaders', 4], ['request:headers', 5], ['request:error', 6], ['client:connectError', 7]]) observe(name, event);
    Object.defineProperty(target, 'fetch', { configurable: true, writable: true, value: function (...args) {
      if (closed) return Reflect.apply(original, this, args);
      const id = ++calls;
      if (!limited(id)) return Reflect.apply(original, this, args);
      if (id <= 3) recordAdmissionThreadCounters(diagnostics, role, 1, id);
      const startedNs = process.hrtime.bigint(); let result, ok = false, returnedNs;
      try {
        result = context.run(id, () => Reflect.apply(original, this, args));
        returnedNs = process.hrtime.bigint(); ok = true; if (isPromise(result)) expectedRequests++; return result;
      } finally {
        returnedNs ??= process.hrtime.bigint();
        record(diagnostics, 'fetches', { id, role, startedNs: startedNs.toString(), returnedNs: returnedNs.toString(), ok, promise: isPromise(result) });
        if (id <= 3) recordAdmissionThreadCounters(diagnostics, role, 2, id);
      }
    } });
  } catch (error) { for (const unsubscribe of subscriptions) unsubscribe(); context.disable(); throw error; }
  return () => {
    if (closed) return; closed = true;
    if (pending.size || observedFetches.size !== expectedRequests) diagnosticFailure(diagnostics);
    pending.clear(); observedFetches.clear(); for (const unsubscribe of subscriptions) unsubscribe(); context.disable();
    if (descriptor) Object.defineProperty(target, 'fetch', descriptor); else delete target.fetch;
  };
}

/** Parent-side worker edges only. Never changes execArgv/env or examines authority payloads. */
export function instrumentAdmissionWorkers(Worker, diagnostics) {
  const emitDescriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'emit');
  const postDescriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage');
  const emit = Worker.prototype.emit, post = Worker.prototype.postMessage, workers = new WeakMap();
  let sequence = 0, closed = false, overflow = false;
  const identify = (worker, role = null) => {
    let entry = workers.get(worker);
    if (!entry) {
      if (sequence >= 4096) { if (!overflow) diagnosticFailure(diagnostics); overflow = true; return null; }
      entry = { id: ++sequence, role }; workers.set(worker, entry);
    } else if (role !== null) entry.role = role;
    return entry;
  };
  const mark = (worker, event, role = null, job = null, ok = true) => {
    if (closed) return;
    try {
      const entry = identify(worker, role); if (!entry) return;
      record(diagnostics, 'workerMilestones', { atNs: process.hrtime.bigint().toString(), event, role: entry.role, worker: entry.id, job, ok });
    } catch { diagnosticFailure(diagnostics); }
  };
  let emitInstalled = false;
  try {
  Object.defineProperty(Worker.prototype, 'emit', { configurable: true, writable: true, value: function (event, ...args) {
    if (!closed) try {
      if (event === 'online') mark(this, WORKER_MILESTONES.online);
      if (event === 'message') {
        const type = ownValue(args[0], 'type');
        if (type === 'ready') mark(this, WORKER_MILESTONES.ready, DIAGNOSTIC_ROLES.inventory);
        if (args[0] === 'ready') mark(this, WORKER_MILESTONES.ready, DIAGNOSTIC_ROLES.poll);
        if (type === 'result' || type === 'error') {
          const id = ownValue(args[0], 'id');
          if (Number.isSafeInteger(id) && id > 0) mark(this, type === 'result' ? WORKER_MILESTONES.resultReceived : WORKER_MILESTONES.errorReceived, DIAGNOSTIC_ROLES.inventory, id);
        }
      }
    } catch { diagnosticFailure(diagnostics); }
    return Reflect.apply(emit, this, [event, ...args]);
  } });
  emitInstalled = true;
  Object.defineProperty(Worker.prototype, 'postMessage', { configurable: true, writable: true, value: function (...args) {
    let id;
    if (!closed) try { if (ownValue(args[0], 'type') === 'snapshot') id = ownValue(args[0], 'id'); } catch { diagnosticFailure(diagnostics); }
    const selected = Number.isSafeInteger(id) && id > 0;
    if (selected) mark(this, WORKER_MILESTONES.postStart, DIAGNOSTIC_ROLES.inventory, id);
    let ok = false;
    try { const result = Reflect.apply(post, this, args); ok = true; return result; }
    finally { if (selected) mark(this, WORKER_MILESTONES.postReturn, DIAGNOSTIC_ROLES.inventory, id, ok); }
  } });
  } catch (error) {
    closed = true;
    if (emitInstalled) {
      try {
        if (emitDescriptor) Object.defineProperty(Worker.prototype, 'emit', emitDescriptor); else delete Worker.prototype.emit;
      } catch { diagnosticFailure(diagnostics); }
    }
    throw error;
  }
  return {
    construct(role, create) {
      record(diagnostics, 'workerMilestones', { atNs: process.hrtime.bigint().toString(), event: WORKER_MILESTONES.constructStart, role, worker: null, job: null, ok: true });
      const worker = create(); mark(worker, WORKER_MILESTONES.constructReturn, role); return worker;
    },
    restore() {
      if (closed) return; closed = true;
      if (emitDescriptor) Object.defineProperty(Worker.prototype, 'emit', emitDescriptor); else delete Worker.prototype.emit;
      if (postDescriptor) Object.defineProperty(Worker.prototype, 'postMessage', postDescriptor); else delete Worker.prototype.postMessage;
    },
  };
}
