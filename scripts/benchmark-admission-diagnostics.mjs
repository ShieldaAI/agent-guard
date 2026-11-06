// Optional synthetic-benchmark instrumentation. Never imported by production packages.
import { performance, PerformanceObserver } from 'node:perf_hooks';
import { threadId } from 'node:worker_threads';
import { isPromise } from 'node:util/types';

const STREAMS = ['polls', 'ticks', 'exports', 'requests', 'heartbeats', 'gc', 'prepare', 'execute', 'ledgerRead', 'ledgerTransaction'];
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
};
for (const name of ['prepare', 'execute', 'ledgerRead', 'ledgerTransaction'])
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
export function instrumentAdmissionMethods(executor, LedgerStore, diagnostics) {
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
    install(executor, 'prepare', 'prepare', true); install(executor, 'execute', 'execute', true);
    install(LedgerStore.prototype, 'read', 'ledgerRead', false);
    install(LedgerStore.prototype, 'transaction', 'ledgerTransaction', false);
  } catch (error) { restore(); throw error; }
  return restore;
}
