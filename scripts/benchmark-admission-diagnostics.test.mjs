import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import { createAdmissionDiagnostics, instrumentInventorySnapshot, instrumentObserverRequests } from './benchmark-admission-diagnostics.mjs';
import { admissionGate, runAdmissionPhase } from './benchmark-admission.mjs';

test('inventory instrumentation preserves private this, arguments, returns and thrown identity', () => {
  const sentinel = { privateResult: 'NOT-RETAINED' }, thrown = new Error('PRIVATE-FAILURE');
  class Executor {
    #value;
    constructor(value) { this.#value = value; }
    inventorySnapshot(scope, fail) { assert.equal(scope, sentinel); if (fail) throw thrown; return this.#value; }
  }
  const first = new Executor(sentinel), second = new Executor('second');
  const original = first.inventorySnapshot;
  const diagnostics = createAdmissionDiagnostics();
  const restore = instrumentInventorySnapshot(first, diagnostics);
  try {
    assert.equal(first.inventorySnapshot(sentinel), sentinel);
    assert.equal(first.inventorySnapshot.call(second, sentinel), 'second');
    assert.throws(() => first.inventorySnapshot(sentinel, true), error => error === thrown);
  } finally { restore(); }
  assert.equal(first.inventorySnapshot, original); assert.equal(Object.hasOwn(first, 'inventorySnapshot'), false);
  restore();
  const result = diagnostics.stop();
  assert.deepEqual(result.streams.exports.samples.map(sample => sample.ok), [true, true, false]);
  assert.ok(result.streams.exports.samples.every(sample => BigInt(sample.endedNs) >= BigInt(sample.startedNs)));
  assert.equal(JSON.stringify(result).includes('NOT-RETAINED'), false);
  assert.equal(JSON.stringify(result).includes('PRIVATE-FAILURE'), false);

  const owned = { inventorySnapshot: original }; const descriptor = Object.getOwnPropertyDescriptor(owned, 'inventorySnapshot');
  const restoreOwned = instrumentInventorySnapshot(owned, diagnostics); restoreOwned();
  assert.deepEqual(Object.getOwnPropertyDescriptor(owned, 'inventorySnapshot'), descriptor);
});

test('instrumentation recording failure cannot replace the original result or exception', () => {
  const thrown = new Error('original'); let failures = 0;
  const executor = { inventorySnapshot(fail) { if (fail) throw thrown; return 42; } };
  const restore = instrumentInventorySnapshot(executor, {
    add() { throw new Error('diagnostic failure'); }, fail() { failures++; },
  });
  try {
    assert.equal(executor.inventorySnapshot(false), 42);
    assert.throws(() => executor.inventorySnapshot(true), error => error === thrown);
    assert.equal(failures, 2);
  } finally { restore(); }
});

test('bounded diagnostic streams expose loss and stop timers and observers idempotently', async () => {
  const diagnostics = createAdmissionDiagnostics({ limit: 2, intervalMs: 10, processMetrics: true });
  for (let i = 0; i < 4; i++) diagnostics.add('ticks', { atNs: String(i) });
  await sleep(15);
  const result = diagnostics.stop(), snapshot = JSON.stringify(result);
  assert.equal(result.closed, true); assert.equal(result.complete, false);
  assert.equal(result.streams.ticks.observed, 4); assert.equal(result.streams.ticks.dropped, 2);
  assert.equal(result.streams.ticks.samples.length, 2);
  assert.ok(Object.values(result.streams).every(stream => stream.samples.length <= 2));
  assert.ok(result.totals.processCpuUserUs >= 0); assert.ok(result.totals.processCpuSystemUs >= 0);
  assert.equal(diagnostics.stop(), result);
  await sleep(30);
  assert.equal(JSON.stringify(result), snapshot);
  const failed = createAdmissionDiagnostics(); failed.add('unknown-stream', {});
  failed.add('__proto__', {}); failed.add('constructor', {});
  assert.equal(Object.hasOwn(Object.prototype, 'observed'), false);
  assert.equal(failed.stop().complete, false); assert.equal(failed.stop().errors, 3);
  assert.throws(() => createAdmissionDiagnostics({ processMetrics: { private: 'config' } }),
    { message: 'ADMISSION_DIAGNOSTICS_CONFIG_INVALID' });
});

test('diagnostic records detach allowed scalars and reject private fields, nested payloads and getters', () => {
  const diagnostics = createAdmissionDiagnostics(); let invoked = false;
  const sample = { atNs: '123', poll: 1 };
  diagnostics.add('ticks', sample); sample.poll = 99;
  diagnostics.add('ticks', { atNs: '124', authorization: 'PRIVATE-TOKEN' });
  diagnostics.add('polls', { poll: { private: 'PRIVATE-BODY' } });
  diagnostics.add('ticks', { get atNs() { invoked = true; return '125'; } });
  const result = diagnostics.stop();
  assert.equal(invoked, false); assert.equal(result.complete, false); assert.equal(result.errors, 3);
  assert.equal(result.streams.ticks.samples.length, 1); assert.equal(result.streams.ticks.samples[0].poll, 1);
  assert.equal(result.streams.polls.samples.length, 0); assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('request instrumentation retains timestamps only and detaches finished and interrupted listeners', () => {
  const server = new EventEmitter(), existing = () => {};
  server.on('request', existing);
  const diagnostics = createAdmissionDiagnostics(), restore = instrumentObserverRequests(server, diagnostics);
  const response = new EventEmitter(); response.statusCode = 200;
  server.emit('request', { headers: { authorization: 'PRIVATE-TOKEN' }, url: '/PRIVATE-PATH' }, response);
  response.emit('finish'); response.emit('close');
  assert.equal(response.listenerCount('finish'), 0); assert.equal(response.listenerCount('close'), 0);
  const unfinished = new EventEmitter(); unfinished.statusCode = 200;
  server.emit('request', {}, unfinished); restore(); restore();
  assert.equal(server.listenerCount('request'), 1);
  assert.equal(unfinished.listenerCount('finish'), 0); assert.equal(unfinished.listenerCount('close'), 0);
  const result = diagnostics.stop();
  assert.equal(result.complete, false); assert.equal(result.errors, 1);
  assert.equal(result.streams.requests.samples.length, 1);
  assert.equal(result.streams.requests.samples[0].finished, true);
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('diagnostic phase retains exact effects and correlated bounded poll and executor spans', async () => {
  const phase = await runAdmissionPhase({ mode: 'polling', samples: 15, warmup: 2, tasks: 2, grants: 2,
    pollIntervalMs: 10, diagnostics: true });
  assert.equal(phase.successfulEffects, 17); assert.equal(phase.finalCalls, 17);
  assert.equal(phase.samples.length, 15); assert.equal(phase.warmupSamples.length, 2);
  assert.deepEqual(phase.cleanup, { worker: true, clientWorker: true, observer: true, taskServer: true, executor: true, directory: true });
  assert.equal(phase.diagnostics.diagnosticOnly, true); assert.equal(phase.diagnostics.acceptanceEvidenceEligible, false);
  assert.equal(phase.diagnostics.complete, true);
  for (const diagnostic of [phase.diagnostics.main, phase.diagnostics.workload, phase.polling.diagnostics]) {
    assert.equal(diagnostic.closed, true); assert.equal(diagnostic.errors, 0);
    assert.ok(Object.values(diagnostic.streams).every(stream => stream.dropped === 0 && stream.samples.length <= 4096));
  }
  assert.equal(phase.diagnostics.main.processMetrics, true);
  assert.equal(phase.polling.diagnostics.processMetrics, false);
  const polls = phase.polling.diagnostics.streams.polls.samples, exports = phase.diagnostics.main.streams.exports.samples;
  assert.equal(polls.length, phase.polling.started); assert.equal(exports.length, polls.length);
  for (const [index, sample] of polls.entries()) {
    const timeline = ['startedNs', 'headersNs', 'bodyNs', 'parseStartedNs', 'parsedNs', 'completedNs'].map(key => BigInt(sample[key]));
    assert.ok(timeline.every((value, i) => i === 0 || value >= timeline[i - 1]));
    assert.ok(BigInt(exports[index].startedNs) >= timeline[0]);
    assert.ok(BigInt(exports[index].endedNs) <= timeline.at(-1));
    assert.equal(sample.status, 200); assert.equal(sample.ok, true);
    assert.equal(sample.startedNs, phase.polling.samples[index].startedNs);
    assert.equal(sample.completedNs, phase.polling.samples[index].completedNs);
  }
  assert.equal(phase.diagnostics.main.streams.requests.samples.length, polls.length);
  const withoutDiagnostics = structuredClone(phase); delete withoutDiagnostics.diagnostics; delete withoutDiagnostics.polling.diagnostics;
  // Diagnostics never affect gate membership, cadence failures, ratios or thresholds.
  const phases = ['baseline', 'polling', 'polling', 'baseline'].map(mode => ({ ...withoutDiagnostics, mode,
    polling: mode === 'baseline' ? null : { failed: 0, skippedBusy: 0, completedDuringMeasurement: 3 } }));
  assert.equal(admissionGate(phases).passed, true);
  assert.deepEqual(admissionGate(phases), admissionGate(phases.map(item => ({ ...item, diagnostics: { complete: false } }))));
  phases[1].polling.skippedBusy = 1;
  assert.equal(admissionGate(phases).passed, false);
  assert.deepEqual(admissionGate(phases), admissionGate(phases.map(item => ({ ...item, diagnostics: { complete: true } }))));
});
