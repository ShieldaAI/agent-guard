import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
import { channel } from 'node:diagnostics_channel';
import { createAdmissionDiagnostics, instrumentInventorySnapshot, instrumentInventoryObservation, instrumentObserverRequests,
  instrumentAdmissionFetch, instrumentAdmissionWorkers, recordAdmissionThreadCounters, HTTP_MILESTONES, WORKER_MILESTONES } from './benchmark-admission-diagnostics.mjs';
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

test('async observation instrumentation preserves private receivers, Promise identity and rejection without retaining payloads', async () => {
  const secret = { data: 'PRIVATE-SNAPSHOT' }, failure = new Error('PRIVATE-FAILURE');
  const resolved = Promise.resolve(secret), rejected = Promise.reject(failure);
  class Observation {
    #result;
    constructor(result) { this.#result = result; }
    snapshot(request, signal) { assert.equal(request, secret); assert.equal(signal, controller.signal); return this.#result; }
  }
  const controller = new AbortController(), first = new Observation(resolved), second = new Observation(rejected);
  const descriptor = Object.getOwnPropertyDescriptor(Observation.prototype, 'snapshot');
  const diagnostics = createAdmissionDiagnostics(), restore = instrumentInventoryObservation(Observation, diagnostics);
  try {
    assert.equal(first.snapshot(secret, controller.signal), resolved);
    assert.equal(first.snapshot.call(second, secret, controller.signal), rejected);
    assert.equal(await resolved, secret);
    await assert.rejects(rejected, error => error === failure);
  } finally { restore(); }
  restore();
  assert.deepEqual(Object.getOwnPropertyDescriptor(Observation.prototype, 'snapshot'), descriptor);
  const result = diagnostics.stop();
  assert.equal(result.errors, 0);
  assert.deepEqual(result.streams.observations.samples.map(sample => sample.ok), [true, false]);
  assert.ok(result.streams.observations.samples.every(sample => sample.asynchronous &&
    BigInt(sample.endedNs) >= BigInt(sample.returnedNs) && BigInt(sample.returnedNs) >= BigInt(sample.startedNs)));
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('unfinished observation capture is incomplete and synchronous throws preserve identity', async () => {
  const failure = new Error('PRIVATE-FAILURE'); let resolve;
  const pending = new Promise(done => { resolve = done; });
  class Observation { snapshot(fail) { if (fail) throw failure; return pending; } }
  const diagnostics = createAdmissionDiagnostics(), restore = instrumentInventoryObservation(Observation, diagnostics);
  const instance = new Observation();
  assert.throws(() => instance.snapshot(true), error => error === failure);
  assert.equal(instance.snapshot(false), pending);
  restore();
  const result = diagnostics.stop();
  assert.equal(result.complete, false); assert.equal(result.errors, 1);
  assert.deepEqual(result.streams.observations.samples.map(sample => [sample.ok, sample.asynchronous]), [[false, false]]);
  resolve(); await pending;
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
  const polls = phase.polling.diagnostics.streams.polls.samples, observations = phase.diagnostics.main.streams.observations.samples;
  assert.equal(phase.diagnostics.main.streams.exports.observed, 0);
  assert.equal(polls.length, phase.polling.started); assert.equal(observations.length, polls.length);
  for (const [index, sample] of polls.entries()) {
    const timeline = ['startedNs', 'headersNs', 'bodyNs', 'parseStartedNs', 'parsedNs', 'completedNs'].map(key => BigInt(sample[key]));
    assert.ok(timeline.every((value, i) => i === 0 || value >= timeline[i - 1]));
    assert.ok(BigInt(observations[index].startedNs) >= timeline[0]);
    assert.ok(BigInt(observations[index].endedNs) <= timeline.at(-1));
    assert.equal(sample.status, 200); assert.equal(sample.ok, true);
    assert.equal(sample.startedNs, phase.polling.samples[index].startedNs);
    assert.equal(sample.completedNs, phase.polling.samples[index].completedNs);
  }
  assert.equal(phase.diagnostics.main.streams.requests.samples.length, polls.length);
  const fetches = phase.polling.diagnostics.streams.fetches.samples;
  assert.equal(fetches.length, polls.length);
  assert.ok(fetches.every((item, i) => item.id === i + 1 && item.promise && item.ok &&
    BigInt(item.startedNs) >= BigInt(polls[i].startedNs) && BigInt(item.returnedNs) <= BigInt(polls[i].headersNs)));
  const http = phase.polling.diagnostics.streams.httpMilestones.samples;
  assert.equal(http.filter(item => item.event === HTTP_MILESTONES.create).length, polls.length);
  assert.equal(http.filter(item => item.event === HTTP_MILESTONES.headers).length, polls.length);
  assert.ok(http.filter(item => [2, 3, 7].includes(item.event)).every(item => item.fetch === null && item.request === null));
  const workers = phase.diagnostics.main.streams.workerMilestones.samples;
  const ready = workers.find(item => item.role === 1 && item.event === WORKER_MILESTONES.ready);
  const workloadConstruct = workers.find(item => item.role === 2 && item.event === WORKER_MILESTONES.constructStart);
  assert.ok(BigInt(polls[0].startedNs) < BigInt(ready.atNs));
  assert.ok(BigInt(ready.atNs) <= BigInt(workloadConstruct.atNs));
  assert.equal(workers.filter(item => item.event === WORKER_MILESTONES.postStart).length, polls.length);
  assert.equal(workers.filter(item => item.event === WORKER_MILESTONES.postReturn).length, polls.length);
  assert.equal(workers.filter(item => item.event === WORKER_MILESTONES.resultReceived).length, polls.length);
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

test('fetch diagnostics preserve exact receiver arguments Promise and throws; never inspect private HTTP fields', async () => {
  const diagnostics = createAdmissionDiagnostics(), request = {}, socket = {}, connectParams = {};
  const body = { secret: 'PRIVATE-BODY' }, failure = new Error('PRIVATE-ERROR');
  let inspected = 0;
  const message = fields => Object.defineProperties({ ...fields }, {
    headers: { get() { inspected++; throw Error('PRIVATE-HEADERS'); } },
    url: { get() { inspected++; throw Error('PRIVATE-URL'); } },
    body: { get() { inspected++; throw Error('PRIVATE-BODY'); } },
  });
  const publish = (name, fields) => channel('undici:' + name).publish(message(fields));
  let result;
  const target = { fetch(url, options) {
    assert.equal(this, target); assert.equal(url, 'PRIVATE-URL'); assert.equal(options, body);
    publish('request:create', { request });
    publish('client:beforeConnect', { connectParams }); publish('client:connected', { connectParams, socket });
    publish('client:sendHeaders', { request, socket }); publish('request:headers', { request });
    return result;
  } };
  const descriptor = Object.getOwnPropertyDescriptor(target, 'fetch');
  result = Promise.resolve(body);
  const restore = instrumentAdmissionFetch(diagnostics, 1, target);
  assert.equal(target.fetch('PRIVATE-URL', body), result); assert.equal(await result, body);
  restore(); restore(); assert.deepEqual(Object.getOwnPropertyDescriptor(target, 'fetch'), descriptor);
  const output = diagnostics.stop(); assert.equal(output.errors, 0); assert.equal(inspected, 0);
  const milestones = output.streams.httpMilestones.samples;
  assert.deepEqual(milestones.map(x => x.event), [1, 2, 3, 4, 5]);
  assert.equal(milestones[2].socket, milestones[3].socket); assert.equal(milestones[1].connection, milestones[2].connection);
  assert.equal(milestones[1].request, null); assert.equal(milestones[1].fetch, null);
  assert.equal(milestones[0].request, milestones[4].request); assert.equal(milestones[0].fetch, 1);
  assert.equal(JSON.stringify(output).includes('PRIVATE'), false);
  const badDiagnostics = { add() { throw Error('diagnostic'); }, fail() { throw Error('diagnostic'); } };
  const throwing = { fetch() { throw failure; } }, undo = instrumentAdmissionFetch(badDiagnostics, 1, throwing);
  try { assert.throws(() => throwing.fetch(), error => error === failure); } finally { undo(); }
});

test('fetch correlation survives asynchronous request creation and restoration removes subscribers', async () => {
  const diagnostics = createAdmissionDiagnostics(), request = {}, headers = channel('undici:request:headers');
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  const target = { fetch() {
    queueMicrotask(() => {
      channel('undici:request:create').publish({ request }); headers.publish({ request }); resolve(42);
    }); return promise;
  } };
  const before = headers.hasSubscribers, restore = instrumentAdmissionFetch(diagnostics, 2, target);
  assert.equal(target.fetch(), promise); assert.equal(await promise, 42); restore();
  assert.equal(headers.hasSubscribers, before);
  const output = diagnostics.stop(); assert.equal(output.errors, 0);
  assert.deepEqual(output.streams.httpMilestones.samples.map(x => [x.fetch, x.request]), [[1, 1], [1, 1]]);
});

test('missing Undici events and bounded stream loss are incomplete rather than invented correlations', async () => {
  const diagnostics = createAdmissionDiagnostics({ limit: 2 }), target = { fetch() { return Promise.resolve(); } };
  const restore = instrumentAdmissionFetch(diagnostics, 1, target);
  for (let i = 0; i < 4; i++) await target.fetch();
  restore();
  const output = diagnostics.stop(); assert.equal(output.complete, false); assert.ok(output.errors > 0);
  assert.equal(output.streams.fetches.observed, 4); assert.equal(output.streams.fetches.dropped, 2);
  assert.equal(output.streams.httpMilestones.samples.length, 0);
  assert.ok(Object.values(output.streams).every(stream => stream.samples.length <= 2));
});

test('thread counters retain fixed numeric fields and explicitly represent unsupported facilities', () => {
  const diagnostics = createAdmissionDiagnostics();
  recordAdmissionThreadCounters(diagnostics, 1, 1, 1, { cpu: () => ({ user: 12, system: 3 }), schedstat: () => ({ run: '100', wait: '200', slices: 4 }) });
  recordAdmissionThreadCounters(diagnostics, 1, 2, 1, { cpu() { throw Error('PRIVATE'); }, schedstat: () => null });
  const result = diagnostics.stop(), [present, absent] = result.streams.threadCounters.samples;
  assert.equal(result.errors, 0); assert.equal(present.threadCpuAvailable, true); assert.equal(present.schedRunNs, '100');
  assert.equal(absent.threadCpuAvailable, false); assert.equal(absent.threadCpuUserUs, null);
  assert.equal(absent.schedstatAvailable, false); assert.equal(absent.schedWaitNs, null);
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('worker diagnostics preserve emit/post identity, transfer lists and failures without retaining payloads', () => {
  const diagnostics = createAdmissionDiagnostics(), sentinel = {}, failure = new Error('PRIVATE-ERROR');
  const transfers = [new ArrayBuffer(32)]; let inspected = 0;
  const payload = Object.defineProperty({ type: 'snapshot', id: 7 }, 'ledger', { get() { inspected++; throw Error('PRIVATE-KEY'); } });
  class Worker extends EventEmitter {
    postMessage(value, list) { assert.equal(value, payload); assert.equal(list, transfers); if (this.fail) throw failure; return sentinel; }
  }
  const emitDescriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'emit'), postDescriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage');
  const hooks = instrumentAdmissionWorkers(Worker, diagnostics), worker = hooks.construct(1, () => new Worker());
  let received; worker.on('message', value => { received = value; });
  worker.emit('online'); const ready = { type: 'ready' }; assert.equal(worker.emit('message', ready), true); assert.equal(received, ready);
  assert.equal(worker.postMessage(payload, transfers), sentinel); worker.fail = true;
  assert.throws(() => worker.postMessage(payload, transfers), error => error === failure);
  const result = Object.defineProperty({ type: 'result', id: 7 }, 'json', { get() { inspected++; throw Error('PRIVATE-RESULT'); } });
  worker.emit('message', result); assert.equal(received, result);
  hooks.restore(); hooks.restore();
  assert.deepEqual(Object.getOwnPropertyDescriptor(Worker.prototype, 'emit'), emitDescriptor);
  assert.deepEqual(Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage'), postDescriptor);
  const output = diagnostics.stop(); assert.equal(output.errors, 0); assert.equal(inspected, 0);
  assert.deepEqual(output.streams.workerMilestones.samples.filter(x => x.event === 8).map(x => x.ok), [true, false]);
  assert.equal(JSON.stringify(output).includes('PRIVATE'), false);
});

test('worker diagnostic setup restores inherited and own emit descriptors when postMessage installation fails', () => {
  for (const ownEmit of [false, true]) {
    class Worker extends EventEmitter {}
    if (ownEmit) Object.defineProperty(Worker.prototype, 'emit', {
      value: EventEmitter.prototype.emit, configurable: true, writable: false, enumerable: true,
    });
    const postMessage = () => 'unchanged';
    Object.defineProperty(Worker.prototype, 'postMessage', { value: postMessage, configurable: false, writable: false });
    const before = Object.getOwnPropertyDescriptors(Worker.prototype), diagnostics = createAdmissionDiagnostics();
    assert.throws(() => instrumentAdmissionWorkers(Worker, diagnostics), TypeError);
    assert.deepEqual(Object.getOwnPropertyDescriptors(Worker.prototype), before);
    const worker = new Worker(); let received;
    worker.on('message', value => { received = value; });
    assert.equal(worker.emit('message', 'ready'), true); assert.equal(received, 'ready');
    assert.equal(worker.postMessage(), 'unchanged');
    const result = diagnostics.stop();
    assert.equal(result.streams.workerMilestones.observed, 0);
  }
});
