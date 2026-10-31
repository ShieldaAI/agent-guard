import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Worker } from 'node:worker_threads';
import { admissionGate, percentile95, PHASE_ORDER, runAdmissionPhase } from './benchmark-admission.mjs';

function phases(ratio = 1.1) {
  return PHASE_ORDER.map(mode => ({ mode, executorThreadId: 0, clientThreadId: 1, successfulEffects: 22, finalCalls: 22,
    cleanup: { worker: true, clientWorker: true, observer: true, taskServer: true, executor: true, directory: true },
    warmupSamples: Array.from({ length: 2 }, () => ({ ok: true, admissionMs: 100, prepareMs: 2, executeMs: 100, totalMs: 102 })),
    samples: Array.from({ length: 20 }, () => ({ ok: true, admissionMs: mode === 'polling' ? ratio * 10 : 10, prepareMs: 2, executeMs: 15, totalMs: 17 })),
    polling: mode === 'polling' ? { failed: 0, skippedBusy: 0, completedDuringMeasurement: 3 } : null }));
}
test('admission gate uses retained samples, fixed order and strict 10% threshold', () => {
  assert.equal(percentile95(Array.from({ length: 20 }, (_, index) => index + 1)), 19);
  assert.equal(admissionGate(phases()).passed, true);
  assert.equal(admissionGate(phases(1.10001)).passed, false);
  assert.equal(admissionGate(phases(1.2), { enforcePerformance: false }).passed, true);
  assert.equal(admissionGate(phases(1.2), { enforcePerformance: false }).performancePassed, false);
  const reordered = phases(); [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  assert.equal(admissionGate(reordered).passed, false);
  for (const change of [p => { p[1].samples.pop(); }, p => { p[0].finalCalls++; },
    p => { p[1].polling.skippedBusy++; }, p => { p[1].polling.failed++; },
    p => { p[1].polling.completedDuringMeasurement = 2; }, p => { p[2].samples[0].ok = false; },
    p => { p[0].samples[0].admissionMs = NaN; }, p => { p[1].warmupSamples.pop(); },
    p => { p[1].cleanup.clientWorker = false; }, p => { delete p[1].cleanup.clientWorker; },
    p => { p[1].clientThreadId = p[1].executorThreadId; }]) {
    const value = phases(); change(value); assert.equal(admissionGate(value).passed, false);
  }
});
test('real admission fixture executes exact effects while nonempty HTTP inventory is polled', async () => {
  const phase = await runAdmissionPhase({ mode: 'polling', samples: 15, warmup: 2, tasks: 2, grants: 2, pollIntervalMs: 10 });
  assert.equal(phase.samples.length, 15); assert.equal(phase.warmupSamples.length, 2);
  assert.equal(phase.successfulEffects, 17); assert.equal(phase.finalCalls, 17);
  assert.notEqual(phase.clientThreadId, phase.executorThreadId);
  assert.deepEqual(phase.cleanup, { worker: true, clientWorker: true, observer: true, taskServer: true, executor: true, directory: true });
  assert.ok(phase.samples.every(sample => sample.ok && sample.admissionMs <= sample.executeMs));
  for (const sample of [...phase.warmupSamples, ...phase.samples]) {
    assert.ok(BigInt(sample.startedNs) <= BigInt(sample.executeStartedNs));
    assert.ok(BigInt(sample.executeStartedNs) <= BigInt(sample.toolEnteredNs));
    assert.ok(BigInt(sample.toolEnteredNs) <= BigInt(sample.finishedNs));
    assert.equal(sample.admissionMs, Number(BigInt(sample.toolEnteredNs) - BigInt(sample.executeStartedNs)) / 1e6);
  }
  assert.ok(phase.polling.completed > 0); assert.equal(phase.polling.failed, 0);
  assert.ok(phase.polling.samples.every(sample => sample.ok && sample.bytes > 0));
  assert.equal(phase.polling.completedDuringMeasurement, phase.polling.samples.filter(sample =>
    BigInt(sample.completedNs) >= BigInt(phase.measurementStartedNs) && BigInt(sample.completedNs) <= BigInt(phase.measurementEndedNs)).length);
});

test('independent HTTP client includes executor event-loop queueing in admission timing', async () => {
  const blocks = [], evidence = [];
  const server = createServer((request, response) => {
    request.resume(); response.setHeader('content-type', 'application/json');
    if (request.url === '/v1/task/prepare') {
      response.end('{"id":"synthetic-action"}', () => {
        // The response is handed to the socket before blocking the server loop.
        // The independent worker can initiate execute while this loop is blocked.
        const start = process.hrtime.bigint(), end = start + 250_000_000n;
        while (process.hrtime.bigint() < end) { /* controlled synchronous exporter stand-in */ }
        blocks.push({ start, end: process.hrtime.bigint() });
      });
    } else response.end(JSON.stringify({ value: { enteredAtNs: process.hrtime.bigint().toString() } }));
  });
  let client;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    client = new Worker(new URL('./benchmark-admission.mjs', import.meta.url), { workerData: {
      kind: 'workload', url: `http://127.0.0.1:${server.address().port}`, token: 'synthetic-test', warmup: 1, samples: 1 } });
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('test client timed out')), 10_000);
      client.on('message', message => {
        if (message.sample) evidence.push(message.sample);
        if (message.kind === 'complete') { clearTimeout(timer); resolve(message); }
      });
      client.once('error', error => { clearTimeout(timer); reject(error); });
    });
    assert.equal(result.ok, true); assert.equal(evidence.length, 2); assert.equal(blocks.length, 2);
    const measured = evidence[1], blocked = blocks[1];
    assert.ok(BigInt(measured.executeStartedNs) < blocked.end - 100_000_000n);
    assert.ok(BigInt(measured.toolEnteredNs) >= blocked.end);
    assert.ok(measured.admissionMs >= 100, 'timing must include request queueing during the server block');
  } finally {
    try { await client?.terminate(); }
    finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  }
});
