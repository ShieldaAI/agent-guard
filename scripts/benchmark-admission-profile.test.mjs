import test from 'node:test';
import assert from 'node:assert/strict';
import { url as inspectorUrl } from 'node:inspector';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createAdmissionDiagnostics, instrumentAdmissionMethods } from './benchmark-admission-diagnostics.mjs';
import { sanitizeAdmissionProfile, startAdmissionCpuProfile } from './benchmark-admission-profile.mjs';
import { main, runAdmissionPhase } from './benchmark-admission.mjs';

test('method spans preserve exact Promise, this, arguments, rejection and nested ledger behavior', async () => {
  let resolve, reject, thenInvoked = false;
  const pending = new Promise(done => { resolve = done; }), rejected = new Promise((_done, fail) => { reject = fail; });
  Object.defineProperty(pending, 'then', { get() { thenInvoked = true; throw new Error('do not probe then'); } });
  const secret = { private: 'SECRET-RESULT' }, reason = new Error('SECRET-REJECTION');
  class Store {
    #state = secret;
    read() { return this.#state; }
    transaction(callback) { return callback(this.read()); }
  }
  class Executor {
    #result;
    constructor(result) { this.#result = result; }
    prepare(argument) { assert.equal(argument, secret); return this.#result; }
    execute(argument) { assert.equal(argument, secret); return rejected; }
  }
  const executor = new Executor(pending), other = new Executor(Promise.resolve('other'));
  const prepare = executor.prepare, execute = executor.execute, read = Store.prototype.read, transaction = Store.prototype.transaction;
  const diagnostics = createAdmissionDiagnostics(), restore = instrumentAdmissionMethods(executor, Store, diagnostics);
  try {
    const returned = executor.prepare(secret), failed = executor.execute(secret);
    assert.equal(returned, pending); assert.equal(failed, rejected);
    assert.equal(await executor.prepare.call(other, secret), 'other');
    const store = new Store(), callback = state => { assert.equal(state, secret); return secret; };
    assert.equal(store.transaction(callback), secret);
    assert.throws(() => store.transaction(() => { throw reason; }), error => error === reason);
    resolve(secret); reject(reason);
    assert.equal(await returned, secret);
    await assert.rejects(failed, error => error === reason);
    assert.equal(thenInvoked, false);
  } finally { restore(); }
  assert.equal(executor.prepare, prepare); assert.equal(executor.execute, execute);
  assert.equal(Store.prototype.read, read); assert.equal(Store.prototype.transaction, transaction);
  assert.equal(Object.hasOwn(executor, 'prepare'), false); restore();
  const result = diagnostics.stop(); assert.equal(result.errors, 0);
  assert.equal(result.streams.prepare.samples.length, 2); assert.equal(result.streams.execute.samples[0].ok, false);
  assert.ok(result.streams.prepare.samples.every(item => item.asynchronous && BigInt(item.returnedNs) <= BigInt(item.endedNs)));
  const transactionSpan = result.streams.ledgerTransaction.samples[0], readSpan = result.streams.ledgerRead.samples[0];
  assert.ok(BigInt(transactionSpan.startedNs) <= BigInt(readSpan.startedNs));
  assert.ok(BigInt(transactionSpan.endedNs) >= BigInt(readSpan.endedNs));
  assert.equal(result.streams.ledgerTransaction.samples[1].ok, false);
  assert.equal(JSON.stringify(result).includes('SECRET'), false);
});

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const profile = () => ({ nodes: [
  { id: 1, callFrame: { functionName: '(root)', url: '', lineNumber: -1, columnNumber: -1 }, children: [2, 3, 4] },
  { id: 2, callFrame: { functionName: 'decode', url: pathToFileURL(join(repositoryRoot, 'packages/executor/dist/store.js')).href,
    lineNumber: 18, columnNumber: 0 }, children: [] },
  { id: 3, callFrame: { functionName: 'SECRET-FUNCTION', url: 'https://user:SECRET@host/private?credential=SECRET', lineNumber: 0, columnNumber: 0 } },
  { id: 4, callFrame: { functionName: 'init', url: 'node:internal/crypto/hash', lineNumber: 3, columnNumber: 4 } },
], samples: [2, 2, 3, 4], timeDeltas: [1000, 1000, 1000, 1000], arguments: 'SECRET-ARGS' });

test('CPU profile retains detached bounded sampling data with checkout and external paths redacted', () => {
  const original = profile(), result = sanitizeAdmissionProfile(original, { repositoryRoot });
  assert.equal(result.complete, true); assert.equal(result.retainedSamples, 4);
  assert.equal(result.nodes[1].source, 'packages/executor/dist/store.js');
  assert.equal(result.nodes[1].functionName, 'decode'); assert.equal(result.nodes[1].selfSamples, 2);
  assert.equal(result.nodes[2].source, '[redacted]'); assert.equal(result.nodes[2].functionName, '[redacted]');
  assert.equal(result.nodes[3].source, 'node:internal/crypto/hash');
  assert.deepEqual(result.sampleOffsetsUs, [1000, 2000, 3000, 4000]);
  const text = JSON.stringify(result);
  assert.equal(text.includes(repositoryRoot), false); assert.equal(text.includes('file:'), false); assert.equal(text.includes('SECRET'), false);
  original.nodes[1].callFrame.functionName = 'changed'; original.samples[0] = 3;
  assert.equal(result.nodes[1].functionName, 'decode'); assert.equal(result.nodeIds[0], 2);
});

test('CPU profile cap and invalid-topology evidence is explicit, never a partial complete profile', () => {
  for (const options of [{ maxNodes: 2 }, { maxSamples: 2 }, { maxDurationMs: 2 }]) {
    const result = sanitizeAdmissionProfile(profile(), options);
    assert.equal(result.complete, false); assert.ok(result.droppedNodes > 0 || result.droppedSamples > 0);
  }
  const invalid = profile(); invalid.samples[0] = 999;
  assert.equal(sanitizeAdmissionProfile(invalid).complete, false);
  const huge = profile(); huge.nodes[0].children = Array.from({ length: 1000 }, () => 2);
  const edges = sanitizeAdmissionProfile(huge, { maxNodes: 4 });
  assert.equal(edges.complete, false); assert.ok(edges.droppedEdges > 0);
  assert.ok(edges.nodes.reduce((count, item) => count + item.children.length, 0) <= 8);
  const many = profile(); many.samples = Array(2000).fill(2); many.timeDeltas = Array(2000).fill(1000);
  const capped = sanitizeAdmissionProfile(many, { maxBytes: 4096 });
  assert.equal(capped.complete, false); assert.equal(capped.byteLimitExceeded, true);
  assert.equal(capped.retainedSamples, 0); assert.ok(Buffer.byteLength(JSON.stringify(capped)) <= 4096);
});

test('in-process profiler closes without a listening port and makes deadline expiry incomplete', async () => {
  const listeningBefore = inspectorUrl();
  const handle = await startAdmissionCpuProfile({ maxDurationMs: 5, maxBytes: 4096 });
  await sleep(25);
  const first = handle.stop(); assert.equal(handle.stop(), first);
  const result = await first;
  assert.equal(result.closed, true); assert.equal(result.complete, false); assert.equal(result.deadlineExceeded, true);
  assert.equal(result.diagnosticOnly, true); assert.equal(result.acceptanceEvidenceEligible, false);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 4096);
  assert.equal(inspectorUrl(), listeningBefore);
});

test('CPU profiling requires diagnostics and captures real method spans in a tiny functional phase', async () => {
  await assert.rejects(runAdmissionPhase({ mode: 'baseline', samples: 2, warmup: 1, cpuProfile: true }), { message: 'ADMISSION_CONFIG_INVALID' });
  await assert.rejects(main(['--cpu-profile', '--output', 'must-not-be-created.json']), { message: 'ADMISSION_CONFIG_INVALID' });
  const phase = await runAdmissionPhase({ mode: 'polling', samples: 5, warmup: 1, tasks: 2, grants: 2,
    pollIntervalMs: 10, diagnostics: true, cpuProfile: true });
  assert.equal(phase.successfulEffects, 6); assert.equal(phase.finalCalls, 6);
  assert.deepEqual(phase.cleanup, { worker: true, clientWorker: true, observer: true, taskServer: true, executor: true, directory: true });
  assert.equal(phase.diagnostics.complete, true);
  const capture = phase.diagnostics.cpuProfile;
  assert.equal(capture.closed, true); assert.equal(capture.complete, true); assert.ok(capture.profile.retainedSamples > 0);
  assert.ok(BigInt(capture.startRequestedNs) <= BigInt(capture.startAcknowledgedNs));
  assert.ok(BigInt(capture.startAcknowledgedNs) <= BigInt(capture.stopRequestedNs));
  assert.ok(BigInt(capture.stopRequestedNs) <= BigInt(capture.stopAcknowledgedNs));
  for (const method of ['prepare', 'execute']) assert.equal(phase.diagnostics.main.streams[method].samples.length, 6);
  assert.ok(phase.diagnostics.main.streams.ledgerRead.samples.length > 6);
  assert.ok(phase.diagnostics.main.streams.ledgerTransaction.samples.length > 6);
  assert.equal(JSON.stringify(capture).includes(repositoryRoot), false);
  assert.equal(JSON.stringify(capture).includes('file:'), false);
});
