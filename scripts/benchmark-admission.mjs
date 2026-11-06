#!/usr/bin/env node
// Synthetic only: never opens an existing authority ledger or accepts credentials.
import { randomBytes } from 'node:crypto';
import { mkdtemp, open, realpath, rm, stat } from 'node:fs/promises';
import { cpus, totalmem, platform, release, arch, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { isEntry } from '../examples/providers/replay.mjs';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { isMainThread, parentPort, threadId, Worker, workerData } from 'node:worker_threads';
import { DurableExecutor, createInventoryObserverToken, startExecutorServer, startInventoryServer } from '../packages/executor/dist/index.js';
import { LedgerStore } from '../packages/executor/dist/store.js';
import { createAdmissionDiagnostics, instrumentInventoryObservation, instrumentObserverRequests, instrumentAdmissionMethods } from './benchmark-admission-diagnostics.mjs';
import { startAdmissionCpuProfile } from './benchmark-admission-profile.mjs';

export const PHASE_ORDER = Object.freeze(['baseline', 'polling', 'polling', 'baseline']);
export function percentile95(values) {
  if (!values.length || values.some(value => typeof value !== 'number' || !Number.isFinite(value) || value < 0)) throw new Error('ADMISSION_MEASUREMENT_INVALID');
  return [...values].sort((a, b) => a - b)[Math.ceil(values.length * 0.95) - 1];
}
export function admissionGate(phases, { enforcePerformance = true } = {}) {
  const valid = phases.length === 4 && phases.every((phase, index) => phase.mode === PHASE_ORDER[index] &&
    Number.isInteger(phase.executorThreadId) && Number.isInteger(phase.clientThreadId) && phase.clientThreadId !== phase.executorThreadId &&
    phase.samples.length === phases[0].samples.length && phase.warmupSamples.length === phases[0].warmupSamples.length &&
    phase.samples.length > 0 && phase.successfulEffects === phase.samples.length + phase.warmupSamples.length &&
    Object.values(phase.cleanup ?? {}).length === 6 && Object.values(phase.cleanup).every(value => value === true) && !phase.error &&
    phase.finalCalls === phase.successfulEffects && [...phase.samples, ...phase.warmupSamples].every(sample => sample.ok === true &&
      [sample.admissionMs, sample.prepareMs, sample.executeMs, sample.totalMs].every(value => typeof value === 'number' && Number.isFinite(value) && value >= 0)) &&
    (phase.mode === 'baseline' ? phase.polling === null : phase.polling?.failed === 0 && phase.polling?.skippedBusy === 0 && phase.polling?.completedDuringMeasurement >= 3));
  // Retain diagnostic timing even when the declared stress cadence was missed.
  // A valid latency sample set does not turn a failed profile into a passing one.
  const latencySamplesValid = phases.length === 4 && phases.every((phase, index) => phase.mode === PHASE_ORDER[index] &&
    phase.samples.length === phases[0].samples.length && phase.samples.length > 0 && phase.samples.every(sample => sample.ok === true &&
      typeof sample.admissionMs === 'number' && Number.isFinite(sample.admissionMs) && sample.admissionMs >= 0));
  const failureReasons = [];
  if (phases.length !== 4 || phases.some((phase, index) => phase.mode !== PHASE_ORDER[index])) failureReasons.push({ code: 'PHASE_ORDER_INVALID' });
  for (const [index, phase] of phases.entries()) {
    const reason = code => failureReasons.push({ phase: index + 1, code });
    if (!Number.isInteger(phase.executorThreadId) || !Number.isInteger(phase.clientThreadId) || phase.clientThreadId === phase.executorThreadId) reason('THREAD_ISOLATION_INVALID');
    if (phase.successfulEffects !== phase.samples.length + phase.warmupSamples.length) reason('EFFECT_COUNT_MISMATCH');
    if (phase.finalCalls !== phase.successfulEffects) reason('CALL_COUNT_MISMATCH');
    if (phase.error) reason('PHASE_FAILED');
    if (Object.values(phase.cleanup ?? {}).length !== 6 || !Object.values(phase.cleanup).every(value => value === true)) reason('CLEANUP_FAILED');
    if (phase.samples.length !== phases[0].samples.length || phase.warmupSamples.length !== phases[0].warmupSamples.length || !phase.samples.length ||
        ![...phase.samples, ...phase.warmupSamples].every(sample => sample.ok === true &&
          [sample.admissionMs, sample.prepareMs, sample.executeMs, sample.totalMs].every(value => typeof value === 'number' && Number.isFinite(value) && value >= 0))) reason('MEASUREMENT_INVALID');
    if (phase.mode === 'baseline' && phase.polling !== null) reason('BASELINE_POLLING_INVALID');
    if (phase.mode === 'polling') {
      if (phase.polling?.failed !== 0) reason('POLL_REQUEST_FAILED');
      if (phase.polling?.skippedBusy !== 0) reason('POLL_CADENCE_SKIPPED');
      if (!(phase.polling?.completedDuringMeasurement >= 3)) reason('POLL_COVERAGE_INSUFFICIENT');
    }
  }
  const times = mode => phases.filter(phase => phase.mode === mode).flatMap(phase => phase.samples.map(sample => sample.admissionMs));
  const baselineP95Ms = latencySamplesValid ? percentile95(times('baseline')) : null;
  const pollingP95Ms = latencySamplesValid ? percentile95(times('polling')) : null;
  const ratio = baselineP95Ms > 0 ? pollingP95Ms / baselineP95Ms : null;
  const performancePassed = valid && ratio !== null && ratio <= 1.10;
  if (valid && enforcePerformance && !performancePassed) failureReasons.push({ code: 'ADMISSION_REGRESSION_EXCEEDED' });
  return { passed: valid && (!enforcePerformance || performancePassed), correctnessPassed: valid,
    effectAccountingPassed: phases.length === 4 && phases.every(phase => phase.successfulEffects === phase.samples.length + phase.warmupSamples.length && phase.finalCalls === phase.successfulEffects),
    stressProfileValid: valid, latencySamplesValid, failureReasons,
    performanceEnforced: enforcePerformance, performancePassed, maximumRatio: 1.10, baselineP95Ms, pollingP95Ms,
    ratio, regressionPercent: ratio === null ? null : (ratio - 1) * 100 };
}

async function pollWorker() {
  const stats = { scheduled: 0, started: 0, completed: 0, failed: 0, skippedBusy: 0, completedDuringMeasurement: 0, samples: [] };
  const diagnostics = workerData.diagnostics ? createAdmissionDiagnostics() : null;
  let stopping = false, pending = null;
  const phaseStarted = BigInt(workerData.clockOriginNs);
  const tick = () => {
    if (stopping) return;
    stats.scheduled++;
    if (pending) {
      stats.skippedBusy++;
      diagnostics?.add('ticks', { atNs: process.hrtime.bigint().toString(), scheduled: stats.scheduled, skippedBusy: true, poll: stats.started });
      return;
    }
    const startedNs = process.hrtime.bigint();
    stats.started++;
    const poll = stats.started;
    diagnostics?.add('ticks', { atNs: startedNs.toString(), scheduled: stats.scheduled, skippedBusy: false, poll });
    pending = (async () => {
      let bytes = 0, ok = false;
      let headersNs = null, bodyNs = null, parseStartedNs = null, parsedNs = null, status = null;
      try {
        const response = await fetch(workerData.url + '/v1/inventory/snapshot', { method: 'POST', redirect: 'error',
          headers: { authorization: `Bearer ${workerData.token}`, 'content-type': 'application/json' },
          body: '{"tenantId":"synthetic-admission"}', signal: AbortSignal.timeout(5000) });
        if (diagnostics) { headersNs = process.hrtime.bigint(); status = response.status; }
        const chunks = []; const reader = response.body.getReader();
        try { for (;;) { const item = await reader.read(); if (item.done) break; bytes += item.value.byteLength;
          if (bytes > 8 * 1024 * 1024) throw new Error('POLL_LIMIT'); chunks.push(item.value); }
        } finally { await reader.cancel().catch(() => {}); }
        if (diagnostics) { bodyNs = process.hrtime.bigint(); parseStartedNs = process.hrtime.bigint(); }
        const value = JSON.parse(Buffer.concat(chunks).toString());
        if (diagnostics) parsedNs = process.hrtime.bigint();
        ok = response.status === 200 && value.profile === 'core' && value.tasks.length === workerData.tasks &&
          value.tasks.reduce((sum, task) => sum + task.grants.length, 0) === workerData.tasks * workerData.grants;
      } catch { /* Stable metrics only; never retain requests, tokens or backend errors. */ }
      const completedNs = process.hrtime.bigint();
      if (ok) stats.completed++; else stats.failed++;
      stats.samples.push({ startedNs: startedNs.toString(), completedNs: completedNs.toString(),
        startedAtMs: Number(startedNs - phaseStarted) / 1e6, durationMs: Number(completedNs - startedNs) / 1e6, bytes, ok });
      diagnostics?.add('polls', { poll, startedNs: startedNs.toString(), headersNs: headersNs?.toString() ?? null,
        bodyNs: bodyNs?.toString() ?? null, parseStartedNs: parseStartedNs?.toString() ?? null,
        parsedNs: parsedNs?.toString() ?? null, completedNs: completedNs.toString(), status, bytes, ok });
    })().finally(() => { pending = null; });
  };
  const timer = setInterval(tick, workerData.pollIntervalMs);
  parentPort.on('message', async message => {
    if (message === 'stop') {
      stopping = true; clearInterval(timer);
      try {
        if (pending) await pending;
        if (diagnostics) stats.diagnostics = diagnostics.stop();
        parentPort.postMessage({ stats });
      } finally { diagnostics?.stop(); parentPort.close(); }
    }
  });
  parentPort.once('close', () => { clearInterval(timer); diagnostics?.stop(); });
  tick(); parentPort.postMessage('ready');
}

// HTTP request initiation must run independently of the executor's event loop:
// owner-thread work can then queue requests after their timestamp.
async function workloadWorker() {
  const diagnostics = workerData.diagnostics ? createAdmissionDiagnostics() : null;
  try {
  const call = async (operation, body) => {
    const response = await fetch(workerData.url + '/v1/task/' + operation, { method: 'POST', redirect: 'error',
      headers: { authorization: `Bearer ${workerData.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
    if (response.status !== 200) { await response.body?.cancel(); throw new Error('ADMISSION_REQUEST_FAILED'); }
    return response.json();
  };
  const record = async () => {
    const startedNs = process.hrtime.bigint();
    let executeStartedNs = null, enteredNs = null, finishedNs;
    try {
      const action = await call('prepare', { tool: 'synthetic.read-0', args: null });
      executeStartedNs = process.hrtime.bigint();
      const result = await call('execute', { actionId: action.id });
      finishedNs = process.hrtime.bigint();
      if (typeof result.value?.enteredAtNs !== 'string' || !/^\d{1,30}$/.test(result.value.enteredAtNs)) throw new Error('ADMISSION_RESULT_INVALID');
      enteredNs = BigInt(result.value.enteredAtNs);
      if (enteredNs < executeStartedNs || enteredNs > finishedNs) throw new Error('ADMISSION_RESULT_INVALID');
      return { ok: true, startedNs: startedNs.toString(), executeStartedNs: executeStartedNs.toString(),
        toolEnteredNs: enteredNs.toString(), finishedNs: finishedNs.toString(),
        admissionMs: Number(enteredNs - executeStartedNs) / 1e6, prepareMs: Number(executeStartedNs - startedNs) / 1e6,
        executeMs: Number(finishedNs - executeStartedNs) / 1e6, totalMs: Number(finishedNs - startedNs) / 1e6 };
    } catch {
      return { ok: false, error: 'ADMISSION_REQUEST_FAILED', startedNs: startedNs.toString(),
        executeStartedNs: executeStartedNs?.toString() ?? null, toolEnteredNs: enteredNs?.toString() ?? null,
        finishedNs: process.hrtime.bigint().toString(), admissionMs: null, prepareMs: null, executeMs: null, totalMs: null };
    }
  };
  let ok = true, measurementStartedNs = null, measurementEndedNs = null;
  for (let index = 0; index < workerData.warmup; index++) {
    const sample = await record(); parentPort.postMessage({ kind: 'warmup-sample', sample });
    if (!sample.ok) { ok = false; break; }
  }
  if (ok) {
    measurementStartedNs = process.hrtime.bigint();
    parentPort.postMessage({ kind: 'measurement-start', measurementStartedNs: measurementStartedNs.toString() });
    for (let index = 0; index < workerData.samples; index++) {
      const sample = await record(); parentPort.postMessage({ kind: 'sample', sample });
      if (!sample.ok) { ok = false; break; }
    }
    measurementEndedNs = process.hrtime.bigint();
  }
  parentPort.postMessage({ kind: 'complete', ok, clientThreadId: threadId, measurementStartedNs: measurementStartedNs?.toString() ?? null,
    measurementEndedNs: measurementEndedNs?.toString() ?? null, ...(diagnostics ? { diagnostics: diagnostics.stop() } : {}) });
  parentPort.close();
  } finally { diagnostics?.stop(); }
}

function waitMessage(worker, predicate, timeout = 10_000) {
  return new Promise((resolveMessage, reject) => {
    const timer = setTimeout(() => done(new Error('ADMISSION_WORKER_TIMEOUT')), timeout);
    const message = value => { if (predicate(value)) done(null, value); };
    const error = () => done(new Error('ADMISSION_WORKER_FAILED'));
    const done = (failure, value) => { clearTimeout(timer); worker.off('message', message); worker.off('error', error); failure ? reject(failure) : resolveMessage(value); };
    worker.on('message', message); worker.once('error', error);
  });
}

export async function runAdmissionPhase({ mode, samples, warmup, tasks = 100, grants = 10, pollIntervalMs = 250, decisionTraces = false, diagnostics = false, cpuProfile = false }) {
  if (!['baseline', 'polling'].includes(mode) || !Number.isInteger(samples) || samples < 1 || samples > 1000 ||
      !Number.isInteger(warmup) || warmup < 1 || warmup > 100 || !Number.isInteger(tasks) || tasks < 1 || tasks > 100 ||
      !Number.isInteger(grants) || grants < 1 || grants > 10 || !Number.isInteger(pollIntervalMs) || pollIntervalMs < 5 || pollIntervalMs > 1000 || typeof decisionTraces !== 'boolean' || typeof diagnostics !== 'boolean' ||
      typeof cpuProfile !== 'boolean' || (cpuProfile && !diagnostics)) throw new Error('ADMISSION_CONFIG_INVALID');
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-guard-admission-')));
  let executor, taskServer, observer, worker, clientWorker, credential;
  let diagnostic, restoreExport, restoreRequests, restoreMethods, profiler;
  let successfulEffects = 0;
  const phase = { mode, executorThreadId: threadId, clientThreadId: null, clockOriginNs: process.hrtime.bigint().toString(), warmupSamples: [], coldFirstCall: null, samples: [],
    measurementStartedNs: null, measurementEndedNs: null, measurementDurationMs: 0,
    successfulEffects: 0, finalCalls: 0, polling: null, cleanup: {} };
  try {
    executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: randomBytes(32),
      ...(decisionTraces ? { decisionTraces: { maxEventsPerTenant: 4096 } } : {}),
      ...(mode === 'polling' ? { inventory: { companyId: 'synthetic-company', sourceId: 'synthetic-executor', enrollmentGeneration: 'synthetic-1' } } : {}) });
    for (let number = 0; number < grants; number++) {
      const name = `synthetic.read-${number}`;
      executor.approveTool(name, executor.registerTool({ name, description: 'Synthetic no-op benchmark tool', maxCost: 0,
        resolve: () => ({ resourceId: 'synthetic-record', tenantId: 'synthetic-admission' }),
        execute: () => { const enteredAtNs = process.hrtime.bigint().toString(); successfulEffects++; return { value: { enteredAtNs } }; } }));
    }
    for (let number = 0; number < tasks; number++) {
      const created = executor.createTask({ id: `synthetic-task-${number}`, tenantId: 'synthetic-admission', principalId: `synthetic-agent-${number}`,
        grants: Array.from({ length: grants }, (_, index) => ({ tool: `synthetic.read-${index}`, resources: ['synthetic-record'] })),
        budget: { maxCalls: samples + warmup + 1, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 3600_000 } });
      if (number === 0) credential = created;
    }
    taskServer = await startExecutorServer({ executor, adminToken: randomBytes(32).toString('base64url'), operatorId: 'synthetic-benchmark' });
    if (diagnostics) {
      diagnostic = createAdmissionDiagnostics({ processMetrics: true });
      phase.diagnostics = { diagnosticOnly: true, acceptanceEvidenceEligible: false, main: null, workload: null };
      if (cpuProfile) {
        restoreMethods = instrumentAdmissionMethods(executor, LedgerStore, diagnostic);
        profiler = await startAdmissionCpuProfile();
      }
    }
    if (mode === 'polling') {
      if (diagnostic) {
        const { InventoryObservationSession } = await import('../packages/executor/dist/inventory-observer.js');
        restoreExport = instrumentInventoryObservation(InventoryObservationSession, diagnostic);
      }
      const token = createInventoryObserverToken();
      observer = await startInventoryServer({ executor, observers: [{ token, tenantIds: ['synthetic-admission'], profile: 'core' }],
        rateLimit: { maxRequests: 10000, windowMs: 60_000 } });
      if (diagnostic) restoreRequests = instrumentObserverRequests(observer.server, diagnostic);
      worker = new Worker(new URL(import.meta.url), { workerData: { kind: 'poll', url: observer.url, token, tasks, grants, pollIntervalMs, clockOriginNs: phase.clockOriginNs, diagnostics } });
      await waitMessage(worker, value => value === 'ready');
    }
    clientWorker = new Worker(new URL(import.meta.url), { workerData: { kind: 'workload', url: taskServer.url,
      token: credential.token, samples, warmup, diagnostics } });
    clientWorker.on('message', value => {
      if (value?.kind === 'warmup-sample') phase.warmupSamples.push(value.sample);
      if (value?.kind === 'sample') phase.samples.push(value.sample);
      if (value?.kind === 'measurement-start') phase.measurementStartedNs = value.measurementStartedNs;
    });
    const result = await waitMessage(clientWorker, value => value?.kind === 'complete', (samples + warmup) * 20_000 + 10_000);
    phase.clientThreadId = result.clientThreadId; phase.measurementStartedNs = result.measurementStartedNs; phase.measurementEndedNs = result.measurementEndedNs;
    if (diagnostic) phase.diagnostics.workload = result.diagnostics ?? null;
    if (result.measurementStartedNs !== null && result.measurementEndedNs !== null)
      phase.measurementDurationMs = Number(BigInt(result.measurementEndedNs) - BigInt(result.measurementStartedNs)) / 1e6;
    if (!result.ok) phase.error = 'ADMISSION_REQUEST_FAILED';
  } catch {
    phase.error = 'ADMISSION_PHASE_FAILED';
  } finally {
    try {
    phase.successfulEffects = successfulEffects; phase.coldFirstCall = phase.warmupSamples[0] ?? null;
    if (decisionTraces && executor) {
      const trace = executor.decisionTraceSnapshot({ tenantId: 'synthetic-admission' });
      phase.decisionTraces = { retained: trace.retained, dropped: trace.dropped, events: trace.events.length };
    }
    try { if (credential) phase.finalCalls = executor.snapshot(credential.taskId).calls; }
    catch { phase.error = 'ADMISSION_PHASE_FAILED'; }
    if (worker) {
      try {
        const finished = waitMessage(worker, value => value?.stats); worker.postMessage('stop'); phase.polling = (await finished).stats;
        if (phase.measurementStartedNs !== null && phase.measurementEndedNs !== null)
          phase.polling.completedDuringMeasurement = phase.polling.samples.filter(sample => sample.ok &&
            BigInt(sample.completedNs) >= BigInt(phase.measurementStartedNs) && BigInt(sample.completedNs) <= BigInt(phase.measurementEndedNs)).length;
      } catch { phase.error = 'ADMISSION_POLLING_FAILED'; }
    }
    for (const [name, close] of [['worker', () => worker?.terminate()], ['clientWorker', () => clientWorker?.terminate()], ['observer', () => observer?.close()],
      ['taskServer', () => taskServer?.close()], ['executor', () => executor?.close()],
      ['directory', () => rm(directory, { recursive: true, force: true })]]) {
      try { await close(); phase.cleanup[name] = true; } catch { phase.cleanup[name] = false; }
    }
    } finally {
    if (diagnostic) {
      for (const restore of [restoreRequests, restoreExport, restoreMethods]) { try { restore?.(); } catch { diagnostic.fail(); } }
      if (profiler) {
        try { phase.diagnostics.cpuProfile = await profiler.stop(); }
        catch { diagnostic.fail(); }
      }
      phase.diagnostics.main = diagnostic.stop();
      phase.diagnostics.complete = phase.diagnostics.main.complete && phase.diagnostics.workload?.complete === true &&
        (mode === 'baseline' || (phase.polling?.diagnostics?.complete === true &&
          phase.diagnostics.main.streams.observations.observed === phase.polling.started)) &&
        (!cpuProfile || phase.diagnostics.cpuProfile?.complete === true);
    }
    }
  }
  return phase;
}

export async function main(argv = process.argv.slice(2)) {
  const { values } = parseArgs({ args: argv, options: { profile: { type: 'string', default: 'acceptance' }, output: { type: 'string' }, diagnostics: { type: 'boolean', default: false }, 'cpu-profile': { type: 'boolean', default: false } }, strict: true });
  if (!['smoke', 'acceptance'].includes(values.profile) || !values.output || (values['cpu-profile'] && !values.diagnostics)) throw new Error('ADMISSION_CONFIG_INVALID');
  const destination = resolve(values.output); await stat(resolve(destination, '..'));
  const output = await open(destination, 'wx', 0o600);
  const acceptance = values.profile === 'acceptance';
  const settings = { samples: acceptance ? 250 : 100, warmup: 50, tasks: 100, grants: 10, pollIntervalMs: 250 };
  const report = { schemaVersion: 2, kind: 'synthetic-admission-polling-benchmark', profile: values.profile,
    diagnosticOnly: values.diagnostics, acceptanceEvidenceEligible: acceptance && !values.diagnostics, cpuProfileEnabled: values['cpu-profile'],
    startedAt: new Date().toISOString(), passed: false, phases: [], workload: settings, phaseOrder: PHASE_ORDER,
    hardware: { platform: platform(), release: release(), architecture: arch(), logicalCpus: cpus().length, memoryBytes: totalmem(), node: process.version },
    measurement: 'Independent workload-worker HTTP execute request initiation to executor-thread governed tool entry, using shared process.hrtime.bigint nanoseconds serialized as strings. Includes durable admission, server event-loop queueing and transport; excludes tool work/settlement. Prepare, complete execute and combined durations and all timestamp boundaries are retained. Successful poll completion membership uses the workload worker exact measured interval.',
    coldHandling: 'Worker startup is outside request timing. All 50 warmup samples per phase are retained and excluded from the steady-state gate. Cold first HTTP call is identified. No measured samples or outliers are excluded.',
    limitations: ['Synthetic 100-task/1000-grant file-backed ledger; no existing executor, cloud or external effect.',
      '250ms serial observer cadence is a declared stress profile; deployed default is five minutes.',
      'Fixed ABBA order and matched starting authority state; timing is local hardware evidence, not a production guarantee.',
      'Smoke verifies correctness and reports the ratio but does not enforce or certify the 10% performance gate.'] };
  if (values.diagnostics) report.diagnosticContract = {
    streamLimit: 4096, heartbeatIntervalMs: 100,
    overhead: 'Opt-in instrumentation adds work to all phases and workers. Diagnostic runs cannot certify acceptance; never filter samples or change cadence/gates.',
    clock: 'Shared process.hrtime.bigint nanoseconds. GC start/duration are calibrated from each thread performance clock, with recorded calibration uncertainty and callback delivery timestamp.',
    stages: 'Poll start→headers→body drained and reader cancelled→UTF-8 decode/JSON parse→shape validation complete. Server request→finish means handed to the OS, not client delivery. Async observation includes bounded queue wait, fresh witnessed ciphertext capture, worker decrypt/decode/projection and serialization through Promise settlement; it is not the historical synchronous export span.',
    attribution: 'Request→observation includes body processing and scheduling, not pure queue delay. Process CPU/resource counters include all workers; event-loop/GC observations and the optional CPU profile are thread-local and do not measure the trusted inventory worker. Missing GC or I/O counter changes cannot prove a host cause.',
    privacy: 'Only bounded timestamps, counters, booleans and fixed labels; no request headers, URLs, credentials, bodies, results or error messages.',
  };
  if (values['cpu-profile']) report.diagnosticContract.cpuProfile = {
    methods: 'Public prepare/execute and repo-private LedgerStore read/transaction are wrapped only in this disposable process. this, arguments, return, thrown values and original Promise identity are preserved; Promise reaction/handledness and profiling overhead are added.',
    nesting: 'Spans are independent shared-hrtime intervals, not async parent attribution. Ledger transaction includes nested reads, serialization/encryption and commit; do not add nested/overlapping spans as separate CPU or I/O time. Async endedNs is observation in a settlement reaction.',
    profiler: 'In-process inspector Session without a port;1ms sampling,120s soft deadline per phase,20000nodes,120000samples,16MiB sanitized output per phase. Deadline overrun, trimming, errors or lost topology make the capture incomplete. Startup/stop hrtime brackets bound V8 relative-clock alignment.',
    privacy: 'Retains only sanitized repo-relative/Node module function labels, bounded call-tree and sampled relative timings. Unknown source paths/function labels are redacted; no arguments, state, source text, headers or credentials. Raw V8 profiles are never written.',
  };
  try {
    for (const mode of PHASE_ORDER) {
      process.stderr.write(`Admission benchmark phase ${report.phases.length + 1}/4: ${mode}\n`);
      report.phases.push(await runAdmissionPhase({ mode, ...settings, diagnostics: values.diagnostics, cpuProfile: values['cpu-profile'] }));
      await sleep(100);
    }
    report.gate = admissionGate(report.phases, { enforcePerformance: acceptance });
    if (values.diagnostics) report.diagnosticsComplete = report.phases.every(phase => phase.diagnostics?.complete === true);
    report.passed = report.gate.passed && (!values.diagnostics || report.diagnosticsComplete);
  } catch { report.error = 'ADMISSION_BENCHMARK_FAILED'; }
  finally { report.completedAt = new Date().toISOString(); await output.writeFile(JSON.stringify(report, null, 2) + '\n'); await output.close(); }
  process.stdout.write(JSON.stringify({ passed: report.passed, profile: values.profile,
    diagnosticOnly: report.diagnosticOnly, acceptanceEvidenceEligible: report.acceptanceEvidenceEligible, output: destination }) + '\n');
  return report.passed ? 0 : 1;
}

if (!isMainThread && workerData?.kind === 'poll') await pollWorker();
else if (!isMainThread && workerData?.kind === 'workload') await workloadWorker();
else if (isEntry(import.meta)) {
  try { process.exitCode = await main(); } catch { process.stderr.write('ADMISSION_START_FAILED\n'); process.exitCode = 1; }
}
