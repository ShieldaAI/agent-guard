#!/usr/bin/env node
// Synthetic only: never opens an existing authority ledger or accepts credentials.
import { randomBytes } from 'node:crypto';
import { mkdtemp, open, realpath, rm, stat } from 'node:fs/promises';
import { cpus, totalmem, platform, release, arch, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { isEntry } from '../examples/providers/replay.mjs';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { isMainThread, threadId, Worker } from 'node:worker_threads';
import { DurableExecutor, createInventoryObserverToken, startExecutorServer, startInventoryServer } from '../packages/executor/dist/index.js';
import { LedgerStore } from '../packages/executor/dist/store.js';
import { createAdmissionDiagnostics, instrumentInventoryObservation, instrumentObserverRequests, instrumentAdmissionMethods,
  instrumentAdmissionWorkers, recordAdmissionThreadCounters, DIAGNOSTIC_ROLES } from './benchmark-admission-diagnostics.mjs';
import { startAdmissionCpuProfile } from './benchmark-admission-profile.mjs';
import { workerSchedulingMode, validateSchedulingReading, schedulingEvidenceValid } from './benchmark-admission-scheduling.mjs';

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


function waitMessage(worker, predicate, timeout = 10_000) {
  return new Promise((resolveMessage, reject) => {
    const timer = setTimeout(() => done(new Error('ADMISSION_WORKER_TIMEOUT')), timeout);
    const message = value => { if (predicate(value)) done(null, value); };
    const error = () => done(new Error('ADMISSION_WORKER_FAILED'));
    const done = (failure, value) => { clearTimeout(timer); worker.off('message', message); worker.off('error', error); failure ? reject(failure) : resolveMessage(value); };
    worker.on('message', message); worker.once('error', error);
  });
}

export async function runAdmissionPhase({ mode, samples, warmup, tasks = 100, grants = 10, pollIntervalMs = 250, decisionTraces = false, diagnostics = false, cpuProfile = false, workerScheduling = 'default' }) {
  if (!['baseline', 'polling'].includes(mode) || !Number.isInteger(samples) || samples < 1 || samples > 1000 ||
      !Number.isInteger(warmup) || warmup < 1 || warmup > 100 || !Number.isInteger(tasks) || tasks < 1 || tasks > 100 ||
      !Number.isInteger(grants) || grants < 1 || grants > 10 || !Number.isInteger(pollIntervalMs) || pollIntervalMs < 5 || pollIntervalMs > 1000 || typeof decisionTraces !== 'boolean' || typeof diagnostics !== 'boolean' ||
      typeof cpuProfile !== 'boolean' || (cpuProfile && !diagnostics)) throw new Error('ADMISSION_CONFIG_INVALID');
  workerSchedulingMode(workerScheduling);
  if (workerScheduling === 'linux-background' && process.platform !== 'linux') throw new Error('ADMISSION_WORKER_SCHEDULING_INVALID');
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-guard-admission-')));
  let executor, taskServer, observer, worker, clientWorker, credential;
  let diagnostic, restoreExport, restoreRequests, restoreMethods, profiler, workerDiagnostics, readScheduling;
  let successfulEffects = 0;
  const phase = { mode, executorThreadId: threadId, clientThreadId: null, clockOriginNs: process.hrtime.bigint().toString(), warmupSamples: [], coldFirstCall: null, samples: [],
    measurementStartedNs: null, measurementEndedNs: null, measurementDurationMs: 0,
    successfulEffects: 0, finalCalls: 0, polling: null, cleanup: {},
    workerScheduling: { requested: workerScheduling, before: null, after: null } };
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
      workerDiagnostics = instrumentAdmissionWorkers(Worker, diagnostic);
      recordAdmissionThreadCounters(diagnostic, DIAGNOSTIC_ROLES.owner, 0);
      phase.diagnostics = { diagnosticOnly: true, acceptanceEvidenceEligible: false, main: null, workload: null };
      if (cpuProfile) {
        restoreMethods = instrumentAdmissionMethods(executor, LedgerStore, diagnostic);
        profiler = await startAdmissionCpuProfile();
      }
    }
    if (mode === 'polling') {
      const { readInventoryWorkerScheduling } = await import('../packages/executor/dist/inventory-observer.js');
      readScheduling = () => {
        const result = readInventoryWorkerScheduling(executor);
        validateSchedulingReading(result, workerScheduling); return result;
      };
      if (diagnostic) {
        const { InventoryObservationSession } = await import('../packages/executor/dist/inventory-observer.js');
        restoreExport = instrumentInventoryObservation(InventoryObservationSession, diagnostic);
      }
      const token = createInventoryObserverToken();
      observer = await startInventoryServer({ executor, observers: [{ token, tenantIds: ['synthetic-admission'], profile: 'core' }],
        rateLimit: { maxRequests: 10000, windowMs: 60_000 }, workerScheduling });
      phase.workerScheduling.before = readScheduling();
      if (diagnostic) restoreRequests = instrumentObserverRequests(observer.server, diagnostic);
      const create = () => new Worker(new URL('./benchmark-admission-client.mjs', import.meta.url), { workerData: { kind: 'poll', url: observer.url, token, tasks, grants, pollIntervalMs, clockOriginNs: phase.clockOriginNs, diagnostics } });
      worker = workerDiagnostics ? workerDiagnostics.construct(DIAGNOSTIC_ROLES.poll, create) : create();
      await waitMessage(worker, value => value === 'ready');
    }
    const createClient = () => new Worker(new URL('./benchmark-admission-client.mjs', import.meta.url), { workerData: { kind: 'workload', url: taskServer.url,
      token: credential.token, samples, warmup, diagnostics } });
    clientWorker = workerDiagnostics ? workerDiagnostics.construct(DIAGNOSTIC_ROLES.workload, createClient) : createClient();
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
    if (observer) {
      try { phase.workerScheduling.after = readScheduling(); }
      catch { phase.error = 'ADMISSION_SCHEDULING_UNVERIFIED'; }
    }
    for (const [name, close] of [['worker', () => worker?.terminate()], ['clientWorker', () => clientWorker?.terminate()], ['observer', () => observer?.close()],
      ['taskServer', () => taskServer?.close()], ['executor', () => executor?.close()],
      ['directory', () => rm(directory, { recursive: true, force: true })]]) {
      try { await close(); phase.cleanup[name] = true; } catch { phase.cleanup[name] = false; }
    }
    } finally {
    if (diagnostic) {
      for (const restore of [restoreRequests, restoreExport, restoreMethods, () => workerDiagnostics?.restore()]) { try { restore?.(); } catch { diagnostic.fail(); } }
      if (profiler) {
        try { phase.diagnostics.cpuProfile = await profiler.stop(); }
        catch { diagnostic.fail(); }
      }
      phase.diagnostics.main = diagnostic.stop();
      phase.diagnostics.complete = phase.diagnostics.main.complete && phase.diagnostics.workload?.complete === true &&
        (mode === 'baseline' || (phase.polling?.diagnostics?.complete === true &&
          phase.diagnostics.main.streams.observations.observed === phase.polling.started &&
          phase.polling.diagnostics.streams.fetches.observed === phase.polling.started)) &&
        (!cpuProfile || phase.diagnostics.cpuProfile?.complete === true);
    }
    }
  }
  return phase;
}

export async function main(argv = process.argv.slice(2)) {
  const { values } = parseArgs({ args: argv, options: { profile: { type: 'string', default: 'acceptance' }, output: { type: 'string' }, diagnostics: { type: 'boolean', default: false }, 'cpu-profile': { type: 'boolean', default: false }, 'worker-scheduling': { type: 'string', default: 'default' } }, strict: true });
  if (!['smoke', 'acceptance'].includes(values.profile) || !values.output || (values['cpu-profile'] && !values.diagnostics)) throw new Error('ADMISSION_CONFIG_INVALID');
  const workerScheduling = workerSchedulingMode(values['worker-scheduling']);
  if (workerScheduling === 'linux-background' && process.platform !== 'linux') throw new Error('ADMISSION_WORKER_SCHEDULING_INVALID');
  const destination = resolve(values.output); await stat(resolve(destination, '..'));
  const output = await open(destination, 'wx', 0o600);
  const acceptance = values.profile === 'acceptance';
  const settings = { samples: acceptance ? 250 : 100, warmup: 50, tasks: 100, grants: 10, pollIntervalMs: 250 };
  const report = { schemaVersion: 2, kind: 'synthetic-admission-polling-benchmark', profile: values.profile,
    diagnosticOnly: values.diagnostics, acceptanceEvidenceEligible: acceptance && !values.diagnostics, cpuProfileEnabled: values['cpu-profile'],
    workerScheduling, schedulingEvidenceValid: false,
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
    stages: 'Poll start→headers→body drained and reader cancelled→UTF-8 decode/JSON parse→shape validation complete. Server request→finish means handed to the OS, not client delivery. Async observation includes bounded queue wait, fresh ledger ciphertext capture, worker decrypt/decode/projection and serialization through Promise settlement; it is not the historical synchronous export span. This synthetic fixture does not configure a rollback witness, so it does not measure witness or recovery-mirror verification.',
    attribution: 'Request→observation includes body processing and scheduling, not pure queue delay. Process CPU/resource counters include all workers; event-loop/GC observations and the optional CPU profile are thread-local and do not measure the trusted inventory worker. Missing GC or I/O counter changes cannot prove a host cause.',
    privacy: 'Only bounded timestamps, counters, booleans and fixed labels; no request headers, URLs, credentials, bodies, results or error messages.',
    coldPath: 'Fetch entry/return preserves the original Promise with no added settlement reaction. AsyncLocalStorage and synchronous Undici subscribers add diagnostic overhead. Connection events are pooled, have no request attribution, and join to sends only by socket object identity. Worker online/role-entry brackets include native startup, module evaluation and scheduling; role-entry is after static imports. Parent post/result edges include IPC, worker processing and owner scheduling, not isolated worker CPU. Thread counters are absolute, sampled only at role entry and the first three fetch boundaries; event 0=role entry, 1=before fetch, 2=after fetch. Missing facilities are explicit nulls. No first poll, warmup or outlier is removed.',
  };
  if (values['cpu-profile']) report.diagnosticContract.cpuProfile = {
    methods: 'Public prepare/execute and repo-private LedgerStore read/transaction are wrapped only in this disposable process. this, arguments, return, thrown values and original Promise identity are preserved; Promise reaction/handledness and profiling overhead are added.',
    nesting: 'Spans are independent shared-hrtime intervals, not async parent attribution. Ledger transaction includes nested reads, serialization/encryption and commit; do not add nested/overlapping spans as separate CPU or I/O time. Async endedNs is observation in a settlement reaction.',
    ownerCapture: 'Observation entry→returnedNs includes synchronous queue admission/capture/post work when immediately dispatched. Worker postStart/postReturn bracket posting; resultReceived→observation settlement includes owner result validation and Promise scheduling. These are overlapping bounds, not private-method spans or proof of native I/O/scheduler cause. Sampled source lines may identify capture frames but are not exact CPU attribution.',
    profiler: 'In-process inspector Session without a port;1ms sampling,120s soft deadline per phase,20000nodes,120000samples,16MiB sanitized output per phase. Deadline overrun, trimming, errors or lost topology make the capture incomplete. Startup/stop hrtime brackets bound V8 relative-clock alignment.',
    privacy: 'Retains only sanitized repo-relative/Node module function labels, bounded call-tree and sampled relative timings. Unknown source paths/function labels are redacted; no arguments, state, source text, headers or credentials. Raw V8 profiles are never written.',
  };
  try {
    for (const mode of PHASE_ORDER) {
      process.stderr.write(`Admission benchmark phase ${report.phases.length + 1}/4: ${mode}\n`);
      report.phases.push(await runAdmissionPhase({ mode, ...settings, diagnostics: values.diagnostics, cpuProfile: values['cpu-profile'], workerScheduling }));
      await sleep(100);
    }
    report.gate = admissionGate(report.phases, { enforcePerformance: acceptance });
    report.schedulingEvidenceValid = schedulingEvidenceValid(report.phases, workerScheduling);
    if (values.diagnostics) report.diagnosticsComplete = report.phases.every(phase => phase.diagnostics?.complete === true);
    report.passed = report.gate.passed && report.schedulingEvidenceValid && (!values.diagnostics || report.diagnosticsComplete);
  } catch { report.error = 'ADMISSION_BENCHMARK_FAILED'; }
  finally { report.completedAt = new Date().toISOString(); await output.writeFile(JSON.stringify(report, null, 2) + '\n'); await output.close(); }
  process.stdout.write(JSON.stringify({ passed: report.passed, profile: values.profile, workerScheduling,
    diagnosticOnly: report.diagnosticOnly, acceptanceEvidenceEligible: report.acceptanceEvidenceEligible, output: destination }) + '\n');
  return report.passed ? 0 : 1;
}

if (!isMainThread) throw new Error('ADMISSION_CLIENT_ENTRY_REQUIRED');
if (isEntry(import.meta)) {
  try { process.exitCode = await main(); } catch { process.stderr.write('ADMISSION_START_FAILED\n'); process.exitCode = 1; }
}
