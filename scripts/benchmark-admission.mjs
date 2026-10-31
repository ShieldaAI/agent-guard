#!/usr/bin/env node
// Synthetic only: never opens an existing authority ledger or accepts credentials.
import { randomBytes } from 'node:crypto';
import { mkdtemp, open, realpath, rm, stat } from 'node:fs/promises';
import { cpus, totalmem, platform, release, arch, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { isMainThread, parentPort, threadId, Worker, workerData } from 'node:worker_threads';
import { DurableExecutor, createInventoryObserverToken, startExecutorServer, startInventoryServer } from '../packages/executor/dist/index.js';

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
  const times = mode => phases.filter(phase => phase.mode === mode).flatMap(phase => phase.samples.map(sample => sample.admissionMs));
  const baselineP95Ms = valid ? percentile95(times('baseline')) : null;
  const pollingP95Ms = valid ? percentile95(times('polling')) : null;
  const ratio = baselineP95Ms > 0 ? pollingP95Ms / baselineP95Ms : null;
  const performancePassed = ratio !== null && ratio <= 1.10;
  return { passed: valid && (!enforcePerformance || performancePassed), correctnessPassed: valid,
    performanceEnforced: enforcePerformance, performancePassed, maximumRatio: 1.10, baselineP95Ms, pollingP95Ms,
    ratio, regressionPercent: ratio === null ? null : (ratio - 1) * 100 };
}

async function pollWorker() {
  const stats = { scheduled: 0, started: 0, completed: 0, failed: 0, skippedBusy: 0, completedDuringMeasurement: 0, samples: [] };
  let stopping = false, pending = null;
  const phaseStarted = BigInt(workerData.clockOriginNs);
  const tick = () => {
    if (stopping) return;
    stats.scheduled++;
    if (pending) { stats.skippedBusy++; return; }
    const startedNs = process.hrtime.bigint();
    stats.started++;
    pending = (async () => {
      let bytes = 0, ok = false;
      try {
        const response = await fetch(workerData.url + '/v1/inventory/snapshot', { method: 'POST', redirect: 'error',
          headers: { authorization: `Bearer ${workerData.token}`, 'content-type': 'application/json' },
          body: '{"tenantId":"synthetic-admission"}', signal: AbortSignal.timeout(5000) });
        const chunks = []; const reader = response.body.getReader();
        try { for (;;) { const item = await reader.read(); if (item.done) break; bytes += item.value.byteLength;
          if (bytes > 8 * 1024 * 1024) throw new Error('POLL_LIMIT'); chunks.push(item.value); }
        } finally { await reader.cancel().catch(() => {}); }
        const value = JSON.parse(Buffer.concat(chunks).toString());
        ok = response.status === 200 && value.profile === 'core' && value.tasks.length === workerData.tasks &&
          value.tasks.reduce((sum, task) => sum + task.grants.length, 0) === workerData.tasks * workerData.grants;
      } catch { /* Stable metrics only; never retain requests, tokens or backend errors. */ }
      const completedNs = process.hrtime.bigint();
      if (ok) stats.completed++; else stats.failed++;
      stats.samples.push({ startedNs: startedNs.toString(), completedNs: completedNs.toString(),
        startedAtMs: Number(startedNs - phaseStarted) / 1e6, durationMs: Number(completedNs - startedNs) / 1e6, bytes, ok });
    })().finally(() => { pending = null; });
  };
  const timer = setInterval(tick, workerData.pollIntervalMs);
  parentPort.on('message', async message => {
    if (message === 'stop') { stopping = true; clearInterval(timer); if (pending) await pending; parentPort.postMessage({ stats }); parentPort.close(); }
  });
  tick(); parentPort.postMessage('ready');
}

// HTTP request initiation must run independently of the executor's event loop:
// synchronous inventory exports can then queue requests after their timestamp.
async function workloadWorker() {
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
    measurementEndedNs: measurementEndedNs?.toString() ?? null });
  parentPort.close();
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

export async function runAdmissionPhase({ mode, samples, warmup, tasks = 100, grants = 10, pollIntervalMs = 250 }) {
  if (!['baseline', 'polling'].includes(mode) || !Number.isInteger(samples) || samples < 1 || samples > 1000 ||
      !Number.isInteger(warmup) || warmup < 1 || warmup > 100 || !Number.isInteger(tasks) || tasks < 1 || tasks > 100 ||
      !Number.isInteger(grants) || grants < 1 || grants > 10 || !Number.isInteger(pollIntervalMs) || pollIntervalMs < 5 || pollIntervalMs > 1000) throw new Error('ADMISSION_CONFIG_INVALID');
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'agent-guard-admission-')));
  let executor, taskServer, observer, worker, clientWorker, credential;
  let successfulEffects = 0;
  const phase = { mode, executorThreadId: threadId, clientThreadId: null, clockOriginNs: process.hrtime.bigint().toString(), warmupSamples: [], coldFirstCall: null, samples: [],
    measurementStartedNs: null, measurementEndedNs: null, measurementDurationMs: 0,
    successfulEffects: 0, finalCalls: 0, polling: null, cleanup: {} };
  try {
    executor = new DurableExecutor({ database: join(directory, 'ledger.sqlite'), encryptionKey: randomBytes(32),
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
    if (mode === 'polling') {
      const token = createInventoryObserverToken();
      observer = await startInventoryServer({ executor, observers: [{ token, tenantIds: ['synthetic-admission'], profile: 'core' }],
        rateLimit: { maxRequests: 10000, windowMs: 60_000 } });
      worker = new Worker(new URL(import.meta.url), { workerData: { kind: 'poll', url: observer.url, token, tasks, grants, pollIntervalMs, clockOriginNs: phase.clockOriginNs } });
      await waitMessage(worker, value => value === 'ready');
    }
    clientWorker = new Worker(new URL(import.meta.url), { workerData: { kind: 'workload', url: taskServer.url,
      token: credential.token, samples, warmup } });
    clientWorker.on('message', value => {
      if (value?.kind === 'warmup-sample') phase.warmupSamples.push(value.sample);
      if (value?.kind === 'sample') phase.samples.push(value.sample);
      if (value?.kind === 'measurement-start') phase.measurementStartedNs = value.measurementStartedNs;
    });
    const result = await waitMessage(clientWorker, value => value?.kind === 'complete', (samples + warmup) * 20_000 + 10_000);
    phase.clientThreadId = result.clientThreadId; phase.measurementStartedNs = result.measurementStartedNs; phase.measurementEndedNs = result.measurementEndedNs;
    if (result.measurementStartedNs !== null && result.measurementEndedNs !== null)
      phase.measurementDurationMs = Number(BigInt(result.measurementEndedNs) - BigInt(result.measurementStartedNs)) / 1e6;
    if (!result.ok) phase.error = 'ADMISSION_REQUEST_FAILED';
  } catch {
    phase.error = 'ADMISSION_PHASE_FAILED';
  } finally {
    phase.successfulEffects = successfulEffects; phase.coldFirstCall = phase.warmupSamples[0] ?? null;
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
  }
  return phase;
}

export async function main(argv = process.argv.slice(2)) {
  const { values } = parseArgs({ args: argv, options: { profile: { type: 'string', default: 'acceptance' }, output: { type: 'string' } }, strict: true });
  if (!['smoke', 'acceptance'].includes(values.profile) || !values.output) throw new Error('ADMISSION_CONFIG_INVALID');
  const destination = resolve(values.output); await stat(resolve(destination, '..'));
  const output = await open(destination, 'wx', 0o600);
  const acceptance = values.profile === 'acceptance';
  const settings = { samples: acceptance ? 250 : 100, warmup: 50, tasks: 100, grants: 10, pollIntervalMs: 250 };
  const report = { schemaVersion: 2, kind: 'synthetic-admission-polling-benchmark', profile: values.profile,
    startedAt: new Date().toISOString(), passed: false, phases: [], workload: settings, phaseOrder: PHASE_ORDER,
    hardware: { platform: platform(), release: release(), architecture: arch(), logicalCpus: cpus().length, memoryBytes: totalmem(), node: process.version },
    measurement: 'Independent workload-worker HTTP execute request initiation to executor-thread governed tool entry, using shared process.hrtime.bigint nanoseconds serialized as strings. Includes durable admission, server event-loop queueing and transport; excludes tool work/settlement. Prepare, complete execute and combined durations and all timestamp boundaries are retained. Successful poll completion membership uses the workload worker exact measured interval.',
    coldHandling: 'Worker startup is outside request timing. All 50 warmup samples per phase are retained and excluded from the steady-state gate. Cold first HTTP call is identified. No measured samples or outliers are excluded.',
    limitations: ['Synthetic 100-task/1000-grant file-backed ledger; no existing executor, cloud or external effect.',
      '250ms serial observer cadence is a declared stress profile; deployed default is five minutes.',
      'Fixed ABBA order and matched starting authority state; timing is local hardware evidence, not a production guarantee.',
      'Smoke verifies correctness and reports the ratio but does not enforce or certify the 10% performance gate.'] };
  try {
    for (const mode of PHASE_ORDER) {
      process.stderr.write(`Admission benchmark phase ${report.phases.length + 1}/4: ${mode}\n`);
      report.phases.push(await runAdmissionPhase({ mode, ...settings }));
      await sleep(100);
    }
    report.gate = admissionGate(report.phases, { enforcePerformance: acceptance }); report.passed = report.gate.passed;
  } catch { report.error = 'ADMISSION_BENCHMARK_FAILED'; }
  finally { report.completedAt = new Date().toISOString(); await output.writeFile(JSON.stringify(report, null, 2) + '\n'); await output.close(); }
  process.stdout.write(JSON.stringify({ passed: report.passed, profile: values.profile, output: destination }) + '\n');
  return report.passed ? 0 : 1;
}

if (!isMainThread && workerData?.kind === 'poll') await pollWorker();
else if (!isMainThread && workerData?.kind === 'workload') await workloadWorker();
else if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try { process.exitCode = await main(); } catch { process.stderr.write('ADMISSION_START_FAILED\n'); process.exitCode = 1; }
}
