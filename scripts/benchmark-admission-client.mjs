// HTTP-only clients for the disposable synthetic admission benchmark.
// Keep SDK/ledger/observer imports in the owner entrypoint: both clients still
// start cold, and the first poll is initiated before its ready message.
import { isMainThread, parentPort, threadId, workerData } from 'node:worker_threads';

let createAdmissionDiagnostics, instrumentAdmissionFetch, recordAdmissionThreadCounters, DIAGNOSTIC_ROLES, WORKER_MILESTONES;
if (workerData?.diagnostics) {
  ({ createAdmissionDiagnostics, instrumentAdmissionFetch, recordAdmissionThreadCounters, DIAGNOSTIC_ROLES, WORKER_MILESTONES } =
    await import('./benchmark-admission-diagnostics.mjs'));
}

async function pollWorker() {
  const stats = { scheduled: 0, started: 0, completed: 0, failed: 0, skippedBusy: 0, completedDuringMeasurement: 0, samples: [] };
  const diagnostics = workerData.diagnostics ? createAdmissionDiagnostics() : null;
  const restoreFetch = diagnostics ? instrumentAdmissionFetch(diagnostics, DIAGNOSTIC_ROLES.poll) : null;
  if (diagnostics) {
    diagnostics.add('workerMilestones', { atNs: process.hrtime.bigint().toString(), event: WORKER_MILESTONES.roleEntered, role: DIAGNOSTIC_ROLES.poll, worker: null, job: null, ok: true });
    recordAdmissionThreadCounters(diagnostics, DIAGNOSTIC_ROLES.poll, 0);
  }
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
    if (diagnostics && poll === 1) diagnostics.add('workerMilestones', { atNs: startedNs.toString(), event: WORKER_MILESTONES.firstRequest, role: DIAGNOSTIC_ROLES.poll, worker: null, job: null, ok: true });
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
        restoreFetch?.();
        if (diagnostics) stats.diagnostics = diagnostics.stop();
        parentPort.postMessage({ stats });
      } finally { restoreFetch?.(); diagnostics?.stop(); parentPort.close(); }
    }
  });
  parentPort.once('close', () => { clearInterval(timer); restoreFetch?.(); diagnostics?.stop(); });
  tick(); parentPort.postMessage('ready');
}

// HTTP request initiation must run independently of the executor's event loop:
// owner-thread work can then queue requests after their timestamp.
async function workloadWorker() {
  const diagnostics = workerData.diagnostics ? createAdmissionDiagnostics() : null;
  const restoreFetch = diagnostics ? instrumentAdmissionFetch(diagnostics, DIAGNOSTIC_ROLES.workload) : null;
  let firstRequest = true;
  if (diagnostics) {
    diagnostics.add('workerMilestones', { atNs: process.hrtime.bigint().toString(), event: WORKER_MILESTONES.roleEntered, role: DIAGNOSTIC_ROLES.workload, worker: null, job: null, ok: true });
    recordAdmissionThreadCounters(diagnostics, DIAGNOSTIC_ROLES.workload, 0);
  }
  try {
  const call = async (operation, body) => {
    if (diagnostics && firstRequest) {
      firstRequest = false;
      diagnostics.add('workerMilestones', { atNs: process.hrtime.bigint().toString(), event: WORKER_MILESTONES.firstRequest, role: DIAGNOSTIC_ROLES.workload, worker: null, job: null, ok: true });
    }
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
  restoreFetch?.();
  parentPort.postMessage({ kind: 'complete', ok, clientThreadId: threadId, measurementStartedNs: measurementStartedNs?.toString() ?? null,
    measurementEndedNs: measurementEndedNs?.toString() ?? null, ...(diagnostics ? { diagnostics: diagnostics.stop() } : {}) });
  parentPort.close();
  } finally { restoreFetch?.(); diagnostics?.stop(); }
}

if (!isMainThread && workerData?.kind === 'poll') await pollWorker();
else if (!isMainThread && workerData?.kind === 'workload') await workloadWorker();
else throw new Error('ADMISSION_CLIENT_ROLE_INVALID');
