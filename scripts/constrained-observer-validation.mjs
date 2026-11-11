// Shared, fixed resource/report contract. No benchmark execution or Docker access.
import assert from 'node:assert/strict';
import { admissionGate, PHASE_ORDER } from './benchmark-admission.mjs';
import { workerSchedulingMode, schedulingEvidenceValid } from './benchmark-admission-scheduling.mjs';

export const PINNED_IMAGE = 'node@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53';
export const MEMORY_BYTES = 512 * 1024 * 1024;
export const CPU_FIELDS = Object.freeze([
  'usage_usec',
  'user_usec',
  'system_usec',
  'nr_periods',
  'nr_throttled',
  'throttled_usec',
]);
export const SAMPLE_LIMIT = 4096,
  SAMPLE_INTERVAL_MS = 100;
export function configuration({
  profile = 'acceptance',
  diagnostics = false,
  cpuProfile = false,
  image = PINNED_IMAGE,
  cpuAffinity = null,
  workerScheduling = 'default',
} = {}) {
  assert.ok(
    ['acceptance', 'smoke'].includes(profile) && typeof diagnostics === 'boolean' && typeof cpuProfile === 'boolean',
    'CONSTRAINED_CONFIG_INVALID',
  );
  assert.ok(!cpuProfile || diagnostics, 'CPU_PROFILE_REQUIRES_DIAGNOSTICS');
  assert.ok(profile !== 'smoke' || diagnostics, 'SMOKE_REQUIRES_DIAGNOSTICS');
  workerSchedulingMode(workerScheduling);
  assert.match(image, /^(?:[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}@)?sha256:[a-f0-9]{64}$/, 'IMMUTABLE_IMAGE_REQUIRED');
  assert.ok(
    cpuAffinity === null ||
      (typeof cpuAffinity === 'string' &&
        /^(?:0|[1-9]\d{0,3})$/.test(cpuAffinity) &&
        cpuAffinity === String(Number(cpuAffinity)) &&
        Number(cpuAffinity) <= 4095),
    'CPU_AFFINITY_INVALID',
  );
  return {
    profile,
    diagnostics,
    cpuProfile,
    image,
    cpuAffinity,
    workerScheduling,
    resourceProfile: cpuAffinity === null ? 'bandwidth-only' : 'single-logical-cpu',
    eligible: profile === 'acceptance' && !diagnostics,
  };
}
/** Validate bounded kernel CPU-list text without expanding ranges or retaining other proc fields. */
export function cpuList(value) {
  assert.ok(typeof value === 'string' && value.length > 0 && value.length <= 4096, 'CPU_LIST_INVALID');
  assert.ok(!/[^0-9,-]/.test(value), 'CPU_LIST_INVALID');
  let previous = -1;
  for (const part of value.split(',')) {
    assert.match(part, /^(?:0|[1-9]\d{0,9})(?:-(?:0|[1-9]\d{0,9}))?$/, 'CPU_LIST_INVALID');
    const [start, end = start] = part.split('-').map(Number);
    assert.ok(start > previous && end >= start && end <= 0xffffffff, 'CPU_LIST_INVALID');
    previous = end;
  }
  return value;
}
const integer = value => Number.isSafeInteger(value) && value >= 0;
const ns = value => {
  assert.equal(typeof value, 'string');
  assert.match(value, /^\d{1,30}$/);
  return BigInt(value);
};
const elapsed = (start, end) => {
  const delta = ns(end) - ns(start);
  assert.ok(delta >= 0n && delta <= BigInt(Number.MAX_SAFE_INTEGER));
  return Number(delta) / 1e6;
};
const cleanupNames = ['clientWorker', 'directory', 'executor', 'observer', 'taskServer', 'worker'];

/** Recompute the unchanged original gate from every retained raw sample. */
export function validateAdmission(report, options) {
  const config = configuration(options),
    samples = config.profile === 'acceptance' ? 250 : 100;
  assert.equal(report.schemaVersion, 2);
  assert.equal(report.kind, 'synthetic-admission-polling-benchmark');
  assert.equal(report.profile, config.profile);
  assert.equal(report.diagnosticOnly, config.diagnostics);
  assert.equal(report.acceptanceEvidenceEligible, config.eligible);
  assert.equal(report.cpuProfileEnabled, config.cpuProfile);
  assert.equal(report.workerScheduling, config.workerScheduling);
  assert.equal(report.hardware.platform, 'linux');
  assert.match(report.hardware.node, /^v\d+\.\d+\.\d+$/);
  assert.deepEqual(report.workload, { samples, warmup: 50, tasks: 100, grants: 10, pollIntervalMs: 250 });
  assert.deepEqual(report.phaseOrder, PHASE_ORDER);
  assert.equal(report.phases.length, 4);
  assert.equal(Object.hasOwn(report, 'error'), false);
  for (const [index, phase] of report.phases.entries()) {
    assert.equal(phase.mode, PHASE_ORDER[index]);
    assert.equal(phase.samples.length, samples);
    assert.equal(phase.warmupSamples.length, 50);
    assert.deepEqual(phase.coldFirstCall, phase.warmupSamples[0]);
    assert.deepEqual(Object.keys(phase.cleanup).sort(), cleanupNames);
    assert.ok(Object.values(phase.cleanup).every(value => typeof value === 'boolean'));
    let previous;
    for (const sample of [...phase.warmupSamples, ...phase.samples]) {
      assert.equal(typeof sample.ok, 'boolean');
      for (const [field, start, end] of [
        ['prepareMs', 'startedNs', 'executeStartedNs'],
        ['admissionMs', 'executeStartedNs', 'toolEnteredNs'],
        ['executeMs', 'executeStartedNs', 'finishedNs'],
        ['totalMs', 'startedNs', 'finishedNs'],
      ])
        assert.equal(sample[field], elapsed(sample[start], sample[end]));
      assert.ok(ns(sample.toolEnteredNs) <= ns(sample.finishedNs));
      if (previous) assert.ok(ns(previous.finishedNs) <= ns(sample.startedNs));
      previous = sample;
    }
    assert.ok(ns(phase.warmupSamples.at(-1).finishedNs) <= ns(phase.measurementStartedNs));
    assert.ok(ns(phase.samples[0].startedNs) >= ns(phase.measurementStartedNs));
    assert.ok(ns(phase.samples.at(-1).finishedNs) <= ns(phase.measurementEndedNs));
    assert.equal(phase.measurementDurationMs, elapsed(phase.measurementStartedNs, phase.measurementEndedNs));
    if (phase.mode === 'polling') {
      const polling = phase.polling;
      for (const name of ['scheduled', 'started', 'completed', 'failed', 'skippedBusy', 'completedDuringMeasurement'])
        assert.ok(integer(polling[name]));
      assert.equal(polling.started, polling.samples.length);
      assert.equal(polling.scheduled, polling.started + polling.skippedBusy);
      assert.equal(polling.completed, polling.samples.filter(sample => sample.ok === true).length);
      assert.equal(polling.failed, polling.samples.filter(sample => sample.ok === false).length);
      assert.equal(polling.started, polling.completed + polling.failed);
      let previousPoll;
      for (const sample of polling.samples) {
        assert.equal(sample.durationMs, elapsed(sample.startedNs, sample.completedNs));
        assert.equal(sample.startedAtMs, elapsed(phase.clockOriginNs, sample.startedNs));
        assert.ok(integer(sample.bytes) && sample.bytes <= 8 * 1024 * 1024);
        if (previousPoll) assert.ok(ns(previousPoll.completedNs) <= ns(sample.startedNs));
        previousPoll = sample;
      }
      assert.equal(
        polling.completedDuringMeasurement,
        polling.samples.filter(
          sample =>
            sample.ok &&
            ns(sample.completedNs) >= ns(phase.measurementStartedNs) &&
            ns(sample.completedNs) <= ns(phase.measurementEndedNs),
        ).length,
      );
    }
  }
  const gate = admissionGate(report.phases, { enforcePerformance: config.profile === 'acceptance' });
  assert.deepEqual(report.gate, gate);
  const cpuProfilesComplete =
    !config.cpuProfile ||
    report.phases.every(phase => {
      const capture = phase.diagnostics?.cpuProfile;
      return (
        capture?.complete === true &&
        capture.closed === true &&
        capture.errors === 0 &&
        capture.deadlineExceeded === false &&
        capture.diagnosticOnly === true &&
        capture.acceptanceEvidenceEligible === false &&
        capture.profile?.complete === true
      );
    });
  const diagnosticsComplete =
    !config.diagnostics || (cpuProfilesComplete && report.phases.every(phase => phase.diagnostics?.complete === true));
  const schedulingValid = schedulingEvidenceValid(report.phases, config.workerScheduling);
  assert.equal(report.schedulingEvidenceValid, schedulingValid);
  if (config.diagnostics) assert.equal(report.diagnosticsComplete, diagnosticsComplete);
  assert.equal(report.passed, gate.passed && diagnosticsComplete && schedulingValid);
  return {
    gate,
    diagnosticsComplete,
    cpuProfilesComplete,
    workerScheduling: config.workerScheduling,
    schedulingEvidenceValid: schedulingValid,
    acceptanceEvidenceEligible: config.eligible && report.passed,
    effects: report.phases.reduce((sum, phase) => sum + phase.successfulEffects, 0),
    polls: report.phases.reduce((sum, phase) => sum + (phase.polling?.completed ?? 0), 0),
  };
}

export function validateResources(report, options) {
  const config = configuration(options);
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.kind, 'constrained-observer-resources');
  assert.equal(report.resourceProfile, config.resourceProfile);
  assert.equal(report.cpuAffinity, config.cpuAffinity);
  assert.equal(report.workerScheduling, config.workerScheduling);
  assert.equal(report.diagnosticOnly, config.diagnostics);
  assert.equal(report.acceptanceEvidenceEligible, false); // Resource counters alone never qualify acceptance.
  assert.equal(report.runtime.platform, 'linux');
  assert.match(report.runtime.node, /^v\d+\.\d+\.\d+$/);
  assert.deepEqual(report.controls, {
    memoryMaxBytes: MEMORY_BYTES,
    memorySwapMaxBytes: 0,
    cpuQuotaUs: 100000,
    cpuPeriodUs: 100000,
    cpuBurstUs: 0,
    pidsMax: 128,
  });
  for (const affinity of [report.affinity.before, report.affinity.after]) {
    assert.deepEqual(Object.keys(affinity).sort(), ['cpusetCpusEffective', 'processCpusAllowedList']);
    for (const value of Object.values(affinity)) {
      cpuList(value);
      if (config.cpuAffinity !== null) assert.equal(value, config.cpuAffinity, 'CPU_AFFINITY_NOT_EFFECTIVE');
    }
  }
  assert.deepEqual(report.affinity.after, report.affinity.before, 'CPU_AFFINITY_CHANGED');
  for (const sample of [report.before, report.after]) {
    assert.ok(integer(sample.memoryPeakBytes) && sample.memoryPeakBytes <= MEMORY_BYTES);
    assert.deepEqual(sample.memoryEvents, { oom: 0, oomKill: 0 });
    assert.deepEqual(Object.keys(sample.cpu).sort(), [...CPU_FIELDS].sort());
    for (const field of CPU_FIELDS) assert.ok(integer(sample.cpu[field]));
  }
  assert.ok(report.after.memoryPeakBytes >= report.before.memoryPeakBytes);
  for (const field of CPU_FIELDS) assert.ok(report.after.cpu[field] >= report.before.cpu[field]);
  const sampler = report.sampler;
  assert.equal(sampler.enabled, config.diagnostics);
  assert.equal(sampler.intervalMs, SAMPLE_INTERVAL_MS);
  assert.equal(sampler.limit, SAMPLE_LIMIT);
  assert.equal(sampler.closed, true);
  assert.equal(sampler.dropped, 0);
  assert.equal(sampler.errors, 0);
  assert.ok(integer(sampler.observed) && sampler.observed <= SAMPLE_LIMIT);
  assert.equal(sampler.samples.length, sampler.observed);
  if (!config.diagnostics) assert.equal(sampler.observed, 0);
  else assert.ok(sampler.observed >= 2);
  let prior;
  for (const sample of sampler.samples) {
    assert.deepEqual(Object.keys(sample).sort(), ['startedNs', 'endedNs', ...CPU_FIELDS].sort());
    elapsed(sample.startedNs, sample.endedNs);
    if (prior) assert.ok(ns(sample.startedNs) >= ns(prior.endedNs));
    for (const field of CPU_FIELDS) {
      assert.ok(integer(sample[field]));
      if (prior) assert.ok(sample[field] >= prior[field]);
    }
    prior = sample;
  }
  return {
    memoryPeakBytes: report.after.memoryPeakBytes,
    oom: 0,
    oomKill: 0,
    samples: sampler.samples.length,
    resourceProfile: config.resourceProfile,
    cpuAffinity: config.cpuAffinity,
    workerScheduling: config.workerScheduling,
    affinity: report.affinity,
  };
}
