import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { execFileSync } from 'node:child_process';
import { admissionGate } from './benchmark-admission.mjs';
import { schedulingEvidenceValid } from './benchmark-admission-scheduling.mjs';
import { configuration, cpuList, validateAdmission, validateResources, PINNED_IMAGE, CPU_FIELDS, MEMORY_BYTES } from './constrained-observer-validation.mjs';
import { boundedKernelText, processCpuList, readResources, resourceSampler } from './constrained-observer-payload.mjs';
import { admissionReportLimit, boundedFile, stageInputs, containerArguments, verifyContainer, cleanupContainer, runConstrainedObserver, dockerCommand, createFailureCode } from './check-constrained-observer.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), posix = { skip: process.platform === 'win32' || !process.getuid || process.getuid() === 0 };
const temporary = t => { const p = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'constrained-unit-'))); t.after(() => fs.rmSync(p, { recursive: true, force: true })); return p; };
const clone = value => JSON.parse(JSON.stringify(value));
const cpu = value => Object.fromEntries(CPU_FIELDS.map(name => [name, value]));
function resourceReport(diagnostics = false, cpuAffinity = null, workerScheduling = 'default') {
  const affinity = { cpusetCpusEffective: cpuAffinity ?? '0-3', processCpusAllowedList: cpuAffinity ?? '0-3' };
  return { schemaVersion: 1, kind: 'constrained-observer-resources', diagnosticOnly: diagnostics, acceptanceEvidenceEligible: false,
    resourceProfile: cpuAffinity === null ? 'bandwidth-only' : 'single-logical-cpu', cpuAffinity, workerScheduling, affinity: { before: { ...affinity }, after: { ...affinity } },
    runtime: { platform: 'linux', node: 'v24.22.2', architecture: 'arm64' },
    controls: { memoryMaxBytes: MEMORY_BYTES, memorySwapMaxBytes: 0, cpuQuotaUs: 100000, cpuPeriodUs: 100000, cpuBurstUs: 0, pidsMax: 128 },
    before: { memoryPeakBytes: 1000, memoryEvents: { oom: 0, oomKill: 0 }, cpu: cpu(0) },
    after: { memoryPeakBytes: 2000, memoryEvents: { oom: 0, oomKill: 0 }, cpu: cpu(10) }, checksPassed: true,
    sampler: { enabled: diagnostics, intervalMs: 100, limit: 4096, observed: diagnostics ? 2 : 0, dropped: 0, errors: 0, closed: true,
      samples: diagnostics ? [{ startedNs: '1', endedNs: '2', ...cpu(0) }, { startedNs: '3', endedNs: '4', ...cpu(10) }] : [] } };
}
// Synthetic raw report for validation only: this never dispatches a workload.
function admissionReport({ samples = 250, pollingCost = 1, workerScheduling = 'default' } = {}) {
  const phaseOrder = ['baseline', 'polling', 'polling', 'baseline'];
  const phases = phaseOrder.map(mode => {
    const cost = mode === 'polling' ? pollingCost : 1, origin = 1000000000n;
    const raw = Array.from({ length: samples + 50 }, (_, index) => {
      const start = origin + BigInt(index * 10_000_000);
      return { ok: true, startedNs: String(start), executeStartedNs: String(start + 1000000n),
        toolEnteredNs: String(start + 1000000n + BigInt(cost * 1000000)), finishedNs: String(start + 4000000n),
        prepareMs: 1, admissionMs: cost, executeMs: 3, totalMs: 4 };
    });
    const from = origin + 500000000n, to = origin + BigInt((samples + 50) * 10_000_000);
    const phase = { mode, executorThreadId: 0, clientThreadId: 1, clockOriginNs: String(origin),
      warmupSamples: raw.slice(0, 50), samples: raw.slice(50), coldFirstCall: raw[0],
      measurementStartedNs: String(from), measurementEndedNs: String(to), measurementDurationMs: samples * 10,
      successfulEffects: samples + 50, finalCalls: samples + 50,
      workerScheduling: { requested: workerScheduling, before: null, after: null },
      cleanup: { worker: true, clientWorker: true, observer: true, taskServer: true, executor: true, directory: true }, polling: null };
    if (mode === 'polling') {
      const reading = workerScheduling === 'default' ? { mode: 'default', verified: false } : {
        mode: 'linux-background', verified: true, workerTid: 12, beforeNice: 0, afterNice: 10, currentNice: 10,
        ownerTid: 10, ownerBeforeNice: 0, ownerCurrentNice: 0,
      };
      phase.workerScheduling.before = { ...reading }; phase.workerScheduling.after = { ...reading };
      const polls = Array.from({ length: Math.floor((samples + 50) * 10 / 250) }, (_, index) => {
        const start = origin + BigInt(index * 250000000), end = start + 1000000n;
        return { startedNs: String(start), completedNs: String(end), startedAtMs: index * 250, durationMs: 1, bytes: 100, ok: true };
      });
      phase.polling = { scheduled: polls.length, started: polls.length, completed: polls.length, failed: 0, skippedBusy: 0,
        completedDuringMeasurement: polls.filter(p => BigInt(p.completedNs) >= from && BigInt(p.completedNs) <= to).length, samples: polls };
    }
    return phase;
  });
  const gate = admissionGate(phases);
  return { schemaVersion: 2, kind: 'synthetic-admission-polling-benchmark', profile: 'acceptance', diagnosticOnly: false,
    workerScheduling, schedulingEvidenceValid: true,
    acceptanceEvidenceEligible: true, cpuProfileEnabled: false, hardware: { platform: 'linux', node: 'v24.22.2', architecture: 'arm64' },
    workload: { samples, warmup: 50, tasks: 100, grants: 10, pollIntervalMs: 250 }, phaseOrder, phases, gate, passed: gate.passed };
}
test('constrained options default to full acceptance and require immutable images and diagnostic smoke', () => {
  assert.deepEqual(configuration(), { profile: 'acceptance', diagnostics: false, cpuProfile: false, image: PINNED_IMAGE, cpuAffinity: null, workerScheduling: 'default', resourceProfile: 'bandwidth-only', eligible: true });
  assert.equal(configuration({ profile: 'smoke', diagnostics: true }).eligible, false);
  assert.equal(configuration({ diagnostics: true }).eligible, false);
  for (const value of [{ profile: 'smoke' }, { image: 'node:24' }, { image: '--privileged' }, { diagnostics: 'false' }, { profile: 'fast' }, { workerScheduling: 'fast' }, { workerScheduling: null }]) assert.throws(() => configuration(value));
  for (const value of ['0', '9', '4095']) assert.equal(configuration({ cpuAffinity: value }).resourceProfile, 'single-logical-cpu');
  for (const cpuAffinity of [0, 1, true, '', '00', '01', '-1', '4096', '1.0', '0-1', '0,1', '0\n', ' 0', '0 ', '0\0', '1e0'])
    assert.throws(() => configuration({ cpuAffinity }), /CPU_AFFINITY_INVALID/);
});
function profiledAdmissionReport() {
  const report = admissionReport();
  Object.assign(report, { diagnosticOnly: true, cpuProfileEnabled: true, acceptanceEvidenceEligible: false, diagnosticsComplete: true });
  for (const phase of report.phases) phase.diagnostics = { complete: true, cpuProfile: {
    diagnosticOnly: true, acceptanceEvidenceEligible: false, complete: true, closed: true, errors: 0,
    deadlineExceeded: false, profile: { complete: true },
  } };
  return report;
}
test('owner CPU profiling requires diagnostics, retains the original gate and cannot qualify acceptance', () => {
  assert.throws(() => configuration({ cpuProfile: true }), /CPU_PROFILE_REQUIRES_DIAGNOSTICS/);
  assert.throws(() => configuration({ diagnostics: true, cpuProfile: 'true' }), /CONSTRAINED_CONFIG_INVALID/);
  const config = configuration({ diagnostics: true, cpuProfile: true, cpuAffinity: '0' });
  assert.equal(config.eligible, false); assert.equal(config.profile, 'acceptance');
  assert.equal(admissionReportLimit(false), 32 * 1024 * 1024);
  assert.equal(admissionReportLimit(true), 96 * 1024 * 1024);
  const report = profiledAdmissionReport(), verified = validateAdmission(report, config);
  assert.equal(verified.cpuProfilesComplete, true); assert.equal(verified.gate.passed, true);
  assert.equal(verified.acceptanceEvidenceEligible, false);
  assert.throws(() => validateAdmission(report, { diagnostics: true }));
  assert.throws(() => validateAdmission(admissionReport(), config));
  for (const mutate of [r => { r.acceptanceEvidenceEligible = true; }, r => { delete r.phases[1].diagnostics.cpuProfile; },
    r => { r.phases[1].diagnostics.cpuProfile.closed = false; }, r => { r.phases[1].diagnostics.cpuProfile.profile.complete = false; },
    r => { r.phases[1].diagnostics.cpuProfile.deadlineExceeded = true; }, r => { r.phases[1].diagnostics.cpuProfile.errors = 1; }]) {
    const changed = clone(report); mutate(changed); assert.throws(() => validateAdmission(changed, config));
  }
  const incomplete = clone(report); incomplete.phases[1].diagnostics.cpuProfile.closed = false;
  incomplete.phases[1].diagnostics.complete = false; incomplete.diagnosticsComplete = false; incomplete.passed = false;
  assert.equal(validateAdmission(incomplete, config).diagnosticsComplete, false);
  const missed = clone(report); missed.phases[1].polling.skippedBusy++; missed.phases[1].polling.scheduled++;
  missed.gate = admissionGate(missed.phases); missed.passed = false;
  assert.equal(validateAdmission(missed, config).gate.failureReasons[0].code, 'POLL_CADENCE_SKIPPED');
});
test('payload forwards explicit profiling once without changing full workload or resource preflight', t => {
  const output = temporary(t), resource = resourceReport(true, '0', 'linux-background');
  // Isolate the mocked Linux resource fixture from the actual host/test process.
  const program = `
    import assert from 'node:assert/strict';
    import { runPayload } from ${JSON.stringify(new URL('./constrained-observer-payload.mjs', import.meta.url).href)};
    Object.defineProperty(process, 'platform', { value: 'linux' });
    const fixture = ${JSON.stringify(resource)};
    let calls = 0;
    const exit = await runPayload('acceptance', true, { cpuAffinity: '0', cpuProfile: true, workerScheduling: 'linux-background',
      output: ${JSON.stringify(output)},
      read: () => ({ controls: fixture.controls, affinity: fixture.affinity.before, sample: fixture.before }),
      sampleCpu: () => fixture.before.cpu,
      benchmark: async args => {
        calls++;
        assert.deepEqual(args, ['--profile', 'acceptance', '--diagnostics', '--cpu-profile', '--worker-scheduling', 'linux-background', '--output', ${JSON.stringify(output + '/admission.json')}]);
        return 0;
      } });
    assert.equal(calls, 1); assert.equal(exit, 0);
  `;
  execFileSync(process.execPath, ['--input-type=module', '-e', program], { timeout: 10000, stdio: 'pipe' });
  const captured = JSON.parse(fs.readFileSync(join(output, 'resources.json')));
  assert.equal(captured.checksPassed, true); assert.equal(captured.diagnosticOnly, true);
  assert.equal(captured.acceptanceEvidenceEligible, false); assert.equal(captured.cpuAffinity, '0');
  assert.equal(captured.workerScheduling, 'linux-background');
});
test('explicit background policy requires exact before/after evidence without changing the original numerical gate', () => {
  const selected = { workerScheduling: 'linux-background' }, report = admissionReport(selected);
  const checked = validateAdmission(report, selected);
  assert.equal(checked.schedulingEvidenceValid, true); assert.equal(checked.acceptanceEvidenceEligible, true);
  assert.deepEqual(checked.gate, admissionGate(report.phases));
  assert.throws(() => validateAdmission(report, {}));
  assert.throws(() => validateAdmission(admissionReport(), selected));
  for (const mutate of [r => { delete r.workerScheduling; }, r => { delete r.schedulingEvidenceValid; },
    r => { r.phases[1].workerScheduling.after.currentNice = 0; }, r => { r.phases[1].workerScheduling.after.ownerCurrentNice = 5; },
    r => { r.phases[1].workerScheduling.after.workerTid++; }, r => { r.phases[1].workerScheduling.before = null; },
    r => { r.phases[0].workerScheduling.before = r.phases[1].workerScheduling.before; },
    r => { r.phases[1].workerScheduling.before.private = 'not allowed'; }]) {
    const changed = clone(report); mutate(changed); assert.throws(() => validateAdmission(changed, selected));
  }
  const drift = clone(report); drift.phases[1].workerScheduling.after.currentNice = 0;
  drift.schedulingEvidenceValid = schedulingEvidenceValid(drift.phases, selected.workerScheduling); drift.passed = false;
  const rejected = validateAdmission(drift, selected);
  assert.equal(rejected.gate.passed, true); assert.equal(rejected.schedulingEvidenceValid, false);
  assert.equal(rejected.acceptanceEvidenceEligible, false);
  assert.throws(() => validateResources(resourceReport(false, null, 'linux-background'), {}));
  assert.equal(validateResources(resourceReport(false, null, 'linux-background'), selected).memoryPeakBytes, 2000);
});
test('a numerically passing report with old five-level worker evidence cannot qualify the ten-level policy', () => {
  const selected = { workerScheduling: 'linux-background' }, old = admissionReport(selected);
  for (const phase of old.phases.filter(value => value.mode === 'polling')) {
    for (const reading of [phase.workerScheduling.before, phase.workerScheduling.after]) {
      reading.afterNice = 5; reading.currentNice = 5;
    }
  }
  assert.equal(admissionGate(old.phases).passed, true);
  // A stale successful evidence claim is rejected, even though the latency/cadence gate passes.
  assert.throws(() => validateAdmission(old, selected));
  old.schedulingEvidenceValid = false; old.passed = false;
  const checked = validateAdmission(old, selected);
  assert.equal(checked.gate.passed, true); assert.equal(checked.schedulingEvidenceValid, false);
  assert.equal(checked.acceptanceEvidenceEligible, false);
});
test('host recomputes exact raw timestamps, sample coverage and original gate without filtering failures', () => {
  const report = admissionReport(); assert.equal(validateAdmission(report, {}).effects, 1200);
  const slower = admissionReport({ pollingCost: 2 }); assert.equal(validateAdmission(slower, {}).gate.passed, false);
  const busy = admissionReport(); busy.phases[1].polling.skippedBusy = 1; busy.phases[1].polling.scheduled++;
  busy.gate = admissionGate(busy.phases); busy.passed = false;
  assert.equal(validateAdmission(busy, {}).gate.failureReasons[0].code, 'POLL_CADENCE_SKIPPED');
  for (const change of [r => { r.phases[1].samples[0].admissionMs = 0; }, r => { r.phases[1].polling.completedDuringMeasurement++; },
    r => { r.phases[1].polling.samples.shift(); }, r => { r.gate.passed = false; }, r => { r.workload.pollIntervalMs = 300; },
    r => { r.phases[0].cleanup = { a: true, b: true, c: true, d: true, e: true, f: true }; }]) {
    const changed = clone(report); change(changed); assert.throws(() => validateAdmission(changed, {}));
  }
  assert.throws(() => validateAdmission(admissionReport({ samples: 100 }), {}));
});
test('resource verification requires actual cgroupv2 memory, no extra swap, one CPU, no OOM and complete diagnostics', () => {
  assert.equal(validateResources(resourceReport(), {}).memoryPeakBytes, 2000);
  assert.equal(validateResources(resourceReport(true), { diagnostics: true }).samples, 2);
  for (const change of [r => { r.controls.memoryMaxBytes *= 2; }, r => { r.controls.memorySwapMaxBytes = 1; },
    r => { r.controls.cpuQuotaUs *= 2; }, r => { r.controls.cpuBurstUs = 1; }, r => { r.controls.pidsMax++; }, r => { r.after.memoryEvents.oomKill++; },
    r => { r.sampler.dropped++; }, r => { r.sampler.closed = false; }, r => { r.after.cpu.usage_usec = -1; }]) {
    const r = resourceReport(); change(r); assert.throws(() => validateResources(r, {}));
  }
});
test('affinity is a distinct explicit profile and both actual CPU sets must remain the exact selected singleton', () => {
  const selected = { cpuAffinity: '2' }, report = resourceReport(false, '2');
  assert.equal(validateResources(report, selected).resourceProfile, 'single-logical-cpu');
  assert.equal(validateResources(resourceReport(), {}).resourceProfile, 'bandwidth-only');
  // Even an already singleton inherited mask remains the unselected bandwidth profile.
  const inherited = resourceReport();
  for (const part of ['before', 'after']) inherited.affinity[part] = { cpusetCpusEffective: '2', processCpusAllowedList: '2' };
  assert.equal(validateResources(inherited, {}).resourceProfile, 'bandwidth-only');
  assert.throws(() => validateResources(report, {}));
  assert.throws(() => validateResources(inherited, selected));
  for (const change of [r => { r.resourceProfile = 'bandwidth-only'; }, r => { r.cpuAffinity = null; },
    r => { r.affinity.before.cpusetCpusEffective = '0-3'; }, r => { r.affinity.before.processCpusAllowedList = '1'; },
    r => { r.affinity.after.cpusetCpusEffective = '2-2'; }, r => { r.affinity.after.processCpusAllowedList = '2,3'; },
    r => { r.controls.cpuQuotaUs++; }, r => { r.controls.cpuPeriodUs /= 10; }, r => { r.controls.cpuBurstUs = 1; }]) {
    const changed = clone(report); change(changed); assert.throws(() => validateResources(changed, selected));
  }
  const changed = resourceReport(); changed.affinity.after.cpusetCpusEffective = '0-2';
  assert.throws(() => validateResources(changed, {}), /CPU_AFFINITY_CHANGED/);
});
test('kernel CPU lists and proc status reads are bounded and retain no unrelated process fields', t => {
  for (const list of ['0', '4095', '0-3', '2,4-7,1024', '0-4294967295']) assert.equal(cpuList(list), list);
  for (const list of ['', '00', '1,1', '2,1', '3-2', '1-2,2', '0\n', '0\n,1', ' 0', '0 ', '0,', '-1', '1.0', '0-4294967296', '0'.repeat(4097)])
    assert.throws(() => cpuList(list));
  const status = 'Name:\tPRIVATE-NAME\nUid:\tPRIVATE-UID\nCpus_allowed_list:\t2,4-7\nMems_allowed_list:\t0\n';
  assert.equal(processCpuList(status), '2,4-7');
  for (const text of ['PRIVATE', status + 'Cpus_allowed_list:\t2\n', 'Cpus_allowed_list:\t0\0\n', 'x'.repeat(65537)])
    assert.throws(() => processCpuList(text));
  const directory = temporary(t), path = join(directory, 'kernel-text');
  fs.writeFileSync(path, 'x'.repeat(4096)); assert.equal(boundedKernelText(path, 4096).length, 4096);
  fs.appendFileSync(path, 'y'); assert.throws(() => boundedKernelText(path, 4096), /KERNEL_TEXT_LIMIT/);
  fs.writeFileSync(path, status); assert.equal(processCpuList(boundedKernelText(path, 65536)), '2,4-7');
});
test('cgroup reader and sampler retain only fixed numeric fields and always close with explicit loss', () => {
  const files = { 'cgroup.controllers': 'cpu memory pids', 'cpu.stat': CPU_FIELDS.map(name => name + ' 0').join('\n') + '\nprivate_field secret',
    'memory.events': 'oom 0\noom_kill 0\nprivate_field secret', 'cpu.max': '100000 100000', 'memory.max': String(MEMORY_BYTES),
    'memory.swap.max': '0', 'memory.peak': '1024', 'cpu.max.burst': '0', 'pids.max': '128', 'cpuset.cpus.effective': '0-3\n' };
  const read = () => readResources(name => files[name], () => 'Name:\tPRIVATE\nCpus_allowed_list:\t0-3\n');
  assert.equal(JSON.stringify(read()).includes('secret'), false);
  const sampler = resourceSampler(true, () => read().sample.cpu);
  for (let i = 0; i < 4096; i++) sampler.sample();
  const result = sampler.stop(); assert.equal(result.samples.length, 4096); assert.equal(result.dropped, 2); assert.equal(result.closed, true);
  assert.equal(sampler.stop(), result); sampler.sample(); assert.equal(result.dropped, 2);
  files['memory.swap.max'] = 'max'; assert.throws(read);
  const failing = resourceSampler(true, read); assert.equal(failing.stop().errors, 2);
});
test('staging uses only reviewed runtime files and rejects links, unexpected dist files and oversized inputs', posix, t => {
  const p = temporary(t), input = join(p, 'input'); fs.mkdirSync(input);
  const manifest = stageInputs(ROOT, input); assert.ok(manifest.files.length > 50 && manifest.bytes < 16 * 1024 * 1024);
  assert.ok(manifest.files.every(f => !f.path.includes('/test/') && !f.path.includes('apps/') && !f.path.includes('.env')));
  assert.equal(fs.readlinkSync(join(input, 'node_modules/@shieldaai/agent-guard')), '../../packages/core');
  fs.writeFileSync(join(input, '.env'), 'PRIVATE-COMPANY-SECRET');
  const target = join(p, 'copy'); fs.mkdirSync(target); stageInputs(input, target); assert.equal(fs.existsSync(join(target, '.env')), false);
  const extra = join(input, 'packages/core/dist/unexpected.js'); fs.writeFileSync(extra, 'PRIVATE');
  assert.throws(() => stageInputs(input, join(p, 'unexpected')), /UNEXPECTED_DIST_INPUT/); fs.unlinkSync(extra);
  const file = join(input, 'packages/core/dist/index.js'); fs.unlinkSync(file); fs.symlinkSync(join(ROOT, 'packages/core/dist/index.js'), file);
  assert.throws(() => stageInputs(input, join(p, 'linked')), /INPUT_SYMLINK_REFUSED/); fs.unlinkSync(file);
  fs.writeFileSync(file, Buffer.alloc(2 * 1024 * 1024 + 1)); assert.throws(() => stageInputs(input, join(p, 'large')), /INPUT_FILE_INVALID/);
  const hard = join(p, 'hard'); fs.linkSync(file, hard); assert.throws(() => boundedFile(hard, 4 * 1024 * 1024), /INPUT_FILE_INVALID/);
});
const id = 'a'.repeat(64), imageId = 'sha256:' + 'b'.repeat(64), owner = 'unit-owner', name = 'guard-constrained-unit';
test('explicit worker policy adds only fixed payload arguments without altering Docker controls or historical default', () => {
  const options = { name, owner, input: '/private/input', output: '/private/output', image: PINNED_IMAGE,
    user: '1001:1001', profile: 'acceptance', diagnostics: false, cpuAffinity: '0' };
  const original = containerArguments(options), selected = containerArguments({ ...options, workerScheduling: 'linux-background' });
  assert.deepEqual(selected.slice(0, -2), original);
  assert.deepEqual(selected.slice(-2), ['--worker-scheduling', 'linux-background']);
  assert.equal(original.includes('--worker-scheduling'), false);
  assert.throws(() => containerArguments({ ...options, workerScheduling: 'invalid' }));
});
function container(input = '/private/input', output = '/private/output', user = '1001:1001') {
  const [uid, gid] = user.split(':');
  return { Id: id, Name: '/' + name, Image: imageId, State: { Running: false, OOMKilled: false, ExitCode: 0 },
    Config: { User: user, Entrypoint: ['node'], WorkingDir: '/app', Labels: { 'ai.shielda.constrained-observer-owner': owner } },
    HostConfig: { Memory: MEMORY_BYTES, MemorySwap: MEMORY_BYTES, NanoCpus: 1e9, CpusetCpus: '', PidsLimit: 128, NetworkMode: 'none', ReadonlyRootfs: true,
      Privileged: false, CapDrop: ['ALL'], CapAdd: [], SecurityOpt: ['no-new-privileges:true'],
      Tmpfs: { '/tmp': `rw,noexec,nosuid,nodev,size=128m,mode=0700,uid=${uid},gid=${gid}` } },
    Mounts: [{ Type: 'bind', Source: input, Destination: '/app', RW: false, Propagation: 'rprivate' },
      { Type: 'bind', Source: output, Destination: '/output', RW: true, Propagation: 'rprivate' }] };
}
test('Docker command and inspect verification keep the exact resource and mount isolation', () => {
  const options = { name, owner, input: '/private/input', output: '/private/output', user: '1001:1001', image: PINNED_IMAGE, profile: 'acceptance', diagnostics: false, imageId };
  const args = containerArguments(options);
  for (const [flag, value] of [['--memory', '512m'], ['--memory-swap', '512m'], ['--cpus', '1.0'], ['--pids-limit', '128'],
    ['--pull', 'never'], ['--network', 'none'], ['--entrypoint', 'node']]) assert.equal(args[args.indexOf(flag) + 1], value);
  assert.equal(args.filter(x => x === '--mount').length, 2); assert.equal(args.includes('--privileged'), false);
  assert.equal(args.includes('scripts/constrained-observer-payload.mjs'), true); assert.ok(args.includes('--read-only'));
  verifyContainer(container(), options);
  assert.equal(args.includes('--cpuset-cpus'), false);
  const pinned = containerArguments({ ...options, cpuAffinity: '2' }), pinnedContainer = container(); pinnedContainer.HostConfig.CpusetCpus = '2';
  assert.equal(pinned[pinned.indexOf('--cpuset-cpus') + 1], '2'); assert.equal(pinned[pinned.indexOf('--cpus') + 1], '1.0');
  assert.deepEqual(pinned.slice(-4), ['scripts/constrained-observer-payload.mjs', 'acceptance', 'false', '2']);
  verifyContainer(pinnedContainer, { ...options, cpuAffinity: '2' });
  assert.throws(() => verifyContainer(pinnedContainer, options), /CONTAINER_CPU_AFFINITY_INVALID/);
  for (const actual of ['', '0', '2-2', '2,3']) {
    pinnedContainer.HostConfig.CpusetCpus = actual;
    assert.throws(() => verifyContainer(pinnedContainer, { ...options, cpuAffinity: '2' }), /CONTAINER_CPU_AFFINITY_INVALID/);
  }
  for (const change of [c => { c.HostConfig.MemorySwap *= 2; }, c => { c.HostConfig.NetworkMode = 'host'; }, c => { c.Config.User = '0:0'; },
    c => { c.Mounts[0].RW = true; }, c => { c.Mounts.push(c.Mounts[0]); }, c => { c.Config.Labels = null; },
    c => { c.HostConfig.Privileged = true; }, c => { c.HostConfig.Tmpfs['/tmp'] = 'rw'; }]) { const c = container(); change(c); assert.throws(() => verifyContainer(c, options)); }
});
const result = (value = '', status = 0, reason = null) => ({ stdout: typeof value === 'string' ? value : JSON.stringify(value), stderr: '', status, reason });
test('Docker command wrapper has no shell, bounds combined output and terminates aborted clients', async () => {
  for (const kind of ['output-limit', 'interrupted', 'spawn']) {
    const abort = new AbortController(), killed = [];
    const value = await dockerCommand(['inspect', 'fixed-name'], { maxBytes: 16, signal: abort.signal, spawnProcess(command, args, options) {
      assert.equal(command, 'docker'); assert.deepEqual(args, ['inspect', 'fixed-name']); assert.equal(options.shell, false);
      if (kind === 'spawn') throw Error('PRIVATE-SPAWN-DETAIL');
      const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
      child.kill = signal => { killed.push(signal); queueMicrotask(() => child.emit('close', null)); };
      queueMicrotask(() => { if (kind === 'interrupted') abort.abort(); else { child.stdout.emit('data', Buffer.alloc(10)); child.stderr.emit('data', Buffer.alloc(7)); } });
      return child;
    } });
    assert.equal(value.status, null); assert.equal(value.reason, kind); assert.ok(Buffer.byteLength(value.stdout) + Buffer.byteLength(value.stderr) <= 16);
    assert.deepEqual(killed, kind === 'spawn' ? [] : ['SIGKILL']); assert.equal(JSON.stringify(value).includes('PRIVATE'), false);
  }
});
test('cleanup removes only exact owned IDs and independently proves absence, never infers it from inspect errors', async () => {
  const calls = [];
  let c = container(), absent = true;
  const docker = async args => { calls.push(args); return args[0] === 'inspect' ? result([c]) : args[0] === 'rm' ? result() : result(absent ? '' : id); };
  assert.deepEqual(await cleanupContainer(docker, name, owner), { attempted: true, ownershipVerified: true, removalSucceeded: true, absenceVerified: true });
  assert.deepEqual(calls.find(a => a[0] === 'rm'), ['rm', '-f', id]);
  calls.length = 0; c.Config.Labels = null; absent = false;
  const wrong = await cleanupContainer(docker, name, owner); assert.equal(wrong.ownershipVerified, false); assert.equal(wrong.absenceVerified, false); assert.equal(calls.some(a => a[0] === 'rm'), false);
  const unavailable = await cleanupContainer(async () => result('PRIVATE-DOCKER-ERROR', 1), name, owner); assert.equal(unavailable.absenceVerified, false); assert.equal(JSON.stringify(unavailable).includes('PRIVATE'), false);
});
test('create failure categories are fixed and never retain daemon paths or private messages', () => {
  assert.equal(createFailureCode({ reason: null, stderr: 'Error response from daemon: invalid mount config for type "bind": bind source path does not exist: /PRIVATE/SECRET' }), 'CONTAINER_BIND_SOURCE_UNAVAILABLE');
  assert.equal(createFailureCode({ reason: 'deadline', stderr: 'PRIVATE' }), 'CONTAINER_CREATE_DEADLINE');
  assert.equal(createFailureCode({ reason: 'interrupted', stderr: 'PRIVATE' }), 'RUN_INTERRUPTED');
  assert.equal(createFailureCode({ reason: '__proto__', stderr: 'PRIVATE' }), 'CONTAINER_CREATE_FAILED');
  assert.equal(createFailureCode({ reason: null, stderr: 'PRIVATE' }), 'CONTAINER_CREATE_FAILED');
});
test('mocked complete run verifies exact reports with private empty output and no workspace mount', posix, async t => {
  const p = temporary(t), output = join(p, 'result'), calls = []; let c, removed = false;
  const docker = async args => {
    calls.push(args);
    if (args[0] === 'image') return result([{ Id: imageId, Os: 'linux', Architecture: 'arm64', Config: {} }]);
    if (args[0] === 'create') {
      assert.deepEqual(fs.readdirSync(output), []);
      const input = args[args.indexOf('--mount') + 1].match(/src=([^,]+)/)[1]; assert.notEqual(input, ROOT);
      assert.equal(dirname(dirname(input)), p); assert.notEqual(dirname(input), output);
      assert.ok(relative(output, input).startsWith('..')); assert.equal(fs.statSync(dirname(input)).mode & 0o077, 0);
      assert.equal(fs.existsSync(join(input, 'apps')), false); assert.equal(fs.statSync(output).mode & 0o077, 0);
      c = container(input, output, args[args.indexOf('--user') + 1]); c.Name = '/' + args[args.indexOf('--name') + 1];
      c.Config.Labels = { 'ai.shielda.constrained-observer-owner': args[args.indexOf('--label') + 1].split('=')[1] }; return result(id);
    }
    if (args[0] === 'inspect') return result([c]);
    if (args[0] === 'start') { for (const [file, value] of [['admission.json', admissionReport()], ['resources.json', resourceReport()]]) fs.writeFileSync(join(output, file), JSON.stringify(value), { mode: 0o600 }); return result(); }
    if (args[0] === 'rm') { removed = true; return result(); }
    if (args[0] === 'ps') return result(removed ? '' : id);
    throw Error('UNEXPECTED_COMMAND');
  };
  const beforeSignals = process.listenerCount('SIGINT');
  const verified = await runConstrainedObserver({ output }, { docker });
  assert.equal(verified.passed, true); assert.equal(verified.admission.effects, 1200); assert.equal(verified.cleanup.absenceVerified, true);
  assert.equal(verified.stagedInputsUnchanged, true); assert.equal(verified.stagingRemoved, true); assert.equal(process.listenerCount('SIGINT'), beforeSignals);
  assert.equal(calls.filter(a => a[0] === 'start').length, 1); assert.equal(calls.some(a => a[0] === 'pull' || a[0] === 'run' || a[0] === 'volume'), false);
  await assert.rejects(runConstrainedObserver({ output }, { docker }));
});
test('mocked explicit affinity run binds requested and effective CPU sets and refuses drift without retry', posix, async t => {
  for (const mismatch of [null, 'requested-after', 'effective-after']) {
    const p = temporary(t), output = join(p, 'result'); let c, removed = false, started = 0;
    const docker = async args => {
      if (args[0] === 'image') return result([{ Id: imageId, Os: 'linux', Architecture: 'arm64', Config: {} }]);
      if (args[0] === 'create') {
        assert.equal(args[args.indexOf('--cpuset-cpus') + 1], '0');
        const input = args[args.indexOf('--mount') + 1].match(/src=([^,]+)/)[1];
        c = container(input, output, args[args.indexOf('--user') + 1]); c.Name = '/' + args[args.indexOf('--name') + 1];
        c.HostConfig.CpusetCpus = '0';
        c.Config.Labels = { 'ai.shielda.constrained-observer-owner': args[args.indexOf('--label') + 1].split('=')[1] }; return result(id);
      }
      if (args[0] === 'inspect') return result([c]);
      if (args[0] === 'start') {
        started++;
        const resource = resourceReport(false, '0');
        if (mismatch === 'requested-after') c.HostConfig.CpusetCpus = '0-3';
        if (mismatch === 'effective-after') resource.affinity.after.processCpusAllowedList = '0-3';
        for (const [file, value] of [['admission.json', admissionReport()], ['resources.json', resource]])
          fs.writeFileSync(join(output, file), JSON.stringify(value), { mode: 0o600 });
        return result();
      }
      if (args[0] === 'rm') { removed = true; return result(); }
      if (args[0] === 'ps') return result(removed ? '' : id);
      throw Error('UNEXPECTED_COMMAND');
    };
    const verified = await runConstrainedObserver({ output, cpuAffinity: '0' }, { docker });
    assert.equal(verified.resourceProfile, 'single-logical-cpu'); assert.equal(verified.cpuAffinity, '0');
    assert.equal(verified.passed, mismatch === null); assert.equal(verified.acceptanceEvidenceEligible, mismatch === null);
    assert.equal(started, 1); assert.equal(verified.cleanup.absenceVerified, true);
    if (mismatch === null) assert.deepEqual(verified.resources.affinity, resourceReport(false, '0').affinity);
  }
});
test('mocked native pinned CPU diagnostic is explicitly ineligible even when every original gate passes', posix, async t => {
  const output = join(temporary(t), 'result'); let c, removed = false, started = 0;
  const docker = async args => {
    if (args[0] === 'image') return result([{ Id: imageId, Os: 'linux', Architecture: 'amd64', Config: {} }]);
    if (args[0] === 'create') {
      assert.deepEqual(args.slice(-5), ['scripts/constrained-observer-payload.mjs', 'acceptance', 'true', '0', '--cpu-profile']);
      assert.equal(args[args.indexOf('--cpus') + 1], '1.0'); assert.equal(args[args.indexOf('--cpuset-cpus') + 1], '0');
      assert.equal(args[args.indexOf('--memory') + 1], '512m'); assert.equal(args[args.indexOf('--memory-swap') + 1], '512m');
      const input = args[args.indexOf('--mount') + 1].match(/src=([^,]+)/)[1];
      c = container(input, output, args[args.indexOf('--user') + 1]); c.Name = '/' + args[args.indexOf('--name') + 1];
      c.HostConfig.CpusetCpus = '0';
      c.Config.Labels = { 'ai.shielda.constrained-observer-owner': args[args.indexOf('--label') + 1].split('=')[1] };
      return result(id);
    }
    if (args[0] === 'inspect') return result([c]);
    if (args[0] === 'start') {
      started++;
      for (const [file, value] of [['admission.json', profiledAdmissionReport()], ['resources.json', resourceReport(true, '0')]])
        fs.writeFileSync(join(output, file), JSON.stringify(value), { mode: 0o600 });
      return result();
    }
    if (args[0] === 'rm') { removed = true; return result(); }
    if (args[0] === 'ps') return result(removed ? '' : id);
    throw Error('UNEXPECTED_COMMAND');
  };
  const verified = await runConstrainedObserver({ output, cpuAffinity: '0', diagnostics: true, cpuProfile: true }, { docker });
  assert.equal(started, 1); assert.equal(verified.passed, true); assert.equal(verified.admission.effects, 1200);
  assert.equal(verified.cpuProfileEnabled, true); assert.equal(verified.diagnosticOnly, true);
  assert.equal(verified.acceptanceEvidenceEligible, false); assert.equal(verified.admission.acceptanceEvidenceEligible, false);
  assert.equal(verified.cleanup.absenceVerified, true); assert.equal(verified.stagedInputsUnchanged, true);
  assert.equal(verified.stagingRemoved, true);
});
test('uncertain create still checks ownership and cleanup; an interrupted run cannot pass or expose command errors', posix, async t => {
  for (const interrupt of [false, true]) {
    const p = temporary(t), output = join(p, 'result'); let c, removed = false;
    const docker = async args => {
      if (args[0] === 'image') return result([{ Id: imageId, Os: 'linux', Architecture: 'arm64', Config: {} }]);
      if (args[0] === 'create') {
        const input = args[args.indexOf('--mount') + 1].match(/src=([^,]+)/)[1]; c = container(input, output, args[args.indexOf('--user') + 1]);
        c.Name = '/' + args[args.indexOf('--name') + 1]; c.Config.Labels = { 'ai.shielda.constrained-observer-owner': args[args.indexOf('--label') + 1].split('=')[1] };
        if (interrupt) process.emit('SIGINT'); return result('PRIVATE-CREDENTIAL', null, interrupt ? 'interrupted' : 'deadline');
      }
      if (args[0] === 'inspect') return result([c]); if (args[0] === 'rm') { removed = true; return result(); }
      if (args[0] === 'ps') return result(removed ? '' : id); throw Error('NO_RETRY_ALLOWED');
    };
    const report = await runConstrainedObserver({ output }, { docker });
    assert.equal(report.passed, false); assert.equal(report.stage, 'create'); assert.equal(report.cleanup.absenceVerified, true);
    assert.equal(report.acceptanceEvidenceEligible, false);
    assert.equal(report.interrupted ?? false, interrupt); assert.equal(JSON.stringify(report).includes('PRIVATE'), false);
  }
});
