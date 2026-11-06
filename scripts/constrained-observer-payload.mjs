// Fixed disposable container entrypoint. Never accepts company paths or credentials.
import { openSync, readSync, writeFileSync, fsyncSync, closeSync } from 'node:fs';
import { main } from './benchmark-admission.mjs';
import { parseArgs } from 'node:util';
import { isEntry } from '../examples/providers/replay.mjs';
import { configuration, cpuList, CPU_FIELDS, SAMPLE_LIMIT, SAMPLE_INTERVAL_MS, validateResources } from './constrained-observer-validation.mjs';

const number = raw => {
  if (!/^\d+$/.test(raw)) throw Error('CGROUP_VALUE_INVALID');
  const value = Number(raw); if (!Number.isSafeInteger(value) || value < 0) throw Error('CGROUP_VALUE_INVALID'); return value;
};
export function boundedKernelText(path, maximum) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64 * 1024) throw Error('KERNEL_TEXT_LIMIT');
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.alloc(maximum + 1); let size = 0, count;
    while (size < buffer.length && (count = readSync(fd, buffer, size, buffer.length - size, null)) > 0) size += count;
    if (size > maximum) throw Error('KERNEL_TEXT_LIMIT');
    return buffer.subarray(0, size).toString('utf8');
  } finally { closeSync(fd); }
}
const readCgroup = name => boundedKernelText('/sys/fs/cgroup/' + name, 4096);
const readStatus = () => boundedKernelText('/proc/self/status', 64 * 1024);
export function processCpuList(value) {
  if (typeof value !== 'string' || value.length > 64 * 1024) throw Error('PROC_STATUS_INVALID');
  const fields = value.split('\n').filter(line => line.startsWith('Cpus_allowed_list:'));
  if (fields.length !== 1) throw Error('PROC_STATUS_INVALID');
  return cpuList(fields[0].slice('Cpus_allowed_list:'.length).trim());
}
const text = (read, name) => { const value = read(name); if (typeof value !== 'string' || value.length > 4096) throw Error('CGROUP_VALUE_INVALID'); return value.trim(); };
function counters(read, name, fields) {
  const found = Object.create(null);
  for (const line of text(read, name).split('\n')) {
    const [key, raw, extra] = line.trim().split(/\s+/); if (!fields.includes(key)) continue;
    if (extra !== undefined || Object.hasOwn(found, key)) throw Error('CGROUP_VALUE_INVALID'); found[key] = number(raw);
  }
  if (fields.some(key => !Object.hasOwn(found, key))) throw Error('CGROUP_VALUE_INVALID'); return { ...found };
}
export const readCpuCounters = (read = readCgroup) => counters(read, 'cpu.stat', CPU_FIELDS);
export function readResources(read = readCgroup, status = readStatus) {
  const value = name => text(read, name);
  value('cgroup.controllers'); // cgroup v2 is mandatory, never infer limits from host CPU/RAM.
  const cpu = readCpuCounters(read), memory = counters(read, 'memory.events', ['oom', 'oom_kill']);
  const split = value('cpu.max').split(/\s+/); if (split.length !== 2) throw Error('CGROUP_VALUE_INVALID');
  return { controls: { memoryMaxBytes: number(value('memory.max')), memorySwapMaxBytes: number(value('memory.swap.max')),
    cpuQuotaUs: number(split[0]), cpuPeriodUs: number(split[1]), cpuBurstUs: number(value('cpu.max.burst')), pidsMax: number(value('pids.max')) },
    affinity: { cpusetCpusEffective: cpuList(value('cpuset.cpus.effective')), processCpusAllowedList: processCpuList(status()) },
    sample: { memoryPeakBytes: number(value('memory.peak')), memoryEvents: { oom: memory.oom, oomKill: memory.oom_kill }, cpu } };
}
export function resourceSampler(enabled, read = readCpuCounters) {
  const result = { enabled, intervalMs: SAMPLE_INTERVAL_MS, limit: SAMPLE_LIMIT, observed: 0, dropped: 0, errors: 0, closed: false, samples: [] };
  const sample = () => {
    if (!enabled || result.closed) return;
    result.observed++;
    if (result.samples.length >= SAMPLE_LIMIT) { result.dropped++; return; }
    try { const startedNs = process.hrtime.bigint().toString(); const cpu = read();
      result.samples.push({ startedNs, endedNs: process.hrtime.bigint().toString(), ...cpu }); }
    catch { result.errors++; }
  };
  sample(); const timer = enabled ? setInterval(sample, SAMPLE_INTERVAL_MS) : undefined; timer?.unref();
  return { sample, stop() { if (!result.closed) { clearInterval(timer); sample(); result.closed = true; } return result; } };
}
export async function runPayload(profile, diagnostics, { cpuAffinity = null, cpuProfile = false, workerScheduling = 'default', benchmark = main, read = readResources, sampleCpu = readCpuCounters, output = '/output' } = {}) {
  const config = configuration({ profile, diagnostics, cpuProfile, cpuAffinity, workerScheduling }), before = read(), sampler = resourceSampler(diagnostics, sampleCpu);
  const report = { schemaVersion: 1, kind: 'constrained-observer-resources', diagnosticOnly: diagnostics,
    resourceProfile: config.resourceProfile, cpuAffinity: config.cpuAffinity, workerScheduling: config.workerScheduling, affinity: { before: before.affinity, after: null },
    acceptanceEvidenceEligible: false, runtime: { node: process.version, architecture: process.arch, platform: process.platform },
    controls: before.controls, before: before.sample, after: null, sampler: null, checksPassed: false };
  let exitCode = 1;
  try {
    // Preflight the real limits before any benchmark. Reuse the final validator
    // with a closed synthetic sampler, without running or discarding a poll.
    validateResources({ ...report, after: before.sample, affinity: { before: before.affinity, after: before.affinity }, sampler: { enabled: false, intervalMs: SAMPLE_INTERVAL_MS,
      limit: SAMPLE_LIMIT, observed: 0, dropped: 0, errors: 0, closed: true, samples: [] }, diagnosticOnly: false,
      acceptanceEvidenceEligible: false }, { profile: 'acceptance', diagnostics: false, cpuAffinity: config.cpuAffinity, workerScheduling });
    exitCode = await benchmark(['--profile', profile, ...(diagnostics ? ['--diagnostics'] : []), ...(cpuProfile ? ['--cpu-profile'] : []),
      ...(workerScheduling === 'default' ? [] : ['--worker-scheduling', workerScheduling]), '--output', output + '/admission.json']);
  } catch { report.failure = 'CONSTRAINED_PAYLOAD_FAILED'; }
  finally {
    report.sampler = sampler.stop();
    try { const after = read(); report.after = after.sample; report.affinity.after = after.affinity;
      if (JSON.stringify(after.controls) !== JSON.stringify(before.controls)) throw Error();
      validateResources(report, config); report.checksPassed = true;
    } catch { report.failure = 'CONSTRAINED_RESOURCES_FAILED'; exitCode = 1; }
    const fd = openSync(output + '/resources.json', 'wx', 0o600);
    try { writeFileSync(fd, JSON.stringify(report, null, 2) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
  }
  return exitCode === 0 && report.checksPassed && !report.failure ? 0 : 1;
}
if (isEntry(import.meta)) {
  try {
    const { values, positionals } = parseArgs({ args: process.argv.slice(2), allowPositionals: true, strict: true,
      options: { 'cpu-profile': { type: 'boolean', default: false }, 'worker-scheduling': { type: 'string', default: 'default' } } });
    if (![2, 3].includes(positionals.length) || !['false', 'true'].includes(positionals[1])) throw Error();
    process.exitCode = await runPayload(positionals[0], positionals[1] === 'true', { cpuAffinity: positionals[2] ?? null,
      cpuProfile: values['cpu-profile'], workerScheduling: values['worker-scheduling'] });
  } catch { process.stderr.write('CONSTRAINED_PAYLOAD_FAILED\n'); process.exitCode = 1; }
}
