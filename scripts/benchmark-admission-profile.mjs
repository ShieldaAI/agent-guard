// In-process, opt-in sampling for the synthetic admission benchmark. No inspector port.
import { Session } from 'node:inspector';
import { isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MAX_NODES = 20000,
  MAX_SAMPLES = 120000,
  MAX_BYTES = 16 * 1024 * 1024,
  MAX_DURATION_MS = 120000;
const integer = value => Number.isSafeInteger(value) && value >= 0;
const limits = ({
  maxNodes = MAX_NODES,
  maxSamples = MAX_SAMPLES,
  maxBytes = MAX_BYTES,
  maxDurationMs = MAX_DURATION_MS,
} = {}) => {
  if (
    !integer(maxNodes) ||
    maxNodes < 1 ||
    maxNodes > MAX_NODES ||
    !integer(maxSamples) ||
    maxSamples < 1 ||
    maxSamples > MAX_SAMPLES ||
    !integer(maxBytes) ||
    maxBytes < 4096 ||
    maxBytes > MAX_BYTES ||
    !integer(maxDurationMs) ||
    maxDurationMs < 1 ||
    maxDurationMs > MAX_DURATION_MS
  )
    throw new Error('ADMISSION_CPU_PROFILE_CONFIG_INVALID');
  return { maxNodes, maxSamples, maxBytes, maxDurationMs };
};
function frame(value, root) {
  let source = '[redacted]',
    known = false;
  const raw = value?.url;
  if (typeof raw === 'string' && raw.length <= 4096) {
    if (/^node:[a-zA-Z0-9_./-]{1,240}$/.test(raw)) {
      source = raw;
      known = true;
    } else {
      try {
        const path = raw.startsWith('file:') ? fileURLToPath(raw) : isAbsolute(raw) ? raw : null;
        const local = path === null ? '' : relative(root, path).replaceAll('\\', '/');
        if (
          /^(?:packages|scripts|node_modules)\/[a-zA-Z0-9_@./-]{1,240}$/.test(local) &&
          !local.split('/').includes('..')
        ) {
          source = local;
          known = true;
        }
      } catch {
        /* Unrecognized paths are never retained. */
      }
    }
  }
  const name = value?.functionName;
  let functionName = '[redacted]';
  if (['(root)', '(program)', '(idle)', '(garbage collector)'].includes(name)) functionName = name;
  else if (known && typeof name === 'string' && /^[a-zA-Z0-9_$# .<>()[\]-]{0,128}$/.test(name))
    functionName = name || '<anonymous>';
  return {
    source,
    functionName,
    line: integer(value?.lineNumber) ? value.lineNumber + 1 : null,
    column: integer(value?.columnNumber) ? value.columnNumber + 1 : null,
    redacted: !known,
  };
}

/** Retain a bounded, detached sampling graph and relative microsecond timeline, never raw V8 frames. */
export function sanitizeAdmissionProfile(profile, options = {}) {
  const cap = limits(options),
    root = resolve(options.repositoryRoot ?? ROOT);
  const rawNodes = Array.isArray(profile?.nodes) ? profile.nodes : [];
  const rawSamples = Array.isArray(profile?.samples) ? profile.samples : [];
  const deltas = Array.isArray(profile?.timeDeltas) ? profile.timeDeltas : [];
  const nodes = [],
    ids = new Set(),
    nodeIds = [],
    sampleOffsetsUs = [],
    sampleDurationsUs = [];
  let invalid = 0,
    redactedFrames = 0,
    durationUs = 0,
    retainedEdges = 0,
    droppedEdges = 0;
  if (!rawNodes.length || !rawSamples.length || rawSamples.length !== deltas.length) invalid++;
  for (const item of rawNodes.slice(0, cap.maxNodes)) {
    if (!integer(item?.id) || ids.has(item.id)) {
      invalid++;
      continue;
    }
    const safeFrame = frame(item.callFrame, root);
    if (safeFrame.redacted) redactedFrames++;
    ids.add(item.id);
    nodes.push({ id: item.id, ...safeFrame, children: [], selfSamples: 0 });
  }
  const byId = new Map(nodes.map(item => [item.id, item]));
  for (const item of rawNodes.slice(0, cap.maxNodes)) {
    const safe = byId.get(item?.id);
    if (!safe) continue;
    if (item.children !== undefined && !Array.isArray(item.children)) {
      invalid++;
      continue;
    }
    const children = item.children ?? [],
      count = Math.min(children.length, cap.maxNodes * 2 - retainedEdges);
    droppedEdges += children.length - count;
    for (const id of children.slice(0, count)) {
      retainedEdges++;
      if (integer(id) && ids.has(id)) safe.children.push(id);
      else invalid++;
    }
  }
  // Sample count and duration cap apply before retaining any timeline entries.
  for (let index = 0; index < Math.min(rawSamples.length, cap.maxSamples); index++) {
    const delta = deltas[index],
      id = rawSamples[index];
    if (!integer(delta) || !integer(id)) {
      invalid++;
      continue;
    }
    durationUs += delta;
    if (durationUs > cap.maxDurationMs * 1000) break;
    if (!ids.has(id)) {
      invalid++;
      continue;
    }
    nodeIds.push(id);
    sampleOffsetsUs.push(durationUs);
    sampleDurationsUs.push(delta);
    byId.get(id).selfSamples++;
  }
  const result = {
    complete:
      invalid === 0 && droppedEdges === 0 && nodes.length === rawNodes.length && nodeIds.length === rawSamples.length,
    invalid,
    redactedFrames,
    droppedEdges,
    droppedNodes: rawNodes.length - nodes.length,
    droppedSamples: rawSamples.length - nodeIds.length,
    observedNodes: rawNodes.length,
    observedSamples: rawSamples.length,
    retainedNodes: nodes.length,
    retainedSamples: nodeIds.length,
    limits: cap,
    nodes,
    nodeIds,
    sampleOffsetsUs,
    sampleDurationsUs,
  };
  if (Buffer.byteLength(JSON.stringify(result)) > cap.maxBytes) {
    result.complete = false;
    result.byteLimitExceeded = true;
    result.droppedNodes = rawNodes.length;
    result.droppedSamples = rawSamples.length;
    result.retainedNodes = 0;
    result.retainedSamples = 0;
    result.nodes = [];
    result.nodeIds = [];
    result.sampleOffsetsUs = [];
    result.sampleDurationsUs = [];
  }
  return result;
}

/** Starts only a Session connection in this process; never inspector.open() or a listening socket. */
export async function startAdmissionCpuProfile(options = {}) {
  const cap = limits(options),
    session = new Session();
  let timer,
    stopping,
    connected = false,
    enabled = false,
    started = false;
  let startRequestedNs = null,
    startAcknowledgedNs = null;
  const command = (method, params = {}) =>
    new Promise((resolveCommand, reject) => {
      const timeout = setTimeout(() => reject(new Error('ADMISSION_CPU_PROFILE_COMMAND_TIMEOUT')), 5000);
      try {
        session.post(method, params, (error, result) => {
          clearTimeout(timeout);
          error ? reject(error) : resolveCommand(result);
        });
      } catch (error) {
        clearTimeout(timeout);
        reject(error);
      }
    });
  const finish = async reason => {
    const stopRequestedNs = process.hrtime.bigint();
    let stopAcknowledgedNs = null,
      profile = null,
      errors = 0;
    clearTimeout(timer);
    try {
      if (!started) errors++;
      else {
        const result = await command('Profiler.stop');
        stopAcknowledgedNs = process.hrtime.bigint();
        started = false;
        // Reserve space for capture metadata within the overall16MiB output ceiling.
        profile = sanitizeAdmissionProfile(result.profile, { ...cap, maxBytes: Math.max(4096, cap.maxBytes - 4096) });
      }
    } catch {
      errors++;
    } finally {
      if (enabled) {
        try {
          await command('Profiler.disable');
        } catch {
          errors++;
        }
        enabled = false;
      }
      if (connected) {
        try {
          session.disconnect();
          connected = false;
        } catch {
          errors++;
        }
      }
    }
    const durationMs = startRequestedNs === null ? null : Number(stopRequestedNs - startRequestedNs) / 1e6;
    const deadlineExceeded = reason === 'deadline' || (durationMs !== null && durationMs > cap.maxDurationMs);
    const result = {
      kind: 'main-thread-sampled-cpu-profile',
      diagnosticOnly: true,
      acceptanceEvidenceEligible: false,
      complete: errors === 0 && profile?.complete === true && !deadlineExceeded,
      errors,
      closed: !connected,
      deadlineExceeded,
      stopReason: reason,
      maximumDurationMs: cap.maxDurationMs,
      samplingIntervalUs: 1000,
      maximumOutputBytes: cap.maxBytes,
      startRequestedNs: startRequestedNs?.toString() ?? null,
      startAcknowledgedNs: startAcknowledgedNs?.toString() ?? null,
      stopRequestedNs: stopRequestedNs.toString(),
      stopAcknowledgedNs: stopAcknowledgedNs?.toString() ?? null,
      captureWallMs: durationMs,
      clock:
        'Sample offsets use V8 relative microseconds. Profile activation is bracketed by startRequestedNs/startAcknowledgedNs; do not assume the V8 epoch equals hrtime. The main-thread deadline can be delayed by blocking work; overrun makes capture incomplete.',
      profile,
    };
    if (Buffer.byteLength(JSON.stringify(result)) > cap.maxBytes) {
      result.complete = false;
      result.outputOmitted = true;
      result.profile = {
        complete: false,
        byteLimitExceeded: true,
        observedNodes: profile?.observedNodes ?? 0,
        observedSamples: profile?.observedSamples ?? 0,
        droppedNodes: profile?.observedNodes ?? 0,
        droppedSamples: profile?.observedSamples ?? 0,
      };
    }
    return result;
  };
  const stop = (reason = 'phase-end') => {
    stopping ??= finish(reason);
    return stopping;
  };
  try {
    session.connect();
    connected = true;
    await command('Profiler.enable');
    enabled = true;
    await command('Profiler.setSamplingInterval', { interval: 1000 });
    startRequestedNs = process.hrtime.bigint();
    await command('Profiler.start');
    startAcknowledgedNs = process.hrtime.bigint();
    started = true;
    timer = setTimeout(() => {
      void stop('deadline');
    }, cap.maxDurationMs);
    timer.unref();
  } catch {
    return { stop: () => stop('start-failed') };
  }
  return { stop };
}
