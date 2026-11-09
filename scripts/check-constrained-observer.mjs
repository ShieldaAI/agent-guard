#!/usr/bin/env node
// Disposable Linux qualification. No network pull, company configuration, existing
// volume, whole-checkout mount, privileged setup, retry or discarded first poll.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  constants,
  closeSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { isEntry } from '../examples/providers/replay.mjs';
import {
  configuration,
  MEMORY_BYTES,
  validateAdmission,
  validateResources,
} from './constrained-observer-validation.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const OWNER_LABEL = 'ai.shielda.constrained-observer-owner';
const FILE_LIMIT = 2 * 1024 * 1024,
  STAGE_LIMIT = 16 * 1024 * 1024,
  REPORT_LIMIT = 32 * 1024 * 1024;
// Four already-bounded16MiB CPU captures plus the unchanged32MiB ordinary report.
// This diagnostic-only allowance never changes acceptance or runtime resource caps.
export const admissionReportLimit = cpuProfile =>
  cpuProfile === true ? REPORT_LIMIT + 4 * 16 * 1024 * 1024 : REPORT_LIMIT;
const modules = {
  core: 'authorization deprecated errors index internal json policy-admission types'.split(' '),
  executor:
    'adapters artifacts build-provenance client custody-cli custody-files custody-snapshot evidence-json executor http index inventory-http inventory-manifest inventory-mcp-capture inventory-mcp inventory-observer inventory-scheduling inventory-worker inventory ledger-custody ledger-maintenance-cli ledger-maintenance ledger-recovery lifecycle model network pilot-review-cli pilot-review response-code retention sandbox signed-evidence store traces workspace-input-windows workspace-input'.split(
      ' ',
    ),
};
const scripts = [
  'benchmark-admission.mjs',
  'benchmark-admission-client.mjs',
  'benchmark-admission-diagnostics.mjs',
  'benchmark-admission-profile.mjs',
  'benchmark-admission-scheduling.mjs',
  'constrained-observer-payload.mjs',
  'constrained-observer-validation.mjs',
];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => {
  throw Error(code);
};
function noLinks(path, root) {
  const local = relative(root, path);
  if (local.startsWith('..' + sep) || local === '..' || resolve(root, local) !== path) fail('INPUT_PATH_INVALID');
  let current = root;
  for (const part of local.split(sep).filter(Boolean)) {
    current = join(current, part);
    if (lstatSync(current).isSymbolicLink()) fail('INPUT_SYMLINK_REFUSED');
  }
}
export function boundedFile(path, maximum, root = dirname(path)) {
  noLinks(path, root);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd),
      named = lstatSync(path);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.size > maximum ||
      before.size < 1 ||
      before.dev !== named.dev ||
      before.ino !== named.ino
    )
      fail('INPUT_FILE_INVALID');
    const buffer = Buffer.alloc(before.size + 1);
    let length = 0,
      count;
    while (length < buffer.length && (count = readSync(fd, buffer, length, buffer.length - length, null)) !== 0)
      length += count;
    const value = buffer.subarray(0, length),
      after = fstatSync(fd),
      end = lstatSync(path);
    if (
      value.length !== before.size ||
      after.size !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ctimeMs !== before.ctimeMs ||
      end.dev !== before.dev ||
      end.ino !== before.ino
    )
      fail('INPUT_FILE_CHANGED');
    return value;
  } finally {
    closeSync(fd);
  }
}
function writeNew(path, value) {
  const fd = openSync(path, 'wx', 0o600);
  try {
    writeFileSync(fd, value);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
export function stageInputs(root, destination) {
  root = realpathSync(root);
  const files = [];
  for (const [name, names] of Object.entries(modules)) {
    const dir = join(root, 'packages', name, 'dist');
    noLinks(dir, root);
    const expected = names.flatMap(name => [name + '.js', name + '.d.ts']).sort();
    assert.deepEqual(readdirSync(dir).sort(), expected, 'UNEXPECTED_DIST_INPUT');
    files.push(`packages/${name}/package.json`, ...expected.map(name2 => `packages/${name}/dist/${name2}`));
  }
  files.push(
    'node_modules/ipaddr.js/package.json',
    'node_modules/ipaddr.js/lib/ipaddr.js',
    'node_modules/ipaddr.js/lib/ipaddr.d.ts',
    ...scripts.map(name => 'scripts/' + name),
    'examples/providers/replay.mjs',
    'examples/providers/protected-ticket.mjs',
  );
  const manifest = [];
  let bytes = 0;
  for (const path of files.sort()) {
    const body = boundedFile(join(root, path), FILE_LIMIT, root);
    bytes += body.length;
    if (bytes > STAGE_LIMIT) fail('STAGED_INPUT_LIMIT');
    mkdirSync(dirname(join(destination, path)), { recursive: true, mode: 0o700 });
    writeNew(join(destination, path), body);
    manifest.push({ path, bytes: body.length, sha256: sha(body) });
  }
  const core = JSON.parse(readFileSync(join(destination, 'packages/core/package.json')));
  const executor = JSON.parse(readFileSync(join(destination, 'packages/executor/package.json')));
  const ip = JSON.parse(readFileSync(join(destination, 'node_modules/ipaddr.js/package.json')));
  assert.equal(core.name, '@shieldaai/agent-guard');
  assert.equal(executor.name, '@shieldaai/agent-guard-executor');
  assert.deepEqual(executor.dependencies, { '@shieldaai/agent-guard': core.version, 'ipaddr.js': ip.version });
  assert.equal(core.type, 'module');
  assert.equal(executor.type, 'module');
  assert.equal(ip.name, 'ipaddr.js');
  assert.equal(ip.main, './lib/ipaddr.js');
  mkdirSync(join(destination, 'node_modules/@shieldaai'), { recursive: true, mode: 0o700 });
  // The only allowed link is constructed here inside the stage, never copied.
  symlinkSync('../../packages/core', join(destination, 'node_modules/@shieldaai/agent-guard'), 'dir');
  const digest = createHash('sha256');
  for (const file of manifest) digest.update(file.path + '\0').update(Buffer.from(file.sha256, 'hex'));
  return {
    files: manifest,
    bytes,
    sha256: digest.digest('hex'),
    generatedLinks: [{ path: 'node_modules/@shieldaai/agent-guard', target: '../../packages/core' }],
  };
}
export function dockerCommand(args, { timeoutMs = 30_000, maxBytes = 1024 * 1024, signal, spawnProcess = spawn } = {}) {
  return new Promise(resolveResult => {
    let child,
      timer,
      reason = null,
      size = 0;
    const stdout = [],
      stderr = [];
    const interrupted = () => {
      reason = 'interrupted';
      child?.kill('SIGKILL');
    };
    const finish = status => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', interrupted);
      resolveResult({
        status,
        reason,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
      });
    };
    if (signal?.aborted) {
      reason = 'interrupted';
      finish(null);
      return;
    }
    try {
      child = spawnProcess('docker', args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    } catch {
      reason = 'spawn';
      finish(null);
      return;
    }
    const data = chunks => bytes => {
      size += bytes.length;
      if (size > maxBytes) {
        reason = 'output-limit';
        child.kill('SIGKILL');
      } else chunks.push(bytes);
    };
    child.stdout.on('data', data(stdout));
    child.stderr.on('data', data(stderr));
    child.on('error', () => {
      reason = 'spawn';
    });
    child.once('close', finish);
    signal?.addEventListener('abort', interrupted, { once: true });
    if (signal?.aborted) interrupted();
    timer = setTimeout(() => {
      reason = 'deadline';
      child.kill('SIGKILL');
    }, timeoutMs);
    timer.unref();
  });
}
const parseInspect = result => {
  if (result.status !== 0 || result.reason) fail('DOCKER_INSPECT_FAILED');
  const rows = JSON.parse(result.stdout);
  if (!Array.isArray(rows) || rows.length !== 1 || !rows[0] || typeof rows[0] !== 'object')
    fail('DOCKER_INSPECT_INVALID');
  return rows[0];
};
function owned(value, name, owner) {
  return (
    value?.Name === '/' + name &&
    typeof value.Id === 'string' &&
    /^[a-f0-9]{64}$/.test(value.Id) &&
    value.Config?.Labels?.[OWNER_LABEL] === owner
  );
}
export function containerArguments({
  name,
  owner,
  input,
  output,
  image,
  user,
  profile,
  diagnostics,
  cpuProfile = false,
  cpuAffinity = null,
  workerScheduling = 'default',
}) {
  configuration({ profile, diagnostics, cpuProfile, image, cpuAffinity, workerScheduling });
  assert.match(user, /^[1-9]\d*:\d+$/);
  const [uid, gid] = user.split(':');
  return [
    'create',
    '--pull',
    'never',
    '--name',
    name,
    '--label',
    `${OWNER_LABEL}=${owner}`,
    '--network',
    'none',
    '--memory',
    '512m',
    '--memory-swap',
    '512m',
    '--cpus',
    '1.0',
    ...(cpuAffinity === null ? [] : ['--cpuset-cpus', cpuAffinity]),
    '--pids-limit',
    '128',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges:true',
    '--user',
    user,
    '--tmpfs',
    `/tmp:rw,noexec,nosuid,nodev,size=128m,mode=0700,uid=${uid},gid=${gid}`,
    '--mount',
    `type=bind,src=${input},dst=/app,readonly,bind-propagation=rprivate`,
    '--mount',
    `type=bind,src=${output},dst=/output,bind-propagation=rprivate`,
    '--workdir',
    '/app',
    '--env',
    'NODE_OPTIONS=',
    '--env',
    'NODE_PATH=',
    '--env',
    'HOME=/tmp',
    '--env',
    'TMPDIR=/tmp',
    '--entrypoint',
    'node',
    image,
    'scripts/constrained-observer-payload.mjs',
    profile,
    String(diagnostics),
    ...(cpuAffinity === null ? [] : [cpuAffinity]),
    ...(cpuProfile ? ['--cpu-profile'] : []),
    ...(workerScheduling === 'default' ? [] : ['--worker-scheduling', workerScheduling]),
  ];
}
export function verifyContainer(value, { name, owner, input, output, user, imageId, cpuAffinity = null }) {
  configuration({ cpuAffinity });
  assert.match(user, /^[1-9]\d*:\d+$/);
  const [uid, gid] = user.split(':');
  assert.ok(owned(value, name, owner), 'CONTAINER_OWNERSHIP_INVALID');
  assert.equal(value.Image, imageId);
  const h = value.HostConfig;
  assert.equal(h.Memory, MEMORY_BYTES);
  assert.equal(h.MemorySwap, MEMORY_BYTES);
  assert.equal(h.NanoCpus, 1e9);
  assert.equal(h.PidsLimit, 128);
  assert.equal(h.CpusetCpus, cpuAffinity ?? '', 'CONTAINER_CPU_AFFINITY_INVALID');
  assert.equal(h.NetworkMode, 'none');
  assert.equal(h.ReadonlyRootfs, true);
  assert.equal(h.Privileged, false);
  assert.deepEqual(h.CapDrop, ['ALL']);
  assert.equal(h.CapAdd?.length ?? 0, 0);
  assert.ok(Array.isArray(h.SecurityOpt));
  assert.ok(h.SecurityOpt.includes('no-new-privileges:true') || h.SecurityOpt.includes('no-new-privileges'));
  for (const field of ['Devices', 'DeviceRequests']) assert.equal(h[field]?.length ?? 0, 0);
  assert.equal(Object.keys(h.PortBindings ?? {}).length, 0);
  assert.equal(h.PidMode ?? '', '');
  assert.equal(h.UTSMode ?? '', '');
  assert.equal(value.Config.User, user);
  assert.deepEqual(value.Config.Entrypoint, ['node']);
  assert.equal(value.Config.WorkingDir, '/app');
  assert.deepEqual(h.Tmpfs, { '/tmp': `rw,noexec,nosuid,nodev,size=128m,mode=0700,uid=${uid},gid=${gid}` });
  assert.equal(value.Mounts.length, 2);
  for (const [target, source, writable] of [
    ['/app', input, false],
    ['/output', output, true],
  ]) {
    const m = value.Mounts.find(m => m.Destination === target);
    assert.ok(m);
    assert.equal(m.Type, 'bind');
    assert.equal(m.Source, source);
    assert.equal(m.RW, writable);
    assert.equal(m.Propagation, 'rprivate');
  }
}
export async function cleanupContainer(docker, name, owner) {
  const result = { attempted: true, ownershipVerified: false, removalSucceeded: false, absenceVerified: false };
  try {
    const value = parseInspect(await docker(['inspect', name]));
    if (owned(value, name, owner)) {
      result.ownershipVerified = true;
      const removed = await docker(['rm', '-f', value.Id]);
      result.removalSucceeded = removed.status === 0 && !removed.reason;
    }
  } catch {
    /* Absence needs a separate successful exact-name query. */
  }
  try {
    const listed = await docker(['ps', '-a', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}']);
    result.absenceVerified = listed.status === 0 && !listed.reason && listed.stdout.trim() === '';
  } catch {
    /* Unknown cleanup is a failed verification, never assumed absent. */
  }
  return result;
}
export function createFailureCode(result) {
  const reasons = {
    deadline: 'CONTAINER_CREATE_DEADLINE',
    interrupted: 'RUN_INTERRUPTED',
    'output-limit': 'CONTAINER_CREATE_OUTPUT_LIMIT',
    spawn: 'CONTAINER_CREATE_UNAVAILABLE',
  };
  if (Object.hasOwn(reasons, result.reason)) return reasons[result.reason];
  // Classify a fixed daemon diagnostic without retaining or reflecting its path.
  if (
    typeof result.stderr === 'string' &&
    result.stderr.includes('invalid mount config for type "bind": bind source path does not exist:')
  )
    return 'CONTAINER_BIND_SOURCE_UNAVAILABLE';
  return 'CONTAINER_CREATE_FAILED';
}
export async function runConstrainedObserver(options, { docker = dockerCommand, root = ROOT } = {}) {
  const config = configuration(options);
  if (typeof options.output !== 'string' || !options.output || !process.getuid || process.getuid() === 0)
    fail('NONROOT_POSIX_HOST_REQUIRED');
  const output = resolve(options.output),
    parent = realpathSync(dirname(output));
  if (dirname(output) !== parent || /[,\r\n\0]/.test(output)) fail('OUTPUT_PATH_INVALID');
  mkdirSync(output, { mode: 0o700 }); // Never reuse, overwrite or mount an existing directory.
  // The output parent is already the operator-selected Docker-shareable custody
  // domain. A separate private sibling avoids both unshared OS temp directories
  // and placing readonly inputs beneath the container's writable output mount.
  const temporary = realpathSync(mkdtempSync(join(parent, '.guard-constrained-'))),
    input = join(temporary, 'input');
  mkdirSync(input, { mode: 0o700 });
  const name = 'guard-constrained-' + randomUUID(),
    owner = randomUUID(),
    user = `${process.getuid()}:${process.getgid()}`;
  const record = {
    schemaVersion: 1,
    kind: 'constrained-observer-verification',
    startedAt: new Date().toISOString(),
    profile: config.profile,
    diagnosticOnly: config.diagnostics,
    cpuProfileEnabled: config.cpuProfile,
    acceptanceEvidenceEligible: false,
    resourceProfile: config.resourceProfile,
    cpuAffinity: config.cpuAffinity,
    workerScheduling: config.workerScheduling,
    image: config.image,
    passed: false,
    stage: 'staging',
    cleanup: { attempted: false, ownershipVerified: false, removalSucceeded: false, absenceVerified: false },
  };
  let staged,
    createAttempted = false;
  const interrupt = new AbortController(),
    onSignal = () => interrupt.abort();
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  const command = (args, limits) => {
    if (interrupt.signal.aborted) fail('RUN_INTERRUPTED');
    return docker(args, { ...limits, signal: interrupt.signal });
  };
  try {
    if (/[,\r\n\0]/.test(input)) fail('INPUT_PATH_INVALID');
    staged = stageInputs(root, input);
    assert.deepEqual(readdirSync(output), []);
    record.stage = 'image';
    const image = parseInspect(await command(['image', 'inspect', config.image]));
    assert.equal(image.Os, 'linux');
    assert.match(image.Id, /^sha256:[a-f0-9]{64}$/);
    assert.ok(image.Config && typeof image.Config === 'object' && !Array.isArray(image.Config));
    assert.ok(
      image.Config.Volumes == null ||
        (typeof image.Config.Volumes === 'object' &&
          !Array.isArray(image.Config.Volumes) &&
          Object.keys(image.Config.Volumes).length === 0),
    );
    record.imageId = image.Id;
    record.imageArchitecture = image.Architecture;
    record.stage = 'create';
    createAttempted = true;
    const created = await command(
      containerArguments({ name, owner, input, output, image: config.image, user, ...config }),
    );
    if (created.status !== 0 || created.reason) {
      record.failure = createFailureCode(created);
      fail(record.failure);
    }
    record.stage = 'controls';
    verifyContainer(parseInspect(await command(['inspect', name])), {
      name,
      owner,
      input,
      output,
      user,
      imageId: image.Id,
      cpuAffinity: config.cpuAffinity,
    });
    record.controlsVerified = true;
    record.stage = 'benchmark';
    const execution = await command(['start', '--attach', name], { timeoutMs: 15 * 60_000, maxBytes: 1024 * 1024 });
    record.execution = {
      exitCode: execution.status,
      failure: execution.reason,
      stdoutBytes: Buffer.byteLength(execution.stdout),
      stderrBytes: Buffer.byteLength(execution.stderr),
      stdoutSha256: sha(execution.stdout),
      stderrSha256: sha(execution.stderr),
    };
    const stopped = parseInspect(await command(['inspect', name]));
    verifyContainer(stopped, { name, owner, input, output, user, imageId: image.Id, cpuAffinity: config.cpuAffinity });
    assert.equal(typeof stopped.State.Running, 'boolean');
    assert.equal(typeof stopped.State.OOMKilled, 'boolean');
    assert.ok(Number.isInteger(stopped.State.ExitCode));
    record.container = {
      running: stopped.State.Running,
      oomKilled: stopped.State.OOMKilled,
      exitCode: stopped.State.ExitCode,
    };
    record.stage = 'reports';
    assert.deepEqual(readdirSync(output).sort(), ['admission.json', 'resources.json']);
    const admissionBytes = boundedFile(join(output, 'admission.json'), admissionReportLimit(config.cpuProfile), output),
      resourceBytes = boundedFile(join(output, 'resources.json'), 4 * 1024 * 1024, output);
    record.artifacts = {
      'admission.json': { bytes: admissionBytes.length, sha256: sha(admissionBytes) },
      'resources.json': { bytes: resourceBytes.length, sha256: sha(resourceBytes) },
    };
    const admission = JSON.parse(admissionBytes),
      resources = JSON.parse(resourceBytes);
    record.admission = validateAdmission(admission, config);
    record.resources = validateResources(resources, config);
    assert.equal(resources.runtime.node, admission.hardware.node);
    assert.equal(resources.runtime.architecture, admission.hardware.architecture);
    record.runtime = resources.runtime;
    record.passed =
      record.admission.gate.passed &&
      record.admission.diagnosticsComplete &&
      record.admission.schedulingEvidenceValid &&
      resources.checksPassed === true &&
      !resources.failure &&
      execution.status === 0 &&
      !execution.reason &&
      !stopped.State.Running &&
      !stopped.State.OOMKilled &&
      stopped.State.ExitCode === 0;
    record.stage = 'complete';
  } catch {
    record.failure ??= 'CONSTRAINED_VERIFICATION_FAILED';
    record.passed = false;
  } finally {
    if (createAttempted) {
      record.cleanup = await cleanupContainer(docker, name, owner);
      if (!record.cleanup.ownershipVerified || !record.cleanup.removalSucceeded || !record.cleanup.absenceVerified)
        record.passed = false;
    }
    if (interrupt.signal.aborted) {
      record.interrupted = true;
      record.passed = false;
    }
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    try {
      if (staged) {
        record.stagedInputsUnchanged = staged.files.every(
          file => sha(boundedFile(join(input, file.path), FILE_LIMIT, input)) === file.sha256,
        );
        if (!record.stagedInputsUnchanged) record.passed = false;
        writeNew(join(output, 'staged-inputs.json'), JSON.stringify(staged, null, 2) + '\n');
      }
    } catch {
      record.passed = false;
      record.stagedInputsUnchanged = false;
    }
    try {
      rmSync(temporary, { recursive: true });
      record.stagingRemoved = true;
    } catch {
      record.stagingRemoved = false;
      record.passed = false;
    }
    record.acceptanceEvidenceEligible = record.passed && config.eligible;
    if (record.admission) record.admission.acceptanceEvidenceEligible = record.acceptanceEvidenceEligible;
    record.failureReasons = [...(record.admission?.gate.failureReasons ?? [])];
    if (record.failure) record.failureReasons.push({ code: record.failure });
    if (record.admission?.schedulingEvidenceValid === false)
      record.failureReasons.push({ code: 'WORKER_SCHEDULING_UNVERIFIED' });
    if (
      createAttempted &&
      (!record.cleanup.ownershipVerified || !record.cleanup.removalSucceeded || !record.cleanup.absenceVerified)
    )
      record.failureReasons.push({ code: 'CONTAINER_CLEANUP_UNVERIFIED' });
    if (record.interrupted) record.failureReasons.push({ code: 'RUN_INTERRUPTED' });
    if (!record.passed && !record.failureReasons.length)
      record.failureReasons.push({ code: 'CONSTRAINED_VERIFICATION_FAILED' });
    record.completedAt = new Date().toISOString();
    record.limitations = [
      'Minimal staged inputs differ from the earlier whole-workspace diagnostic mount; this is a separately bound measurement.',
      'Synthetic observer embedding, not an Agent Ops exporter deployment or a universal real-time guarantee.',
      'A selected CPU is one allowed logical CPU, not an exclusive or physical-core reservation. The bandwidth-only profile does not pin CPUs.',
      'Diagnostics add work and cannot certify acceptance. Every first poll and original gate is retained.',
    ];
    writeNew(join(output, 'verification.json'), JSON.stringify(record, null, 2) + '\n');
  }
  return record;
}
export async function main(argv = process.argv.slice(2)) {
  try {
    const { values } = parseArgs({
      args: argv,
      options: {
        output: { type: 'string' },
        profile: { type: 'string', default: 'acceptance' },
        diagnostics: { type: 'boolean', default: false },
        'cpu-profile': { type: 'boolean', default: false },
        image: { type: 'string' },
        'cpu-affinity': { type: 'string' },
        'worker-scheduling': { type: 'string', default: 'default' },
      },
      strict: true,
      allowPositionals: false,
    });
    const result = await runConstrainedObserver({
      ...values,
      cpuProfile: values['cpu-profile'],
      cpuAffinity: values['cpu-affinity'] ?? null,
      workerScheduling: values['worker-scheduling'],
    });
    process.stdout.write(
      JSON.stringify({
        passed: result.passed,
        profile: result.profile,
        diagnosticOnly: result.diagnosticOnly,
        resourceProfile: result.resourceProfile,
        cpuAffinity: result.cpuAffinity,
        cpuProfileEnabled: result.cpuProfileEnabled,
        workerScheduling: result.workerScheduling,
        acceptanceEvidenceEligible: result.acceptanceEvidenceEligible,
        output: resolve(values.output),
        stage: result.stage,
        failureReasons: result.failureReasons,
        cleanup: result.cleanup,
      }) + '\n',
    );
    return result.passed ? 0 : 1;
  } catch {
    process.stderr.write(
      JSON.stringify({
        passed: false,
        acceptanceEvidenceEligible: false,
        stage: 'configuration',
        failureReasons: [{ code: 'CONSTRAINED_RUNNER_FAILED' }],
      }) + '\n',
    );
    return 1;
  }
}
if (isEntry(import.meta)) process.exitCode = await main();
