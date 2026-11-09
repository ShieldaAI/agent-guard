// Disposable synthetic deployment acceptance. Never pulls an image or reads company credentials.
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID, randomBytes, createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { homedir, platform, arch } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { DurableExecutor, createRestrictedFetch } from '@shieldaai/agent-guard-executor';
import { buildDockerCreateArgs, runDockerSandbox } from '@shieldaai/agent-guard-executor/sandbox';
import {
  ManagedMcpConnection,
  createRestrictedMcpHttpTransport,
  assertVerifiedMcpClaims,
} from '@shieldaai/agent-guard-mcp';
import { isEntry } from '../examples/providers/replay.mjs';

const guestPath = fileURLToPath(new URL('./fixtures/mcp-isolation/guest.mjs', import.meta.url));
const imagePattern = /^[a-z0-9][a-z0-9._/:\-]*@sha256:[a-f0-9]{64}$/;
const hostPlatforms = { Linux: 'linux', macOS: 'darwin', Windows: 'win32' };
export const REQUIRED_MCP_CHECKS = Object.freeze([
  'runtime-image',
  'guest-isolation',
  'host-secret-custody',
  'approved-effect',
  'foreign-tenant-before-dispatch',
  'approval-before-dispatch',
  'metadata-quarantine',
  'reviewed-refresh',
  'reconnect-invalidates-work',
  'revocation-before-dispatch',
  'inflight-unknown-no-replay',
  'unknown-reconciliation',
  'bounded-stdio',
  'remote-approved-dispatch',
  'remote-credential-custody',
  'remote-claim-binding',
  'remote-refresh-review',
  'remote-redirect-no-forward',
  'remote-private-address-denied',
  'trace-privacy',
  'cleanup',
]);
const assert = (condition, code) => {
  if (!condition) throw new Error(code);
};
const waitFor = async predicate => {
  const end = Date.now() + 4000;
  while (!(await predicate())) {
    assert(Date.now() < end, 'WAIT_EXPIRED');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
};
const denied = async action => {
  try {
    await action();
  } catch {
    return;
  }
  throw new Error('EXPECTED_DENIAL');
};
function command(args, maximum = 1_048_576) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: 15_000,
    maxBuffer: maximum,
    windowsHide: true,
  });
  assert(result.status === 0, 'DOCKER_COMMAND_FAILED');
  return result.stdout;
}
// Harness-only observations. No request data, stderr text, paths or error messages.
export function makeStdio(
  name,
  canary,
  { spawnProcess = spawn, clock = () => Number(process.hrtime.bigint()) / 1e6 } = {},
) {
  const origin = clock(),
    elapsed = () => Math.max(0, clock() - origin);
  const trace = {
    spawnStartedMs: null,
    spawnedMs: null,
    firstStdoutMs: null,
    firstStderrMs: null,
    closeRequestedMs: null,
    closedMs: null,
    exitCode: null,
    exitSignal: null,
    stdoutBytes: 0,
    stderrBytes: 0,
    receivedFrames: 0,
    failure: null,
  };
  const requests = new Map();
  const observeRequest = message => {
    const kind = message.method === 'initialize' ? 'initialize' : message.method === 'tools/list' ? 'tools-list' : null;
    if (!kind || !Number.isSafeInteger(message.id)) return null;
    const observation = { id: message.id, sentMs: elapsed(), writeCompletedMs: null, responseMs: null };
    requests.set(kind, observation);
    return observation;
  };
  const observeResponse = message => {
    if (!message || typeof message !== 'object' || !Number.isSafeInteger(message.id)) return;
    for (const value of requests.values())
      if (value.id === message.id && value.responseMs === null) value.responseMs = elapsed();
  };
  let child,
    pending = '',
    bytes = 0,
    ended = false,
    closed = false,
    closing;
  const transport = {
    diagnostics() {
      const atMs = elapsed(),
        requestTimeoutMs = 1500;
      // A later inspect/cleanup delay must not turn an earlier rejection into a
      // supposed timeout. Stop the unanswered interval when close first began.
      const cutoffMs = trace.closeRequestedMs ?? trace.closedMs ?? atMs;
      const observed = [...requests].map(([kind, value]) => ({
        kind,
        sentMs: value.sentMs,
        writeCompletedMs: value.writeCompletedMs,
        responseMs: value.responseMs,
        unansweredMs: value.responseMs === null ? Math.max(0, cutoffMs - value.sentMs) : null,
      }));
      const reason =
        trace.failure ??
        (observed.some(value => value.unansweredMs !== null && value.unansweredMs >= requestTimeoutMs)
          ? 'RESPONSE_NOT_OBSERVED_BY_DEADLINE'
          : observed.some(value => value.responseMs !== null)
            ? 'RESPONSE_OBSERVED'
            : 'CONNECTION_FAILURE_UNCLASSIFIED');
      return {
        ...trace,
        observedAtMs: atMs,
        requestTimeoutMs,
        requests: observed,
        reason,
        interpretation:
          'Missing reply at the configured deadline is an observation, not proof of an SDK timeout or its cause.',
      };
    },
    async start() {
      trace.spawnStartedMs = elapsed();
      try {
        child = spawnProcess('docker', ['exec', '-i', name, 'node', '/input/guest.mjs'], {
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true,
          shell: false,
          env: { ...process.env, HOST_ONLY_CANARY: canary },
        });
      } catch (error) {
        trace.failure = 'STDIO_SPAWN_ERROR';
        throw error;
      }
      const failed = reason => {
        if (!ended) {
          trace.failure ??= reason;
          ended = true;
          child.kill('SIGKILL');
          transport.onerror?.(new Error('ISOLATED_TRANSPORT_FAILED'));
          transport.onclose?.();
        }
      };
      child.once('spawn', () => {
        trace.spawnedMs = elapsed();
      });
      child.stdin.on('error', () => failed('STDIO_INPUT_ERROR'));
      child.stdout.on('error', () => failed('STDIO_OUTPUT_ERROR'));
      child.stderr.on('error', () => failed('STDIO_STDERR_ERROR'));
      child.once('error', () => failed('STDIO_SPAWN_ERROR'));
      child.once('close', (code, signal) => {
        trace.closedMs = elapsed();
        trace.exitCode = Number.isInteger(code) ? code : null;
        trace.exitSignal = ['SIGTERM', 'SIGKILL', 'SIGABRT', 'SIGSEGV', 'SIGPIPE'].includes(signal) ? signal : null;
        closed = true;
        if (!ended) {
          trace.failure ??= 'STDIO_UNEXPECTED_CLOSE';
          ended = true;
          transport.onclose?.();
        }
      });
      child.stderr.on('data', value => {
        trace.firstStderrMs ??= elapsed();
        trace.stderrBytes += value.length;
        bytes += value.length;
        if (bytes > 262144) failed('STDIO_OUTPUT_LIMIT');
      });
      child.stdout.on('data', value => {
        trace.firstStdoutMs ??= elapsed();
        trace.stdoutBytes += value.length;
        bytes += value.length;
        if (bytes > 262144) return failed('STDIO_OUTPUT_LIMIT');
        if (Buffer.byteLength(pending) + value.length > 65536) return failed('STDIO_FRAME_LIMIT');
        pending += value.toString('utf8');
        for (;;) {
          const end = pending.indexOf('\n');
          if (end < 0) break;
          const line = pending.slice(0, end);
          pending = pending.slice(end + 1);
          let message;
          try {
            message = JSON.parse(line);
          } catch {
            failed('STDIO_FRAME_INVALID');
            break;
          }
          trace.receivedFrames++;
          observeResponse(message);
          try {
            transport.onmessage?.(message);
          } catch {
            failed('STDIO_DELIVERY_FAILED');
            break;
          }
        }
      });
    },
    async send(message) {
      assert(child && !ended, 'ISOLATED_TRANSPORT_CLOSED');
      const line = JSON.stringify(message) + '\n';
      assert(Buffer.byteLength(line) <= 65536, 'ISOLATED_REQUEST_LIMIT');
      const observation = observeRequest(message);
      await new Promise((resolve, reject) =>
        child.stdin.write(line, error => {
          if (error) {
            trace.failure ??= 'STDIO_WRITE_FAILED';
            reject(new Error('ISOLATED_TRANSPORT_FAILED'));
          } else {
            if (observation) observation.writeCompletedMs = elapsed();
            resolve();
          }
        }),
      );
    },
    async close() {
      if (!child || !child.pid || closed) return;
      if (closing) return closing;
      trace.closeRequestedMs = elapsed();
      ended = true;
      closing = new Promise((resolve, reject) => {
        const term = setTimeout(() => child.kill('SIGTERM'), 500);
        const kill = setTimeout(() => child.kill('SIGKILL'), 1000);
        const limit = setTimeout(() => reject(new Error('TRANSPORT_CLOSE_TIMEOUT')), 2000);
        child.once('close', () => {
          clearTimeout(term);
          clearTimeout(kill);
          clearTimeout(limit);
          resolve();
        });
        child.stdin.end();
      });
      return closing;
    },
  };
  return transport;
}
export function safeGuestState(value, name, id) {
  if (
    !value ||
    value.Name !== '/' + name ||
    !/^[a-f0-9]{64}$/.test(id ?? '') ||
    value.Id !== id ||
    value.Config?.Labels?.['io.shielda.agent-guard.owner-pid'] !== String(process.pid) ||
    typeof value.State?.Running !== 'boolean' ||
    typeof value.State?.OOMKilled !== 'boolean' ||
    !Number.isInteger(value.State?.ExitCode)
  )
    return { available: false };
  return {
    available: true,
    running: value.State.Running,
    oomKilled: value.State.OOMKilled,
    exitCode: value.State.ExitCode,
  };
}
export function cleanupGuestStage({ name, directory, input, created }, remove = command) {
  let failure;
  try {
    if (created) remove(['rm', '--force', '--volumes', name]);
  } catch {
    failure = new Error('CONTAINER_CLEANUP_FAILED');
    failure.container = name;
  } finally {
    if (existsSync(input)) chmodSync(input, 0o755);
    rmSync(directory, { recursive: true, force: true });
  }
  if (failure) throw failure;
}
async function startGuest(image, canary, hostSecret) {
  const directory = mkdtempSync(join(homedir(), '.agent-guard-mcp-'));
  const input = join(directory, 'input');
  mkdirSync(input, { mode: 0o755 });
  writeFileSync(join(input, 'guest.mjs'), readFileSync(guestPath), {
    mode: 0o444,
  });
  writeFileSync(join(input, 'config.json'), JSON.stringify({ hostSecretPath: hostSecret }), { mode: 0o444 });
  chmodSync(input, 0o555);
  const name = `agent-guard-${randomUUID()}`;
  let containerId,
    lastTransport,
    created = false,
    cleaned = false;
  const close = async () => {
    if (cleaned) return true;
    cleanupGuestStage({ name, directory, input, created });
    if (created)
      assert(
        spawnSync('docker', ['inspect', name], {
          stdio: 'ignore',
          timeout: 5000,
        }).status !== 0,
        'CONTAINER_REMAINED',
      );
    cleaned = true;
    return true;
  };
  try {
    containerId = command(buildDockerCreateArgs({ image, timeoutMs: 10_000, memoryMb: 128 }, input, name)).trim();
    created = true;
    command(['start', name]);
    return {
      name,
      transport: () => (lastTransport = makeStdio(name, canary)),
      connectionDiagnostics: () => lastTransport?.diagnostics() ?? null,
      diagnostics: () => {
        const transport = lastTransport?.diagnostics() ?? null;
        let state = { available: false };
        try {
          state = safeGuestState(JSON.parse(command(['inspect', name]))?.[0], name, containerId);
        } catch {
          /* Never replace the original failure. */
        }
        return { transport, container: state };
      },
      close,
      counts: () =>
        JSON.parse(
          command([
            'exec',
            name,
            'node',
            '-e',
            "process.stdout.write(require('fs').readFileSync('/workspace/effects.json','utf8'))",
          ]),
        ),
      exists: path =>
        command([
          'exec',
          name,
          'node',
          '-e',
          `process.stdout.write(String(require('fs').existsSync(${JSON.stringify(path)})))`,
        ]).trim() === 'true',
      profile: () => JSON.parse(command(['inspect', name, '--format', '{{json .HostConfig}}'])),
      environment: () => JSON.parse(command(['inspect', name, '--format', '{{json .Config.Env}}'])),
    };
  } catch (error) {
    if (!created)
      created =
        spawnSync('docker', ['inspect', name], {
          stdio: 'ignore',
          timeout: 5000,
        }).status === 0;
    await close();
    throw error;
  }
}
function identity() {
  return {
    serverId: 'isolated-fixture',
    transportIdentity: 'reviewed-disposable-launch-v1',
    tenantId: 'tenant-a',
    principalId: 'host-operator',
  };
}
function bindings() {
  return ['read', 'write'].map(name => ({
    name,
    requiresApproval: name === 'write',
    resolve: args => ({
      resourceId: args.resource,
      tenantId: args.resource === 'foreign' ? 'tenant-b' : 'tenant-a',
    }),
  }));
}
function task(executor, tools, suffix) {
  return executor.createTask({
    id: `task-${suffix}`,
    tenantId: 'tenant-a',
    principalId: 'host-operator',
    grants: tools.map(tool => ({
      tool: tool.name,
      resources: ['allowed', 'foreign'],
    })),
    budget: {
      maxCalls: 30,
      maxConcurrent: 2,
      maxCost: 0,
      deadline: Date.now() + 120_000,
    },
  }).taskId;
}
function reviewTools(executor, connection) {
  for (const item of connection.registrations) executor.approveTool(item.name, item.fingerprint);
}
const toolName = name => `mcp:isolated-fixture:${name}`;
const prepare = (executor, taskId, name = 'read', mode = 'normal', resource = 'allowed') =>
  executor.prepare(taskId, { tool: toolName(name), args: { resource, mode } });
const approve = (executor, action) =>
  executor.approve(action.id, {
    approverId: 'synthetic-host-reviewer',
    expiresAt: Date.now() + 30000,
  });
const resultValue = result => JSON.parse(result.content[0].text);
async function gateway(transport, token) {
  let requests = 0,
    authenticated = 0,
    redirectTo = null;
  const pending = new Map();
  transport.onmessage = message => {
    if (Object.hasOwn(message, 'id')) {
      pending.get(message.id)?.(message);
      pending.delete(message.id);
    }
  };
  await transport.start();
  const server = createServer(async (req, res) => {
    requests++;
    if (req.headers.authorization !== `Bearer ${token}`) {
      res.writeHead(401);
      res.end();
      return;
    }
    authenticated++;
    if (redirectTo) {
      res.writeHead(307, { location: redirectTo });
      res.end();
      return;
    }
    if (req.method === 'GET') {
      res.writeHead(405);
      res.end();
      return;
    }
    if (req.method === 'DELETE') {
      res.writeHead(204);
      res.end();
      return;
    }
    try {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 65536) throw new Error();
      }
      const message = JSON.parse(body);
      if (!Object.hasOwn(message, 'id')) {
        await transport.send(message);
        res.writeHead(202);
        res.end();
        return;
      }
      let timer;
      const reply = await new Promise(async (resolve, reject) => {
        timer = setTimeout(() => {
          pending.delete(message.id);
          reject(new Error());
        }, 2000);
        pending.set(message.id, resolve);
        try {
          await transport.send(message);
        } catch {
          reject(new Error());
        }
      }).finally(() => clearTimeout(timer));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(reply));
    } catch {
      res.writeHead(500);
      res.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    endpoint: `http://127.0.0.1:${server.address().port}/mcp`,
    stats: () => ({ requests, authenticated }),
    redirect: url => {
      redirectTo = url;
    },
    close: async () => {
      await transport.close();
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    },
  };
}
export function validateMcpIsolationReport(report) {
  if (
    !report ||
    !Array.isArray(report.checks) ||
    report.checks.some(check => !check || typeof check.name !== 'string' || typeof check.passed !== 'boolean')
  )
    return false;
  const names = report?.checks?.map(check => check.name) ?? [];
  const nodeVersion = value => typeof value === 'string' && /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(value);
  const sha256 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  return (
    report?.version === 1 &&
    (report.expectedHost === undefined ||
      (typeof report.expectedHost === 'string' &&
        Object.hasOwn(hostPlatforms, report.expectedHost) &&
        hostPlatforms[report.expectedHost] === report.host?.platform)) &&
    report.failure === undefined &&
    report.cleanupFailures === undefined &&
    ['linux', 'darwin', 'win32'].includes(report.host?.platform) &&
    ['arm', 'arm64', 'ia32', 'loong64', 'mips', 'mipsel', 'ppc', 'ppc64', 'riscv64', 's390', 's390x', 'x64'].includes(
      report.host?.architecture,
    ) &&
    nodeVersion(report.host?.node) &&
    nodeVersion(report.guestNode) &&
    sha256(report.sourceSha256) &&
    sha256(report.fixtureSha256) &&
    typeof report.image === 'string' &&
    imagePattern.test(report.image) &&
    report.isolation === 'linux-container-network-none' &&
    report.checks.length === REQUIRED_MCP_CHECKS.length &&
    new Set(names).size === names.length &&
    REQUIRED_MCP_CHECKS.every(name => report.checks.some(check => check.name === name && check.passed === true)) &&
    report.cleanup === true &&
    report.local?.approvedWrites === 1 &&
    report.remote?.approvedCalls === 1 &&
    report.remote?.redirectLeaks === 0 &&
    report.remote?.claimDenials === 7 &&
    report.remote?.reconciledAuthFailures === 7
  );
}
export async function verifyMcpIsolation({
  image = process.env.AGENT_GUARD_MCP_ISOLATION_IMAGE,
  expectedHost = process.env.AGENT_GUARD_EXPECTED_HOST,
} = {}) {
  const report = {
    version: 1,
    ...(expectedHost === undefined ? {} : { expectedHost }),
    time: new Date().toISOString(),
    image,
    isolation: 'linux-container-network-none',
    host: { platform: platform(), architecture: arch(), node: process.version },
    checks: [],
    cleanup: false,
    passed: false,
  };
  const mark = name => report.checks.push({ name, passed: true });
  let local,
    remote,
    connection,
    executor,
    bridge,
    collector,
    stage = 'configuration';
  const hostDirectory = mkdtempSync(join(homedir(), '.agent-guard-mcp-host-')),
    hostSecret = join(hostDirectory, 'host-secret');
  const canary = `HOST_PRIVATE_${randomBytes(24).toString('hex')}`;
  writeFileSync(hostSecret, canary, { mode: 0o600 });
  try {
    assert(imagePattern.test(image ?? ''), 'PINNED_NODE_IMAGE_REQUIRED');
    assert(expectedHost === undefined || hostPlatforms[expectedHost] === platform(), 'EXPECTED_HOST_MISMATCH');
    stage = 'runtime-image';
    const preflight = await runDockerSandbox({
      profile: { image, timeoutMs: 10000 },
      workspace: hostDirectory,
      inputFiles: [],
      command: ['node', '-e', 'process.stdout.write(process.version)'],
    });
    assert(preflight.exitCode === 0 && /^v\d+\./.test(preflight.stdout), 'NODE_IMAGE_REQUIRED');
    report.guestNode = preflight.stdout;
    mark(stage);
    executor = new DurableExecutor({
      database: ':memory:',
      encryptionKey: randomBytes(32),
      decisionTraces: { maxEventsPerTenant: 256 },
    });
    stage = 'local-guest-start';
    local = await startGuest(image, canary, hostSecret);
    stage = 'local-connection';
    connection = await ManagedMcpConnection.connect({
      guard: executor,
      identity: identity(),
      transport: local.transport(),
      tools: bindings(),
      limits: { requestTimeoutMs: 1500 },
    });
    report.initialConnection = local.connectionDiagnostics();
    const taskId = task(executor, connection.registrations, 'local');
    await denied(() => prepare(executor, taskId));
    reviewTools(executor, connection);
    stage = 'guest-isolation';
    const first = resultValue(await executor.execute(taskId, (await prepare(executor, taskId)).id));
    const probe = first.probe,
      profile = local.profile();
    assert(
      probe.uid === 1000 &&
        !probe.rootWrite &&
        !probe.egress &&
        probe.interfaces.length === 1 &&
        probe.interfaces[0] === 'lo' &&
        probe.capabilities &&
        probe.noNewPrivileges &&
        probe.seccomp,
      'GUEST_ISOLATION_FAILED',
    );
    assert(
      profile.NetworkMode === 'none' &&
        profile.ReadonlyRootfs &&
        profile.Privileged === false &&
        profile.CapDrop.includes('ALL') &&
        profile.Mounts.length === 1 &&
        profile.Mounts[0].Target === '/input' &&
        profile.Mounts[0].ReadOnly === true &&
        profile.SecurityOpt.includes('no-new-privileges:true'),
      'LAUNCH_PROFILE_FAILED',
    );
    mark(stage);
    stage = 'host-secret-custody';
    assert(
      existsSync(hostSecret) &&
        readFileSync(hostSecret, 'utf8') === canary &&
        !probe.hostFile &&
        !probe.hostCredential &&
        !probe.dockerSocket &&
        !local.environment().some(value => value.includes(canary) || value.startsWith('HOST_ONLY_CANARY=')),
      'HOST_SECRET_LEAK',
    );
    mark(stage);
    stage = 'foreign-tenant-before-dispatch';
    let before = local.counts().calls;
    await denied(() => prepare(executor, taskId, 'read', 'normal', 'foreign'));
    assert(local.counts().calls === before, 'FOREIGN_CALL_DISPATCHED');
    mark(stage);
    stage = 'approval-before-dispatch';
    const write = await prepare(executor, taskId, 'write');
    await denied(() => executor.execute(taskId, write.id));
    assert(local.counts().calls === before, 'UNAPPROVED_DISPATCH');
    mark(stage);
    stage = 'approved-effect';
    await executor.execute(taskId, write.id, {
      approvalId: approve(executor, write),
    });
    assert(local.counts().writes === 1 && local.exists('/workspace/approved-effect'), 'MISSING_APPROVED_EFFECT');
    report.local = { approvedWrites: 1 };
    mark(stage);
    stage = 'metadata-quarantine';
    const stale = await prepare(executor, taskId),
      drift = await prepare(executor, taskId, 'read', 'drift');
    await denied(() => executor.execute(taskId, drift.id));
    assert(connection.status === 'quarantined', 'NOT_QUARANTINED');
    before = local.counts().calls;
    await denied(() => executor.execute(taskId, stale.id));
    assert(local.counts().calls === before, 'STALE_DISPATCH');
    mark(stage);
    stage = 'reviewed-refresh';
    await connection.refresh();
    await denied(() => prepare(executor, taskId));
    reviewTools(executor, connection);
    await executor.execute(taskId, (await prepare(executor, taskId)).id);
    mark(stage);
    stage = 'reconnect-invalidates-work';
    const old = await prepare(executor, taskId),
      oldSession = connection.sessionId;
    await connection.close();
    await local.close();
    executor.reconcile(drift.id, {
      outcome: 'FAILED',
      actualCost: 0,
      reference: 'Disposed original fixture after metadata drift; no pending handler survives.',
    });
    local = await startGuest(image, canary, hostSecret);
    connection = await ManagedMcpConnection.connect({
      guard: executor,
      identity: identity(),
      transport: local.transport(),
      tools: bindings(),
      limits: { requestTimeoutMs: 1500 },
    });
    assert(connection.sessionId !== oldSession, 'SESSION_REUSED');
    await denied(() => executor.execute(taskId, old.id));
    await denied(() => prepare(executor, taskId));
    reviewTools(executor, connection);
    mark(stage);
    stage = 'revocation-before-dispatch';
    const revoked = task(executor, connection.registrations, 'revoked'),
      revokedAction = await prepare(executor, revoked);
    before = local.counts().calls;
    executor.revokeTask(revoked);
    await denied(() => executor.execute(revoked, revokedAction.id));
    assert(local.counts().calls === before, 'REVOKED_DISPATCH');
    mark(stage);
    stage = 'inflight-unknown-no-replay';
    const running = task(executor, connection.registrations, 'running'),
      hang = await prepare(executor, running, 'read', 'hang');
    const pending = executor.execute(running, hang.id);
    const rejection = denied(() => pending);
    await waitFor(() => local.exists('/workspace/entered'));
    executor.revokeTask(running);
    await rejection;
    assert(executor.snapshot(running).concurrent === 1, 'UNKNOWN_RESERVATION_LOST');
    before = local.counts().calls;
    await denied(() => executor.execute(running, hang.id));
    assert(local.counts().calls === before, 'UNKNOWN_REPLAY');
    mark(stage);
    await connection.close();
    connection = null;
    await local.close();
    local = null;
    stage = 'unknown-reconciliation';
    executor.reconcile(hang.id, {
      outcome: 'FAILED',
      actualCost: 0,
      reference: 'Disposed guest container; pending handler cannot resume.',
    });
    assert(executor.snapshot(running).concurrent === 0, 'RECONCILIATION_FAILED');
    mark(stage);
    stage = 'bounded-stdio';
    local = await startGuest(image, canary, hostSecret);
    connection = await ManagedMcpConnection.connect({
      guard: executor,
      identity: identity(),
      transport: local.transport(),
      tools: bindings(),
      limits: { requestTimeoutMs: 1500 },
    });
    reviewTools(executor, connection);
    const floodTask = task(executor, connection.registrations, 'flood'),
      flood = await prepare(executor, floodTask, 'read', 'flood');
    await denied(() => executor.execute(floodTask, flood.id));
    assert(connection.status !== 'ready', 'FLOOD_NOT_QUARANTINED');
    await connection.close();
    connection = null;
    await local.close();
    local = null;
    executor.reconcile(flood.id, {
      outcome: 'FAILED',
      actualCost: 0,
      reference: 'Disposed flooding fixture; pending work cannot resume.',
    });
    mark(stage);
    stage = 'remote-approved-dispatch';
    remote = await startGuest(image, canary, hostSecret);
    const token = randomBytes(24).toString('base64url');
    bridge = await gateway(remote.transport(), token);
    const origin = new URL(bridge.endpoint).origin;
    const network = createRestrictedFetch({
      allowedOrigins: [origin],
      allowPrivateOrigins: [origin],
      timeoutMs: 3000,
    });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const policy = {
      issuer: 'https://fixture-issuer.invalid',
      audience: bridge.endpoint,
      subject: 'host-operator',
      requiredScopes: ['mcp:call'],
    };
    const claims = {
      issuer: policy.issuer,
      audience: policy.audience,
      subject: policy.subject,
      scopes: ['mcp:call'],
      credentialSha256: createHash('sha256').update(token).digest('hex'),
      expiresAt: Date.now() / 1000 + 60,
    };
    const credential = value => {
      const body = Buffer.from(JSON.stringify(value));
      return { body, signature: sign(null, body, privateKey) };
    };
    let signed = credential(claims);
    const authorize = () => {
      assert(verify(null, signed.body, publicKey, signed.signature), 'SIGNATURE_INVALID');
      const verified = JSON.parse(signed.body);
      assert(
        verified.credentialSha256 === createHash('sha256').update(token).digest('hex'),
        'CREDENTIAL_BINDING_INVALID',
      );
      assertVerifiedMcpClaims(verified, policy);
    };
    connection = await ManagedMcpConnection.connect({
      guard: executor,
      identity: {
        ...identity(),
        transportIdentity: 'reviewed-remote-endpoint-v1',
      },
      transport: createRestrictedMcpHttpTransport({
        endpoint: bridge.endpoint,
        allowInsecureLoopback: true,
        fetch: network,
        headers: { authorization: `Bearer ${token}` },
      }),
      authorize,
      tools: bindings(),
      limits: { requestTimeoutMs: 1500 },
    });
    reviewTools(executor, connection);
    const remoteTask = task(executor, connection.registrations, 'remote');
    const remoteResult = resultValue(await executor.execute(remoteTask, (await prepare(executor, remoteTask)).id));
    assert(remoteResult.calls === 1, 'REMOTE_BENIGN_FAILED');
    report.remote = { approvedCalls: 1, redirectLeaks: 0 };
    mark(stage);
    stage = 'remote-credential-custody';
    const unauthenticated = await network(bridge.endpoint, {
      method: 'POST',
      headers: {
        authorization: 'Bearer wrong-fixture-token',
        'content-type': 'application/json',
      },
      body: '{}',
    });
    assert(unauthenticated.status === 401 && remote.counts().calls === 1, 'INVALID_GATEWAY_CREDENTIAL_ACCEPTED');
    await unauthenticated.body?.cancel();
    assert(
      bridge.stats().authenticated > 0 &&
        !remoteResult.probe.hostCredential &&
        !remoteResult.probe.hostFile &&
        !JSON.stringify(remoteResult).includes(token) &&
        !remote.environment().some(value => value.includes(token) || value.includes(canary)),
      'REMOTE_CREDENTIAL_LEAK',
    );
    mark(stage);
    stage = 'remote-claim-binding';
    for (const changed of [
      { issuer: 'https://wrong.invalid' },
      { audience: 'https://wrong.invalid' },
      { subject: 'wrong' },
      { scopes: [] },
      { expiresAt: 0 },
      { badSignature: true },
      { credentialSha256: '0'.repeat(64) },
    ]) {
      const action = await prepare(executor, remoteTask);
      const count = bridge.stats().requests;
      signed = credential({ ...claims, ...changed });
      if (changed.badSignature) signed.signature[0] ^= 1;
      await denied(() => executor.execute(remoteTask, action.id));
      assert(bridge.stats().requests === count, 'INVALID_CLAIMS_DISPATCHED');
      assert(executor.snapshot(remoteTask).concurrent === 1, 'AUTH_FAILURE_NOT_UNKNOWN');
      executor.reconcile(action.id, {
        outcome: 'FAILED',
        actualCost: 0,
        reference: 'Synthetic gateway received no request after failed authorization.',
      });
      signed = credential(claims);
      await connection.refresh();
      await denied(() => prepare(executor, remoteTask));
      reviewTools(executor, connection);
    }
    report.remote.claimDenials = 7;
    report.remote.reconciledAuthFailures = 7;
    mark(stage);
    mark('remote-refresh-review');
    stage = 'remote-redirect-no-forward';
    let leaks = 0;
    collector = createServer((_req, res) => {
      leaks++;
      res.end('unexpected');
    });
    await new Promise(resolve => collector.listen(0, '127.0.0.1', resolve));
    const deniedOrigin = `http://127.0.0.1:${collector.address().port}`;
    bridge.redirect(deniedOrigin + '/leak');
    before = remote.counts().calls;
    const redirectAction = await prepare(executor, remoteTask);
    await denied(() => executor.execute(remoteTask, redirectAction.id));
    assert(leaks === 0 && remote.counts().calls === before, 'REDIRECT_FORWARDED');
    executor.reconcile(redirectAction.id, {
      outcome: 'FAILED',
      actualCost: 0,
      reference: 'Fixture gateway redirected before forwarding and collector received no request.',
    });
    mark(stage);
    stage = 'remote-private-address-denied';
    await denied(() => createRestrictedFetch({ allowedOrigins: [deniedOrigin] })(deniedOrigin));
    assert(leaks === 0, 'PRIVATE_DESTINATION_CONTACTED');
    mark(stage);
    stage = 'trace-privacy';
    const traces = JSON.stringify(executor.decisionTraceSnapshot({ tenantId: 'tenant-a' }));
    assert(
      !traces.includes(canary) &&
        !traces.includes(token) &&
        !traces.includes(hostSecret) &&
        !traces.includes('task-local'),
      'TRACE_LEAK',
    );
    mark(stage);
  } catch (error) {
    try {
      if (local) report.localDiagnostics = local.diagnostics();
    } catch {
      report.localDiagnostics = { available: false };
    }
    if (error.container) (report.cleanupFailures ??= []).push({ container: error.container });
    report.failure = {
      stage,
      code: /^[A-Z_]+$/.test(error?.message ?? '') ? error.message : 'ISOLATION_CHECK_FAILED',
    };
  } finally {
    let cleaned = true;
    try {
      await connection?.close();
    } catch {
      cleaned = false;
    }
    try {
      await bridge?.close();
    } catch {
      cleaned = false;
    }
    if (collector) {
      collector.closeAllConnections();
      await new Promise(resolve => collector.close(resolve));
    }
    for (const guest of [local, remote])
      try {
        await guest?.close();
      } catch (error) {
        cleaned = false;
        if (error.container) (report.cleanupFailures ??= []).push({ container: error.container });
      }
    try {
      executor?.close();
    } catch {
      cleaned = false;
    }
    rmSync(hostDirectory, { recursive: true, force: true });
    report.cleanup = cleaned && !existsSync(hostDirectory) && report.cleanupFailures === undefined;
    if (report.cleanup) mark('cleanup');
  }
  report.sourceSha256 = createHash('sha256')
    .update(readFileSync(fileURLToPath(import.meta.url)))
    .digest('hex');
  report.fixtureSha256 = createHash('sha256').update(readFileSync(guestPath)).digest('hex');
  report.passed = validateMcpIsolationReport(report);
  report.limitations = [
    'Synthetic disposable MCP fixture and loopback credential gateway, not a real identity provider or production MCP service.',
    'Kernel isolation is the Linux Docker daemon/VM boundary. Native host ACL and separate Linux/Windows matrix evidence remain required.',
    'Remote authorization proofs are verified with a synthetic Ed25519 fixture key and bind the gateway token fingerprint. Production OAuth discovery/JWKS/token renewal is outside this report.',
    'Denied or cancelled admitted calls may be UNKNOWN; container disposal establishes termination before reconciliation.',
  ];
  return report;
}
export function parseOptions(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    assert(
      args[i] === '--output' && !options.output && args[i + 1] && !args[i + 1].startsWith('--'),
      'INVALID_OPTIONS',
    );
    options.output = args[++i];
  }
  return options;
}
if (isEntry(import.meta)) {
  try {
    const options = parseOptions(process.argv.slice(2));
    const report = await verifyMcpIsolation();
    const json = JSON.stringify(report, null, 2) + '\n';
    if (options.output) writeFileSync(options.output, json, { mode: 0o600 });
    else process.stdout.write(json);
    process.exitCode = report.passed ? 0 : 1;
  } catch {
    process.stderr.write('MCP isolation verification could not start or write its report.\n');
    process.exitCode = 2;
  }
}
