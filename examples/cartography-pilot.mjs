#!/usr/bin/env node
// Synthetic, local pilot host. Collector/reference outages never enter admission.
// Launch through the pilot runner; never point this example at an existing ledger.
import { randomBytes, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { DurableExecutor, validateInventoryManifest, startInventoryServer } from '../packages/executor/dist/index.js';
import { MapService, createNeo4jMapStore, startMapServer } from '../packages/agent-map/dist/index.js';
import { parseRequest } from '../packages/agent-map/dist/boundary.js';

const fail = code => { throw new Error(code); };
const keys = (value, allowed, required = allowed) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![null, Object.prototype].includes(Object.getPrototypeOf(value)) || Object.getOwnPropertySymbols(value).length) fail('PILOT_CONFIG_INVALID');
  for (const key of Object.getOwnPropertyNames(value)) {
    const entry = Object.getOwnPropertyDescriptor(value, key);
    if (!allowed.includes(key) || !entry.enumerable || !('value' in entry)) fail('PILOT_CONFIG_INVALID');
  }
  if (required.some(key => !Object.hasOwn(value, key))) fail('PILOT_CONFIG_INVALID');
  return value;
};
const port = value => { if (value !== undefined && (!Number.isInteger(value) || value < 0 || value > 65535)) fail('PILOT_CONFIG_INVALID'); return value ?? 0; };
const id = value => { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) fail('PILOT_CONFIG_INVALID'); return value; };
const principals = Object.freeze({
  blue: Object.freeze({ agentId: 'pilot-blue', taskId: 'pilot-blue-task', tenantId: 'alpha', teamId: 'blue' }),
  red: Object.freeze({ agentId: 'pilot-red', taskId: 'pilot-red-task', tenantId: 'alpha', teamId: 'red' }),
  beta: Object.freeze({ agentId: 'pilot-beta', taskId: 'pilot-beta-task', tenantId: 'beta', teamId: 'blue' }),
});

async function privateDirectory(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) fail('PILOT_CONFIG_INVALID');
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()))) fail('PILOT_PRIVATE_PATH_REQUIRED');
  const canonical = await realpath(path), current = await lstat(canonical);
  if (current.dev !== stat.dev || current.ino !== stat.ino || !current.isDirectory()) fail('PILOT_PRIVATE_PATH_REQUIRED');
  return canonical;
}

/** The launcher reads only a bounded regular owner-private file, never stdin secrets. */
export async function readPilotConfig(path) {
  // Native Windows needs an independently verified ACL provisioning path.
  // A POSIX mode bit is not evidence of privacy there; use the pilot from WSL2.
  if (process.platform === 'win32') fail('PILOT_PLATFORM_UNSUPPORTED');
  let handle;
  try {
    if (typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number') fail('PILOT_CONFIG_INVALID');
    // Open once without following symlinks or waiting for a FIFO writer. Check
    // the same descriptor that supplies bytes; a path check before open can race.
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.size > 65_536 ||
        (opened.mode & 0o077) !== 0 || opened.uid !== process.getuid()) fail('PILOT_CONFIG_INVALID');
    const bytes = Buffer.alloc(65_537); let size = 0;
    while (size < bytes.length) { const read = await handle.read(bytes, size, bytes.length - size, null); if (!read.bytesRead) break; size += read.bytesRead; }
    return parseRequest(bytes.subarray(0, size), 65_536);
  } catch { return fail('PILOT_CONFIG_INVALID'); }
  finally { await handle?.close(); }
}

/** Trusted-host API used by the pilot runner and lifecycle tests. */
export async function startPilotHost(input) {
  const config = keys(input, ['stateDirectory', 'observerToken', 'referenceTokens', 'neo4j', 'viewerDirectory', 'companyId', 'observerPort', 'referencePort'],
    ['stateDirectory', 'observerToken', 'referenceTokens', 'neo4j']);
  if (typeof config.observerToken !== 'string' || !/^agi_v1\.[A-Za-z0-9_-]{43}$/.test(config.observerToken)) fail('PILOT_CONFIG_INVALID');
  const tokens = keys(config.referenceTokens, ['blue', 'red', 'beta']);
  if (Object.values(tokens).some(token => typeof token !== 'string' || !/^agm_v1\.[A-Za-z0-9_-]{43}$/.test(token)) || new Set(Object.values(tokens)).size !== 3) fail('PILOT_CONFIG_INVALID');
  const connection = keys(config.neo4j, ['uri', 'username', 'password', 'database'], ['uri', 'username', 'password']);
  if (config.viewerDirectory !== undefined && (typeof config.viewerDirectory !== 'string' || !isAbsolute(config.viewerDirectory))) fail('PILOT_CONFIG_INVALID');
  const companyId = config.companyId === undefined ? `pilot-${randomUUID()}` : id(config.companyId);
  const observerPort = port(config.observerPort), referencePort = port(config.referencePort);
  const directory = await privateDirectory(config.stateDirectory);
  // mkdir is deliberately exclusive: an existing authority directory is never opened.
  const authority = join(directory, 'synthetic-authority');
  await mkdir(authority, { mode: 0o700 });
  const executor = new DurableExecutor({ database: join(authority, 'ledger.sqlite'), encryptionKey: randomBytes(32),
    inventory: { companyId, sourceId: 'synthetic-pilot-executor', enrollmentGeneration: randomUUID() } });
  let observer, reference, store, closed = false, executions = 0;
  const tool = 'reports.read';
  const selection = name => { if (!Object.hasOwn(principals, name)) fail('PILOT_REQUEST_INVALID'); return principals[name]; };
  const status = () => {
    const inventory = executor.inventorySnapshot({ tenantId: 'alpha' });
    return { ledgerRevision: inventory.ledgerRevision, inventoryInstanceId: inventory.source.inventoryInstanceId,
      observerRunning: observer !== undefined, referenceRunning: reference !== undefined, executions,
      calls: Object.fromEntries(Object.entries(principals).map(([name, agent]) => [name, executor.snapshot(agent.taskId).calls])) };
  };
  async function close() {
    if (closed) return; closed = true;
    const results = await Promise.allSettled([reference?.close(), observer?.close(), store?.close()]);
    reference = undefined; observer = undefined;
    executor.close();
    if (results.some(result => result.status === 'rejected')) fail('PILOT_CLOSE_FAILED');
  }
  try {
    const fingerprint = executor.registerTool({ name: tool, description: 'Synthetic pilot report reader',
      resolve(args) { const target = selection(args.report); return { resourceId: `report-${args.report}`, tenantId: target.tenantId }; },
      execute() { executions++; return { value: { text: 'Synthetic report content' } }; } });
    executor.approveTool(tool, fingerprint);
    for (const [name, agent] of Object.entries(principals)) executor.createTask({ id: agent.taskId, principalId: `synthetic-${name}-caller`, tenantId: agent.tenantId,
      grants: [{ tool, resources: [`report-${name}`] }],
      budget: { maxCalls: 1000, maxConcurrent: 1, maxCost: 0, deadline: Date.now() + 86_400_000 } });
    const sources = [], manifests = [];
    for (const tenantId of ['alpha', 'beta']) {
      const snapshot = executor.inventorySnapshot({ tenantId }); sources.push(snapshot.source);
      const agents = Object.entries(principals).filter(([, agent]) => agent.tenantId === tenantId);
      manifests.push(validateInventoryManifest({ schemaVersion: 1, evidenceKind: 'host_asserted', source: snapshot.source,
        manifestId: `pilot-${tenantId}`, revision: 1, observedAt: snapshot.generatedAt,
        agents: agents.map(([name, agent]) => ({ id: agent.agentId, name: `Synthetic ${name} assistant`, ownerId: `pilot-${name}-owner`, teamId: agent.teamId })),
        deployments: agents.map(([, agent]) => ({ id: `${agent.agentId}-deployment`, agentId: agent.agentId, environment: 'isolated-pilot' })),
        taskBindings: agents.map(([, agent]) => ({ taskId: agent.taskId, deploymentId: `${agent.agentId}-deployment` })),
        resourceBindings: agents.map(([name, agent]) => ({ id: `${agent.agentId}-report`, tool,
          resourceRef: snapshot.tasks.find(task => task.id === agent.taskId).grants[0].resources[0],
          target: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '', arn: `arn:aws:s3:::synthetic-pilot-reports/${name}.txt`, kind: 'object' },
          actions: ['s3:GetObject'], scope: 'exact' })),
        executionBindings: agents.map(([name, agent]) => ({ id: `${agent.agentId}-execution`, tool, deploymentId: `${agent.agentId}-deployment`, connectionId: null,
          identitySelection: 'static', identity: { provider: 'aws', partition: 'aws', accountId: '111122223333', region: '', arn: `arn:aws:iam::111122223333:role/SyntheticPilot-${name}` } })),
      }));
    }
    observer = await startInventoryServer({ executor, port: observerPort, observers: [{ token: config.observerToken, tenantIds: ['alpha', 'beta'], profile: 'host' }], manifests });
    store = createNeo4jMapStore({ ...connection });
    const service = new MapService(store);
    const referenceOptions = { service, port: referencePort, credentials: Object.entries(principals).map(([name, agent]) => ({ token: tokens[name],
      scope: { subject: `pilot-${name}-reader`, companyId, tenantIds: [agent.tenantId], teamIds: [agent.teamId], allTeams: false } })),
      ...(config.viewerDirectory ? { viewerDirectory: config.viewerDirectory } : {}) };
    reference = await startMapServer(referenceOptions);
    const ready = { event: 'ready', observerUrl: observer.url, observerEndpoint: `${observer.url}/v1/inventory/snapshot`,
      referenceUrl: reference.url, sources, profile: 'host', agents: principals, inventory: status() };
    const command = async input => {
      if (closed) fail('PILOT_CLOSED');
      let request;
      try { request = keys(input, ['command', 'task', 'resource', 'neo4j'], ['command']); } catch { return { ok: false, code: 'PILOT_REQUEST_INVALID' }; }
      if (typeof request.command !== 'string' || !['execute', 'revoke', 'status', 'stop-observer', 'stop-reference', 'start-reference', 'close'].includes(request.command)) return { ok: false, code: 'PILOT_REQUEST_INVALID' };
      if ((!['execute', 'revoke'].includes(request.command) && (request.task !== undefined || request.resource !== undefined)) ||
          (request.command === 'revoke' && request.resource !== undefined) ||
          (request.neo4j !== undefined && (request.command !== 'start-reference' || reference))) return { ok: false, code: 'PILOT_REQUEST_INVALID' };
      try {
        if (request.command === 'close') { await close(); return { ok: true, closed: true }; }
        if (request.command === 'execute') {
          const name = request.task ?? 'blue', task = selection(name); selection(request.resource ?? name);
          const action = await executor.prepare(task.taskId, { tool, args: { report: request.resource ?? name, privateCanary: 'pilot-private-argument-canary' } });
          await executor.execute(task.taskId, action.id);
        } else if (request.command === 'revoke') executor.revokeTask(selection(request.task ?? 'blue').taskId);
        else if (request.command === 'stop-observer') { await observer?.close(); observer = undefined; }
        else if (request.command === 'stop-reference') { await reference?.close(); reference = undefined; }
        else if (request.command === 'start-reference' && !reference) {
          if (request.neo4j !== undefined) {
            const updated = keys(request.neo4j, ['uri', 'username', 'password', 'database'], ['uri', 'username', 'password']);
            const nextStore = createNeo4jMapStore({ ...updated });
            await store.close(); store = nextStore; referenceOptions.service = new MapService(store);
          }
          reference = await startMapServer(referenceOptions);
        }
        return { ok: true, ...status(), ...(reference ? { referenceUrl: reference.url } : {}) };
      } catch (error) {
        const code = ['PILOT_REQUEST_INVALID', 'GRANT_DENIED', 'TENANT_DENIED', 'TASK_REVOKED', 'TASK_EXPIRED', 'CALL_BUDGET_EXCEEDED', 'COST_BUDGET_EXCEEDED'].includes(error?.code ?? error?.message)
          ? error.code ?? error.message : 'PILOT_COMMAND_FAILED';
        return { ok: false, code, ...status() };
      }
    };
    return { ready, command, close };
  } catch (error) { await close(); throw error; }
}

export async function runPilotHost(argv = process.argv.slice(2)) {
  const { values } = parseArgs({ args: argv, options: { config: { type: 'string' }, help: { type: 'boolean' } }, strict: true });
  if (values.help) { process.stdout.write('cartography-pilot --config PRIVATE_CONFIG.json\n'); return; }
  if (!values.config) fail('PILOT_CONFIG_INVALID');
  const host = await startPilotHost(await readPilotConfig(resolve(values.config)));
  const abort = new AbortController();
  const stop = () => { abort.abort(); process.stdin.destroy(); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    process.stdout.write(`${JSON.stringify(host.ready)}\n`);
    let pending = Buffer.alloc(0);
    for await (const chunk of process.stdin) {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > 4096) fail('PILOT_REQUEST_INVALID');
      let end;
      while ((end = pending.indexOf(10)) >= 0) {
        const line = pending.subarray(0, end); pending = pending.subarray(end + 1);
        let request; try { request = parseRequest(line, 4096); } catch { fail('PILOT_REQUEST_INVALID'); }
        const result = await host.command(request); process.stdout.write(`${JSON.stringify(result)}\n`);
        if (result.closed) return;
      }
    }
    if (pending.length && !abort.signal.aborted) fail('PILOT_REQUEST_INVALID');
  } catch (error) { if (!abort.signal.aborted) throw error; }
  finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); await host.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void runPilotHost().catch(() => { process.stderr.write('PILOT_HOST_FAILED\n'); process.exitCode = 1; });
}
