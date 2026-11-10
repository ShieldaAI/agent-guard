import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { DurableExecutor } from '@shieldaai/agent-guard-executor';
import { LedgerStore } from '@shieldaai/agent-guard-executor/internal';
import { describeLedgerFormat } from '@shieldaai/agent-guard-executor/ops';
import { loadLedgerKey, readLedgerKeyring, readLedgerKeyringPolicy } from '@shieldaai/agent-guard-executor/ops';
import { parseEvidenceJson } from '@shieldaai/agent-guard-executor/internal';
import {
  TicketWorkflow,
  normalizeRequestPolicy,
  initializeTickets,
  validateTicketSeed,
  fields,
  fail,
  identifier,
} from './workflow.mjs';
import { normalizeLimits, assertCapacity, LIMIT_BOUNDS } from './limits.mjs';
import { validateIdentityEnrollment } from './server.mjs';
import { historyState } from './history-state.mjs';
import { historyDirectoryEnrollment, historyMirrorEnrollment, verifyHistoryStorage } from './retention.mjs';

const MAX_CONFIGURED_PATH_BYTES = 512;
/** Keep startup/onboarding within the paths accepted by offline current recovery. */
export function validateConfiguredPaths(config) {
  if (config.agents !== undefined && !Array.isArray(config.agents)) fail('CONFIG_INVALID');
  const paths = [
    config.ledgerDatabase,
    config.backendDatabase,
    config.ledgerWitness,
    config.backendWitness,
    config.keyringFile,
  ];
  for (const path of paths) if (typeof path !== 'string' || !isAbsolute(path)) fail('CONFIG_INVALID');
  paths.push(
    config.historyDirectory,
    config.historyMirrorDirectory,
    config.tls?.keyFile,
    config.tls?.certFile,
    config.oidc?.clientSecretFile,
    config.oidc?.caFile,
    ...(config.agents ?? []).map(agent => agent?.tokenFile),
  );
  for (const path of paths) {
    if (path === undefined) continue;
    if (typeof path !== 'string' || !isAbsolute(path)) fail('CONFIG_INVALID');
    if (Buffer.byteLength(path, 'utf8') > MAX_CONFIGURED_PATH_BYTES) fail('CONFIG_PATH_TOO_LONG');
  }
}

export function privateFile(path, maximum = 256 * 1024) {
  if (typeof path !== 'string' || !isAbsolute(path) || realpathSync(dirname(path)) !== dirname(path))
    fail('PRIVATE_FILE_REQUIRED');
  for (let parent = dirname(path); ; parent = dirname(parent)) {
    const stat = lstatSync(parent);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.uid !== 0 && stat.uid !== process.geteuid()) ||
      (stat.mode & 0o022 && !(stat.mode & 0o1000))
    )
      fail('PRIVATE_FILE_REQUIRED');
    if (parent === dirname(path) && (stat.uid !== process.geteuid() || stat.mode & 0o077))
      fail('PRIVATE_FILE_REQUIRED');
    if (parent === dirname(parent)) break;
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd),
      named = lstatSync(path);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.uid !== process.geteuid() ||
      before.mode & 0o077 ||
      before.size > maximum ||
      before.dev !== named.dev ||
      before.ino !== named.ino
    )
      fail('PRIVATE_FILE_REQUIRED');
    const data = readFileSync(fd),
      after = fstatSync(fd);
    if (
      data.length > maximum ||
      data.length !== before.size ||
      before.ctimeMs !== after.ctimeMs ||
      before.mtimeMs !== after.mtimeMs
    )
      fail('PRIVATE_FILE_CHANGED');
    return data;
  } finally {
    closeSync(fd);
  }
}
export function loadConfig(path) {
  const config = fields(parseEvidenceJson(privateFile(path), 256 * 1024), [
    'version',
    'company',
    'limits',
    'historyDirectory',
    'historyMirrorDirectory',
    'publicOrigin',
    'listenHost',
    'port',
    'ledgerDatabase',
    'backendDatabase',
    'ledgerWitness',
    'backendWitness',
    'keyringFile',
    'tls',
    'oidc',
    'bindings',
    'agents',
    'requests',
  ]);
  if (config.version !== 1 || !Array.isArray(config.bindings)) fail('CONFIG_INVALID');
  if (config.agents !== undefined && !Array.isArray(config.agents)) fail('CONFIG_INVALID');
  validateConfiguredPaths(config);
  const limits = normalizeLimits(config.limits);
  if (config.requests !== undefined) normalizeRequestPolicy(config.requests);
  if (
    config.historyDirectory !== undefined &&
    (typeof config.historyDirectory !== 'string' || !isAbsolute(config.historyDirectory))
  )
    fail('CONFIG_INVALID');
  if (
    config.historyMirrorDirectory !== undefined &&
    (typeof config.historyMirrorDirectory !== 'string' ||
      !isAbsolute(config.historyMirrorDirectory) ||
      !config.historyDirectory)
  )
    fail('CONFIG_INVALID');
  if (config.company !== undefined) {
    fields(config.company, ['id', 'name']);
    identifier(config.company.id);
    if (
      config.company.name !== undefined &&
      (typeof config.company.name !== 'string' || !config.company.name.trim() || config.company.name.length > 120)
    )
      fail('CONFIG_INVALID');
  }
  let origin;
  try {
    origin = new URL(config.publicOrigin);
  } catch {
    fail('PUBLIC_ORIGIN_INVALID');
  }
  if (origin.protocol !== 'https:' || origin.origin !== config.publicOrigin || origin.username || origin.password)
    fail('PUBLIC_ORIGIN_INVALID');
  fields(config.tls, ['keyFile', 'certFile']);
  fields(config.oidc, ['issuer', 'clientId', 'clientSecretFile', 'endpointOrigins', 'caFile', 'clientAuthMethod']);
  for (const key of ['ledgerDatabase', 'backendDatabase', 'ledgerWitness', 'backendWitness', 'keyringFile'])
    if (typeof config[key] !== 'string' || !isAbsolute(config[key])) fail('CONFIG_INVALID');
  if (
    new Set([
      config.ledgerDatabase,
      config.backendDatabase,
      config.ledgerWitness,
      config.backendWitness,
      config.keyringFile,
    ]).size !== 5
  )
    fail('CONFIG_INVALID');
  if (config.listenHost !== undefined && !['127.0.0.1', '0.0.0.0', '::1'].includes(config.listenHost))
    fail('CONFIG_INVALID');
  if (config.port !== undefined && (!Number.isInteger(config.port) || config.port < 1024 || config.port > 65535))
    fail('CONFIG_INVALID');
  if (config.agents !== undefined && !Array.isArray(config.agents)) fail('CONFIG_INVALID');
  const agents = (config.agents ?? []).map(agent => {
    fields(agent, ['id', 'tenantId', 'tokenFile', 'allowedTicketIds']);
    const { tokenFile, ...value } = agent;
    return { ...value, token: privateFile(tokenFile, 256).toString('utf8').trim() };
  });
  validateIdentityEnrollment(config.bindings, agents);
  const { clientSecretFile, caFile, ...oidc } = config.oidc;
  return {
    ...config,
    limits,
    agents,
    oidc: {
      ...oidc,
      clientSecret: privateFile(clientSecretFile, 4096).toString('utf8').trim(),
      ...(caFile ? { ca: privateFile(caFile).toString('utf8') } : {}),
    },
    tls: { key: privateFile(config.tls.keyFile), cert: privateFile(config.tls.certFile) },
  };
}
export function validateInitializationCapacity(tickets, policy) {
  const limits = normalizeLimits(policy),
    normalized = validateTicketSeed(tickets, limits);
  const prospective = {
    version: 1,
    guardInstanceId: '00000000-0000-0000-0000-000000000000',
    tickets: Object.fromEntries(normalized.map(ticket => [ticket.id, { ...ticket, version: 1 }])),
    requests: {},
    receipts: {},
    audit: [],
    lastClock: 0,
    limits,
  };
  assertCapacity(prospective, limits);
  // Reserve the initial ledger envelope and startup metadata before creating any
  // durable authority. Later writes still enforce the exact full-state byte cap.
  if (Buffer.byteLength(JSON.stringify(prospective)) + 4096 > limits.maxBackendBytes) fail('LIMITS_BELOW_USAGE');
  return normalized;
}
export function initializeRuntime(config, tickets) {
  validateConfiguredPaths(config);
  const limits = normalizeLimits(config.limits);
  const historyEnrollment = config.historyDirectory ? historyDirectoryEnrollment(config) : null;
  const mirrorEnrollment = config.historyMirrorDirectory ? historyMirrorEnrollment(config) : null;
  tickets = validateInitializationCapacity(tickets, limits);
  const policy = readLedgerKeyringPolicy({ keyringFile: config.keyringFile });
  if (policy.maxKeys !== limits.maxRetainedKeys) fail('KEY_LIMIT_MISMATCH');
  for (const path of [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness])
    if (existsSync(path)) fail('INITIALIZATION_REQUIRES_NEW_FILES');
  const keys = readLedgerKeyring({ keyringFile: config.keyringFile });
  let guard, backend;
  try {
    const recovery = mirrorEnrollment ? { recovery: 'mirror' } : {};
    guard = new LedgerStore(config.ledgerDatabase, keys[0].key, limits.maxLedgerBytes, {
      path: config.ledgerWitness,
      mode: 'create',
      ...recovery,
    });
    backend = new LedgerStore(config.backendDatabase, keys[0].key, limits.maxBackendBytes, {
      path: config.backendWitness,
      mode: 'create',
      ...recovery,
    });
    initializeTickets(backend, { guardInstanceId: guard.read().inventoryInstanceId, tickets, limits });
    if (historyEnrollment)
      backend.transaction(state => {
        if (state.schema === 1) state.schema = 2;
        const history = historyState(state.ticketService, true);
        history.enrollment = historyEnrollment;
        if (mirrorEnrollment) history.mirrorEnrollment = mirrorEnrollment;
      });
    return { initialized: true, keyId: keys[0].keyId };
  } finally {
    backend?.close();
    guard?.close();
    keys.forEach(entry => entry.key.fill(0));
  }
}
/** Offline access holds both owners simultaneously. No constructor recovery or policy mutation. */
export function openMaintenance(
  config,
  {
    ignorePolicy = false,
    allowHistoryPending = false,
    ignoreHistoryEnrollment = false,
    allowRecoveryEnrollment = false,
  } = {},
) {
  validateConfiguredPaths(config);
  const limits = normalizeLimits(config.limits);
  const guardBytes = ignorePolicy ? LIMIT_BOUNDS.maxLedgerBytes.max : limits.maxLedgerBytes;
  const backendBytes = ignorePolicy ? LIMIT_BOUNDS.maxBackendBytes.max : limits.maxBackendBytes;
  const guardKey = loadLedgerKey({
    database: config.ledgerDatabase,
    keyringFile: config.keyringFile,
    witnessPath: config.ledgerWitness,
    maxBytes: guardBytes,
  });
  let backendKey, guard, backend;
  try {
    backendKey = loadLedgerKey({
      database: config.backendDatabase,
      keyringFile: config.keyringFile,
      witnessPath: config.backendWitness,
      maxBytes: backendBytes,
    });
    guard = new LedgerStore(
      config.ledgerDatabase,
      guardKey.key,
      guardBytes,
      { path: config.ledgerWitness, mode: 'resume' },
      { existingOnly: true },
    );
    backend = new LedgerStore(
      config.backendDatabase,
      backendKey.key,
      backendBytes,
      { path: config.backendWitness, mode: 'resume' },
      { existingOnly: true },
    );
    const state = backend.read(),
      authority = guard.read(),
      keyring = readLedgerKeyringPolicy({ keyringFile: config.keyringFile });
    if (state.ticketService?.guardInstanceId !== authority.inventoryInstanceId) fail('AUTHORITY_STORE_MISMATCH', 503);
    if (
      Buffer.byteLength(JSON.stringify(state)) > limits.maxBackendBytes ||
      Buffer.byteLength(JSON.stringify(authority)) > limits.maxLedgerBytes
    )
      fail('LIMITS_BELOW_USAGE');
    assertCapacity(state.ticketService, limits);
    if (!ignorePolicy && JSON.stringify(normalizeLimits(state.ticketService.limits)) !== JSON.stringify(limits))
      fail('LIMITS_CHANGE_REQUIRES_OFFLINE');
    if (!ignorePolicy && keyring.maxKeys !== limits.maxRetainedKeys) fail('KEY_LIMIT_MISMATCH');
    if (keyring.keyCount > limits.maxRetainedKeys) fail('LIMITS_BELOW_USAGE');
    if (
      !allowRecoveryEnrollment &&
      config.historyMirrorDirectory &&
      (state.recoveryMirror !== 1 || authority.recoveryMirror !== 1)
    )
      fail('RECOVERY_ENROLLMENT_REQUIRED');
    verifyHistoryStorage({ guard, backend }, config, {
      allowPending: allowHistoryPending,
      ignoreEnrollment: ignoreHistoryEnrollment,
      verifyMirror: !allowRecoveryEnrollment,
    });
    return {
      guard,
      backend,
      limits,
      keyring,
      guardKeyId: guardKey.keyId,
      backendKeyId: backendKey.keyId,
      close() {
        backend.close();
        guard.close();
      },
    };
  } catch (error) {
    backend?.close();
    guard?.close();
    throw error;
  } finally {
    guardKey.key.fill(0);
    backendKey?.key.fill(0);
  }
}
export function openRuntime(config, { checkOnly = false, afterCommit, acceptClockSkewMs } = {}) {
  const limits = normalizeLimits(config.limits),
    preflight = openMaintenance(config);
  try {
    if (checkOnly)
      return {
        status: 'verified',
        guardKeyId: preflight.guardKeyId,
        backendKeyId: preflight.backendKeyId,
        // On-disk layout of the authority ledger; the executor migrates it at the next start.
        ledgerFormat: describeLedgerFormat(preflight.guard.read()),
      };
  } finally {
    preflight.close();
  }
  const guardKey = loadLedgerKey({
    database: config.ledgerDatabase,
    keyringFile: config.keyringFile,
    witnessPath: config.ledgerWitness,
    maxBytes: limits.maxLedgerBytes,
  });
  let backendKey, guard, backend, executor;
  try {
    backendKey = loadLedgerKey({
      database: config.backendDatabase,
      keyringFile: config.keyringFile,
      witnessPath: config.backendWitness,
      maxBytes: limits.maxBackendBytes,
    });
    guard = new LedgerStore(
      config.ledgerDatabase,
      guardKey.key,
      limits.maxLedgerBytes,
      { path: config.ledgerWitness, mode: 'resume' },
      { existingOnly: true },
    );
    const authority = guard.read(),
      guardInstanceId = authority.inventoryInstanceId;
    backend = new LedgerStore(
      config.backendDatabase,
      backendKey.key,
      limits.maxBackendBytes,
      { path: config.backendWitness, mode: 'resume' },
      { existingOnly: true },
    );
    const backendState = backend.read(),
      service = backendState.ticketService;
    if (service?.guardInstanceId !== guardInstanceId) fail('AUTHORITY_STORE_MISMATCH', 503);
    assertCapacity(service, limits);
    if (JSON.stringify(normalizeLimits(service.limits)) !== JSON.stringify(limits))
      fail('LIMITS_CHANGE_REQUIRES_OFFLINE');
    if (readLedgerKeyringPolicy({ keyringFile: config.keyringFile }).maxKeys !== limits.maxRetainedKeys)
      fail('KEY_LIMIT_MISMATCH');
    if (config.historyMirrorDirectory && (authority.recoveryMirror !== 1 || backendState.recoveryMirror !== 1))
      fail('RECOVERY_ENROLLMENT_REQUIRED');
    verifyHistoryStorage({ guard, backend }, config);
    // Only report enrollment after both encrypted stores and the bound history
    // directory/chain have been verified. This is a startup observation, not a
    // claim about independent-volume durability or an external restore drill.
    const executorMirror = authority.schema === 3 && authority.recoveryMirror === 1;
    const backendMirror = backendState.schema === 3 && backendState.recoveryMirror === 1;
    const historyMirror = Boolean(config.historyMirrorDirectory && historyState(service)?.mirrorEnrollment);
    const recovery = Object.freeze({
      mode: executorMirror && backendMirror && historyMirror ? 'current-state-mirror' : 'not-enrolled',
      executorMirror,
      backendMirror,
      historyMirror,
      verifiedAt: Date.now(),
    });
    guard.close();
    guard = undefined;
    executor = new DurableExecutor({
      database: config.ledgerDatabase,
      encryptionKey: guardKey.key,
      maxLedgerBytes: limits.maxLedgerBytes,
      rollbackWitness: { path: config.ledgerWitness, mode: 'resume' },
      ...(acceptClockSkewMs === undefined ? {} : { acceptClockSkewMs }),
    });
    const workflow = new TicketWorkflow({
      executor,
      store: backend,
      guardInstanceId,
      afterCommit,
      limits,
      requestPolicy: config.requests,
      ...(acceptClockSkewMs === undefined ? {} : { acceptClockSkewMs }),
    });
    return {
      workflow,
      executor,
      backend,
      recovery,
      close() {
        executor.close();
        backend.close();
      },
    };
  } catch (error) {
    executor?.close();
    backend?.close();
    throw error;
  } finally {
    guard?.close();
    guardKey.key.fill(0);
    backendKey?.key.fill(0);
  }
}
