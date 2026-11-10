import { createHash, randomUUID } from 'node:crypto';
import {
  constants,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import {
  createLedgerKeyring,
  configureLedgerKeyring,
  readLedgerKeyringPolicy,
} from '@shieldaai/agent-guard-executor/ops';
import { parseEvidenceJson } from '@shieldaai/agent-guard-executor/internal';
import { createMapOidcClient } from '@shieldaai/agent-map/oidc';
import { privateFile, openMaintenance, validateInitializationCapacity, validateConfiguredPaths } from './runtime.mjs';
import { validateIdentityEnrollment } from './server.mjs';
import { normalizeLimits, assertCapacity } from './limits.mjs';
import { privateHistoryDirectory, privateHistoryMirrorDirectory } from './history-files.mjs';
import { fields, fail, identifier, validateTicketSeed } from './workflow.mjs';
import { validateTls } from './tls-policy.mjs';

const jsonBytes = value => Buffer.byteLength(JSON.stringify(value));
const sha = value => createHash('sha256').update(value).digest('hex');
const encoded = value => JSON.stringify(value);
const INPUT_BYTES = 8 * 1024 * 1024;
export function readTicketFile(path) {
  return fields(parseEvidenceJson(privateFile(path, INPUT_BYTES), INPUT_BYTES, 100_000), ['tickets']);
}
function directory(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || realpathSync(path) !== path) fail('PRIVATE_DIRECTORY_REQUIRED');
  for (let current = path; ; current = dirname(current)) {
    const stat = lstatSync(current);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.uid !== 0 && stat.uid !== process.geteuid()) ||
      (stat.mode & 0o022 && !(stat.mode & 0o1000))
    )
      fail('PRIVATE_DIRECTORY_REQUIRED');
    if (current === path && (stat.uid !== process.geteuid() || stat.mode & 0o077)) fail('PRIVATE_DIRECTORY_REQUIRED');
    if (current === dirname(current)) break;
  }
}
function storage(dataDirectory, witnessDirectory) {
  directory(dataDirectory);
  directory(witnessDirectory);
  if (
    dataDirectory === witnessDirectory ||
    dataDirectory.startsWith(`${witnessDirectory}/`) ||
    witnessDirectory.startsWith(`${dataDirectory}/`)
  )
    fail('INDEPENDENT_WITNESS_DIRECTORY_REQUIRED');
}
function separate(left, right) {
  return left !== right && !left.startsWith(`${right}/`) && !right.startsWith(`${left}/`);
}
export function validateStoragePaths(config) {
  validateConfiguredPaths(config);
  for (const data of [dirname(config.ledgerDatabase), dirname(config.backendDatabase)]) {
    for (const witness of [dirname(config.ledgerWitness), dirname(config.backendWitness)]) storage(data, witness);
    if (!separate(dirname(config.keyringFile), data)) fail('INDEPENDENT_KEY_DIRECTORY_REQUIRED');
  }
  for (const witness of [dirname(config.ledgerWitness), dirname(config.backendWitness)])
    if (!separate(dirname(config.keyringFile), witness)) fail('INDEPENDENT_KEY_DIRECTORY_REQUIRED');
  directory(dirname(config.keyringFile));
  if (config.historyDirectory !== undefined) privateHistoryDirectory(config);
  if (config.historyMirrorDirectory !== undefined) privateHistoryMirrorDirectory(config);
}
function writePrivate(path, bytes) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function syncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Private local bundle only: no hosted account, bootstrap HTTP endpoint or authority reset. */
export function onboard({ manifestFile, outputDirectory }) {
  const manifest = fields(parseEvidenceJson(privateFile(manifestFile), 256 * 1024), [
    'version',
    'company',
    'publicOrigin',
    'oidc',
    'tls',
    'owner',
    'storage',
    'ticketsFile',
    'limits',
  ]);
  if (manifest.version !== 1) fail('ONBOARDING_MANIFEST_INVALID');
  fields(manifest.company, ['id', 'name']);
  identifier(manifest.company.id);
  if (
    manifest.company.name !== undefined &&
    (typeof manifest.company.name !== 'string' || !manifest.company.name.trim() || manifest.company.name.length > 120)
  )
    fail('ONBOARDING_MANIFEST_INVALID');
  fields(manifest.owner, ['subject', 'id', 'name']);
  const owner = { ...manifest.owner, tenantId: manifest.company.id, roles: ['requester', 'reviewer', 'operator'] };
  validateIdentityEnrollment([owner]);
  fields(manifest.storage, ['dataDirectory', 'witnessDirectory', 'historyDirectory', 'historyMirrorDirectory']);
  storage(manifest.storage.dataDirectory, manifest.storage.witnessDirectory);
  fields(manifest.tls, ['keyFile', 'certFile']);
  fields(manifest.oidc, ['issuer', 'clientId', 'clientSecretFile', 'caFile', 'endpointOrigins', 'clientAuthMethod']);
  const limits = normalizeLimits(manifest.limits);
  const tls = { key: privateFile(manifest.tls.keyFile), cert: privateFile(manifest.tls.certFile) };
  validateTls(tls, manifest.publicOrigin);
  const secret = privateFile(manifest.oidc.clientSecretFile, 4096),
    ca = manifest.oidc.caFile ? privateFile(manifest.oidc.caFile) : undefined;
  if (!secret.toString().trim()) fail('OIDC_CONFIG_INVALID');
  let issuer;
  try {
    issuer = new URL(manifest.oidc.issuer);
  } catch {
    fail('OIDC_CONFIG_INVALID');
  }
  if (
    issuer.protocol !== 'https:' ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash ||
    typeof manifest.oidc.clientId !== 'string' ||
    !manifest.oidc.clientId.trim()
  )
    fail('OIDC_CONFIG_INVALID');
  if (
    manifest.oidc.clientAuthMethod !== undefined &&
    !['client_secret_basic', 'client_secret_post'].includes(manifest.oidc.clientAuthMethod)
  )
    fail('OIDC_CONFIG_INVALID');
  if (
    manifest.oidc.endpointOrigins !== undefined &&
    (!Array.isArray(manifest.oidc.endpointOrigins) ||
      manifest.oidc.endpointOrigins.length > 16 ||
      manifest.oidc.endpointOrigins.some(value => {
        try {
          const u = new URL(value);
          return u.protocol !== 'https:' || u.origin !== value;
        } catch {
          return true;
        }
      }))
  )
    fail('OIDC_CONFIG_INVALID');
  const seed = manifest.ticketsFile ? readTicketFile(manifest.ticketsFile) : { tickets: [] };
  const tickets = validateInitializationCapacity(seed.tickets, limits);
  if (tickets.some(ticket => ticket.tenantId !== manifest.company.id)) fail('IMPORT_TENANT_NOT_ENROLLED');
  if (!isAbsolute(outputDirectory) || existsSync(outputDirectory)) fail('ONBOARDING_OUTPUT_EXISTS_OR_UNSAFE');
  const parent = dirname(outputDirectory);
  directory(parent);
  if (
    ![manifest.storage.dataDirectory, manifest.storage.witnessDirectory].every(path => separate(path, outputDirectory))
  )
    fail('INDEPENDENT_KEY_DIRECTORY_REQUIRED');
  const config = {
    version: 1,
    company: manifest.company,
    limits,
    publicOrigin: manifest.publicOrigin,
    listenHost: '0.0.0.0',
    port: 8443,
    historyDirectory: manifest.storage.historyDirectory ?? `${manifest.storage.dataDirectory}-history`,
    historyMirrorDirectory:
      manifest.storage.historyMirrorDirectory ?? join(manifest.storage.witnessDirectory, 'history-mirror'),
    ledgerDatabase: join(manifest.storage.dataDirectory, 'authority.sqlite'),
    backendDatabase: join(manifest.storage.dataDirectory, 'tickets.sqlite'),
    ledgerWitness: join(manifest.storage.witnessDirectory, 'authority.sqlite'),
    backendWitness: join(manifest.storage.witnessDirectory, 'tickets.sqlite'),
    keyringFile: join(outputDirectory, 'keyring.json'),
    tls: { keyFile: join(outputDirectory, 'tls.key'), certFile: join(outputDirectory, 'tls.pem') },
    oidc: {
      issuer: manifest.oidc.issuer,
      clientId: manifest.oidc.clientId,
      clientSecretFile: join(outputDirectory, 'oidc-client-secret'),
      ...(ca ? { caFile: join(outputDirectory, 'oidc-ca.pem') } : {}),
      ...(manifest.oidc.endpointOrigins ? { endpointOrigins: manifest.oidc.endpointOrigins } : {}),
      ...(manifest.oidc.clientAuthMethod ? { clientAuthMethod: manifest.oidc.clientAuthMethod } : {}),
    },
    bindings: [owner],
    agents: [],
  };
  validateConfiguredPaths(config);
  const staged = join(parent, `.agent-ops-setup-${randomUUID()}`);
  mkdirSync(staged, { mode: 0o700 });
  let createdHistory = false,
    createdMirror = false,
    published = false;
  try {
    if (!isAbsolute(config.historyDirectory)) fail('HISTORY_DIRECTORY_REQUIRED');
    if (!existsSync(config.historyDirectory)) {
      mkdirSync(config.historyDirectory, { mode: 0o700 });
      createdHistory = true;
    }
    privateHistoryDirectory(config);
    if (
      !isAbsolute(config.historyMirrorDirectory) ||
      dirname(config.historyMirrorDirectory) !== manifest.storage.witnessDirectory
    )
      fail('HISTORY_MIRROR_CUSTODY_REQUIRED');
    if (!existsSync(config.historyMirrorDirectory)) {
      mkdirSync(config.historyMirrorDirectory, { mode: 0o700 });
      createdMirror = true;
    }
    privateHistoryMirrorDirectory(config);
    for (const [name, bytes] of [
      ['config.json', encoded(config) + '\n'],
      ['tickets.json', encoded({ tickets }) + '\n'],
      ['tls.key', tls.key],
      ['tls.pem', tls.cert],
      ['oidc-client-secret', secret],
    ])
      writePrivate(join(staged, name), bytes);
    if (ca) writePrivate(join(staged, 'oidc-ca.pem'), ca);
    createLedgerKeyring({
      keyringFile: join(staged, 'keyring.json'),
      keyId: 'initial',
      maxKeys: limits.maxRetainedKeys,
    });
    syncDirectory(staged);
    if (existsSync(outputDirectory)) fail('ONBOARDING_OUTPUT_EXISTS_OR_UNSAFE');
    renameSync(staged, outputDirectory);
    syncDirectory(parent);
    published = true;
    return {
      status: 'prepared',
      company: manifest.company.id,
      tickets: tickets.length,
      limits,
      configFile: join(outputDirectory, 'config.json'),
      historyDirectory: config.historyDirectory,
      historyMirrorDirectory: config.historyMirrorDirectory,
      callbackUrl: `${manifest.publicOrigin}/auth/callback`,
      next: [
        'Enroll the exact callback URL and owner subject with your identity provider.',
        'Run preflight, then initialize using the generated tickets.json, then start the service.',
        'Sign in to verify your account; keep witness custody separate from data backups.',
      ],
    };
  } finally {
    tls.key.fill(0);
    secret.fill(0);
    rmSync(staged, { recursive: true, force: true });
    if (createdHistory && !published) {
      try {
        rmdirSync(config.historyDirectory);
      } catch {
        /* Never remove another writer's files. */
      }
    }
    if (createdMirror && !published) {
      try {
        rmdirSync(config.historyMirrorDirectory);
      } catch {
        /* Never remove another writer's files. */
      }
    }
  }
}

export async function preflight(config) {
  const checks = [];
  async function check(id, label, operation, message) {
    try {
      await operation();
      checks.push({ id, label, status: 'passed', message });
    } catch (error) {
      checks.push({
        id,
        label,
        status: 'failed',
        code: /^[A-Z_]{1,64}$/.test(error?.code ?? '') ? error.code : 'CHECK_FAILED',
        message: 'Correct this configuration before starting. Existing authority was not reset.',
      });
    }
  }
  await check(
    'tls',
    'HTTPS certificate and private key',
    () => validateTls(config.tls, config.publicOrigin),
    'Certificate matches the public hostname and private key, and is currently valid.',
  );
  await check(
    'identities',
    'Enrolled company identities',
    () => validateIdentityEnrollment(config.bindings, config.agents),
    'Explicit subjects, tenant scopes and roles are valid.',
  );
  await check(
    'storage',
    'Private storage paths',
    () => validateStoragePaths(config),
    'Private data, key and witness directories are separate. Keep their backup custody independent.',
  );
  await check(
    'keyring',
    'Key retention policy',
    () => {
      const policy = readLedgerKeyringPolicy({ keyringFile: config.keyringFile });
      if (policy.maxKeys !== normalizeLimits(config.limits).maxRetainedKeys) fail('KEY_LIMIT_MISMATCH');
    },
    'Keyring retention policy matches configuration.',
  );
  await check(
    'oidc',
    'Company identity provider discovery',
    () => createMapOidcClient({ ...config.oidc, redirectUri: `${config.publicOrigin}/auth/callback` }),
    'Discovery, HTTPS and protocol support verified. Complete browser sign-in to verify the client credential and enrolled subject.',
  );
  const paths = [config.ledgerDatabase, config.backendDatabase, config.ledgerWitness, config.backendWitness];
  if (paths.some(existsSync))
    await check(
      'state',
      'Existing durable authority',
      () => {
        if (!paths.every(existsSync)) fail('INCOMPLETE_AUTHORITY');
        const stores = openMaintenance(config);
        stores.close();
      },
      'Both existing stores authenticate under the configured policies.',
    );
  else
    checks.push({
      id: 'state',
      label: 'Durable authority',
      status: 'pending',
      message: 'No authority is enrolled yet. Run init once with the reviewed company ticket file.',
    });
  return {
    status: checks.some(c => c.status === 'failed') ? 'failed' : 'ready',
    callbackUrl: `${config.publicOrigin}/auth/callback`,
    checks,
  };
}

function reviewDigest(kind, stores, config, payload) {
  return sha(
    encoded({
      kind,
      guardInstanceId: stores.guard.read().inventoryInstanceId,
      guardRevision: stores.guard.read().revision,
      backendRevision: stores.backend.read().revision,
      limits: stores.limits,
      keyring: sha(privateFile(config.keyringFile, 32768)),
      tenants: [...new Set(config.bindings?.map(b => b.tenantId) ?? [])].sort(),
      payload,
    }),
  );
}
function approveDigest(input, expected) {
  if (!/^[a-f0-9]{64}$/.test(input ?? '') || input !== expected) fail('MAINTENANCE_PREVIEW_STALE');
}
export function configureLimits(config, { apply = false, digest } = {}) {
  const stores = openMaintenance(config, { ignorePolicy: true });
  try {
    const state = stores.backend.read(),
      current = normalizeLimits(state.ticketService.limits),
      desired = stores.limits;
    assertCapacity(state.ticketService, desired);
    const nextState = structuredClone(state);
    nextState.ticketService.limits = desired;
    if (jsonBytes(nextState) + 64 > desired.maxBackendBytes) fail('LIMITS_BELOW_USAGE');
    const expected = reviewDigest('configure-limits', stores, config, { current, desired });
    const review = {
      current,
      requested: desired,
      keyring: stores.keyring,
      retained: {
        tickets: Object.keys(state.ticketService.tickets).length,
        requests: Object.keys(state.ticketService.requests).length,
        receipts: Object.keys(state.ticketService.receipts).length,
      },
      digest: expected,
    };
    if (!apply)
      return {
        status: 'preview',
        ...review,
        next: 'Review the requested limits, then rerun with --apply --digest followed by this digest.',
      };
    approveDigest(digest, expected);
    // Keys are never deleted. If interrupted between these two commits, startup
    // refuses the policy mismatch; rerun preview/apply to finish the same change.
    configureLedgerKeyring({ keyringFile: config.keyringFile, maxKeys: desired.maxRetainedKeys });
    stores.backend.transaction(ledger => {
      assertCapacity(ledger.ticketService, desired);
      ledger.ticketService.limits = desired;
    });
    return {
      status: 'configured',
      limits: desired,
      keysRetained: stores.keyring.keyCount,
      next: 'Run check, then restart. Existing requests, receipts and budgets were retained.',
    };
  } finally {
    stores.close();
  }
}
export function importTickets(config, { ticketsFile, apply = false, digest }) {
  const limits = normalizeLimits(config.limits);
  const seed = readTicketFile(ticketsFile);
  const tickets = validateTicketSeed(seed.tickets, limits);
  if (!tickets.length) fail('IMPORT_EMPTY');
  const enrolled = new Set(config.bindings.map(binding => binding.tenantId));
  if (tickets.some(ticket => !enrolled.has(ticket.tenantId))) fail('IMPORT_TENANT_NOT_ENROLLED');
  const stores = openMaintenance(config);
  try {
    const state = stores.backend.read();
    for (const ticket of tickets) {
      if (Object.hasOwn(state.ticketService.tickets, ticket.id)) fail('IMPORT_TICKET_EXISTS');
      state.ticketService.tickets[ticket.id] = { ...ticket, version: 1 };
    }
    assertCapacity(state.ticketService, limits);
    if (jsonBytes(state) + 64 > limits.maxBackendBytes) fail('LIMITS_BELOW_USAGE');
    const expected = reviewDigest('import-tickets', stores, config, tickets);
    if (!apply)
      return {
        status: 'preview',
        added: tickets.length,
        existing: Object.keys(state.ticketService.tickets).length - tickets.length,
        total: Object.keys(state.ticketService.tickets).length,
        tenants: [...new Set(tickets.map(t => t.tenantId))].sort(),
        digest: expected,
        next: 'Only new ticket IDs will be added. Review this preview, then rerun with --apply --digest followed by this digest.',
      };
    approveDigest(digest, expected);
    stores.backend.transaction(ledger => {
      for (const ticket of tickets) {
        if (Object.hasOwn(ledger.ticketService.tickets, ticket.id)) fail('IMPORT_TICKET_EXISTS');
        ledger.ticketService.tickets[ticket.id] = { ...ticket, version: 1 };
      }
      assertCapacity(ledger.ticketService, limits);
    });
    return {
      status: 'imported',
      added: tickets.length,
      total: Object.keys(state.ticketService.tickets).length,
      next: 'Restart the service. Existing ticket versions, requests and receipts were preserved.',
    };
  } finally {
    stores.close();
  }
}
