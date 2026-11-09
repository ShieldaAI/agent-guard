#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import { readLedgerKeyringPolicy } from '../../packages/executor/dist/ledger-maintenance.js';
import { loadConfig, initializeRuntime, openRuntime, openMaintenance } from './runtime.mjs';
import { enrollBusinessHistoryMirror, enrollBusinessHistory, previewBusinessHistory, applyBusinessHistory, verifyHistoryStorage, lookupBusinessHistory } from './retention.mjs';
import { startOpsServer } from './server.mjs';
import { fail } from './workflow.mjs';
import { onboard, preflight, configureLimits, importTickets, readTicketFile, validateStoragePaths } from './onboarding.mjs';
import { manageBusinessCustody, manageBusinessRecovery } from './custody.mjs';
import { validateTls } from './tls-policy.mjs';

const log = (event, details = {}) => process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), event, ...details })}\n`);
const usage = `Agent Ops single-owner Linux service
  node apps/agent-ops/cli.mjs onboard --manifest /private/company.json --output-dir /private/new-company-bundle
  node apps/agent-ops/cli.mjs preflight --config /absolute/private/config.json
  node apps/agent-ops/cli.mjs --config /absolute/private/config.json
  node apps/agent-ops/cli.mjs init --config /absolute/private/config.json --tickets /absolute/private/tickets.json
  node apps/agent-ops/cli.mjs check --config /absolute/private/config.json
  node apps/agent-ops/cli.mjs configure-limits --config PATH [--apply --digest REVIEW_DIGEST]
  node apps/agent-ops/cli.mjs import-tickets --config PATH --tickets PATH [--apply --digest REVIEW_DIGEST]
  node apps/agent-ops/cli.mjs custody --config PATH --custody-config OFFLINE_PATH --operation OP [--key-id ID | --backup-id ID] [--apply --digest HASH]
  node apps/agent-ops/cli.mjs recovery --config PATH --operation enroll|repair [--apply --digest HASH]
  node apps/agent-ops/cli.mjs enroll-history-mirror --config PATH [--apply --digest HASH]
  node apps/agent-ops/cli.mjs enroll-history --config PATH [--apply --digest REVIEW_DIGEST]
  node apps/agent-ops/cli.mjs compact-history --config PATH --tenant COMPANY [--limit 100] [--apply --digest REVIEW_DIGEST]
  node apps/agent-ops/cli.mjs verify-history --config PATH
  node apps/agent-ops/cli.mjs lookup-history --config PATH --tenant COMPANY --request REQUEST_ID
Init accepts new stores only. Check and key rotation require the running owner to be stopped.
See deployment/production/README.md for enrollment, backup, rotation and recovery.`;
let runtime, http;
try {
  if (process.argv.slice(2).length === 1 && process.argv[2] === '--help') { process.stdout.write(usage + '\n'); process.exit(0); }
  if (process.platform !== 'linux') fail('LINUX_DEPLOYMENT_REQUIRED');
  const args = process.argv.slice(2), command = args[0]?.startsWith('--') ? 'serve' : args.shift();
  const parsed = parseArgs({ args, strict: true, tokens: true, options: {
    config: { type: 'string' }, tickets: { type: 'string' }, manifest: { type: 'string' }, 'output-dir': { type: 'string' }, apply: { type: 'boolean' }, digest: { type: 'string' },
    'custody-config': {type:'string'}, operation:{type:'string'}, 'key-id':{type:'string'}, 'backup-id':{type:'string'},
    tenant: { type: 'string' }, request: { type: 'string' }, limit: { type: 'string' },
  } });
  const flags = parsed.values, names = parsed.tokens.filter(token => token.kind === 'option').map(token => token.name);
  if (new Set(names).size !== names.length) fail('USAGE_INVALID');
  const allowed = { serve: ['config'], init: ['config', 'tickets'], check: ['config'], preflight: ['config'],
    onboard: ['manifest', 'output-dir'], 'configure-limits': ['config', 'apply', 'digest'], 'import-tickets': ['config', 'tickets', 'apply', 'digest'],
    recovery:['config','operation','apply','digest'], 'enroll-history-mirror':['config','apply','digest'],
    custody:['config','custody-config','operation','key-id','backup-id','apply','digest'],
    'enroll-history': ['config', 'apply', 'digest'], 'compact-history': ['config', 'tenant', 'limit', 'apply', 'digest'],
    'verify-history': ['config'], 'lookup-history': ['config', 'tenant', 'request'] };
  if (!allowed[command] || names.some(name => !allowed[command].includes(name)) || (flags.apply ? !flags.digest : flags.digest !== undefined)) fail('USAGE_INVALID');
  if (command === 'onboard') {
    if (!flags.manifest || !flags['output-dir']) fail('USAGE_INVALID');
    log('ONBOARDING_PREPARED', onboard({ manifestFile: flags.manifest, outputDirectory: flags['output-dir'] }));
  } else {
  if (!flags.config) fail('USAGE_INVALID');
  const config = loadConfig(flags.config);
  // The actual entry point enforces custody even when preflight was skipped.
  if (command !== 'preflight') validateStoragePaths(config);
  if (command === 'serve' || command === 'init') validateTls(config.tls, config.publicOrigin);
  if (command === 'init') {
    if (!flags.tickets) fail('USAGE_INVALID');
    const seed = readTicketFile(flags.tickets);
    const enrolled = new Set(config.bindings.map(binding => binding.tenantId));
    if (!Array.isArray(seed.tickets) || seed.tickets.some(ticket => !enrolled.has(ticket?.tenantId))) fail('IMPORT_TENANT_NOT_ENROLLED');
    log('INITIALIZED', initializeRuntime(config, seed.tickets));
  } else if (command === 'check') log('STORES_VERIFIED', openRuntime(config, { checkOnly: true }));
  else if (command === 'preflight') { const result = await preflight(config); log('PREFLIGHT', result); if (result.status === 'failed') process.exitCode = 1; }
  else if (command === 'configure-limits') log('LIMIT_CONFIGURATION', configureLimits(config, { apply: flags.apply, digest: flags.digest }));
  else if (command === 'import-tickets') {
    if (!flags.tickets) fail('USAGE_INVALID');
    log('TICKET_IMPORT', importTickets(config, { ticketsFile: flags.tickets, apply: flags.apply, digest: flags.digest }));
  }
  else if (command === 'recovery') {
    if (!flags.operation) fail('USAGE_INVALID');
    log('CURRENT_STATE_RECOVERY',manageBusinessRecovery(config,{operation:flags.operation,apply:flags.apply,digest:flags.digest}));
  }
  else if (command === 'custody') {
    if (!flags['custody-config'] || !flags.operation) fail('USAGE_INVALID');
    log('OFFLINE_CUSTODY', manageBusinessCustody(config,{custodyConfigFile:flags['custody-config'],operation:flags.operation,keyId:flags['key-id'],backupId:flags['backup-id'],apply:flags.apply,digest:flags.digest}));
  }
  else if (['enroll-history-mirror', 'enroll-history', 'compact-history', 'verify-history', 'lookup-history'].includes(command)) {
    if (['compact-history', 'lookup-history'].includes(command) && !config.bindings.some(binding => binding.tenantId === flags.tenant)) fail('HISTORY_SCOPE_INVALID');
    if (flags.limit !== undefined && (!/^[1-9][0-9]{0,2}$/.test(flags.limit) || Number(flags.limit) > 100)) fail('USAGE_INVALID');
    const stores = openMaintenance(config, { allowHistoryPending: ['compact-history', 'enroll-history', 'enroll-history-mirror'].includes(command), allowRecoveryEnrollment: command === 'enroll-history-mirror', ignoreHistoryEnrollment: command === 'enroll-history' });
    try {
      if (command === 'enroll-history-mirror') log('HISTORY_MIRROR_ENROLLMENT',enrollBusinessHistoryMirror(stores,config,{apply:flags.apply,digest:flags.digest}));
      else if (command === 'enroll-history') log('HISTORY_ENROLLMENT', enrollBusinessHistory(stores, config, { apply: flags.apply, digest: flags.digest }));
      else if (command === 'compact-history') {
        const options = { tenantId: flags.tenant, limit: flags.limit === undefined ? 100 : Number(flags.limit), digest: flags.digest };
        log('COMPANY_HISTORY', flags.apply ? applyBusinessHistory(stores, config, options) : previewBusinessHistory(stores, config, options));
      } else if (command === 'verify-history') log('HISTORY_VERIFIED', verifyHistoryStorage(stores, config));
      else {
        const found = lookupBusinessHistory(stores, config, { tenantId: flags.tenant, requestId: flags.request });
        log('HISTORY_LOOKUP', found ? { found: true, requestId: found.request.id, state: found.request.state,
          receipt: found.receipt, segment: found.segment, commitment: found.commitment } : { found: false });
      }
    } finally { stores.close(); }
  }
  else {
    runtime = openRuntime(config);
    http = await startOpsServer({ ...config, host: config.listenHost, workflow: runtime.workflow, recovery: runtime.recovery,
      onSecurityEvent: ({ event, ...details }) => {
        if (process.stdout.destroyed || process.stdout.writableLength > 1_048_576) throw Error('SECURITY_LOG_BACKPRESSURE');
        log(event, details);
      },
      keyringPolicy: () => readLedgerKeyringPolicy({ keyringFile: config.keyringFile }) });
    // Identities and TLS material reload in place; anything else needs a restart.
    const fingerprint = value => { const { bindings, agents, tls, ...fixed } = value; return createHash('sha256').update(JSON.stringify(fixed)).digest('hex'); };
    let stopping = false;
    const stop = async (event, exitCode = 0) => {
      if (stopping) return; stopping = true; clearInterval(monitor);
      log(event);
      const timeout = setTimeout(() => process.exit(1), 25_000); timeout.unref();
      await http.close(); runtime.close(); clearTimeout(timeout); process.exitCode = exitCode;
    };
    process.on('SIGHUP', () => {
      try {
        const next = loadConfig(flags.config);
        if (fingerprint(next) !== fingerprint(config)) fail('RESTART_REQUIRED');
        http.replaceTls(next.tls); log('TLS_RELOADED');
        http.replaceBindings(next.bindings, next.agents); log('IDENTITIES_RELOADED');
      } catch { void stop('CONFIG_RELOAD_FAILED', 1); }
    });
    process.on('SIGTERM', () => { void stop('SHUTTING_DOWN'); });
    process.on('SIGINT', () => { void stop('SHUTTING_DOWN'); });
    const monitor = setInterval(() => {
      try {
        log('OPERATIONS_STATUS', http.monitoringSummary());
      } catch { void stop('STORE_HEALTH_FAILED', 1); }
    }, 60_000); monitor.unref();
    log('READY', { publicOrigin: config.publicOrigin });
  }
  }
} catch (error) {
  await http?.close(); runtime?.close();
  const code = typeof error?.code === 'string' && /^[A-Z_]{1,64}$/.test(error.code) ? error.code : 'CONFIG_OR_STORE_UNAVAILABLE';
  process.stderr.write(`${JSON.stringify({ event: 'START_FAILED', code, help: 'See deployment/production/README.md. Preserve existing state; do not initialize as a repair.' })}\n`);
  if (code === 'USAGE_INVALID') process.stderr.write(usage + '\n');
  process.exitCode = 1;
}
