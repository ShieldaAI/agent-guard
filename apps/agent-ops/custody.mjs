import { manageLedgerRecovery } from '../../packages/executor/dist/ledger-recovery.js';
import { manageLedgerCustody } from '../../packages/executor/dist/ledger-custody.js';
import { custodyRequest } from '../../packages/executor/dist/custody-cli.js';
import { privateBytes } from '../../packages/executor/dist/custody-files.js';
import { parseEvidenceJson } from '../../packages/executor/dist/evidence-json.js';
import { businessHistoryBackupAdapter } from './retention.mjs';
import { fail } from './workflow.mjs';

/** Offline-only. Runtime config and UI never load or mount independent custody keys. */
export function manageBusinessCustody(config, {custodyConfigFile, operation, keyId, backupId, apply, digest}) {
  const bytes = privateBytes(custodyConfigFile,16384); let value;
  try { value = parseEvidenceJson(bytes,16384); } finally { bytes.fill(0); }
  if (!value || value.version !== 1 || Object.keys(value).sort().join(',') !== 'backupDirectory,custodyDatabase,custodyKeyringFile,custodyWitness,version') fail('CUSTODY_CONFIG_INVALID');
  const request = custodyRequest(operation,keyId,backupId);
  if (apply ? !digest || ['status','verify'].includes(operation) : digest !== undefined) fail('USAGE_INVALID');
  return manageLedgerCustody({ ...value, keyringFile:config.keyringFile,
    stores:[{id:'authority',database:config.ledgerDatabase,witnessPath:config.ledgerWitness},{id:'tickets',database:config.backendDatabase,witnessPath:config.backendWitness}],
    history:businessHistoryBackupAdapter(config),
  },request,apply ? {expectedDigest:digest} : undefined);
}

/** Repair only current mirrored state; never uses a historical checkpoint. */
export function manageBusinessRecovery(config,{operation,apply,digest}) {
  if (!['enroll','repair'].includes(operation) || (apply ? !digest : digest !== undefined) || !config.historyMirrorDirectory) fail('RECOVERY_CONFIG_INVALID');
  return manageLedgerRecovery({keyringFile:config.keyringFile,
    stores:[{id:'authority',database:config.ledgerDatabase,witnessPath:config.ledgerWitness},{id:'tickets',database:config.backendDatabase,witnessPath:config.backendWitness}],
    history:businessHistoryBackupAdapter(config),
  },{operation},apply?{expectedDigest:digest}:undefined);
}
