import { manageLedgerRecovery, type LedgerRecoveryOptions } from './ledger-recovery.js';
import { parseArgs } from 'node:util';
import { parseEvidenceJson } from './evidence-json.js';
import { privateBytes, custodyFail } from './custody-files.js';
import { manageLedgerCustody, type CustodyRequest, type LedgerCustodyOptions } from './ledger-custody.js';

function readLedgerCustodyConfig(path: string): LedgerCustodyOptions {
  const bytes = privateBytes(path, 32768);
  try {
    const value = parseEvidenceJson(bytes, 32768) as unknown as LedgerCustodyOptions & { version?: number };
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      value.version !== 1 ||
      Object.keys(value).sort().join(',') !==
        'backupDirectory,custodyDatabase,custodyKeyringFile,custodyWitness,keyringFile,stores,version' ||
      !Array.isArray(value.stores) ||
      value.stores.some(
        s => !s || typeof s !== 'object' || Object.keys(s).sort().join(',') !== 'database,id,witnessPath',
      )
    )
      custodyFail('CUSTODY_CONFIG_INVALID');
    return value;
  } finally {
    bytes.fill(0);
  }
}
export function custodyRequest(operation: string, keyId?: string, backupId?: string): CustodyRequest {
  if (['enroll', 'backup', 'status', 'recover'].includes(operation) && keyId === undefined && backupId === undefined)
    return { operation: operation as 'enroll' | 'backup' | 'status' | 'recover' };
  if (['verify', 'restore'].includes(operation) && backupId && keyId === undefined)
    return { operation: operation as 'verify' | 'restore', backupId };
  if (operation === 'retire' && keyId && backupId === undefined) return { operation, keyId };
  if (operation === 'rotate' && keyId && backupId === undefined) return { operation, nextKeyId: keyId };
  return custodyFail('CUSTODY_REQUEST_INVALID');
}
export function runLedgerCustodyCli(args: string[]): void {
  const { values, positionals, tokens } = parseArgs({
    args,
    tokens: true,
    allowPositionals: true,
    strict: true,
    options: {
      config: { type: 'string' },
      'key-id': { type: 'string' },
      'backup-id': { type: 'string' },
      apply: { type: 'boolean' },
      digest: { type: 'string' },
    },
  });
  const names = tokens.filter(token => token.kind === 'option').map(token => token.name);
  if (
    new Set(names).size !== names.length ||
    positionals.length !== 1 ||
    !values.config ||
    (values.apply ? !values.digest : values.digest !== undefined)
  )
    custodyFail('MAINTENANCE_ARGUMENT_INVALID');
  const request = custodyRequest(positionals[0]!, values['key-id'], values['backup-id']);
  if (values.apply && ['status', 'verify'].includes(request.operation)) custodyFail('MAINTENANCE_ARGUMENT_INVALID');
  const result = manageLedgerCustody(
    readLedgerCustodyConfig(values.config),
    request,
    values.apply ? { expectedDigest: values.digest! } : undefined,
  );
  process.stdout.write(JSON.stringify(result) + '\n');
}

/** Generic stores without external history; applications supply their own authoritative adapter. */
export function runLedgerRecoveryCli(args: string[]): void {
  const { values, positionals, tokens } = parseArgs({
    args,
    tokens: true,
    allowPositionals: true,
    strict: true,
    options: { config: { type: 'string' }, apply: { type: 'boolean' }, digest: { type: 'string' } },
  });
  const names = tokens.filter(token => token.kind === 'option').map(token => token.name);
  if (
    new Set(names).size !== names.length ||
    positionals.length !== 1 ||
    !['enroll', 'repair'].includes(positionals[0]!) ||
    !values.config ||
    (values.apply ? !values.digest : values.digest !== undefined)
  )
    custodyFail('MAINTENANCE_ARGUMENT_INVALID');
  const bytes = privateBytes(values.config, 32768);
  let config: LedgerRecoveryOptions;
  try {
    const value = parseEvidenceJson(bytes, 32768) as unknown as LedgerRecoveryOptions & { version?: number };
    if (
      !value ||
      value.version !== 1 ||
      Object.keys(value).sort().join(',') !== 'keyringFile,stores,version' ||
      !Array.isArray(value.stores) ||
      value.stores.some(s => !s || Object.keys(s).sort().join(',') !== 'database,id,witnessPath')
    )
      custodyFail('RECOVERY_CONFIG_INVALID');
    config = value;
  } finally {
    bytes.fill(0);
  }
  const result = manageLedgerRecovery(
    config,
    { operation: positionals[0] as 'enroll' | 'repair' },
    values.apply ? { expectedDigest: values.digest! } : undefined,
  );
  process.stdout.write(JSON.stringify(result) + '\n');
}
