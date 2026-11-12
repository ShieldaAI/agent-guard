import { manageLedgerRecovery, type LedgerRecoveryOptions } from './ledger-recovery.js';
import { parseArgs } from 'node:util';
import { parseEvidenceJson } from './evidence-json.js';
import { privateBytes, custodyFail } from './custody-files.js';
import { ExecutorError } from './store.js';
import { manageLedgerCustody, type CustodyRequest, type LedgerCustodyOptions } from './ledger-custody.js';

/** Read a private config file. A missing or unsafe file is reported as the config, not as custody state. */
function configBytes(path: string): Buffer {
  try {
    return privateBytes(path, 32768);
  } catch (error) {
    if (!(error instanceof ExecutorError)) throw error;
    throw new ExecutorError('MAINTENANCE_CONFIG_UNREADABLE', {
      ...(error.detail === undefined ? {} : { detail: error.detail }),
      cause: error,
    });
  }
}
function configJson(bytes: Buffer, code: string): unknown {
  try {
    return parseEvidenceJson(bytes, 32768);
  } catch {
    // No cause: a parser message could quote the file.
    return custodyFail(code);
  }
}
function readLedgerCustodyConfig(path: string): LedgerCustodyOptions {
  const bytes = configBytes(path);
  try {
    const value = configJson(bytes, 'CUSTODY_CONFIG_INVALID') as LedgerCustodyOptions & { version?: number };
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
    // The API takes the options alone: the file's version member stays here.
    return {
      keyringFile: value.keyringFile,
      custodyDatabase: value.custodyDatabase,
      custodyWitness: value.custodyWitness,
      custodyKeyringFile: value.custodyKeyringFile,
      backupDirectory: value.backupDirectory,
      stores: value.stores,
    };
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
  const bytes = configBytes(values.config);
  let config: LedgerRecoveryOptions;
  try {
    const value = configJson(bytes, 'RECOVERY_CONFIG_INVALID') as LedgerRecoveryOptions & { version?: number };
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      value.version !== 1 ||
      Object.keys(value).sort().join(',') !== 'keyringFile,stores,version' ||
      !Array.isArray(value.stores) ||
      value.stores.some(
        s => !s || typeof s !== 'object' || Object.keys(s).sort().join(',') !== 'database,id,witnessPath',
      )
    )
      custodyFail('RECOVERY_CONFIG_INVALID');
    config = { keyringFile: value.keyringFile, stores: value.stores };
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

const problemHints: Record<string, (subject: string) => string> = {
  FILE_MISSING: s => `The ${s} file does not exist.`,
  DIRECTORY_MISSING: s => `The directory that should hold the ${s} file does not exist.`,
  DIRECTORY_UNSAFE: s =>
    `The ${s} directory must belong to you with mode 0700 and no symbolic link in its path (chmod 700).`,
  DIRECTORY_UNREADABLE: s => `The ${s} directory cannot be read. Check its owner and permissions.`,
  FILE_UNSAFE: s => `The ${s} file must be an ordinary file that you own, with mode 0600 and one link (chmod 600).`,
  FILE_UNREADABLE: s => `The ${s} file cannot be opened. Check its owner and permissions; a symbolic link is refused.`,
  FILE_TOO_LARGE: s => `The ${s} file is larger than allowed.`,
  FILE_CHANGED: s => `The ${s} file changed while it was being read. Retry.`,
  FILE_EXISTS: () => 'A file already exists where a new one would be written. Nothing was overwritten.',
  LOCKED: () => 'The ledger is still owned by a running process. Stop every ledger owner, then retry.',
  KEY_MISMATCH: () => 'No key in the keyring opens this ledger.',
  EACCES: () => 'A file or directory is not writable by you. Check its owner and permissions.',
  EPERM: () => 'A file or directory is not writable by you. Check its owner and permissions.',
  EROFS: () => 'The file system is read-only.',
  ENOSPC: () => 'The disk is full.',
};
const codeHints: Record<string, string> = {
  MAINTENANCE_ARGUMENT_INVALID: 'Run agent-guard-ledger --help for usage.',
  CUSTODY_REQUEST_INVALID: 'Run agent-guard-ledger --help for usage.',
  RECOVERY_REQUEST_INVALID: 'Run agent-guard-ledger --help for usage.',
  MAINTENANCE_CONFIG_INVALID: 'Every path must be absolute, and the host must be Linux or macOS.',
  STORE_CONFIG_INVALID: '--max-bytes must be between 1048576 and 67108864.',
  KEYRING_LIMIT_INVALID: 'The key limit must be between 1 and 64 and not below the number of keys already held.',
  KEYRING_EXISTS: 'A keyring already exists at that path. keygen never replaces one.',
  KEYRING_BUSY: 'Another maintenance command is using this keyring. Wait for it to finish, then retry.',
  KEYRING_CAPACITY: 'The keyring is full. Raise its limit with configure --max-keys.',
  KEYRING_INVALID: 'The keyring file is not a valid keyring.',
  CUSTODY_CONFIG_INVALID: 'The config file does not have the documented custody shape.',
  RECOVERY_CONFIG_INVALID: 'The config file does not have the documented recovery shape.',
  CUSTODY_PREVIEW_CHANGED: 'State changed after the preview. Run the preview again and apply its new digest.',
  RECOVERY_PREVIEW_CHANGED: 'State changed after the preview. Run the preview again and apply its new digest.',
  CUSTODY_NOT_ENROLLED: 'Run custody enroll first.',
  CUSTODY_RECOVERY_REQUIRED: 'An earlier operation was interrupted. Run custody recover.',
  LEDGER_KEY_UNAVAILABLE: 'No key in the keyring opens this ledger. Check --witness and --max-bytes.',
};
const subjects: readonly (readonly [prefix: string, subject: string])[] = [
  ['MAINTENANCE_CONFIG_', 'config'],
  ['KEYRING_', 'keyring'],
  ['CUSTODY_', 'custody'],
  ['RECOVERY_', 'ledger'],
  ['LEDGER_', 'ledger'],
  ['STORE_', 'ledger'],
];
/**
 * One plain sentence for the second stderr line, or undefined when there is nothing
 * useful to add. Built only from the error code and its safe detail: it never contains
 * a path, a key or anything read from a config file.
 */
export function maintenanceHint(code: string, detail?: string): string | undefined {
  const subject = subjects.find(([prefix]) => code.startsWith(prefix))?.[1] ?? 'named';
  const problem = detail !== undefined && Object.hasOwn(problemHints, detail) ? problemHints[detail] : undefined;
  return problem?.(subject) ?? (Object.hasOwn(codeHints, code) ? codeHints[code] : undefined);
}
