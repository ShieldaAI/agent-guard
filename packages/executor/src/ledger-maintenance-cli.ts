#!/usr/bin/env node
import { parseArgs } from 'node:util';
import {
  createLedgerKeyring,
  configureLedgerKeyring,
  readLedgerKeyringPolicy,
  loadLedgerKey,
  rotateLedgerKeyring,
} from './ledger-maintenance.js';
import { maintenanceHint, runLedgerCustodyCli, runLedgerRecoveryCli } from './custody-cli.js';
import { ExecutorError } from './store.js';

// Node 22 prints "SQLite is an experimental feature" on standard error the first time
// node:sqlite loads. This command's standard error carries its own error code and hint, so
// that one warning is dropped; every other warning is printed as usual. The warning is
// emitted after the imports above have run, so this filter is in place in time.
const printWarning = process.listeners('warning');
process.removeAllListeners('warning');
process.on('warning', warning => {
  if (warning.name === 'ExperimentalWarning' && /\bSQLite\b/.test(warning.message)) return;
  for (const listener of printWarning) listener(warning);
});

const usage = `agent-guard-ledger keygen --keyring PATH --key-id ID [--max-keys N]
agent-guard-ledger configure --keyring PATH --max-keys N
agent-guard-ledger status --keyring PATH [--database PATH [--witness PATH] [--max-bytes N]]
agent-guard-ledger rotate --keyring PATH --database PATH --next-key-id ID [--witness PATH] [--max-bytes N]
agent-guard-ledger recovery enroll|repair --config PATH [--apply --digest HASH]
agent-guard-ledger custody OPERATION --config PATH [--key-id ID | --backup-id ID] [--apply --digest HASH]
Custody operations: enroll, backup, verify, restore, rotate, retire, recover, status.
Generic CLI refuses external history; use the application custody command for its authoritative closure.
Retirement removes only inactive runtime keys after independent encrypted escrow; no key destruction.
Key limits: default 4, range 1..64; unmanaged rotation retains all keys.
Ledger byte limits: default 16777216, range 1048576..67108864.
Use canonical absolute paths on a private POSIX host. Stop every ledger owner before rotation.
Retain all keyring keys and use the same next-key-id when retrying an interrupted rotation.
Success prints one JSON line and exits 0. Failure exits 1 and prints an error code on the
first stderr line, then a one-line hint when one applies. Without --apply, recovery and custody
commands only preview and print a digest; repeat with --apply --digest HASH to act.`;

function main(args: string[]): void {
  if (args.length === 0 || args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    process.stdout.write(usage + '\n');
    return;
  }
  try {
    if (args[0] === 'recovery') {
      runLedgerRecoveryCli(args.slice(1));
      return;
    }
    if (args[0] === 'custody') {
      runLedgerCustodyCli(args.slice(1));
      return;
    }
    const { values, positionals, tokens } = parseArgs({
      args,
      tokens: true,
      allowPositionals: true,
      options: {
        keyring: { type: 'string' },
        database: { type: 'string' },
        witness: { type: 'string' },
        'key-id': { type: 'string' },
        'next-key-id': { type: 'string' },
        'max-keys': { type: 'string' },
        'max-bytes': { type: 'string' },
      },
    });
    const seen = new Set<string>();
    for (const token of tokens)
      if (token.kind === 'option') {
        if (seen.has(token.name)) throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
        seen.add(token.name);
      }
    if (positionals.length !== 1 || !values.keyring) throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
    const operation = positionals[0];
    const integer = (value: string): number => {
      if (!/^(?:0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value)))
        throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
      return Number(value);
    };
    if (operation === 'keygen') {
      if (!values['key-id'] || values.database || values.witness || values['next-key-id'] || values['max-bytes'])
        throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
      const result = createLedgerKeyring({
        keyringFile: values.keyring,
        keyId: values['key-id'],
        ...(values['max-keys'] === undefined ? {} : { maxKeys: integer(values['max-keys']) }),
      });
      process.stdout.write(JSON.stringify({ operation, keyId: result.keyId }) + '\n');
      return;
    }
    if (operation === 'configure') {
      if (
        !values['max-keys'] ||
        values.database ||
        values.witness ||
        values['key-id'] ||
        values['next-key-id'] ||
        values['max-bytes']
      )
        throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
      const result = configureLedgerKeyring({ keyringFile: values.keyring, maxKeys: integer(values['max-keys']) });
      process.stdout.write(JSON.stringify({ operation, ...result }) + '\n');
      return;
    }
    if (values['key-id'] || values['max-keys']) throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
    if (operation === 'status' && values['next-key-id'] === undefined && values.database === undefined) {
      if (values.witness || values['max-bytes']) throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
      process.stdout.write(
        JSON.stringify({ operation, ...readLedgerKeyringPolicy({ keyringFile: values.keyring }) }) + '\n',
      );
      return;
    }
    if (!values.database) throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
    const options = {
      database: values.database,
      keyringFile: values.keyring,
      ...(values.witness === undefined ? {} : { witnessPath: values.witness }),
      ...(values['max-bytes'] === undefined ? {} : { maxBytes: integer(values['max-bytes']) }),
    };
    if (operation === 'status' && values['next-key-id'] === undefined) {
      const policy = readLedgerKeyringPolicy(options),
        result = loadLedgerKey(options);
      try {
        process.stdout.write(JSON.stringify({ operation, keyId: result.keyId, ...policy }) + '\n');
      } finally {
        result.key.fill(0);
      }
    } else if (operation === 'rotate' && values['next-key-id']) {
      const result = rotateLedgerKeyring({ ...options, nextKeyId: values['next-key-id'] });
      process.stdout.write(
        JSON.stringify({
          operation,
          status: result.status,
          keyId: result.keyId,
          revision: result.revision,
          witnessed: result.witnessed,
          observationReenrollmentRequired: result.observationReenrollmentRequired,
        }) + '\n',
      );
    } else throw new ExecutorError('MAINTENANCE_ARGUMENT_INVALID');
  } catch (error) {
    // An unknown or malformed flag is an argument error, like a missing or repeated one.
    const parse =
      typeof (error as { code?: unknown })?.code === 'string' &&
      (error as { code: string }).code.startsWith('ERR_PARSE_ARGS_');
    const code =
      error instanceof ExecutorError ? error.code : parse ? 'MAINTENANCE_ARGUMENT_INVALID' : 'MAINTENANCE_FAILED';
    // The code stays alone on the first line. A plain hint follows for argument and common
    // environment mistakes; it is built from the code and its safe detail, never from a path.
    const hint = maintenanceHint(code, error instanceof ExecutorError ? error.detail : undefined);
    process.stderr.write(code + '\n' + (hint === undefined ? '' : hint + '\n'));
    process.exitCode = 1;
  }
}
main(process.argv.slice(2));
