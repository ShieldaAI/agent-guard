#!/usr/bin/env node
// agent-guard-explain CODE [CODE ...] | --list | --json CODE
import { explainCode, knownCodes } from './explain.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const codes = args.filter(arg => !arg.startsWith('--')).map(arg => arg.trim().toUpperCase());

if (args.includes('--help') || args.includes('-h') || (codes.length === 0 && !args.includes('--list'))) {
  process.stdout.write(
    'Usage: agent-guard-explain CODE [CODE ...]\n' +
      '       agent-guard-explain --list\n' +
      '       agent-guard-explain --json CODE\n\n' +
      'Explains an Agent Guard denial code (for example GRANT_DENIED): what it means, the usual\n' +
      'cause, whether retrying can help, and what the model is told.\n',
  );
  process.exitCode =
    codes.length === 0 && !args.includes('--list') && !args.includes('--help') && !args.includes('-h') ? 2 : 0;
} else if (args.includes('--list')) {
  process.stdout.write(`${knownCodes().join('\n')}\n`);
} else {
  let unknown = 0;
  const found = [];
  for (const code of codes) {
    const info = explainCode(code);
    if (!info) {
      unknown += 1;
      process.stderr.write(`Unknown code: ${code.replace(/[^A-Z0-9_]/g, '?')}. Run with --list to see every code.\n`);
      continue;
    }
    found.push(info);
    if (!json)
      process.stdout.write(
        `${info.code} (${info.source})\n` +
          `  Meaning:   ${info.meaning}\n` +
          `  Cause:     ${info.cause}\n` +
          `  Retryable: ${info.retryable ? 'yes' : 'no'}\n` +
          `  Model is told: ${info.modelMessage}\n`,
      );
  }
  if (json) process.stdout.write(`${JSON.stringify(found.length === 1 ? found[0] : found, null, 2)}\n`);
  if (unknown > 0) process.exitCode = 1;
}
