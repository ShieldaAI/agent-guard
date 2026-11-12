#!/usr/bin/env node
import { dirname, resolve, sep } from 'node:path';
import { parseArgs } from 'node:util';
import { parseEvidenceJson } from './evidence-json.js';
import { verifyPilotReview, type PilotReviewPolicy, type PilotReviewBundle } from './pilot-review.js';
import {
  readPrivateFile,
  trustedDirectoryChain,
  type PrivateFileProblem,
  type PrivateFileRule,
} from './private-files.js';
import { ExecutorError } from './store.js';

const usage = 'agent-guard-pilot-review --policy PATH --candidate PATH --bundle PATH [--rehearsal]';
const limits = { policy: 32 * 1024, candidate: 64 * 1024 * 1024, bundle: 1024 * 1024 };
type Input = keyof typeof limits;
/**
 * The policy is the trust root: owned by root or this user and not writable by anyone
 * else. The bundle is confidential evidence: no group or other access. The candidate is
 * the public build output, bound by its digest.
 */
const rules: Record<Input, PrivateFileRule & { maximum: number }> = {
  policy: { owner: 'trusted', deny: 0o022, quiet: true, maximum: limits.policy },
  candidate: { owner: 'any', deny: 0, quiet: true, maximum: limits.candidate },
  bundle: { owner: 'any', deny: 0o077, quiet: true, maximum: limits.bundle },
};

/** A refusal with a code for the first stderr line and one plain sentence for the second. */
class CliFailure extends Error {
  constructor(
    readonly code: string,
    readonly hint: string,
  ) {
    super(code);
  }
}
const problems: Record<PrivateFileProblem, readonly [code: string, hint: string]> = {
  DIRECTORY_MISSING: ['PILOT_INPUT_UNAVAILABLE', 'its directory does not exist'],
  DIRECTORY_UNREADABLE: ['PILOT_INPUT_UNAVAILABLE', 'its directory cannot be read'],
  DIRECTORY_UNSAFE: [
    'PILOT_INPUT_UNSAFE',
    'a directory above it is a link, or is writable by or owned by another user (use chmod go-w)',
  ],
  FILE_MISSING: ['PILOT_INPUT_UNAVAILABLE', 'the file does not exist'],
  FILE_UNREADABLE: ['PILOT_INPUT_UNAVAILABLE', 'the file cannot be opened (check its permissions; a link is refused)'],
  FILE_EXISTS: ['PILOT_INPUT_UNAVAILABLE', 'the file cannot be opened'],
  FILE_UNSAFE: ['PILOT_INPUT_UNSAFE', 'it must be an ordinary file with one link and the permissions listed in --help'],
  FILE_TOO_LARGE: ['PILOT_INPUT_TOO_LARGE', 'the file is larger than the limit listed in --help'],
  FILE_CHANGED: ['PILOT_INPUT_CHANGED', 'the file changed while it was being read'],
};
const help = `${usage}
Prints one JSON line on success and exits 0. On failure exits 1 and prints an error code
on the first stderr line and a one-line explanation on the second.
Files: policy up to 32768 bytes, owned by you or root, not writable by group or others;
bundle up to 1048576 bytes, no group or other access (chmod 600); candidate up to 67108864 bytes.
Each must be an ordinary file with a single link. The policy path may not contain '..'.`;

function policyPath(path: string): string {
  // Use the same physical path for validation and opening. Reject ambiguous traversal
  // so normalizing '..' cannot silently select a different enrollment through a link.
  if (path.split(process.platform === 'win32' ? /[\\/]/u : sep).includes('..'))
    throw new CliFailure('PILOT_INPUT_UNSAFE', "Policy: the path may not contain '..'.");
  const absolute = resolve(path);
  // A trusted sticky directory such as /tmp protects each trusted-owned child against
  // replacement; the file check below verifies the policy's own owner.
  trustedDirectoryChain(dirname(absolute), problem => {
    throw new CliFailure(problems[problem][0], `Policy: ${problems[problem][1]}.`);
  });
  return absolute;
}

function readFile(path: string, kind: Input): Buffer {
  if (kind === 'policy') path = policyPath(path);
  // The descriptor that supplies the bytes is the one that is checked, before and after
  // the read. A link, a FIFO, a second hard link or a swapped file is refused.
  return readPrivateFile(path, rules[kind], problem => {
    throw new CliFailure(problems[problem][0], `${kind[0]!.toUpperCase()}${kind.slice(1)}: ${problems[problem][1]}.`);
  });
}
function json<T>(bytes: Buffer, kind: 'policy' | 'bundle'): T {
  try {
    return parseEvidenceJson(bytes, limits[kind]) as unknown as T;
  } catch {
    throw new CliFailure(
      'PILOT_INPUT_INVALID',
      `${kind === 'policy' ? 'Policy' : 'Bundle'}: the file is not UTF-8 JSON without duplicate object keys.`,
    );
  }
}

function inputs(args: string[]) {
  const { values, tokens } = parseArgs({
    args,
    tokens: true,
    allowPositionals: false,
    options: {
      policy: { type: 'string' },
      candidate: { type: 'string' },
      bundle: { type: 'string' },
      rehearsal: { type: 'boolean' },
    },
  });
  const seen = new Set<string>();
  for (const token of tokens) {
    if (token.kind !== 'option' || seen.has(token.name)) throw new Error();
    seen.add(token.name);
  }
  if (!values.policy || !values.candidate || !values.bundle) throw new Error();
  return { policy: values.policy, candidate: values.candidate, bundle: values.bundle, rehearsal: values.rehearsal };
}

/** One sentence per verification stage. Fixed text: nothing from the evidence is echoed. */
const checks: Record<string, string> = {
  POLICY: 'the policy does not have the documented fields and values',
  MODE: 'the policy mode differs from the requested mode (--rehearsal selects a rehearsal policy)',
  CANDIDATE: 'the candidate bytes are not acceptable',
  BUNDLE: 'the bundle does not have the documented fields',
  BOUNDARY: 'the boundary document does not match the policy digest, company, deployment or candidate',
  BUILD_ATTESTATION:
    'the build attestation does not verify for this candidate, or its signer is also the observer or reviewer',
  OBSERVATIONS: 'the signed observations do not verify, or do not bind this policy, run, candidate and build',
  REVIEW: 'the signed review does not verify, is not an approval without open exceptions, or is out of order',
  ACCESS_EVIDENCE: 'the access evidence does not match its signed digest or the required probe outcomes',
  RECOVERY_EVIDENCE: 'the recovery evidence does not match its signed digest or the required outcome',
  LOAD_EVIDENCE: 'the load evidence does not match its signed digest or the policy thresholds',
  VALIDITY_WINDOW: 'the current time is outside the window from the review to the policy expiry',
};

function main(args: string[]): void {
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
    process.stdout.write(help + '\n');
    return;
  }
  try {
    let options;
    try {
      options = inputs(args);
    } catch {
      throw new CliFailure('PILOT_ARGUMENT_INVALID', `Usage: ${usage}`);
    }
    const policy = json<PilotReviewPolicy>(readFile(options.policy, 'policy'), 'policy');
    const candidate = readFile(options.candidate, 'candidate');
    const bundle = json<PilotReviewBundle>(readFile(options.bundle, 'bundle'), 'bundle');
    const result = verifyPilotReview(policy, candidate, bundle, options.rehearsal ? 'rehearsal' : 'company-pilot');
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (error) {
    let code = 'PILOT_REVIEW_FAILED',
      hint = 'Unexpected failure. No evidence was accepted.';
    if (error instanceof CliFailure) ({ code, hint } = error);
    else if (error instanceof ExecutorError) {
      code = error.code;
      const check = error.detail !== undefined && Object.hasOwn(checks, error.detail) ? error.detail : undefined;
      hint = check ? `Failed check ${check}: ${checks[check]}.` : 'Pilot review verification failed.';
    }
    // The code stays alone on the first line. Neither line carries a path or file content.
    process.stderr.write(`${code}\n${hint}\n`);
    process.exitCode = 1;
  }
}

main(process.argv.slice(2));
